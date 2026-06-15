#!/usr/bin/env python3
"""
RFID Attendance System — Raspberry Pi 4B (Ubuntu Server 24.04 LTS)

RC522 wiring (SPI, BCM pin numbering):
  SS/SDA  ->  GPIO8  (Pin 24)  — hardware CE0
  SCK     ->  GPIO11 (Pin 23)
  MOSI    ->  GPIO10 (Pin 19)
  MISO    ->  GPIO9  (Pin 21)
  RST     ->  GPIO27 (Pin 13)
  GND     ->  Pin 9
  VCC     ->  Pin 17  (3.3 V)

Dependencies:
  sudo apt install -y python3-rpi.gpio python3-spidev
  sudo python3 -m pip install mfrc522 --break-system-packages

Usage:
  sudo python3 rfid_attendance.py           # normal operation
  sudo python3 rfid_attendance.py --scan    # discover card UIDs
"""

import io
import logging
import os
import signal
import sqlite3
import sys
import time
from datetime import datetime

import RPi.GPIO as GPIO
from mfrc522 import SimpleMFRC522

# ---------------------------------------------------------------------------
# Suppress AUTH ERROR spam printed by the mfrc522 library to stdout/stderr.
# The library uses the root logger and also writes directly to stdout in some
# versions — redirect both to /dev/null during normal operation.
# ---------------------------------------------------------------------------
logging.getLogger().setLevel(logging.CRITICAL)

class _SuppressAuthErrors(io.TextIOBase):
    """Drop any line that contains known mfrc522 noise."""
    _NOISE = ("AUTH ERROR", "status2reg")

    def __init__(self, wrapped: io.TextIOBase) -> None:
        self._wrapped = wrapped

    def write(self, s: str) -> int:
        if any(tag in s for tag in self._NOISE):
            return len(s)
        return self._wrapped.write(s)

    def flush(self) -> None:
        self._wrapped.flush()

sys.stdout = _SuppressAuthErrors(sys.__stdout__)  # type: ignore[assignment]
sys.stderr = _SuppressAuthErrors(sys.__stderr__)  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Card registry — maps integer UID to (first_name, last_name).
# Run with --scan to discover the UID of an unknown card.
# ---------------------------------------------------------------------------
CARDS: dict[int, tuple[str, str]] = {
    584187865769: ("Rick",    "Sanchez"),
    584189365924: ("Antonio", "Margaretti"),
    3394371378: ("Bibo",    "Bortoleto"),
    2284849230: ("Max",     "Verstappen"),
}

# Path to the SQLite database file used for persistent event storage.
DB_FILE = "attendance.db"

# Minimum interval (seconds) before the same card can trigger another event.
# Prevents duplicate reads from a single tap.
DEBOUNCE_SEC = 3

# ANSI color codes for terminal output.
_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GRAY   = "\033[90m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def init_db(path: str) -> sqlite3.Connection:
    """Open (or create) the SQLite database and ensure the schema exists."""
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # safer concurrent writes
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name  TEXT    NOT NULL,
            event      TEXT    NOT NULL CHECK(event IN ('in', 'out')),
            ts         TEXT    NOT NULL
        )
    """)
    conn.commit()
    return conn


def log_event(conn: sqlite3.Connection, full_name: str, event: str, ts: str) -> None:
    """Persist a single check-in or check-out event to the database."""
    conn.execute(
        "INSERT INTO attendance (full_name, event, ts) VALUES (?, ?, ?)",
        (full_name, event, ts),
    )
    conn.commit()


def last_event(conn: sqlite3.Connection, full_name: str) -> str | None:
    """Return the most recent event type ('in' or 'out') for a person, or None if no record exists."""
    row = conn.execute(
        "SELECT event FROM attendance WHERE full_name = ? ORDER BY id DESC LIMIT 1",
        (full_name,),
    ).fetchone()
    return row["event"] if row else None


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

def now_str() -> str:
    """Return the current local time as a formatted string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _clear() -> None:
    """Clear the terminal screen."""
    sys.__stdout__.write("\033[2J\033[H")
    sys.__stdout__.flush()


def print_header() -> None:
    """Print the application header bar."""
    sys.__stdout__.write(
        f"\n{_BOLD}{_CYAN}  RFID Attendance System{_RESET}"
        f"  {_GRAY}{now_str()}{_RESET}\n"
        f"  {_GRAY}{'─' * 44}{_RESET}\n"
    )
    sys.__stdout__.flush()


def print_event(full_name: str, event: str, ts: str) -> None:
    """Print a colour-coded attendance event to stdout."""
    if event == "in":
        color, arrow, label = _GREEN, "→", "IN "
    else:
        color, arrow, label = _RED, "←", "OUT"
    sys.__stdout__.write(
        f"  {_GRAY}{ts}{_RESET}  "
        f"{color}{_BOLD}[{label}]{_RESET}  "
        f"{arrow}  {_BOLD}{full_name}{_RESET}\n"
    )
    sys.__stdout__.flush()


def print_unknown(uid: int) -> None:
    """Print a warning for an unregistered card UID."""
    sys.__stdout__.write(
        f"  {_GRAY}{now_str()}{_RESET}  "
        f"{_YELLOW}{_BOLD}[???]{_RESET}  "
        f"Unknown card  UID: {uid}\n"
    )
    sys.__stdout__.flush()


def print_status(conn: sqlite3.Connection) -> None:
    """Print the current attendance status of every registered card holder."""
    sys.__stdout__.write(f"\n  {'Name':<22} Status\n")
    sys.__stdout__.write(f"  {'─'*22} {'─'*8}\n")
    for _, (first, last) in CARDS.items():
        full = f"{first} {last}"
        ev = last_event(conn, full)
        if ev == "in":
            status = f"{_GREEN}● IN    {_RESET}"
        elif ev == "out":
            status = f"{_YELLOW}○ OUT   {_RESET}"
        else:
            status = f"{_RED}  ABSENT{_RESET}"
        sys.__stdout__.write(f"  {full:<22} {status}\n")
    sys.__stdout__.write("\n")
    sys.__stdout__.flush()


# ---------------------------------------------------------------------------
# Main reader loop
# ---------------------------------------------------------------------------

def run(conn: sqlite3.Connection) -> None:
    """Continuously poll the RC522 reader and process card events."""
    reader = SimpleMFRC522()

    last_uid: int | None = None
    last_scan: float = 0.0

    print_header()
    print_status(conn)
    sys.__stdout__.write(f"  {_GRAY}Waiting for card...{_RESET}\n\n")
    sys.__stdout__.flush()

    try:
        while True:
            uid, _ = reader.read_no_block()  # non-blocking; returns None when no card is present

            if uid is None:
                time.sleep(0.1)
                continue

            now = time.monotonic()

            # Ignore repeated reads of the same card within the debounce window.
            if uid == last_uid and (now - last_scan) < DEBOUNCE_SEC:
                time.sleep(0.1)
                continue

            last_uid  = uid
            last_scan = now
            ts        = now_str()

            if uid not in CARDS:
                print_unknown(uid)
                time.sleep(0.1)
                continue

            first, last = CARDS[uid]
            full_name = f"{first} {last}"

            # Toggle the event: if the last recorded event was 'in', register 'out', and vice versa.
            prev  = last_event(conn, full_name)
            event = "out" if prev == "in" else "in"

            log_event(conn, full_name, event, ts)
            print_event(full_name, event, ts)

    finally:
        GPIO.cleanup()


# ---------------------------------------------------------------------------
# Scan mode — prints the UID of every card presented (for initial registration)
# ---------------------------------------------------------------------------

def scan_mode() -> None:
    """Read and display card UIDs without recording any attendance events."""
    reader = SimpleMFRC522()
    sys.__stdout__.write(
        f"\n{_BOLD}{_CYAN}  Scan Mode{_RESET}"
        f"  {_GRAY}present cards to discover their UIDs  |  Ctrl+C to exit{_RESET}\n"
        f"  {_GRAY}{'─' * 54}{_RESET}\n\n"
    )
    sys.__stdout__.flush()
    seen: set[int] = set()
    try:
        while True:
            uid, _ = reader.read_no_block()
            if uid and uid not in seen:
                seen.add(uid)
                sys.__stdout__.write(f"  UID: {_CYAN}{_BOLD}{uid}{_RESET}\n")
                sys.__stdout__.flush()
            time.sleep(0.2)
    finally:
        GPIO.cleanup()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if "--scan" in sys.argv:
        scan_mode()
        return

    conn = init_db(DB_FILE)

    # Gracefully handle Ctrl+C: print a final status summary before exiting.
    def _handle_sigint(sig, frame):
        sys.__stdout__.write(f"\n{_BOLD}  Shutting down...{_RESET}\n")
        print_status(conn)
        conn.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_sigint)

    run(conn)


if __name__ == "__main__":
    main()