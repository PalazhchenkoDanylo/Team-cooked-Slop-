#!/usr/bin/env python3
#aiudaiud
"""
RFID Attendance System — Raspberry Pi 4B (Ubuntu Server 24.04 LTS)

RC522 wiring (SPI, BCM pin numbering):
  SS/SDA  ->  GPIO5  (Pin 29)
  SCK     ->  GPIO11 (Pin 23)
  MOSI    ->  GPIO10 (Pin 19)
  MISO    ->  GPIO9  (Pin 21)
  RST     ->  GPIO27 (Pin 13)
  GND     ->  Pin 9
  VCC     ->  Pin 17  (3.3 V)

Dependencies:
  sudo apt update && sudo apt install -y python3-pip python3-dev
  pip3 install mfrc522 RPi.GPIO spidev

Enable SPI interface:
  sudo raspi-config  ->  Interface Options -> SPI -> Enable
  (or manually: add 'dtparam=spi=on' to /boot/firmware/config.txt)
  sudo reboot

Usage:
  sudo python3 rfid_attendance.py           # normal operation
  sudo python3 rfid_attendance.py --scan    # discover card UIDs
"""

import signal
import sqlite3
import sys
import time
from datetime import datetime

import RPi.GPIO as GPIO
from mfrc522 import SimpleMFRC522

# ---------------------------------------------------------------------------
# Card registry — maps integer UID to (first_name, last_name).
# Run with --scan to discover the UID of an unknown card.
# ---------------------------------------------------------------------------
CARDS: dict[int, tuple[str, str]] = {
    3840082862: ("Rick",    "Sanchez"),
    2284718442: ("Antonio", "Margaretti"),
    3394371378: ("Bibo",    "Bortoleto"),
    2284849230: ("Max",     "Verstappen"),
}

# Path to the SQLite database file used for persistent event storage.
DB_FILE = "attendance.db"

# RC522 control pins (BCM numbering).
# SCK / MOSI / MISO are managed by the hardware SPI driver automatically.
PIN_RST = 27   # GPIO27 — Pin 13
PIN_CS  = 5    # GPIO5  — Pin 29 (SS/SDA)

# Minimum interval (seconds) before the same card can trigger another event.
# Prevents duplicate reads from a single tap.
DEBOUNCE_SEC = 3


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


def print_event(full_name: str, event: str, ts: str) -> None:
    """Print a single attendance event to stdout."""
    print(f"{ts}  {full_name}  -  {event.upper()}")


def print_unknown(uid: int) -> None:
    """Print a warning for an unregistered card UID."""
    print(f"{now_str()}  Unknown card  -  UID {uid}")


def print_status(conn: sqlite3.Connection) -> None:
    """Print the current attendance status of every registered card holder."""
    print()
    for uid, (first, last) in CARDS.items():
        full = f"{first} {last}"
        ev = last_event(conn, full) or "absent"
        print(f"  {full}  -  {ev.upper()}")
    print()


# ---------------------------------------------------------------------------
# Main reader loop
# ---------------------------------------------------------------------------

def run(conn: sqlite3.Connection) -> None:
    """Continuously poll the RC522 reader and process card events."""
    reader = SimpleMFRC522()

    last_uid: int | None = None
    last_scan: float = 0.0

    print("RFID Attendance System - ready. Scan a card...\n")
    print_status(conn)

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
    print("Scan mode - present cards to discover their UIDs. Press Ctrl+C to exit.\n")
    seen: set[int] = set()
    try:
        while True:
            uid, _ = reader.read_no_block()
            if uid and uid not in seen:
                seen.add(uid)
                print(f"  UID: {uid}")
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
        print("\nShutting down...")
        print_status(conn)
        conn.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_sigint)

    run(conn)


if __name__ == "__main__":
    main()