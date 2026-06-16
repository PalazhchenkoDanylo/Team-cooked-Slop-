#!/usr/bin/env python3
import argparse
import configparser
import curses
import os
import queue
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

try:
    import serial
except ImportError:  # pragma: no cover - handled in UI at runtime
    serial = None

CONFIG_PATH = Path("gateway.ini")
DB_FILE = "gateway.db"


@dataclass
class Settings:
    rfid_source: str
    serial_port: str
    serial_baud: int
    serial_timeout: float
    file_path: Path
    file_poll_seconds: float
    debounce_seconds: float
    lan_interface: str
    wifi_interface: str
    vpn_interface: str  # Added for VPN routing tracking
    authorized_keys_path: Path
    require_authorized_key: bool


class EventLog:
    def __init__(self, max_items=8):
        self.max_items = max_items
        self.items = []

    def add(self, message):
        stamp = datetime.now().strftime("%H:%M:%S")
        self.items.append(f"{stamp}  {message}")
        self.items = self.items[-self.max_items :]


class GatewayController:
    def __init__(self, lan_interface, wifi_interface, vpn_interface, log):
        self.lan = lan_interface
        self.wifi = wifi_interface
        self.vpn = vpn_interface
        self.log = log
        self.has_root = hasattr(os, "geteuid") and os.geteuid() == 0

    def status(self):
        return self._vpn_interface_exists() and self._iptables_has_forward_rule() and self._ip_forward_enabled()

    def enable(self):
        self._require_root()
        
        # 1. Enable IP Forwarding kernel parameter
        self._run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        
        # 2. Bring up the WireGuard VPN Tunnel
        if not self._vpn_interface_exists():
            self.log.add(f"Starting VPN tunnel ({self.vpn})...")
            self._run(["wg-quick", "up", self.vpn])
        
        # 3. Route Traffic: LAN interface -> VPN interface (NOT wifi directly)
        self._ensure_rule(["iptables", "-I", "FORWARD", "-i", self.lan, "-o", self.vpn, "-j", "ACCEPT"])
        self._ensure_rule(
            [
                "iptables",
                "-I",
                "FORWARD",
                "-i",
                self.vpn,
                "-o",
                self.lan,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ]
        )
        
        # 4. NAT/Masquerade out of the VPN interface so traffic is encrypted
        self._ensure_rule(["iptables", "-t", "nat", "-I", "POSTROUTING", "-o", self.vpn, "-j", "MASQUERADE"])
        self.log.add("Secure VPN traffic enabled")

    def disable(self):
        self._require_root()
        
        # 1. Remove IPTables Forwarding rules
        self._delete_rule(["iptables", "-D", "FORWARD", "-i", self.lan, "-o", self.vpn, "-j", "ACCEPT"])
        self._delete_rule(
            [
                "iptables",
                "-D",
                "FORWARD",
                "-i",
                self.vpn,
                "-o",
                self.lan,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ]
        )
        self._delete_rule(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", self.vpn, "-j", "MASQUERADE"])
        
        # 2. Kill the WireGuard VPN Tunnel cleanly
        if self._vpn_interface_exists():
            self.log.add(f"Stopping VPN tunnel ({self.vpn})...")
            self._run(["wg-quick", "down", self.vpn])

        self.log.add("VPN traffic disabled")

    def toggle(self):
        if self.status():
            self.disable()
            return False
        self.enable()
        return True

    def _ip_forward_enabled(self):
        try:
            value = Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="utf-8").strip()
            return value == "1"
        except OSError:
            return False

    def _vpn_interface_exists(self):
        # Check if the virtual VPN network interface card is currently up
        return os.path.exists(f"/sys/class/net/{self.vpn}")

    def _iptables_has_forward_rule(self):
        return self._check_rule(["iptables", "-C", "FORWARD", "-i", self.lan, "-o", self.vpn, "-j", "ACCEPT"])

    def _ensure_rule(self, insert_command):
        check_command = insert_command.copy()
        check_command[1] = "-C" if check_command[1] != "-t" else check_command[1]
        if check_command[1] == "-t":
            check_command[3] = "-C"
        if not self._check_rule(check_command):
            self._run(insert_command)

    def _delete_rule(self, command):
        while self._check_rule(command):
            self._run(command)

    def _check_rule(self, command):
        check_command = command.copy()
        if "-D" in check_command:
            check_command[check_command.index("-D")] = "-C"
        result = subprocess.run(check_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return result.returncode == 0

    def _run(self, command):
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip() or "unknown error"
            raise RuntimeError(f"{' '.join(command)}: {error}")

    def _require_root(self):
        if not self.has_root:
            script_name = Path(sys.argv[0]).name
            if not script_name.endswith(".py"):
                script_name = "new_rfid_gateway.py"
            command = f"sudo {sys.executable} {script_name}"
            raise RuntimeError(f"root required for firewall changes; run: {command}")


class AuthorizedKeys:
    def __init__(self, path, required):
        self.path = path
        self.required = required
        self.keys = {} 
        self.reload()

    def reload(self):
        self.keys.clear()
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            clean = line.strip()
            if clean and not clean.startswith("#"):
                parts = clean.split(",", 1)
                tag = parts[0].strip()
                name = parts[1].strip() if len(parts) > 1 else f"User ({tag})"
                self.keys[tag] = name

    def accepts(self, tag):
        if self.keys:
            return tag in self.keys
        return not self.required

    def get_name(self, tag):
        return self.keys.get(tag, f"Unknown ({tag})")


class RFIDReader(threading.Thread):
    def __init__(self, settings, events, stop_event, log):
        super().__init__(daemon=True)
        self.settings = settings
        self.events = events
        self.stop_event = stop_event
        self.log = log
        self.last_tag = None
        self.last_seen_at = 0

    def run(self):
        if self.settings.rfid_source == "file":
            self._run_file_reader()
            return
        self._run_serial_reader()

    def _run_serial_reader(self):
            if serial is None:
                self.log.add("pyserial is not installed")
                return

            while not self.stop_event.is_set():
                try:
                    with serial.Serial(
                        self.settings.serial_port,
                        self.settings.serial_baud,
                        timeout=None,  # <-- Change this to None so it blocks until a full line is received
                    ) as device:
                        device.reset_input_buffer()  # <-- Clear out old junk data on connect
                        self.log.add(f"RFID reader connected: {self.settings.serial_port}")
                        self._read_loop(device)
                except Exception as exc:
                    self.log.add(f"RFID reader error: {exc}")
                    time.sleep(1)

    def _read_loop(self, device):
            while not self.stop_event.is_set():
                raw = device.readline()
                if not raw:
                    continue
                
                # Clean trailing and leading whitespace/newlines safely
                tag = raw.decode(errors="ignore").strip()
                
                # If the reader sends extra characters, ensure we only keep the alphanumeric ID
                tag = "".join(c for c in tag if c.isalnum())

                if len(tag) < 4:
                    continue

                self._publish(tag)

    def _run_file_reader(self):
        self.log.add(f"RFID file reader: {self.settings.file_path}")
        last_content = None
        while not self.stop_event.is_set():
            try:
                content = self.settings.file_path.read_text(encoding="utf-8").strip()
                tag = content.splitlines()[-1].strip() if content else ""
                if tag and tag != last_content:
                    last_content = tag
                    self._publish(tag)
            except OSError as exc:
                self.log.add(f"RFID file error: {exc}")
            time.sleep(self.settings.file_poll_seconds)

    def _publish(self, tag):
        now = time.monotonic()
        if now - self.last_seen_at < self.settings.debounce_seconds:
            return
            
        self.last_tag = tag
        self.last_seen_at = now
        self.events.put(tag)


def load_settings(path):
    config = configparser.ConfigParser()
    config.read(path)

    def get(section, option, fallback):
        return config.get(section, option, fallback=fallback)

    rfid_source = get("rfid", "source", "serial").lower()
    if rfid_source not in {"serial", "file"}:
        raise ValueError("rfid.source must be 'serial' or 'file'")

    return Settings(
        rfid_source=rfid_source,
        serial_port=get("rfid", "port", "/dev/ttyACM0"),
        serial_baud=config.getint("rfid", "baud", fallback=115200),
        serial_timeout=config.getfloat("rfid", "timeout", fallback=1.0),
        file_path=Path(get("rfid", "file_path", "/tmp/rfid_tag")),
        file_poll_seconds=config.getfloat("rfid", "file_poll_seconds", fallback=0.25),
        debounce_seconds=config.getfloat("rfid", "debounce_seconds", fallback=2.0),
        lan_interface=get("network", "lan_interface", "eth0"),
        wifi_interface=get("network", "wifi_interface", "wlan0"),
        vpn_interface=get("network", "vpn_interface", "wg0"),  # Wireguard default interface
        authorized_keys_path=Path(get("auth", "authorized_keys_path", "authorized_keys.txt")),
        require_authorized_key=config.getboolean("auth", "require_authorized_key", fallback=True),
    )


def draw_center(stdscr, y, text, attr=0):
    height, width = stdscr.getmaxyx()
    if y < 0 or y >= height:
        return
    clipped = text[: max(0, width - 1)]
    x = max(0, (width - len(clipped)) // 2)
    stdscr.addstr(y, x, clipped, attr)


def draw_ui(stdscr, settings, gateway, log, last_tag, last_event):
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    now = datetime.now().strftime("%H:%M:%S")
    date = datetime.now().strftime("%Y-%m-%d")
    enabled = gateway.status()

    title_attr = curses.color_pair(1) | curses.A_BOLD
    status_attr = curses.color_pair(2 if enabled else 3) | curses.A_BOLD

    draw_center(stdscr, 1, "RFID SECURE VPN GATEWAY", title_attr)
    draw_center(stdscr, 3, now, curses.A_BOLD)
    draw_center(stdscr, 4, date)
    draw_center(stdscr, 7, "VPN TRAFFIC TUNNEL", curses.A_DIM)
    draw_center(stdscr, 8, "TUNNEL SECURED" if enabled else "DISCONNECTED", status_attr)

    info_y = 11
    lines = [
        f"LAN: {settings.lan_interface}   VPN Interface: {settings.vpn_interface}",
        f"RFID source: {settings.rfid_source}",
        f"RFID serial: {settings.serial_port} @ {settings.serial_baud}",
        f"Last tag: {last_tag or '-'}",
        f"Last event: {last_event or '-'}",
        "Keys file: " + str(settings.authorized_keys_path),
    ]
    for offset, line in enumerate(lines):
        draw_center(stdscr, info_y + offset, line)

    log_title_y = max(info_y + len(lines) + 2, height - len(log.items) - 4)
    if log_title_y < height - 2:
        draw_center(stdscr, log_title_y, "EVENTS", curses.A_DIM)
        for index, item in enumerate(log.items):
            y = log_title_y + 1 + index
            if y >= height - 2:
                break
            draw_center(stdscr, y, item)

    footer = "q: quit   r: reload keys   t: manual toggle"
    stdscr.addstr(height - 1, max(0, (width - len(footer)) // 2), footer[: max(0, width - 1)], curses.A_DIM)
    stdscr.refresh()


def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                login_time TEXT NOT NULL,
                logout_time TEXT,
                duration TEXT
            )
        """)
        conn.commit()


def db_log_in(username):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO sessions (name, login_time) VALUES (?, ?)",
            (username, now_str),
        )
        conn.commit()


def db_log_out(username):
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, login_time FROM sessions WHERE name = ? AND logout_time IS NULL ORDER BY id DESC LIMIT 1",
            (username,),
        )
        row = cursor.fetchone()
        if row:
            session_id, login_time_str = row
            login_time = datetime.strptime(login_time_str, "%Y-%m-%d %H:%M:%S")
            duration_delta = now - login_time
            
            total_seconds = int(duration_delta.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            
            cursor.execute(
                "UPDATE sessions SET logout_time = ?, duration = ? WHERE id = ?",
                (now_str, duration_str, session_id),
            )
            conn.commit()


def db_log_rejected(username, reason):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO sessions (name, login_time, logout_time, duration) VALUES (?, ?, ?, ?)",
            (username, now_str, "REJECTED", reason),
        )
        conn.commit()


def get_current_active_user():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sessions WHERE logout_time IS NULL ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        return row[0] if row else None


def curses_main(stdscr, settings):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(200)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_RED, -1)

    init_db()

    log = EventLog()
    events = queue.Queue()
    stop_event = threading.Event()
    keys = AuthorizedKeys(settings.authorized_keys_path, settings.require_authorized_key)
    gateway = GatewayController(settings.lan_interface, settings.wifi_interface, settings.vpn_interface, log)
    reader = RFIDReader(settings, events, stop_event, log)
    reader.start()

    last_tag = None
    last_event = None
    
    if gateway.status():
        active_user = get_current_active_user() or "Unknown (Restored)"
    else:
        active_user = None

    log.add("application started")
    if not gateway.has_root:
        log.add("root required for traffic toggle")

    try:
        while True:
            try:
                tag = events.get_nowait()
                last_tag = tag
                
                if keys.accepts(tag):
                    user_name = keys.get_name(tag)
                    
                    if active_user is None:
                        gateway.enable()
                        active_user = user_name
                        db_log_in(active_user)
                        last_event = f"login: VPN tunnel established for {user_name}"
                        log.add(last_event)
                    elif active_user == user_name:
                        gateway.disable()
                        db_log_out(active_user)
                        active_user = None
                        last_event = f"logout: VPN tunnel terminated for {user_name}"
                        log.add(last_event)
                    else:
                        last_event = f"rejected: system locked to {active_user}"
                        log.add(last_event)
                        db_log_rejected(user_name, f"System locked by {active_user}")
                else:
                    last_event = "rejected unknown key"
                    log.add(last_event)
                    db_log_rejected(f"Unknown ({tag})", "Unregistered Card")
            except queue.Empty:
                pass
            except Exception as exc:
                last_event = f"gateway error: {exc}"
                log.add(last_event)

            key = stdscr.getch()
            if key == ord("q"):
                # Clean up and drop the tunnel if quitting application
                if gateway.status():
                    gateway.disable()
                break
            if key == ord("r"):
                keys.reload()
                last_event = f"keys reloaded: {len(keys.keys)}"
                log.add(last_event)
            if key == ord("t"):
                try:
                    enabled = gateway.toggle()
                    if not enabled:
                        if active_user:
                            db_log_out(active_user)
                        active_user = None
                    else:
                        active_user = "manual_override"
                        db_log_in(active_user)
                    last_event = f"manual toggle, VPN {'enabled' if enabled else 'disabled'}"
                    log.add(last_event)
                except Exception as exc:
                    last_event = f"gateway error: {exc}"
                    log.add(last_event)

            draw_ui(stdscr, settings, gateway, log, last_tag, last_event)
    finally:
        stop_event.set()


def main():
    parser = argparse.ArgumentParser(description="RFID-controlled Raspberry Pi VPN gateway")
    parser.add_argument("-c", "--config", default=str(CONFIG_PATH), help="Path to gateway.ini")
    args = parser.parse_args()
    settings = load_settings(Path(args.config))
    curses.wrapper(curses_main, settings)


if __name__ == "__main__":
    main()
