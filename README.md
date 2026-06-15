# RFID Wi-Fi Gateway

Terminal UI for a Raspberry Pi that works as a physical gateway between a computer on Ethernet and Wi-Fi. An RFID tag toggles traffic forwarding on and off.

## Hardware

- Raspberry Pi connected to Wi-Fi.
- Computer connected to the Pi by Ethernet.
- RFID reader/Pico connected to the Pi over serial, for example `/dev/ttyACM0`.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Edit `gateway.ini` if your interfaces or serial port are different:

```ini
[rfid]
source = serial
port = /dev/ttyACM0

[network]
lan_interface = eth0
wifi_interface = wlan0
```

If another script writes the last RFID tag into a file, use file mode:

```ini
[rfid]
source = file
file_path = /tmp/rfid_tag
```

Put allowed RFID values into `authorized_keys.txt`, one key per line. The value must match exactly what the Pico prints over serial.

## Run

Firewall and forwarding changes require root:

```bash
sudo .venv/bin/python rfid_gateway.py
```

If you run `python rfid_gateway.py` without `sudo`, the UI can still open and read RFID tags, but traffic toggling will fail because Linux does not allow an ordinary user to change `net.ipv4.ip_forward` or `iptables`.

The UI is fullscreen in the terminal:

- `q` exits
- `r` reloads `authorized_keys.txt`
- `t` toggles traffic manually for testing

## Network Behavior

When enabled, the app sets `net.ipv4.ip_forward=1` and adds these rules:

- forward `eth0 -> wlan0`
- allow established return traffic `wlan0 -> eth0`
- NAT/MASQUERADE through `wlan0`

When disabled, it removes only those exact `iptables` rules. It does not change your Wi-Fi connection or DHCP settings.
