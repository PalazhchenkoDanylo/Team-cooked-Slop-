# RFID VPN Gateway

Hardware-controlled network gateway built on a **Raspberry Pi 4** and a **Raspberry Pi Pico**. Network access is controlled by RFID cards: an authorized card enables routing, activates a WireGuard VPN tunnel, and allows clients to access the Internet through Pi-hole DNS filtering.

## Architecture

```plaintext
[ RFID Card ]
      │
      ▼
[ Raspberry Pi Pico ]
      │ USB Serial (/dev/ttyACM0)
      ▼
[ Raspberry Pi 4 ]
      │
      ├─ RFID Gateway Service
      │    ├─ Validates RFID tags
      │    ├─ Manages gateway state
      │    ├─ Controls firewall and routing
      │    └─ Starts/stops WireGuard
      │
      ├─ Pi-hole (DNS filtering)
      │
      └─ WireGuard VPN (wg0)
               │
               ▼
           Internet
```

### Components

* **Raspberry Pi Pico** reads RFID tags and sends them to the Pi over USB serial (`/dev/ttyACM0`).
* **RFID Gateway Service** (`rfid_gateway.py`) monitors RFID events, validates authorized cards, and controls network access.
* **WireGuard** provides secure outbound connectivity.
* **Pi-hole** filters advertisements, trackers, and unwanted domains.
* **Flask Dashboard** (`app.py`) displays gateway status by reading data from a shared SQLite database (`gateway.db`).

## Requirements

### Hardware

* Raspberry Pi 4
* Raspberry Pi Pico
* RFID reader connected to the Pico
* Network uplink (Wi-Fi or hotspot)
* Client connected through the Pi

### Software

* Python 3
* WireGuard
* Pi-hole (optional but recommended)

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Edit `gateway.ini`:

```ini
[rfid]
source = serial
port = /dev/ttyACM0

[network]
lan_interface = eth0
wifi_interface = wlan0
vpn_interface = wg0
```

If RFID data is provided by another process:

```ini
[rfid]
source = file
file_path = /tmp/rfid_tag
```

Authorized RFID values are stored in:

```text
authorized_keys.txt
```

One RFID value per line. Values must match the data received from the Pico.

### WireGuard Example

`/etc/wireguard/wg0.conf`

```ini
[Interface]
PrivateKey = YOUR_PRIVATE_KEY
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = VPN_PROVIDER_PUBLIC_KEY
Endpoint = VPN_SERVER:51820
AllowedIPs = 0.0.0.0/0
```

## Running

Root privileges are required because the application modifies:

* `iptables`
* `sysctl net.ipv4.ip_forward`
* WireGuard interfaces

```bash
sudo .venv/bin/python rfid_gateway.py
```

The web dashboard can be started separately:

```bash
python app.py
```

Default dashboard address:

```text
http://localhost:5000
```

## Operation

### Authorized RFID Card

When a valid RFID card is presented:

1. The card is validated against `authorized_keys.txt`.
2. IP forwarding is enabled.
3. Firewall rules are applied.
4. WireGuard (`wg0`) is started.
5. Client traffic is routed through the VPN.
6. DNS requests are filtered by Pi-hole.

### Unauthorized RFID Card

Unauthorized cards are ignored and do not affect an active session.

### Session End

When access is revoked:

1. WireGuard is stopped.
2. Gateway firewall rules are removed.
3. IP forwarding is disabled.
4. Internet access through the gateway is blocked.

## Network Behavior

When enabled:

* `net.ipv4.ip_forward = 1`
* Forwarding from LAN to uplink interface
* Return traffic allowed
* NAT/MASQUERADE enabled
* Traffic routed through WireGuard VPN

When disabled:

* Gateway-specific firewall rules are removed
* IP forwarding is disabled
* VPN tunnel is stopped

The application only modifies rules created by the gateway and does not alter existing network configuration outside its scope.
