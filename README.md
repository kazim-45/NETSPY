# NetSpy 🌐

**Live network packet sniffer with a browser-based dashboard.**

Captures packets off your network interface in real time and streams them to a dark-themed dashboard in your browser — protocol breakdown, top IPs, packets-per-second timeline, and a live-scrolling packet table with colour-coded severity.

```
sudo /path/to/venv/bin/netspy     →     http://127.0.0.1:5000
```

---

## What it looks like

Once running, you get a live dashboard showing:
- Every packet your machine sends and receives
- Protocol breakdown: HTTPS, TCP, UDP, DNS, ICMP, ARP
- Top source and destination IPs
- Packets per second sparkline
- Colour-coded severity (red = suspicious, yellow = worth watching)
- Filter buttons: ALL / TCP / UDP / DNS / HTTP / HTTPS / ICMP / ARP / ⚠ SUSPICIOUS
- Search by IP, port, or any keyword

---

## Requirements

- Python 3.8+
- Linux or macOS (Windows not supported — Scapy requires raw sockets)
- `sudo` / root access (required for packet capture)
- Your network interface name (find it with `ip a` — usually `wlan0` or `eth0`)

---

## Installation

```bash
# 1. Clone the repo
git clone https://github.com/kazim-45/netspy.git
cd netspy

# 2. Create a virtual environment
python3 -m venv venv

# 3. Activate it
source venv/bin/activate

# 4. Install dependencies manually first
pip install scapy flask rich

# 5. Install the package
pip install -e .
```

---

## Running NetSpy

**Important:** You must use the full path to the venv binary with sudo. Using just `sudo netspy` will fail because sudo uses a different PATH that doesn't know about your venv.

```bash
# From inside your netspy folder:
sudo $(pwd)/venv/bin/netspy
```

Or with the full absolute path:

```bash
sudo /home/yourname/netspy/venv/bin/netspy
```

The dashboard will open automatically at `http://127.0.0.1:5000`.

---

## Using the dashboard

1. **Select your interface** from the dropdown in the top right (e.g. `wlan0` for WiFi, `eth0` for ethernet). Run `ip a` in a terminal if you're unsure which one.
2. **Optionally set a BPF filter** — see examples below.
3. **Press ▶ START** — packets appear immediately.
4. Use the **filter buttons** to focus on specific protocols.
5. Use the **search box** to filter by IP address, port, or keyword.
6. Press **■ STOP** to pause capture. **CLR** to clear all packets.

---

## Finding your network interface

```bash
ip a
```

Look for the interface that has your local IP (e.g. `192.168.x.x`). Common names:

| Interface | Meaning |
|---|---|
| `wlan0` | WiFi (most common on Linux) |
| `eth0` | Ethernet cable |
| `enp3s0` | Ethernet (newer naming) |
| `lo` | Loopback — skip this one |

---

## BPF filter examples

Type these into the filter box before pressing START to focus on specific traffic:

| Filter | What it captures |
|---|---|
| `tcp port 443` | HTTPS traffic only |
| `tcp port 80` | HTTP traffic only |
| `udp port 53` | DNS queries only |
| `icmp` | Ping traffic only |
| `host 8.8.8.8` | Traffic to/from Google DNS |
| `not port 22` | Everything except SSH |
| `src net 192.168.1.0/24` | All traffic from your LAN |

---

## Cool things to try

**Watch your DNS queries in real time:**
```bash
nslookup google.com
nslookup instagram.com
```
Click the **DNS** filter — see every domain your machine resolves.

**Watch your browser's connections:**
Open any website, click **HTTPS** filter. See every server your browser contacts — a single webpage often hits 10+ different IPs.

**Ping something and watch it:**
```bash
ping 8.8.8.8 -c 5
```
Click **ICMP** — see Echo Request and Echo Reply packets in real time.

**Scan yourself and see what a port scan looks like:**
```bash
nmap -sS 192.168.1.x   # your own IP
```
Watch the SUSPICIOUS filter light up with a flood of TCP SYN packets.

**Identify an IP in your top sources:**
```bash
whois 57.144.148.145   # replace with any IP from the dashboard
```

---

## Project structure

```
netspy/
├── netspy_pkg/
│   ├── __init__.py
│   ├── capture.py          ← Scapy sniffer, packet parser, ring buffer
│   ├── app.py              ← Flask routes and JSON API
│   ├── cli.py              ← netspy command entry point
│   └── templates/
│       └── dashboard.html  ← entire frontend (HTML + CSS + JS)
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## How it works

**Capture thread** — Scapy's `sniff()` runs in a background thread with root privileges. Every packet gets parsed into a structured dict (protocol, source IP, destination IP, ports, TCP flags, info string, severity level) and added to a thread-safe ring buffer capped at 500 packets.

**Flask server** — serves the dashboard and exposes two API endpoints. The browser polls `/api/packets?since=N` every second to fetch only new packets, and `/api/stats` for the sidebar counters and timeline data.

**Dashboard** — pure HTML/CSS/JS, no frameworks, no build step. The donut chart is SVG, the sparkline is Canvas 2D. The packet table uses a fast-append path when auto-scrolled to the bottom so it stays smooth even at high packet rates.

---

## Troubleshooting

**`sudo netspy: command not found`**
Don't use `sudo netspy`. Use the full venv path:
```bash
sudo $(pwd)/venv/bin/netspy
```

**Dashboard loads but 0 packets after pressing START**
You're running without sudo. Scapy needs root to open raw sockets. Stop and relaunch with `sudo`.

**`No module named 'netspy_pkg'`**
The package folder structure is wrong. Make sure your folder looks like this — `netspy_pkg/` must be a subfolder containing `__init__.py`, not loose files in the root:
```
netspy/
├── netspy_pkg/
│   ├── __init__.py
│   ├── app.py
│   ├── capture.py
│   ├── cli.py
│   └── templates/
│       └── dashboard.html
└── pyproject.toml
```
Then reinstall: `pip install -e .`

**500 Internal Server Error in browser**
The templates folder is in the wrong place. It must be inside `netspy_pkg/`, not at the project root. Move it:
```bash
mv templates/ netspy_pkg/templates/
pip install -e .
```

---

## Dependencies

- [`scapy`](https://scapy.net/) — packet capture and parsing
- [`flask`](https://flask.palletsprojects.com/) — web server and JSON API
- [`rich`](https://pypi.org/project/rich/) — terminal startup output

---

## Legal & ethical use

Only capture traffic on networks you own or have explicit permission to monitor. Capturing traffic on public or corporate networks without authorization is illegal in most countries. Use NetSpy on your own machine or home lab only.

---

## License

MIT — use it, fork it, build on it.

---

*Built by [kazim-45](https://github.com/kazim-45) — part of a cybersecurity CLI toolkit alongside [MetaHunter](https://github.com/kazim-45/MetaHunter), [MilkyWay-CTF](https://github.com/kazim-45/MilkyWay-CTF), [PassAudit](https://github.com/kazim-45/passaudit), [LogWatch](https://github.com/kazim-45/logwatch), and [VaultScan](https://github.com/kazim-45/vaultscan).*
