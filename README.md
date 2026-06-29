# NetSpy 🌐

**Live network packet sniffer with a browser-based dashboard.**

Captures packets off your network interface using Scapy, parses them in real time, and streams the results to a dark-themed dashboard in your browser — protocol breakdown, top IPs, packets-per-second timeline, and a live-scrolling packet table with colour-coded severity.

```
sudo netspy     →     http://127.0.0.1:5000
```

---

## Installation

```bash
git clone https://github.com/kazim-45/netspy.git
cd netspy
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Packet capture requires root on Linux/macOS (Scapy needs raw socket access).

---

## Usage

```bash
# Start the dashboard (opens browser automatically)
sudo venv/bin/netspy

# Custom port
sudo venv/bin/netspy --port 8080

# Expose on your local network so other devices can view it
sudo venv/bin/netspy --host 0.0.0.0

# Don't open browser automatically
sudo venv/bin/netspy --no-browser

# Help
netspy --help
```

Then in the browser:

1. Pick a network interface from the dropdown (or leave blank for auto-detect)
2. Optionally enter a BPF filter — e.g. `tcp port 443` or `host 192.168.1.1`
3. Press **▶ START** — packets stream in live
4. Use the filter buttons to focus on TCP / UDP / DNS / HTTP / suspicious traffic
5. Search by IP, port, or keyword in the search box

---

## Project structure

```
netspy/
├── netspy_pkg/
│   ├── __init__.py         ← package marker
│   ├── capture.py          ← Scapy sniffer, packet parser, ring buffer
│   ├── app.py              ← Flask routes and JSON API
│   ├── cli.py              ← netspy command entry point
│   └── templates/
│       └── dashboard.html  ← single-file dashboard (HTML + CSS + JS)
├── pyproject.toml          ← registers the netspy command via pip
├── requirements.txt
├── README.md
└── .gitignore
```

---

## What you see

**Sidebar — live counters**
- Total packet count and bytes captured
- Per-protocol breakdown: TCP, UDP, DNS, ICMP, ARP
- Top 5 source IPs (who's sending the most traffic)
- Top 5 destination IPs (where traffic is going)
- Top 8 services by port (HTTP, HTTPS, DNS, SSH, etc.)

**Chart row**
- Protocol donut — visual split of traffic by type, updates every second
- Packets/sec sparkline — the last 60 seconds of traffic volume as a canvas graph

**Packet table**
- Every captured packet: time, protocol pill, source, destination, length, info
- Colour coded by severity: 🔴 danger (Telnet, RDP), 🟡 warning (SSH attempts), normal
- Filter buttons: ALL / TCP / UDP / DNS / HTTP / HTTPS / ICMP / ARP / ⚠ SUSPICIOUS
- Search box: filter by IP address, port number, or any info string
- Auto-scrolls as packets arrive; stops when you scroll up to inspect

---

## Severity colour coding

| Colour | Meaning | Examples |
|---|---|---|
| 🔴 Red | Dangerous protocol | Telnet (port 23) — sends credentials in plaintext |
| 🟡 Yellow | Worth watching | SSH SYN attempts, SMB (445), RDP (3389) |
| 🔵 Blue | Informational | ICMP pings, ARP requests |
| Teal | Normal | HTTP, HTTPS, DNS, general TCP/UDP |

---

## BPF filter examples

BPF (Berkeley Packet Filter) is the standard syntax for scoping what gets captured. Enter these in the filter box before pressing START:

| Filter | What it captures |
|---|---|
| `tcp port 80` | HTTP traffic only |
| `tcp port 443` | HTTPS traffic only |
| `host 8.8.8.8` | Traffic to/from Google DNS |
| `src net 192.168.1.0/24` | All traffic from your LAN |
| `icmp` | Ping traffic only |
| `not port 22` | Everything except SSH |
| `udp port 53` | DNS queries only |

---

## How it works

NetSpy runs two things at once:

**Capture thread** — Scapy's `sniff()` runs in a background thread, calling a callback for every packet. The callback parses the packet into a structured dict (protocol, IPs, ports, flags, info string, severity) and appends it to a thread-safe ring buffer capped at 500 packets.

**Flask server** — serves the dashboard HTML and exposes a JSON API. The browser polls `/api/packets?since=N` every second, fetching only packets it hasn't seen yet. It also polls `/api/stats` for sidebar counters and timeline data. Progress and status messages are routed to stderr so the API responses are always clean JSON.

The two are fully decoupled — the sniffer never waits on the browser, and the browser never blocks the sniffer.

---

## Supported protocols

TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS, SSH, FTP, SMTP, Telnet, RDP, SMB, MySQL, PostgreSQL, Redis, MongoDB — automatically identified by port number with human-readable labels.

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

*Built by [kazim-45](https://github.com/kazim-45) — part of a cybersecurity CLI toolkit alongside [MetaHunter](https://github.com/kazim-45/MetaHunter), [MilkyWay-CTF](https://github.com/kazim-45/MilkyWay-CTF), [PassAudit](https://github.com/kazim-45/passaudit), and [LogWatch](https://github.com/kazim-45/logwatch).*
