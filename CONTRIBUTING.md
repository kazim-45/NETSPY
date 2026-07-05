# Contributing to NetSpy 🌐

Thanks for your interest! NetSpy has two sides — a Python packet capture backend and a browser-based dashboard. Contributions to either are welcome.

---

## What we'd love help with

**Backend (capture.py)**
- New protocol parsers — FTP, SMTP, Telnet content extraction, HTTP host header parsing
- Better threat detection — port scan heuristics, ARP spoofing detection, suspicious DNS queries
- PCAP export — save captured packets as `.pcap` files openable in Wireshark
- `--watch` style alerts — desktop notifications when suspicious traffic is detected

**Frontend (dashboard.html)**
- Packet detail panel — click a row to expand full packet info
- IP geolocation — flag external IPs with country info
- Dark/light theme toggle
- Export table as CSV

**General**
- Performance — the ring buffer and polling work well at low traffic; improvements for high-volume interfaces
- Tests — fixtures using pre-recorded packet data

---

## Setting up locally

```bash
# 1. Fork the repo on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/netspy.git
cd netspy

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install in editable mode
pip install -e .

# 4. Run it (packet capture needs sudo on Linux/macOS)
sudo venv/bin/netspy
# Dashboard opens at http://127.0.0.1:5000
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
│       └── dashboard.html  ← entire frontend: HTML + CSS + JS in one file
├── pyproject.toml
├── requirements.txt
└── README.md
```

**How the two sides talk:**
- `capture.py` runs Scapy in a background thread and stores parsed packets in a thread-safe ring buffer
- `app.py` exposes `/api/packets?since=N` and `/api/stats` — the browser polls these every second
- `dashboard.html` fetches from those endpoints and updates the UI — no build step, no framework

---

## Working on the backend (capture.py)

**Adding a new protocol parser:**

Find the `parse_packet()` function and add your protocol after the existing ones. Follow the same pattern:

```python
# Example: detect HTTP Host headers
if pkt.haslayer(TCP) and pkt.haslayer(Raw):
    payload = pkt[Raw].load.decode(errors="replace")
    if payload.startswith("GET") or payload.startswith("POST"):
        host_match = re.search(r"Host: (.+)", payload)
        if host_match:
            result["info"] = f"HTTP → {host_match.group(1).strip()}"
            result["protocol"] = "HTTP"
```

**Adding a new severity rule:**

In the `severity()` function, add your condition:

```python
def severity(pkt_dict):
    port = pkt_dict.get("dst_port")
    # Add yours here:
    if port == 21:
        return "warning"   # FTP — plaintext protocol
    ...
```

**Testing without real traffic:**

Use Scapy to craft test packets in a Python shell:

```python
from scapy.all import IP, TCP, send
# Craft a SYN packet
pkt = IP(dst="127.0.0.1") / TCP(dport=80, flags="S")
send(pkt, verbose=False)
```

---

## Working on the frontend (dashboard.html)

The entire frontend is in `netspy_pkg/templates/dashboard.html`. It's split into three clear sections inside the file:

| Section | Where |
|---|---|
| HTML structure | Top of file, inside `<body>` |
| CSS styles | Inside `<style>` tag in `<head>` |
| JavaScript logic | Inside `<script>` tag at bottom |

Key JS functions to know:

| Function | What it does |
|---|---|
| `poll()` | Fetches new packets and stats every second |
| `renderTable()` | Builds the packet table rows |
| `updateStats()` | Updates sidebar counters and charts |
| `drawTimeline()` | Draws the packets/sec sparkline on canvas |
| `updateDonut()` | Updates the protocol donut chart |

To test frontend changes, just run `netspy` and refresh the browser — Flask serves the template file directly so changes are live immediately.

---

## Making a change

```bash
git checkout -b feat/pcap-export

# Make your changes
# Test:
sudo venv/bin/netspy
# or for frontend-only changes (no sudo needed if you disable capture):
venv/bin/netspy --no-browser   # then open http://127.0.0.1:5000 manually

git add netspy_pkg/capture.py   # or whichever file you changed
git commit -m "feat: add PCAP export via /api/export endpoint"
git push origin feat/pcap-export
```

---

## Commit message format

```
type: short description

Examples:
feat: parse HTTP Host header from raw TCP payload
fix: race condition in ring buffer when clearing during capture
docs: add BPF filter examples to README
refactor: extract protocol detection into separate functions
```

Types: `feat` `fix` `docs` `refactor` `test`

---

## Pull request checklist

- [ ] `sudo venv/bin/netspy` starts without errors
- [ ] Dashboard loads at `http://127.0.0.1:5000`
- [ ] START/STOP/CLR buttons work correctly
- [ ] `/api/stats` returns valid JSON: `curl http://127.0.0.1:5000/api/stats`
- [ ] No new console errors in browser devtools
- [ ] Commit message follows the format above

---

## Questions?

Open a [GitHub Issue](https://github.com/kazim-45/netspy/issues) and tag it `question`.

MIT Licensed — contributions are welcome from everyone.
