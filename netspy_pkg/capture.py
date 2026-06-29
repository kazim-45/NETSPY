"""
NetSpy — capture.py
Packet capture engine using Scapy. Runs in a background thread,
parses each packet into a structured dict, and stores them in a
ring buffer that the Flask API reads from.
"""

import threading
import time
from collections import deque, Counter
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, ARP, Ether, Raw
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── Ring buffer shared between capture thread and Flask ──────────────────────

MAX_PACKETS  = 500          # keep last N packets in memory
_lock        = threading.Lock()
_packets     = deque(maxlen=MAX_PACKETS)
_stats       = {
    "total":     0,
    "tcp":       0,
    "udp":       0,
    "icmp":      0,
    "arp":       0,
    "dns":       0,
    "other":     0,
    "bytes":     0,
    "top_src":   Counter(),
    "top_dst":   Counter(),
    "top_ports": Counter(),
    "timeline":  deque(maxlen=60),   # packets per second, last 60 seconds
    "last_tick": time.time(),
    "tick_count": 0,
}
_capture_running = False
_capture_thread  = None

# ── Protocol helpers ──────────────────────────────────────────────────────────

WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    27017: "MongoDB",
}

FLAG_NAMES = {
    0x02: "SYN", 0x10: "ACK", 0x01: "FIN",
    0x04: "RST", 0x18: "PSH+ACK", 0x12: "SYN+ACK",
}

def port_label(port):
    return WELL_KNOWN_PORTS.get(port, str(port))

def tcp_flags(flags):
    names = []
    for bit, name in FLAG_NAMES.items():
        if int(flags) & bit == bit:
            names.append(name)
    return "+".join(names) if names else str(flags)

def severity(pkt_dict):
    """Assign a threat hint to a packet for colour coding."""
    port = pkt_dict.get("dst_port") or pkt_dict.get("src_port")
    flags = pkt_dict.get("flags", "")
    proto = pkt_dict.get("protocol", "")

    if proto == "Telnet" or port == 23:
        return "danger"       # plaintext auth
    if port == 22 and "SYN" in flags and "ACK" not in flags:
        return "warning"      # SSH connection attempt
    if port in (3389, 445):
        return "warning"      # RDP / SMB
    if proto == "ICMP":
        return "info"
    if proto == "ARP":
        return "info"
    if proto in ("DNS", "HTTP", "HTTPS"):
        return "normal"
    return "normal"


# ── Packet parser ─────────────────────────────────────────────────────────────

def parse_packet(pkt):
    now = datetime.now()
    result = {
        "id":        _stats["total"] + 1,
        "time":      now.strftime("%H:%M:%S"),
        "timestamp": now.isoformat(),
        "protocol":  "Other",
        "src_ip":    None,
        "dst_ip":    None,
        "src_port":  None,
        "dst_port":  None,
        "length":    len(pkt),
        "info":      "",
        "flags":     "",
        "severity":  "normal",
    }

    # ARP
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        result["protocol"] = "ARP"
        result["src_ip"]   = arp.psrc
        result["dst_ip"]   = arp.pdst
        result["info"]     = f"Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else f"{arp.psrc} is at {arp.hwsrc}"
        result["severity"] = "info"
        return result

    if not pkt.haslayer(IP):
        return None     # skip non-IP, non-ARP frames

    ip = pkt[IP]
    result["src_ip"] = ip.src
    result["dst_ip"] = ip.dst

    # ICMP
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        result["protocol"] = "ICMP"
        type_names = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "TTL Exceeded"}
        result["info"]     = type_names.get(icmp.type, f"Type {icmp.type}")
        result["severity"] = "info"
        return result

    # DNS (UDP/53 or TCP/53)
    if pkt.haslayer(DNS):
        result["protocol"] = "DNS"
        dns = pkt[DNS]
        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            result["info"] = f"Query: {qname}"
        else:
            result["info"] = "Response"
        result["src_port"] = pkt[UDP].sport if pkt.haslayer(UDP) else None
        result["dst_port"] = pkt[UDP].dport if pkt.haslayer(UDP) else None
        return result

    # TCP
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        result["protocol"] = "TCP"
        result["src_port"] = tcp.sport
        result["dst_port"] = tcp.dport
        result["flags"]    = tcp_flags(tcp.flags)

        # Upgrade label if well-known port
        service = WELL_KNOWN_PORTS.get(tcp.dport) or WELL_KNOWN_PORTS.get(tcp.sport)
        if service:
            result["protocol"] = service

        result["info"] = (
            f"{result['src_port']} → {result['dst_port']}  [{result['flags']}]"
            f"  seq={tcp.seq}"
        )
        result["severity"] = severity(result)
        return result

    # UDP
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        result["protocol"] = "UDP"
        result["src_port"] = udp.sport
        result["dst_port"] = udp.dport
        service = WELL_KNOWN_PORTS.get(udp.dport) or WELL_KNOWN_PORTS.get(udp.sport)
        if service:
            result["protocol"] = service
        result["info"] = f"{udp.sport} → {udp.dport}  len={udp.len}"
        result["severity"] = severity(result)
        return result

    return result


# ── Callback called by Scapy for each sniffed packet ─────────────────────────

def _on_packet(pkt):
    parsed = parse_packet(pkt)
    if parsed is None:
        return

    with _lock:
        _packets.append(parsed)
        _stats["total"] += 1
        _stats["bytes"] += parsed["length"]

        proto = parsed["protocol"]
        if proto == "TCP" or proto in WELL_KNOWN_PORTS.values():
            _stats["tcp"] += 1
        elif proto == "UDP":
            _stats["udp"] += 1
        elif proto == "ICMP":
            _stats["icmp"] += 1
        elif proto == "ARP":
            _stats["arp"] += 1
        elif proto == "DNS":
            _stats["dns"] += 1
        else:
            _stats["other"] += 1

        if parsed["src_ip"]:
            _stats["top_src"][parsed["src_ip"]] += 1
        if parsed["dst_ip"]:
            _stats["top_dst"][parsed["dst_ip"]] += 1
        if parsed["dst_port"]:
            _stats["top_ports"][parsed["dst_port"]] += 1

        # Timeline tick
        now = time.time()
        elapsed = now - _stats["last_tick"]
        if elapsed >= 1.0:
            _stats["timeline"].append(_stats["tick_count"])
            _stats["tick_count"] = 0
            _stats["last_tick"]  = now
        _stats["tick_count"] += 1


# ── Capture thread ────────────────────────────────────────────────────────────

def _capture_loop(iface, bpf_filter):
    global _capture_running
    try:
        sniff(
            iface=iface,
            filter=bpf_filter,
            prn=_on_packet,
            store=False,
            stop_filter=lambda _: not _capture_running,
        )
    except Exception as e:
        pass
    finally:
        _capture_running = False


def start_capture(iface=None, bpf_filter=""):
    global _capture_running, _capture_thread
    if _capture_running:
        return False

    _capture_running = True
    _capture_thread  = threading.Thread(
        target=_capture_loop,
        args=(iface, bpf_filter),
        daemon=True,
    )
    _capture_thread.start()
    return True


def stop_capture():
    global _capture_running
    _capture_running = False


def is_running():
    return _capture_running


# ── Data accessors (called by Flask routes) ───────────────────────────────────

def get_packets(since_id=0, limit=100):
    with _lock:
        all_pkts = list(_packets)
    return [p for p in all_pkts if p["id"] > since_id][-limit:]


def get_stats():
    with _lock:
        s = _stats.copy()
        top_src   = s["top_src"].most_common(5)
        top_dst   = s["top_dst"].most_common(5)
        top_ports = [
            (port_label(p), c) for p, c in s["top_ports"].most_common(8)
        ]
        timeline  = list(s["timeline"])

    return {
        "total":     s["total"],
        "tcp":       s["tcp"],
        "udp":       s["udp"],
        "icmp":      s["icmp"],
        "arp":       s["arp"],
        "dns":       s["dns"],
        "other":     s["other"],
        "bytes":     s["bytes"],
        "running":   _capture_running,
        "top_src":   top_src,
        "top_dst":   top_dst,
        "top_ports": top_ports,
        "timeline":  timeline,
    }


def clear():
    global _packets, _stats
    with _lock:
        _packets.clear()
        _stats.update({
            "total": 0, "tcp": 0, "udp": 0, "icmp": 0,
            "arp": 0, "dns": 0, "other": 0, "bytes": 0,
            "top_src": Counter(), "top_dst": Counter(),
            "top_ports": Counter(),
            "timeline": deque(maxlen=60),
            "last_tick": time.time(), "tick_count": 0,
        })


def list_interfaces():
    """Return available network interfaces."""
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except Exception:
        return []
