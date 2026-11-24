"""
simulate_traffic.py
====================
Generates a SIMULATED packet capture for safely testing the pipeline.
Packets are crafted entirely in memory with Scapy and written to a .pcap
file -- nothing is ever transmitted on any network, so this is safe to run
anywhere.

Produces a mix of:
  - normal traffic:  web/HTTPS/SSH sessions, DNS lookups, pings
  - SYN flood:        ~300 unanswered SYNs to one web server in a few seconds
  - port scan:         SYNs across 200 ports of one host (closed ports reply RST)
  - ping sweep:        ICMP echo to 100 hosts, only some reply

Run directly:
    python backend/simulate_traffic.py
"""
import random
import time
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = ROOT / "data" / "sim_traffic.pcap"

# All addresses are in the private, non-routable 192.168.56.0/24 range
# (VirtualBox's conventional host-only network), used here only as labels.
ATTACKER = "192.168.56.66"
WEB_SERVER, SSH_SERVER, DNS_SERVER = "192.168.56.20", "192.168.56.21", "192.168.56.1"
CLIENTS = ["192.168.56.101", "192.168.56.102", "192.168.56.103", "192.168.56.104"]


def _at(t, pkt):
    pkt.time = t
    return pkt


def _tcp_session(packets, t0, client, server, sport, dport, client_bytes, server_bytes, duration):
    """Three-way handshake, a few data segments, then a clean close."""
    packets.append(_at(t0, IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="S", seq=1000)))
    packets.append(_at(t0 + .001, IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=1001)))
    packets.append(_at(t0 + .002, IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=5001)))

    chunks = [("client", min(1400, client_bytes))] if client_bytes else []
    remaining = server_bytes
    while remaining > 0:
        n = min(1400, remaining)
        chunks.append(("server", n))
        remaining -= n

    step = max(duration - 0.02, 0.01) / (len(chunks) + 1)
    for i, (who, n) in enumerate(chunks, start=1):
        t = t0 + 0.01 + i * step
        if who == "client":
            packets.append(_at(t, IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="PA") / Raw(b"x" * n)))
        else:
            packets.append(_at(t, IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="PA") / Raw(b"y" * n)))

    t_end = t0 + duration
    packets.append(_at(t_end, IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="FA")))
    packets.append(_at(t_end + .001, IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="FA")))
    packets.append(_at(t_end + .002, IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="A")))


def _normal_traffic(packets, base, n_sessions=120, spread=150):
    for _ in range(n_sessions):
        t0 = base + random.uniform(0, spread)
        client = random.choice(CLIENTS)
        sport = random.randint(20000, 60000)
        kind = random.choices(["web", "https", "ssh", "dns", "ping"], weights=[4, 3, 1, 4, 1])[0]

        if kind == "web":
            _tcp_session(packets, t0, client, WEB_SERVER, sport, 80,
                        random.randint(300, 800), random.randint(2000, 60000), random.uniform(.05, 3))
        elif kind == "https":
            _tcp_session(packets, t0, client, WEB_SERVER, sport, 443,
                        random.randint(300, 900), random.randint(3000, 80000), random.uniform(.05, 3))
        elif kind == "ssh":
            _tcp_session(packets, t0, client, SSH_SERVER, sport, 22,
                        random.randint(200, 1400), random.randint(200, 3000), random.uniform(5, 20))
        elif kind == "dns":
            packets.append(_at(t0, IP(src=client, dst=DNS_SERVER) / UDP(sport=sport, dport=53) / Raw(b"q" * random.randint(30, 60))))
            packets.append(_at(t0 + .02, IP(src=DNS_SERVER, dst=client) / UDP(sport=53, dport=sport) / Raw(b"r" * random.randint(60, 200))))
        else:  # ping
            ident = random.randint(1, 65000)
            dest = random.choice([WEB_SERVER, SSH_SERVER, DNS_SERVER])
            for seq in range(3):
                packets.append(_at(t0 + seq, IP(src=client, dst=dest) / ICMP(type=8, id=ident, seq=seq) / Raw(b"p" * 56)))


def _syn_flood(packets, t0, n=300):
    """Many SYNs to one port, none completed -- the classic DoS signature."""
    for i in range(n):
        sport = random.randint(1024, 65000)
        packets.append(_at(t0 + i * 0.01, IP(src=ATTACKER, dst=WEB_SERVER) / TCP(sport=sport, dport=80, flags="S")))


def _port_scan(packets, t0, n_ports=200):
    """SYN to each port; closed ports answer RST, the one or two open ports get reset by the scanner."""
    for port in range(1, n_ports + 1):
        sport = random.randint(30000, 60000)
        t = t0 + port * 0.005
        packets.append(_at(t, IP(src=ATTACKER, dst=SSH_SERVER) / TCP(sport=sport, dport=port, flags="S", seq=1)))
        if port in (22, 80):
            packets.append(_at(t + .0005, IP(src=SSH_SERVER, dst=ATTACKER) / TCP(sport=port, dport=sport, flags="SA", seq=9, ack=2)))
            packets.append(_at(t + .001, IP(src=ATTACKER, dst=SSH_SERVER) / TCP(sport=sport, dport=port, flags="R", seq=2)))
        else:
            packets.append(_at(t + .0005, IP(src=SSH_SERVER, dst=ATTACKER) / TCP(sport=port, dport=sport, flags="RA", seq=0, ack=2)))


def _ping_sweep(packets, t0, n_hosts=100):
    """ICMP echo to a whole subnet; only a handful of hosts reply."""
    for h in range(1, n_hosts + 1):
        dest = f"192.168.56.{h}"
        t = t0 + h * 0.02
        packets.append(_at(t, IP(src=ATTACKER, dst=dest) / ICMP(type=8, id=777, seq=h) / Raw(b"s" * 56)))
        if h % 10 == 0:
            packets.append(_at(t + .001, IP(src=dest, dst=ATTACKER) / ICMP(type=0, id=777, seq=h) / Raw(b"s" * 56)))


def build(seed=7, base_time=None):
    """Return a time-sorted list of crafted Scapy packets (not yet written to disk)."""
    random.seed(seed)
    base_time = base_time if base_time is not None else (time.time() - 300)

    packets = []
    _normal_traffic(packets, base_time)
    _syn_flood(packets, base_time + 60)
    _port_scan(packets, base_time + 90)
    _ping_sweep(packets, base_time + 120)

    packets.sort(key=lambda p: float(p.time))
    return packets


if __name__ == "__main__":
    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    pkts = build()
    wrpcap(str(OUTPUT_PATH), pkts)
    print(f"Wrote {len(pkts)} simulated packets to {OUTPUT_PATH}")
