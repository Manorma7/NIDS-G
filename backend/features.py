"""
features.py
===========
Converts raw packets into connections ("flows") and computes the
NSL-KDD-style feature vector (FEATURES_LIVE) for each one.

Core ideas (cyber security concepts):

1. Flow / connection: packets sharing the same 5-tuple (protocol, src IP,
   src port, dst IP, dst port), independent of direction, belong to the
   same connection. ML-based NIDS classify connections, not single packets.

2. The 2-second window features (count, srv_count, serror_rate,
   rerror_rate, same_srv_rate, diff_srv_rate) describe how a host has been
   behaving *recently*. A SYN flood produces many connections with a high
   serror_rate (half-open handshakes). A port scan produces many
   connections to different ports with a high rerror_rate (RST replies
   from closed ports).

This module has NO network or file I/O of its own -- it only processes
packet objects handed to it, which makes it easy to unit-test with a pcap
and reuse unchanged for both offline replay and live capture.
"""
import threading
from collections import deque
from datetime import datetime

from scapy.layers.inet import IP, TCP, UDP, ICMP

from backend.schema import FEATURES_LIVE

WINDOW = 2.0          # seconds: NSL-KDD's "past two seconds" traffic window
RETENTION = 30.0      # keep finished connections this long for window statistics
CLOSE_GRACE = 1.0     # after FIN/RST, wait this long for trailing packets

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def _payload_len(pkt, l4_header_len):
    """Best-effort payload length for a packet's transport layer."""
    ip = pkt[IP]
    if ip.len is not None and ip.ihl is not None:
        return max(0, ip.len - ip.ihl * 4 - l4_header_len)
    return max(0, len(bytes(ip.payload)) - l4_header_len)


def packet_info(pkt):
    """
    Reduce a Scapy packet to the handful of fields the flow table needs.
    Returns None for anything that is not IPv4 TCP/UDP/ICMP.
    """
    if IP not in pkt:
        return None
    ip = pkt[IP]
    info = {
        "ts": float(pkt.time), "src": ip.src, "dst": ip.dst,
        "sport": 0, "dport": 0, "flags": 0, "icmp_id": 0, "payload": 0,
        "frag": bool((int(ip.flags) & 1) or (ip.frag or 0) > 0),
    }
    if TCP in pkt:
        t = pkt[TCP]
        info.update(proto="tcp", sport=t.sport, dport=t.dport, flags=int(t.flags),
                    payload=_payload_len(pkt, (t.dataofs or 5) * 4))
    elif UDP in pkt:
        u = pkt[UDP]
        udp_len = u.len if u.len is not None else 8 + len(u.payload)
        info.update(proto="udp", sport=u.sport, dport=u.dport, payload=max(0, udp_len - 8))
    elif ICMP in pkt:
        info.update(proto="icmp", icmp_id=int(getattr(pkt[ICMP], "id", 0) or 0),
                    payload=_payload_len(pkt, 8))
    else:
        return None
    return info


class Flow:
    """One network connection. The sender of the first packet is the originator."""

    def __init__(self, info):
        self.proto, self.src, self.dst = info["proto"], info["src"], info["dst"]
        self.sport, self.dport = info["sport"], info["dport"]
        self.start = self.last = info["ts"]
        self.src_bytes = self.dst_bytes = self.npkts = 0
        self.syn = self.synack = self.established = False
        self.rst_orig = self.rst_resp = self.fin_orig = self.fin_resp = False
        self.wrong_fragment = self.urgent = 0
        self.closed = self.finalized = False

    @property
    def service(self):
        """(protocol, destination port) stands in for NSL-KDD's 'service' label."""
        return (self.proto, self.dport)

    @property
    def serror(self):
        """Half-open handshake: SYN sent, never established, never reset -- SYN-flood signature."""
        return (self.proto == "tcp" and self.syn and not self.established
                and not self.rst_resp and not self.rst_orig)

    @property
    def rerror(self):
        """Responder rejected the connection with RST -- closed-port / scan signature."""
        return self.proto == "tcp" and self.rst_resp

    def update(self, info):
        from_originator = info["src"] == self.src and info["sport"] == self.sport
        self.last = max(self.last, info["ts"])
        self.npkts += 1
        if from_originator:
            self.src_bytes += info["payload"]
        else:
            self.dst_bytes += info["payload"]
        if info["frag"]:
            self.wrong_fragment += 1
        if self.proto != "tcp":
            return
        f = info["flags"]
        if f & URG:
            self.urgent += 1
        if f & RST:
            if from_originator:
                self.rst_orig = True
            else:
                self.rst_resp = True
            self.closed = True
        if from_originator:
            if (f & SYN) and not (f & ACK):
                self.syn = True
            elif (f & ACK) and self.synack:
                self.established = True
            if f & FIN:
                self.fin_orig = True
        else:
            if (f & SYN) and (f & ACK):
                self.synack = True
            if f & FIN:
                self.fin_resp = True
        if self.fin_orig and self.fin_resp:
            self.closed = True


class FlowTable:
    """
    Thread-safe table of in-progress and recent connections.

    Usage:
        table = FlowTable()
        table.add_packet(pkt)          # called once per captured packet
        records = table.expire(now)    # called periodically; returns finished flows as feature dicts
    """

    def __init__(self, idle_timeout=5.0, max_duration=120.0):
        self.idle_timeout = idle_timeout
        self.max_duration = max_duration
        self.active = {}
        self.recent = deque()    # all flows, ordered by start time (drives the 2-second window)
        self._lock = threading.RLock()

    @staticmethod
    def _key(info):
        a, b = (info["src"], info["sport"]), (info["dst"], info["dport"])
        return (info["proto"],) + tuple(sorted([a, b])) + (info["icmp_id"],)

    def add_packet(self, pkt):
        info = packet_info(pkt)
        if info is None:
            return
        key = self._key(info)
        with self._lock:
            flow = self.active.get(key)
            if flow is None:
                flow = Flow(info)
                self.active[key] = flow
                self.recent.append(flow)
            flow.update(info)

    def expire(self, now, force=False):
        """Finalize connections that are closed, idle, or too long. Returns a list of feature dicts."""
        finished = []
        with self._lock:
            for key, flow in list(self.active.items()):
                is_done = (
                    force
                    or (flow.closed and now - flow.last >= CLOSE_GRACE)
                    or now - flow.last >= self.idle_timeout
                    or now - flow.start >= self.max_duration
                )
                if is_done:
                    finished.append(self._to_record(flow))
                    flow.finalized = True
                    del self.active[key]
            while self.recent and self.recent[0].finalized and now - self.recent[0].start > RETENTION:
                self.recent.popleft()
        return finished

    def _to_record(self, flow):
        """Compute the full feature record (FEATURES_LIVE + metadata) for one finished flow."""
        window_start = flow.start - WINDOW
        same_dst_host, srv_count = [], 0
        for other in reversed(self.recent):          # ordered by start time -> can stop early
            if other.start > flow.start:
                continue
            if other.start < window_start:
                break
            if other.dst == flow.dst:
                same_dst_host.append(other)
            if other.service == flow.service:
                srv_count += 1
        n = max(len(same_dst_host), 1)
        same_srv_rate = sum(o.service == flow.service for o in same_dst_host) / n

        record = {
            "timestamp": datetime.fromtimestamp(flow.start).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": flow.src, "dst_ip": flow.dst,
            "src_port": flow.sport, "dst_port": flow.dport, "protocol": flow.proto,
            # ---- model input features: names/order must match schema.FEATURES_LIVE ----
            "duration": int(flow.last - flow.start),
            "protocol_type": flow.proto,
            "src_bytes": flow.src_bytes, "dst_bytes": flow.dst_bytes,
            "land": int(flow.src == flow.dst and flow.sport == flow.dport),
            "wrong_fragment": flow.wrong_fragment,
            "urgent": flow.urgent,
            "count": len(same_dst_host),
            "srv_count": srv_count,
            "serror_rate": sum(o.serror for o in same_dst_host) / n,
            "rerror_rate": sum(o.rerror for o in same_dst_host) / n,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": 1.0 - same_srv_rate,
        }
        return record


assert len(FEATURES_LIVE) == 13, "FEATURES_LIVE changed -- update this module's _to_record()"
