"""
capture.py
==========
The capture / replay engine: packets -> FlowTable -> Detector -> SQLite.

This is a standalone command-line program, deliberately separate from the
Streamlit frontend, because Streamlit re-runs its script on every UI
interaction -- a sniffer loop does not belong inside that process. Run this
as its own process; the dashboard (frontend/app.py) only reads the
database it writes to.

Examples (run from the project root):
    python backend/capture.py --pcap data/sim_traffic.pcap
    python backend/capture.py --list-ifaces
    python backend/capture.py --live --iface "Wi-Fi" --authorized

IMPORTANT: --live only ever captures traffic visible to your own machine's
network interface. Only use it on networks and devices you are authorized
to monitor. Live capture requires Npcap (Windows) and an Administrator /
root terminal.
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend import capture_control as control
from backend import db
from backend.detector import Detector
from backend.features import FlowTable


def _process(records, detector, db_path, verbose=True):
    rows = detector.predict_records(records)
    db.insert_detections(rows, db_path)
    if verbose:
        for r in rows:
            if r["prediction"] == "malicious":
                print(
                    f"[ALERT] {r['timestamp']} {r['src_ip']}:{r['src_port']} -> "
                    f"{r['dst_ip']}:{r['dst_port']} {r['protocol']} "
                    f"P(malicious)={r['confidence']:.2f}"
                )
    return rows


def run_pcap(path, threshold=None, db_path=None, idle_timeout=5.0, verbose=False):
    """Replay a pcap file through the full pipeline. Returns a summary dict."""
    from scapy.utils import PcapReader

    detector = Detector(threshold=threshold)
    table = FlowTable(idle_timeout=idle_timeout)
    n_pkts = total = malicious = 0
    last_check = ts = 0.0

    with PcapReader(str(path)) as reader:
        for pkt in reader:
            ts = float(pkt.time)
            table.add_packet(pkt)
            n_pkts += 1
            if ts - last_check >= 1.0:
                last_check = ts
                rows = _process(table.expire(ts), detector, db_path, verbose)
                total += len(rows)
                malicious += sum(r["prediction"] == "malicious" for r in rows)

    rows = _process(table.expire(ts, force=True), detector, db_path, verbose)
    total += len(rows)
    malicious += sum(r["prediction"] == "malicious" for r in rows)
    return {"packets": n_pkts, "flows": total, "malicious": malicious, "benign": total - malicious}


def run_live(iface=None, threshold=None, db_path=None, idle_timeout=5.0, bpf="ip"):
    """
    Sniff live traffic until Ctrl+C or until the dashboard asks us to stop (capture.stop file).
    Writes a heartbeat file every second so the dashboard can show the capture status.
    Only capture networks/devices you are authorized to monitor.
    """
    from scapy.all import AsyncSniffer

    detector = Detector(threshold=threshold)
    table = FlowTable(idle_timeout=idle_timeout)
    control.clear_stop_request()

    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=table.add_packet, store=False)
    sniffer.start()
    time.sleep(1.0)                      # a sniffer that cannot start (no admin rights, no Npcap, bad interface) dies here
    if sniffer.exception is not None or (sniffer.thread is not None and not sniffer.thread.is_alive()):
        sys.exit(f"Could not start capture on {iface!r}: {sniffer.exception}\n"
                 "On Windows, run as Administrator and make sure Npcap is installed.")

    started, written = time.time(), 0
    print(f"Capturing on {iface or 'default interface'} (threshold={detector.threshold}). "
          "Ctrl+C to stop.", flush=True)
    control.write_heartbeat(iface, detector.threshold, started, written)
    try:
        while not control.stop_requested():
            time.sleep(1.0)
            rows = _process(table.expire(time.time()), detector, db_path)
            written += len(rows)
            control.write_heartbeat(iface, detector.threshold, started, written)
    except KeyboardInterrupt:
        print("\nStopping...", flush=True)
    finally:
        sniffer.stop()
        _process(table.expire(time.time(), force=True), detector, db_path)
        control.clear_status()
        control.clear_stop_request()
        print("Capture stopped.", flush=True)


def list_interfaces():
    from scapy.all import conf
    print(conf.ifaces)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ML NIDS capture engine (authorized use only)")
    parser.add_argument("--pcap", help="replay this pcap file")
    parser.add_argument("--live", action="store_true", help="sniff live traffic")
    parser.add_argument("--iface", help="interface name (see --list-ifaces)")
    parser.add_argument("--list-ifaces", action="store_true")
    parser.add_argument("--threshold", type=float, help="alert threshold (default: from models/feature_list.json)")
    parser.add_argument("--authorized", action="store_true",
                        help="confirm you are authorized to monitor this network")
    args = parser.parse_args()

    if args.list_ifaces:
        list_interfaces()
    elif args.pcap:
        print(run_pcap(args.pcap, args.threshold, verbose=True))
    elif args.live:
        if not args.authorized:
            sys.exit("Refusing to capture: pass --authorized to confirm you may monitor this network.")
        run_live(args.iface, args.threshold)
    else:
        parser.print_help()
