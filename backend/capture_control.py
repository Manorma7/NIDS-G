"""
capture_control.py
==================
Start / stop / monitor the live-capture process (backend/capture.py).

Why this exists: the Streamlit dashboard must never run the sniffer itself
(Streamlit re-runs its script on every click, which would restart the
sniffer). Instead the dashboard calls start() here, which launches
backend/capture.py as a SEPARATE background process. The two communicate
only through small files in the project root:

    capture_status.json   written by capture.py every second ("heartbeat")
    capture.stop          created by stop(); capture.py sees it and exits cleanly
    capture.log           stdout/stderr of the capture process (for error messages)

A capture is considered "running" only if its heartbeat is fresh (< 5 s old),
so a crashed process is never reported as running.

This module is deliberately light (no scapy / sklearn imports at the top) so
both capture.py and the frontend can import it cheaply.

IMPORTANT: live capture only sees traffic on your own machine's network
interface. Use it only on networks/devices you are authorized to monitor.
"""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATUS_FILE = ROOT / "capture_status.json"
STOP_FILE = ROOT / "capture.stop"
LOG_FILE = ROOT / "capture.log"
CAPTURE_SCRIPT = ROOT / "backend" / "capture.py"
HEARTBEAT_TIMEOUT = 5.0     # seconds without a heartbeat => not running


# ======================================================================
# Used by the capture process (backend/capture.py)
# ======================================================================
def write_heartbeat(iface, threshold, started, flows_written):
    """Atomically write the status file. Silently skips a beat if the file is momentarily locked."""
    payload = {
        "pid": os.getpid(), "iface": iface, "threshold": threshold,
        "started": started, "flows_written": flows_written, "heartbeat": time.time(),
    }
    tmp = STATUS_FILE.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(payload))
        os.replace(tmp, STATUS_FILE)
    except OSError:
        pass


def clear_status():
    try:
        STATUS_FILE.unlink()
    except FileNotFoundError:
        pass


def stop_requested():
    return STOP_FILE.exists()


def clear_stop_request():
    try:
        STOP_FILE.unlink()
    except FileNotFoundError:
        pass


# ======================================================================
# Used by the frontend
# ======================================================================
def status():
    """Return {'running': bool, ...status-file fields...}."""
    for _ in range(2):                                  # retry once: the file may be mid-replace
        try:
            info = json.loads(STATUS_FILE.read_text())
            info["running"] = (time.time() - info.get("heartbeat", 0)) < HEARTBEAT_TIMEOUT
            return info
        except (FileNotFoundError, ValueError):
            time.sleep(0.05)
    return {"running": False}


def start(iface, threshold=None, wait=10.0):
    """
    Launch backend/capture.py --live in the background.
    Returns (ok, message). Waits up to `wait` seconds for the first heartbeat so that
    start-up problems (no admin rights, Npcap missing, bad interface) can be reported immediately.
    """
    if not iface:
        return False, "Choose a network interface first."
    if status()["running"]:
        return False, "A capture is already running."

    clear_stop_request()
    clear_status()
    cmd = [sys.executable, str(CAPTURE_SCRIPT), "--live", "--iface", iface, "--authorized"]
    if threshold is not None:
        cmd += ["--threshold", str(threshold)]

    # The child shares the parent's console (no new window), so Ctrl+C in the terminal that runs
    # Streamlit also stops the capture cleanly. Its output goes to capture.log.
    log = open(LOG_FILE, "w")
    proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL)
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(0.25)
        if status()["running"]:
            return True, f"Capture started on '{iface}'."
        if proc.poll() is not None:                      # process already exited => failed to start
            return False, "Capture process exited immediately. See the log below."
    return False, "Capture did not report in time. See the log below."


def stop(timeout=10.0):
    """Ask the capture process to stop (clean exit flushes unfinished connections). Returns (ok, message)."""
    info = status()
    if not info["running"]:
        clear_status()
        clear_stop_request()
        return True, "No capture was running."

    STOP_FILE.write_text("stop")
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.3)
        if not status()["running"]:
            clear_stop_request()
            return True, "Capture stopped."

    pid = info.get("pid")                                # did not exit in time: force it
    if pid:
        try:
            os.kill(int(pid), signal.SIGTERM)
        except OSError:
            pass
    clear_status()
    clear_stop_request()
    return True, "Capture did not stop in time and was terminated."


def tail_log(n=15):
    try:
        lines = LOG_FILE.read_text(errors="replace").splitlines()
    except FileNotFoundError:
        return ""
    return "\n".join(lines[-n:])


def is_admin():
    """True if this process has admin/root rights (needed for packet capture). None if unknown."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return None


def list_interfaces():
    """[(label, name), ...] for the interface picker. Interfaces that have an IP come first."""
    try:
        from scapy.all import conf
        items = []
        for i in conf.ifaces.values():
            name = getattr(i, "name", str(i))
            ip = getattr(i, "ip", "") or ""
            has_ip = bool(ip) and ip != "0.0.0.0"
            items.append((not has_ip, f"{name}  [{ip}]" if has_ip else name, name))
        items.sort(key=lambda t: (t[0], t[1]))
        return [(label, name) for _, label, name in items]
    except Exception:
        return []
