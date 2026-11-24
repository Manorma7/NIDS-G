"""
app.py  (FRONTEND)
===================
Streamlit dashboard for the Intelligent Network Intrusion Detection System
(NIDS). This file contains ONLY presentation logic -- feature extraction,
detection, database and packet-capture work is delegated to the backend
package (backend.detector, backend.db, backend.capture, backend.capture_control).
The frontend never computes a feature or touches the model directly.

Run from the project root:
    streamlit run frontend/app.py
"""
import json
import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend import capture, capture_control, db
from backend.detector import Detector
from backend.schema import COLUMNS, FEATURES_LIVE

st.set_page_config(page_title="NIDS", page_icon="🛡️", layout="wide")
st.title("🛡️ Network Intrusion Detection System (NIDS)")
st.warning("**Authorized use only.** Monitor only networks and devices you own or have written permission to test.")

db.init_db()


@st.cache_resource
def load_detector(threshold):
    return Detector(threshold=threshold)


@st.cache_data(show_spinner=False)
def get_interfaces():
    return capture_control.list_interfaces()


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.header("Controls")
    meta_path = ROOT / "models" / "feature_list.json"
    if not meta_path.exists():
        st.error("No trained model found. Run `python backend/train_model.py` first.")
        st.stop()
    meta = json.loads(meta_path.read_text())

    threshold = st.slider(
        "Alert threshold  P(malicious) ≥", 0.05, 0.95,
        float(meta.get("default_threshold", 0.5)), 0.05,
        help="Lower = catch more attacks but raise more false alarms.",
    )
    auto_refresh = st.checkbox("Auto-refresh", value=False)
    refresh_interval = st.slider("Refresh every (s)", 2, 30, 5)

    st.divider()
    st.subheader("Replay a pcap (demo)")
    pcap_path = st.text_input("pcap path", str(ROOT / "data" / "sim_traffic.pcap"))
    if st.button("Replay through NIDS"):
        try:
            with st.spinner("Processing packets..."):
                summary = capture.run_pcap(pcap_path, threshold=threshold)
            st.success(f"{summary['packets']} packets -> {summary['flows']} flows, {summary['malicious']} malicious")
        except Exception as e:
            st.error(f"Could not replay: {e}")

    st.divider()
    st.caption("Live capture: use the 📡 Capture tab. Command-line alternative (Administrator terminal):")
    st.code('python backend/capture.py --live --iface "Wi-Fi" --authorized', language="bash")

    if st.checkbox("Enable database reset"):
        if st.button("🗑️ Clear detection history"):
            db.clear()
            st.rerun()

tab_live, tab_capture, tab_history, tab_charts, tab_batch, tab_model = st.tabs(
    ["🚨 Live alerts", "📡 Capture", "📜 History", "📊 Charts", "📁 Batch CSV", "🧪 Model"]
)

# ---------------------------------------------------------------- live alerts
with tab_live:
    stats = db.counts()
    col1, col2, col3 = st.columns(3)
    col1.metric("Flows analysed", f"{stats['total']:,}")
    col2.metric("Malicious flagged", f"{stats['malicious']:,}")
    rate = (100 * stats["malicious"] / stats["total"]) if stats["total"] else 0
    col3.metric("Alert rate", f"{rate:.1f}%")

    st.subheader("Most recent alerts")
    alerts = db.fetch(limit=50, prediction=["malicious"])
    if alerts.empty:
        st.info("No alerts yet. Replay the demo pcap from the sidebar, or start backend/capture.py.")
    else:
        st.dataframe(alerts, use_container_width=True, hide_index=True)

# ---------------------------------------------------------------- capture control
with tab_capture:
    st.subheader("Live packet capture")
    st.caption("Start/Stop launches backend/capture.py as a separate background process. "
               "It only sees traffic on this computer's own network interface.")

    if capture_control.is_admin() is False:
        st.warning("This dashboard is **not** running with Administrator/root rights. Packet capture needs them "
                   "(and Npcap on Windows). Re-open VS Code / your terminal as Administrator and restart the dashboard.")

    cap = capture_control.status()
    if cap["running"]:
        since = time.strftime("%H:%M:%S", time.localtime(cap.get("started", time.time())))
        st.success(f"● Capture RUNNING on **{cap.get('iface')}** since {since} (PID {cap.get('pid')}). "
                   f"Flows written this session: {cap.get('flows_written', 0)}. "
                   f"Alert threshold: {cap.get('threshold')}.")
        st.caption("The threshold is fixed when capture starts; stop and start again to change it. "
                   "Turn on Auto-refresh in the sidebar to watch results arrive.")
        if st.button("⏹ Stop capture", type="primary"):
            with st.spinner("Stopping capture..."):
                ok, msg = capture_control.stop()
            st.session_state["capture_msg"] = ("success" if ok else "error", msg)
            st.rerun()
    else:
        st.info("○ Capture is stopped.")
        interfaces = get_interfaces()
        labels = [label for label, _ in interfaces]
        choice = st.selectbox("Network interface", labels) if labels else None
        manual = st.text_input("...or type the interface name yourself", placeholder="Wi-Fi")
        iface = manual.strip()
        if not iface and choice:
            iface = dict(interfaces)[choice]
        authorized = st.checkbox("I confirm this is my own device/network, or I have written permission to monitor it.")
        if st.button("▶ Start capture", type="primary", disabled=not (authorized and iface)):
            with st.spinner("Starting capture..."):
                ok, msg = capture_control.start(iface, threshold=threshold)
            st.session_state["capture_msg"] = ("success" if ok else "error", msg)
            st.rerun()

    flash = st.session_state.pop("capture_msg", None)
    if flash:
        if flash[0] == "success":
            st.success(flash[1])
        else:
            st.error(flash[1])

    log_text = capture_control.tail_log(15)
    if log_text:
        with st.expander("Capture log (last lines)"):
            st.code(log_text)

# ---------------------------------------------------------------- history
with tab_history:
    f1, f2, f3, f4 = st.columns(4)
    pred_filter = f1.multiselect("Prediction", ["malicious", "benign"], default=["malicious", "benign"])
    proto_filter = f2.multiselect("Protocol", ["tcp", "udp", "icmp"], default=["tcp", "udp", "icmp"])
    ip_filter = f3.text_input("Source IP contains")
    conf_filter = f4.slider("Min confidence", 0.0, 1.0, 0.0, 0.05)
    limit = st.number_input("Max rows", 50, 20000, 1000, step=50)

    history = db.fetch(limit=limit, prediction=pred_filter, protocol=proto_filter,
                       src_ip=ip_filter or None, min_conf=conf_filter)
    st.caption(f"{len(history):,} rows")
    st.dataframe(history, use_container_width=True, hide_index=True)
    st.download_button("Download CSV", history.to_csv(index=False).encode(), "nids_history.csv", "text/csv")

# ---------------------------------------------------------------- charts
with tab_charts:
    data = db.fetch(limit=50000)
    if data.empty:
        st.info("No data yet.")
    else:
        data["timestamp"] = pd.to_datetime(data["timestamp"])
        bucket = st.selectbox("Time bucket", ["10s", "30s", "1min", "5min"], index=2)
        series = (
            data.set_index("timestamp")
            .groupby([pd.Grouper(freq=bucket), "prediction"])
            .size()
            .unstack(fill_value=0)
        )
        st.subheader("Benign vs malicious flows over time")
        st.area_chart(series)

        left, right = st.columns(2)
        malicious = data[data.prediction == "malicious"]
        with left:
            st.subheader("Top source IPs (malicious)")
            if not malicious.empty:
                st.bar_chart(malicious.src_ip.value_counts().head(10))
            else:
                st.caption("none")
        with right:
            st.subheader("Top destination ports (malicious)")
            if not malicious.empty:
                st.bar_chart(malicious.dst_port.astype(str).value_counts().head(10))
            else:
                st.caption("none")

        st.subheader("Confidence distribution")
        bins = pd.cut(data.confidence, [0, .1, .2, .3, .4, .5, .6, .7, .8, .9, 1.0], include_lowest=True)
        st.bar_chart(bins.value_counts().sort_index().rename(lambda i: str(i)))

# ---------------------------------------------------------------- batch csv
with tab_batch:
    st.write("Upload a CSV containing these columns (or a raw NSL-KDD `.txt`/`.csv` file with no header):")
    st.code(", ".join(FEATURES_LIVE))
    uploaded = st.file_uploader("CSV file", type=["csv", "txt"])
    if uploaded is not None:
        df = pd.read_csv(uploaded)
        if not set(FEATURES_LIVE) <= set(df.columns):
            uploaded.seek(0)
            raw = pd.read_csv(uploaded, header=None)
            raw.columns = COLUMNS[: raw.shape[1]]
            df = raw

        missing = [c for c in FEATURES_LIVE if c not in df.columns]
        if missing:
            st.error(f"Missing columns: {missing}")
        else:
            result = load_detector(threshold).predict_frame(df)
            n_malicious = int((result.prediction == "malicious").sum())
            st.success(f"{len(result):,} rows analysed, {n_malicious:,} flagged malicious "
                      f"({100 * n_malicious / len(result):.1f}%)")
            st.dataframe(result[FEATURES_LIVE + ["confidence", "prediction"]].head(1000), use_container_width=True)

            if "label" in result.columns:
                truth = result["label"].ne("normal").map({True: "malicious", False: "benign"})
                st.subheader("Comparison with the file's labels")
                st.dataframe(pd.crosstab(truth, result.prediction, rownames=["truth"], colnames=["predicted"]))

            st.download_button("Download results", result.to_csv(index=False).encode(),
                               "nids_batch_results.csv", "text/csv")

# ---------------------------------------------------------------- model info
with tab_model:
    metrics_path = ROOT / "models" / "metrics.json"
    if metrics_path.exists():
        metrics = json.loads(metrics_path.read_text())
        st.subheader("Deployed model performance (NSL-KDD official test set)")
        st.dataframe(pd.DataFrame([metrics["live_model"]]).round(4))
        st.metric("Alert threshold", metrics["threshold"])
    for image_name in ["confusion_matrix.png", "feature_importance_full.png", "confusion_and_roc_full.png"]:
        image_path = ROOT / "models" / image_name
        if image_path.exists():
            st.image(str(image_path), caption=image_name)
    st.info(
        "NSL-KDD is a 1998-era lab dataset. Scores here do not predict accuracy on real modern networks, "
        "and unseen attack types are often missed. See notebooks/01_EDA_and_Model_Training.ipynb and the "
        "project report for full limitations."
    )

# ---------------------------------------------------------------- auto refresh
if auto_refresh:
    time.sleep(refresh_interval)
    st.rerun()
