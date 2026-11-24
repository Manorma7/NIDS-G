# Intelligent Network Intrusion Detection System (NIDS)

A software-based Network Intrusion Detection System. It captures or replays network
traffic, groups packets into connections, extracts traffic features, classifies each
connection as **benign** or **malicious** with a trained scikit-learn model, stores every
decision in SQLite, and presents alerts and charts in a Streamlit dashboard.

> **Authorized use only.** Monitor only networks and devices you own or have written
> permission to test. Never run scans or floods against college or public networks.
> `backend/simulate_traffic.py` creates attack-like traffic as a pcap file without
> sending anything on a network.

## Project structure

```
NIDS_project/
├── backend/                  Detection engine (pure Python, no UI code)
│   ├── schema.py               feature names shared by every module
│   ├── features.py             packets -> connections -> 13 traffic features
│   ├── detector.py             loads the saved model, scores connections
│   ├── db.py                   SQLite detection history
│   ├── capture.py              command line: pcap replay and live capture
│   ├── capture_control.py      start / stop / status of the live-capture process
│   ├── simulate_traffic.py     safe, in-memory test traffic -> data/sim_traffic.pcap
│   └── train_model.py          trains and saves the model
├── frontend/
│   └── app.py                  Streamlit dashboard (presentation only)
├── notebooks/                  dataset analysis and model comparison
├── data/                       NSL-KDD files, sim_traffic.pcap
├── models/                     nids_pipeline.joblib, feature_list.json, metrics.json
└── requirements.txt
```

The dashboard never extracts features or touches the model itself; it calls into `backend`.
The packet sniffer runs as its own process (`backend/capture.py`) because Streamlit
re-runs its script on every click. The two sides share only the SQLite file and three small
status files in the project folder (`capture_status.json`, `capture.stop`, `capture.log`).

## Setup (Windows)

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python backend\train_model.py        # recommended once: re-creates the model for YOUR scikit-learn version
```

Live capture additionally needs **Npcap** (https://npcap.com, tick "WinPcap API-compatible
Mode") and VS Code / the terminal started **as Administrator**. Pcap replay needs neither.

## Running

```powershell
python backend\simulate_traffic.py       # once: creates data\sim_traffic.pcap
streamlit run frontend\app.py
```

In the dashboard:

| Tab | Purpose |
|---|---|
| Live alerts | counters and the 50 most recent malicious detections |
| Capture | choose an interface, confirm authorization, **Start / Stop** live capture |
| History | all detections with filters (prediction, protocol, source IP, confidence) and CSV download |
| Charts | traffic over time, top malicious sources and ports, confidence distribution |
| Batch CSV | classify an uploaded CSV of the 13 features (or a raw NSL-KDD file) |
| Model | stored evaluation numbers and figures |

Sidebar: alert threshold, auto-refresh, pcap replay, database reset.

Command-line alternatives:

```powershell
python backend\capture.py --pcap data\sim_traffic.pcap
python backend\capture.py --list-ifaces
python backend\capture.py --live --iface "Wi-Fi" --authorized
```

## Limitations

- The model is trained on NSL-KDD, a 1998-era lab dataset; modern encrypted traffic looks different.
- Supervised models struggle with attack types that were absent from the training data.
- Only IPv4 TCP/UDP/ICMP is analysed. Content-based attacks (R2L/U2R) are not visible at connection level.
- Normal bursts of connections to one host (for example, a browser opening many connections)
  can be flagged as malicious; the threshold trades missed attacks against false alarms.
- The simulated pcap shows that the pipeline works end to end; it is not a measure of real-world accuracy.
