"""
db.py
=====
SQLite data-access layer for detection history. Used by both the capture
engine (writer) and the Streamlit frontend (reader), so it must be safe for
concurrent access -- hence WAL journal mode.
"""
import json
import sqlite3
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = ROOT / "nids.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT,
    src_ip      TEXT,
    dst_ip      TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    protocol    TEXT,
    prediction  TEXT,     -- 'benign' or 'malicious'
    confidence  REAL,     -- P(malicious), 0..1
    features    TEXT      -- JSON blob of the raw feature values used for this prediction
);
CREATE INDEX IF NOT EXISTS idx_detections_timestamp  ON detections(timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_prediction ON detections(prediction);
"""


def connect(db_path=None):
    conn = sqlite3.connect(str(db_path or DEFAULT_DB_PATH), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")   # lets the dashboard read while capture.py writes
    return conn


def init_db(db_path=None):
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


def insert_detections(rows, db_path=None):
    """rows: list of dicts with timestamp, src_ip, dst_ip, src_port, dst_port,
    protocol, prediction, confidence, features (dict)."""
    if not rows:
        return 0
    init_db(db_path)
    values = [
        (r["timestamp"], r["src_ip"], r["dst_ip"], int(r["src_port"]), int(r["dst_port"]),
         r["protocol"], r["prediction"], float(r["confidence"]), json.dumps(r.get("features", {})))
        for r in rows
    ]
    with connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO detections "
            "(timestamp, src_ip, dst_ip, src_port, dst_port, protocol, prediction, confidence, features) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            values,
        )
    return len(values)


def fetch(db_path=None, limit=500, prediction=None, protocol=None, src_ip=None, min_conf=0.0):
    """Query detection history with optional filters. Returns a pandas DataFrame."""
    init_db(db_path)
    where, params = ["confidence >= ?"], [min_conf]
    if prediction:
        where.append(f"prediction IN ({','.join('?' * len(prediction))})")
        params += list(prediction)
    if protocol:
        where.append(f"protocol IN ({','.join('?' * len(protocol))})")
        params += list(protocol)
    if src_ip:
        where.append("src_ip LIKE ?")
        params.append(f"%{src_ip}%")
    sql = (
        "SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, prediction, confidence "
        f"FROM detections WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?"
    )
    with connect(db_path) as conn:
        return pd.read_sql_query(sql, conn, params=params + [int(limit)])


def counts(db_path=None):
    init_db(db_path)
    with connect(db_path) as conn:
        total, malicious = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(prediction='malicious'), 0) FROM detections"
        ).fetchone()
    return {"total": total, "malicious": malicious, "benign": total - malicious}


def clear(db_path=None):
    init_db(db_path)
    with connect(db_path) as conn:
        conn.execute("DELETE FROM detections")
