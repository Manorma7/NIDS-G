"""
detector.py
===========
Loads the trained scikit-learn pipeline (produced by train_model.py) and
applies it to flow feature records. This is the only place in the backend
that touches the ML model, so retraining or swapping algorithms never
requires touching features.py, db.py, or capture.py.
"""
import json
from pathlib import Path

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL_PATH = ROOT / "models" / "nids_pipeline.joblib"
DEFAULT_META_PATH = ROOT / "models" / "feature_list.json"


class Detector:
    def __init__(self, model_path=None, meta_path=None, threshold=None):
        self.pipeline = joblib.load(model_path or DEFAULT_MODEL_PATH)
        with open(meta_path or DEFAULT_META_PATH) as f:
            self.meta = json.load(f)
        self.features = self.meta["features"]
        default_threshold = self.meta.get("default_threshold", 0.5)
        self.threshold = default_threshold if threshold is None else float(threshold)

    def predict_frame(self, df):
        """
        df must contain self.features columns.
        Returns a copy of df with added 'confidence' (P(malicious)) and 'prediction' columns.
        """
        out = df.copy()
        out["confidence"] = self.pipeline.predict_proba(df[self.features])[:, 1].round(4)
        out["prediction"] = out["confidence"].map(
            lambda p: "malicious" if p >= self.threshold else "benign"
        )
        return out

    def predict_records(self, records):
        """
        records: list of dicts produced by backend.features.FlowTable.expire().
        Returns a list of dicts ready for backend.db.insert_detections().
        """
        if not records:
            return []
        scored = self.predict_frame(pd.DataFrame(records))
        rows = scored.to_dict("records")
        for row in rows:
            row["features"] = {k: row[k] for k in self.features}
        return rows
