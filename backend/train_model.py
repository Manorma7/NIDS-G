"""
train_model.py
===============
Trains the deployable ML-NIDS model on NSL-KDD and saves it for the
detector to load. This is the backend's training logic as a standalone,
re-runnable script; notebooks/01_EDA_and_Model_Training.ipynb imports and
calls train_and_save() so the exploratory notebook and the "real" training
code never fall out of sync.

Run directly:
    python backend/train_model.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from backend.schema import CATEGORICAL, COLUMNS, FEATURES_LIVE
DATA_DIR = ROOT / "data"
MODELS_DIR = ROOT / "models"
RANDOM_STATE = 42
DEFAULT_THRESHOLD = 0.3   # favors recall; see the notebook's threshold-tuning section for the justification


def load_nsl_kdd():
    train = pd.read_csv(DATA_DIR / "KDDTrain+.txt", names=COLUMNS)
    test = pd.read_csv(DATA_DIR / "KDDTest+.txt", names=COLUMNS)
    for df in (train, test):
        df["target"] = (df["label"] != "normal").astype(int)
        df.drop(columns=["difficulty"], inplace=True)
    return train, test


def make_pipeline(model, features):
    categorical = [c for c in features if c in CATEGORICAL]
    numeric = [c for c in features if c not in CATEGORICAL]
    transformers = [("num", StandardScaler(), numeric)]
    if categorical:
        transformers.append(("cat", OneHotEncoder(handle_unknown="ignore"), categorical))
    return Pipeline([("prep", ColumnTransformer(transformers)), ("model", model)])


def evaluate(pipeline, X, y, threshold=0.5):
    proba = pipeline.predict_proba(X)[:, 1]
    pred = (proba >= threshold).astype(int)
    return {
        "accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred),
        "recall": recall_score(y, pred), "f1": f1_score(y, pred), "roc_auc": roc_auc_score(y, proba),
    }


def train_and_save(threshold=DEFAULT_THRESHOLD):
    """Train the live-feature Random Forest and save pipeline + metadata. Returns the metrics dict."""
    MODELS_DIR.mkdir(exist_ok=True)
    train, test = load_nsl_kdd()

    model = RandomForestClassifier(n_estimators=150, min_samples_leaf=2, n_jobs=-1, random_state=RANDOM_STATE)
    pipeline = make_pipeline(model, FEATURES_LIVE).fit(train[FEATURES_LIVE], train.target)

    metrics = evaluate(pipeline, test[FEATURES_LIVE], test.target, threshold=threshold)

    joblib.dump(pipeline, MODELS_DIR / "nids_pipeline.joblib", compress=3)
    meta = {
        "features": FEATURES_LIVE,
        "categorical": [c for c in FEATURES_LIVE if c in CATEGORICAL],
        "dataset": "NSL-KDD", "positive_class": "attack", "default_threshold": threshold,
    }
    (MODELS_DIR / "feature_list.json").write_text(json.dumps(meta, indent=2))
    (MODELS_DIR / "metrics.json").write_text(json.dumps({"live_model": metrics, "threshold": threshold}, indent=2))
    return metrics


if __name__ == "__main__":
    results = train_and_save()
    print("Saved models/nids_pipeline.joblib and models/feature_list.json")
    print({k: round(v, 4) for k, v in results.items()})
