"""Hybrid detector: Isolation Forest (unusual combinations) plus magnitude limits (extreme single counts).

Input:  ai/data/features.csv, ai/data/labelled_events.csv
Output: ai/models/hybrid_model.joblib
"""
import os

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEATURES_FILE = os.path.join(ROOT, "ai", "data", "features.csv")
EVENTS_FILE = os.path.join(ROOT, "ai", "data", "labelled_events.csv")
MODEL_DIR = os.path.join(ROOT, "ai", "models")
MODEL_FILE = os.path.join(MODEL_DIR, "hybrid_model.joblib")
WINDOW_SECONDS = 10
MARGIN = 1.5  # a count may exceed the highest value seen in training by 50% before it is suspicious

FEATURES = [
    "msg_count",
    "distinct_recipients",
    "avg_msg_size",
    "max_msg_size",
    "failed_logins",
    "login_successes",
    "ws_connects",
    "global_failed_logins",
    "global_distinct_failed_emails",
]
COUNT_FEATURES = [
    "msg_count",
    "failed_logins",
    "login_successes",
    "ws_connects",
    "global_failed_logins",
    "global_distinct_failed_emails",
]

rows = pd.read_csv(FEATURES_FILE)
rows["window"] = pd.to_datetime(rows["window"], utc=True)

ev = pd.read_csv(EVENTS_FILE)
ev["occurred_at"] = pd.to_datetime(ev["occurred_at"], utc=True)
ev["window"] = ev["occurred_at"].dt.floor(f"{WINDOW_SECONDS}s")
scenario_per_row = (
    ev.groupby(["email", "window"])["scenario"]
    .agg(lambda s: s.value_counts().idxmax())
    .reset_index()
)
rows = rows.merge(scenario_per_row, on=["email", "window"], how="left")

# Same time-based split as train_model.py, so the results are comparable
windows = rows["window"].drop_duplicates().sort_values().tolist()
cutoff = windows[int(len(windows) * 0.6)]
train = rows[(rows["window"] < cutoff) & (rows["label"] == "normal")]
test = rows[rows["window"] >= cutoff].copy()

model = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
model.fit(train[FEATURES])

# Magnitude limits, learned from normal training behaviour only
limits = {f: float(train[f].max()) * MARGIN + 1 for f in COUNT_FEATURES}
print("Magnitude limits learned from normal training rows:")
for f, v in limits.items():
    print(f"  {f:<32} {v:.1f}")
print()


def magnitude_flag(df):
    flag = pd.Series(False, index=df.index)
    for f, limit in limits.items():
        flag = flag | (df[f] > limit)
    return flag


test["iforest_flag"] = model.predict(test[FEATURES]) == -1
test["magnitude_flag"] = magnitude_flag(test)
test["hybrid_flag"] = test["iforest_flag"] | test["magnitude_flag"]
test["actual_attack"] = test["label"] == "attack"


def report(name, col):
    y_true, y_pred = test["actual_attack"], test[col]
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[False, True]).ravel()
    print(
        f"{name:<24} precision {precision_score(y_true, y_pred, zero_division=0):.3f}"
        f"  recall {recall_score(y_true, y_pred, zero_division=0):.3f}"
        f"  F1 {f1_score(y_true, y_pred, zero_division=0):.3f}"
        f"  false positive rate {fp / (fp + tn):.3f}"
        f"  (TP {tp}, FN {fn}, FP {fp}, TN {tn})"
    )


print("Results on the test set")
report("Isolation Forest only", "iforest_flag")
report("Magnitude limits only", "magnitude_flag")
report("Hybrid (either flags)", "hybrid_flag")
print()

print("Share of rows flagged, per scenario")
per = test.groupby("scenario")[["iforest_flag", "magnitude_flag", "hybrid_flag"]].mean().round(3)
per["rows"] = test.groupby("scenario").size()
print(per)

os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(
    {"model": model, "features": FEATURES, "limits": limits, "margin": MARGIN},
    MODEL_FILE,
)
print()
print("Hybrid model saved to", MODEL_FILE)