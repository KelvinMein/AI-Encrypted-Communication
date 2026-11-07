"""Trains an Isolation Forest on normal behaviour and reports first results.

Input:  ai/data/features.csv, ai/data/labelled_events.csv
Output: ai/models/anomaly_model.joblib
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
MODEL_FILE = os.path.join(MODEL_DIR, "anomaly_model.joblib")
WINDOW_SECONDS = 10

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

rows = pd.read_csv(FEATURES_FILE)
rows["window"] = pd.to_datetime(rows["window"], utc=True)

# Attach the scenario name to each row, so results can be shown per attack type
ev = pd.read_csv(EVENTS_FILE)
ev["occurred_at"] = pd.to_datetime(ev["occurred_at"], utc=True)
ev["window"] = ev["occurred_at"].dt.floor(f"{WINDOW_SECONDS}s")
scenario_per_row = (
    ev.groupby(["email", "window"])["scenario"]
    .agg(lambda s: s.value_counts().idxmax())
    .reset_index()
)
rows = rows.merge(scenario_per_row, on=["email", "window"], how="left")

# Time-based split: first 60% of windows for training, last 40% for testing
windows = rows["window"].drop_duplicates().sort_values().tolist()
cutoff = windows[int(len(windows) * 0.6)]
train = rows[(rows["window"] < cutoff) & (rows["label"] == "normal")]
test = rows[rows["window"] >= cutoff].copy()

print("Training rows (normal only):", len(train))
print("Test rows:", len(test), "-", int((test["label"] == "attack").sum()), "attack,",
      int((test["label"] == "normal").sum()), "normal")
print()

model = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
model.fit(train[FEATURES])

test["predicted_attack"] = model.predict(test[FEATURES]) == -1
test["actual_attack"] = test["label"] == "attack"

y_true = test["actual_attack"]
y_pred = test["predicted_attack"]
tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[False, True]).ravel()

print("Results on the test set")
print("  Precision:", round(precision_score(y_true, y_pred), 3))
print("  Recall:   ", round(recall_score(y_true, y_pred), 3))
print("  F1 score: ", round(f1_score(y_true, y_pred), 3))
print("  False positive rate:", round(fp / (fp + tn), 3))
print("  Confusion matrix: true positives", tp, "| false negatives", fn,
      "| false positives", fp, "| true negatives", tn)
print()

print("Share of rows flagged, per scenario")
per_scenario = test.groupby("scenario")["predicted_attack"].agg(["mean", "sum", "count"])
per_scenario.columns = ["share_flagged", "flagged", "rows"]
print(per_scenario.round(3))

os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump({"model": model, "features": FEATURES}, MODEL_FILE)
print()
print("Model saved to", MODEL_FILE)