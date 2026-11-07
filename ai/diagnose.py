"""Shows why flooding and replay rows were not flagged: training range vs attack values, and anomaly scores."""
import os

import joblib
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
bundle = joblib.load(os.path.join(ROOT, "ai", "models", "anomaly_model.joblib"))
model, FEATURES = bundle["model"], bundle["features"]

rows = pd.read_csv(os.path.join(ROOT, "ai", "data", "features.csv"))
ev = pd.read_csv(os.path.join(ROOT, "ai", "data", "labelled_events.csv"))
ev["window"] = pd.to_datetime(ev["occurred_at"], utc=True).dt.floor("10s")
rows["window"] = pd.to_datetime(rows["window"], utc=True)
scen = (ev.groupby(["email", "window"])["scenario"]
          .agg(lambda s: s.value_counts().idxmax()).reset_index())
rows = rows.merge(scen, on=["email", "window"], how="left")

rows["score"] = model.score_samples(rows[FEATURES])  # lower = more anomalous
normal = rows[rows["scenario"] == "normal"]

print("Anomaly score by scenario (lower = more anomalous):")
print(rows.groupby("scenario")["score"].agg(["min", "mean", "max"]).round(3))
print()
print("Model's flagging threshold:", round(model.offset_, 3))
print()
print("Highest value of each feature among NORMAL rows vs among flooding / replay rows:")
cmp = pd.DataFrame({
    "normal_max": normal[FEATURES].max(),
    "flooding_max": rows[rows["scenario"] == "flooding"][FEATURES].max(),
    "replay_max": rows[rows["scenario"] == "replay_burst"][FEATURES].max(),
})
print(cmp.round(1))