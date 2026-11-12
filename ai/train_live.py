"""Trains the hybrid detector (Isolation Forest + magnitude limits) on live-style features.

Input:  ai/data/labelled_events.csv
Output: ai/models/hybrid_live_model.joblib

Usage:  python ai\\train_live.py [--contamination 0.005]
"""
import argparse
import os

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from features_live import FEATURES, COUNT_FEATURES, add_runs, build_live_features

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVENTS_FILE = os.path.join(ROOT, "ai", "data", "labelled_events.csv")
MODEL_DIR = os.path.join(ROOT, "ai", "models")
MODEL_FILE = os.path.join(MODEL_DIR, "hybrid_live_model.joblib")

MARGIN = 1.5  # a count may exceed the highest normal value seen in training by 50% before it is suspicious
TRY_CONTAMINATION = [0.02, 0.01, 0.005]

parser = argparse.ArgumentParser()
parser.add_argument("--contamination", type=float, default=0.005)
args = parser.parse_args()
CHOSEN = args.contamination

ev = pd.read_csv(EVENTS_FILE)
ev["occurred_at"] = pd.to_datetime(ev["occurred_at"], utc=True)
ev = add_runs(ev)
feat = build_live_features(ev)
print("Scored events:", len(feat))

# Time-based split by run: first 60% of runs train, last 40% are used to choose the setting
runs = sorted(feat["run"].unique())
cut_run = runs[int(len(runs) * 0.6)]
train = feat[(feat["run"] < cut_run) & (feat["label"] == "normal")]
valid = feat[feat["run"] >= cut_run].copy()
print("Training events (normal only):", len(train))
print("Validation events:", len(valid), "from", valid["run"].nunique(), "runs")

limits = {f: float(train[f].max()) * MARGIN + 1 for f in COUNT_FEATURES}
print()
print("Magnitude limits learned from normal training events")
print("(the previous version learned 17.5, 17.5, 2.5, 2.5, 47.5, 47.5 in this order):")
for f, v in limits.items():
    print(f"  {f:<32} {v:.1f}")


def evaluate(contamination):
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    model.fit(train[FEATURES])
    t = valid.copy()
    t["iforest"] = model.predict(t[FEATURES]) == -1
    t["magnitude"] = False
    for f, limit in limits.items():
        t["magnitude"] = t["magnitude"] | (t[f] > limit)
    t["flag"] = t["iforest"] | t["magnitude"]
    return model, t


print()
print("Comparison across contamination values (validation runs)")
print(f"{'contamination':<14}{'attack runs detected':<24}{'normal sessions flagged':<26}{'normal events flagged'}")
for c in TRY_CONTAMINATION:
    _, t = evaluate(c)
    att = t[t["label"] == "attack"].groupby("run")["flag"].any()
    nor = t[t["label"] == "normal"].groupby(["run", "email"])["flag"].any()
    nev = t[t["label"] == "normal"]["flag"].mean()
    print(f"{c:<14}{int(att.sum())} of {len(att):<19}{int(nor.sum())} of {len(nor):<21}{nev:.3f}")

model, t = evaluate(CHOSEN)
print()
print(f"Detail for the saved model (contamination {CHOSEN})")
print("Attack runs detected, per scenario:")
att = t[t["label"] == "attack"].groupby(["scenario", "run"])["flag"].any().reset_index()
print(att.groupby("scenario")["flag"].agg(detected="sum", runs="count"))

print()
print("Events into the attack before the first flag (smaller is faster):")
lat = []
for (scn, run), g in t[t["label"] == "attack"].groupby(["scenario", "run"]):
    flags = g["flag"].to_numpy()
    lat.append({"scenario": scn, "events_before_first_flag": int(flags.argmax()) if flags.any() else None})
print(pd.DataFrame(lat).groupby("scenario")["events_before_first_flag"].agg(["min", "max"]))

os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(
    {"model": model, "features": FEATURES, "limits": limits, "margin": MARGIN, "contamination": CHOSEN},
    MODEL_FILE,
)
print()
print("Saved to", MODEL_FILE)