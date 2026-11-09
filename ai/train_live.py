"""Trains the hybrid detector on features computed the way the LIVE detector computes them.

The Week 8 model was trained on fixed 10-second buckets, but the live detector looks at a
sliding 10-second window at every event. Training on the same kind of window removes that mismatch.

Input:  ai/data/labelled_events.csv
Output: ai/models/hybrid_live_model.joblib
"""
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVENTS_FILE = os.path.join(ROOT, "ai", "data", "labelled_events.csv")
MODEL_DIR = os.path.join(ROOT, "ai", "models")
MODEL_FILE = os.path.join(MODEL_DIR, "hybrid_live_model.joblib")

WINDOW_SECONDS = 10
MARGIN = 1.5
TRY_CONTAMINATION = [0.02, 0.01, 0.005]
CHOSEN_CONTAMINATION = 0.005   # the value saved for the live detector

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
SCORED = {"message_sent", "login_failure", "login_success", "ws_connect"}

ev = pd.read_csv(EVENTS_FILE)
ev["occurred_at"] = pd.to_datetime(ev["occurred_at"], utc=True)
ev = ev.sort_values(["occurred_at", "id"]).reset_index(drop=True)

# A new "run" starts whenever the scenario changes (runs alternate normal / attack)
ev["run"] = (ev["scenario"] != ev["scenario"].shift()).cumsum()

ts = (ev["occurred_at"] - ev["occurred_at"].iloc[0]).dt.total_seconds().to_numpy()
etype = ev["event_type"].to_numpy()
email = ev["email"].to_numpy()
recip = ev["recipient_email"].to_numpy()
size = ev["size_bytes"].to_numpy(dtype=float)

rows = []
for i in range(len(ev)):
    if etype[i] not in SCORED:
        continue
    lo = np.searchsorted(ts, ts[i] - WINDOW_SECONDS, side="left")
    idx = np.arange(lo, i + 1)

    t_win, e_win = etype[idx], email[idx]
    mine = e_win == email[i]
    msgs = mine & (t_win == "message_sent")
    sizes = size[idx][msgs]
    sizes = sizes[~np.isnan(sizes)]
    fails = t_win == "login_failure"

    rows.append({
        "run": ev["run"].iloc[i],
        "scenario": ev["scenario"].iloc[i],
        "label": ev["label"].iloc[i],
        "email": email[i],
        "msg_count": int(msgs.sum()),
        "distinct_recipients": len({r for r in recip[idx][msgs] if isinstance(r, str)}),
        "avg_msg_size": float(sizes.mean()) if len(sizes) else 0.0,
        "max_msg_size": float(sizes.max()) if len(sizes) else 0.0,
        "failed_logins": int((mine & fails).sum()),
        "login_successes": int((mine & (t_win == "login_success")).sum()),
        "ws_connects": int((mine & (t_win == "ws_connect")).sum()),
        "global_failed_logins": int(fails.sum()),
        "global_distinct_failed_emails": len(set(e_win[fails])),
    })

feat = pd.DataFrame(rows)
print("Scored events:", len(feat))

# Time-based split by run: first 60% of runs train, last 40% test
runs = sorted(feat["run"].unique())
cut_run = runs[int(len(runs) * 0.6)]
train = feat[(feat["run"] < cut_run) & (feat["label"] == "normal")]
test = feat[feat["run"] >= cut_run].copy()
print("Training events (normal only):", len(train))
print("Test events:", len(test), "from", test["run"].nunique(), "runs")

limits = {f: float(train[f].max()) * MARGIN + 1 for f in COUNT_FEATURES}
print()
print("Magnitude limits learned from normal training events:")
for f, v in limits.items():
    print(f"  {f:<32} {v:.1f}")


def evaluate(contamination):
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    model.fit(train[FEATURES])
    t = test.copy()
    t["iforest"] = model.predict(t[FEATURES]) == -1
    t["magnitude"] = False
    for f, limit in limits.items():
        t["magnitude"] = t["magnitude"] | (t[f] > limit)
    t["flag"] = t["iforest"] | t["magnitude"]
    return model, t


print()
print("Comparison across contamination values")
print(f"{'contamination':<14}{'attack runs detected':<24}{'normal sessions flagged':<26}{'normal events flagged'}")
for c in TRY_CONTAMINATION:
    _, t = evaluate(c)
    att = t[t["label"] == "attack"].groupby("run")["flag"].any()
    nor = t[t["label"] == "normal"].groupby(["run", "email"])["flag"].any()
    nev = t[t["label"] == "normal"]["flag"].mean()
    print(f"{c:<14}{int(att.sum())} of {len(att):<19}{int(nor.sum())} of {len(nor):<21}{nev:.3f}")

model, t = evaluate(CHOSEN_CONTAMINATION)
print()
print(f"Detail for the saved model (contamination {CHOSEN_CONTAMINATION})")
print("Attack runs detected, per scenario:")
att = t[t["label"] == "attack"].groupby(["scenario", "run"])["flag"].any().reset_index()
print(att.groupby("scenario")["flag"].agg(detected="sum", runs="count"))

# How quickly was each attack caught? Events seen in the run before the first flag
print()
print("Events into the attack before the first flag (smaller is faster):")
lat = []
for (scn, run), g in t[t["label"] == "attack"].groupby(["scenario", "run"]):
    flags = g["flag"].to_numpy()
    lat.append({"scenario": scn, "events_before_first_flag": int(flags.argmax()) if flags.any() else None})
print(pd.DataFrame(lat).groupby("scenario")["events_before_first_flag"].agg(["min", "max"]))

os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(
    {"model": model, "features": FEATURES, "limits": limits, "margin": MARGIN,
     "contamination": CHOSEN_CONTAMINATION},
    MODEL_FILE,
)
print()
print("Saved to", MODEL_FILE)