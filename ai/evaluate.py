"""Evaluates the detectors on held-out data the models never saw during training.

Held-out data = simulator runs logged after a start time (the models were trained on earlier runs).
Compares the deployed hybrid, its two halves, and a simple hand-written rule.

Usage:  python ai\\evaluate.py --start 2026-11-12T07:27:18+00:00
"""
import argparse
import math
import os

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from sklearn.metrics import f1_score, precision_score, recall_score
from sqlalchemy import create_engine, text

from features_live import add_runs, build_live_features

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT, "backend", ".env"))

LABEL_FILE = os.path.join(ROOT, "ai", "data", "scenario_labels.csv")
HELDOUT_FILE = os.path.join(ROOT, "ai", "data", "heldout_events.csv")
MODEL_FILE = os.path.join(ROOT, "ai", "models", "hybrid_live_model.joblib")
RESULTS_DIR = os.path.join(ROOT, "ai", "results")
FIGURE_DIR = os.path.join(ROOT, "docs", "figures")

SCENARIOS = ["brute_force", "credential_stuffing", "flooding", "replay_burst"]
DET = [
    ("Hybrid (deployed)", "hybrid"),
    ("Isolation Forest only", "iforest"),
    ("Magnitude limits only", "magnitude"),
    ("Simple rule", "rule"),
]

# The simple rule: no learning, thresholds chosen by hand (not tuned on this data)
RULE_FAILED = 5    # failed logins from one account within 10 seconds
RULE_MSGS = 20     # messages from one account within 10 seconds
RULE_EMAILS = 10   # different accounts with failed logins within 10 seconds

parser = argparse.ArgumentParser()
parser.add_argument("--start", required=True, help="UTC time the held-out data starts")
args = parser.parse_args()
START = pd.to_datetime(args.start, utc=True)


def wilson(k, n, z=1.96):
    """95% Wilson confidence interval for a proportion k out of n."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


# ---------- load and label the held-out events ----------
engine = create_engine(os.getenv("DATABASE_URL"))
events = pd.read_sql(
    text(
        "SELECT id, event_type, status, email, recipient_email, size_bytes, occurred_at "
        "FROM metadata_logs WHERE email LIKE :pat AND occurred_at >= :t ORDER BY occurred_at"
    ),
    engine,
    params={"pat": "sim.%", "t": START.to_pydatetime()},
)
events["occurred_at"] = pd.to_datetime(events["occurred_at"], utc=True)

windows = pd.read_csv(LABEL_FILE)
windows["start_utc"] = pd.to_datetime(windows["start_utc"], utc=True)
windows["end_utc"] = pd.to_datetime(windows["end_utc"], utc=True)
windows = windows[windows["start_utc"] >= START]

events["scenario"] = None
events["label"] = None
for _, w in windows.iterrows():
    mask = (events["occurred_at"] >= w["start_utc"]) & (events["occurred_at"] <= w["end_utc"])
    events.loc[mask, "scenario"] = w["scenario"]
    events.loc[mask, "label"] = w["label"]

labelled = events[events["label"].isin(["normal", "attack"])].copy()
os.makedirs(os.path.dirname(HELDOUT_FILE), exist_ok=True)
labelled.to_csv(HELDOUT_FILE, index=False)

ev = add_runs(labelled)
feat = build_live_features(ev)

# ---------- score with every detector ----------
bundle = joblib.load(MODEL_FILE)
model, FEATURES, limits = bundle["model"], bundle["features"], bundle["limits"]

feat["iforest"] = model.predict(feat[FEATURES]) == -1
feat["magnitude"] = False
for f, lim in limits.items():
    feat["magnitude"] = feat["magnitude"] | (feat[f] > lim)
feat["hybrid"] = feat["iforest"] | feat["magnitude"]
feat["rule"] = (
    (feat["failed_logins"] >= RULE_FAILED)
    | (feat["msg_count"] > RULE_MSGS)
    | (feat["global_distinct_failed_emails"] >= RULE_EMAILS)
)

attack = feat[feat["label"] == "attack"]
normal = feat[feat["label"] == "normal"]

print("HELD-OUT DATA")
print(f"  Events read from the database since {START}: {len(events)}")
print(f"  Events inside a normal or attack window:      {len(labelled)}  (saved to ai/data/heldout_events.csv)")
print(f"  Scored events:                                {len(feat)}")
print(f"  Attack runs per scenario: " + ", ".join(
    f"{s} {attack[attack['scenario'] == s]['run'].nunique()}" for s in SCENARIOS))
print(f"  Normal runs: {normal['run'].nunique()}   Normal sessions (run x user): "
      f"{len(normal.groupby(['run', 'email']))}")
print("  (expect 6 runs of each attack, 24 normal runs, about 144 normal sessions)")
print()

# ---------- 1. Attack runs detected ----------
det = {}
for s in SCENARIOS:
    for _, col in DET:
        sub = attack[attack["scenario"] == s].groupby("run")[col].any()
        det[(s, col)] = (int(sub.sum()), len(sub))

print("1. ATTACK RUNS DETECTED (at least one flag during the run)")
print(f"{'Scenario':<22}" + "".join(f"{name:>24}" for name, _ in DET))
for s in SCENARIOS:
    print(f"{s:<22}" + "".join(f"{str(det[(s, c)][0]) + ' of ' + str(det[(s, c)][1]):>24}" for _, c in DET))
print(f"{'OVERALL (95% CI)':<22}", end="")
overall = {}
for _, c in DET:
    k = sum(det[(s, c)][0] for s in SCENARIOS)
    n = sum(det[(s, c)][1] for s in SCENARIOS)
    lo, hi = wilson(k, n)
    overall[c] = (k, n, lo, hi)
    print(f"{f'{k}/{n} ({lo:.2f}-{hi:.2f})':>24}", end="")
print("\n")

# ---------- 2. False alarms on normal sessions ----------
print("2. FALSE ALARMS: normal sessions with at least one flag")
fa = {}
for name, c in DET:
    sess = normal.groupby(["run", "email"])[c].any()
    k, n = int(sess.sum()), len(sess)
    lo, hi = wilson(k, n)
    ev_rate = float(normal[c].mean())
    fa[c] = (k, n, lo, hi, ev_rate)
    print(f"  {name:<24} {k:>3} of {n}  ({100 * k / n:.1f}%, 95% CI {100 * lo:.1f}-{100 * hi:.1f}%)"
          f"   normal events flagged: {100 * ev_rate:.2f}%")
print()

# ---------- 3. Event-level precision / recall / F1 ----------
print("3. EVENT-LEVEL RESULTS (every scored event counted separately)")
print("   Caution: an attacker's own login and connect events are labelled attack but look normal,")
print("   and the first events of an attack come before any detector can react, so recall is low")
print("   by construction. The run-level table above is the fairer view of detection.")
y_true = feat["label"] == "attack"
event_scores = {}
print(f"{'Detector':<26}{'Precision':>10}{'Recall':>10}{'F1':>8}")
for name, c in DET:
    y_pred = feat[c]
    p = precision_score(y_true, y_pred, zero_division=0)
    r = recall_score(y_true, y_pred, zero_division=0)
    f = f1_score(y_true, y_pred, zero_division=0)
    event_scores[c] = (p, r, f)
    print(f"{name:<26}{p:>10.3f}{r:>10.3f}{f:>8.3f}")
print()


# ---------- 4. Time to first flag ----------
def delay_stats(col):
    out = {}
    for s in SCENARIOS:
        secs, missed = [], 0
        for _, g in attack[attack["scenario"] == s].groupby("run"):
            g = g.sort_values("t")
            flags = g[col].to_numpy()
            if flags.any():
                secs.append(float(g["t"].iloc[int(flags.argmax())] - g["t"].iloc[0]))
            else:
                missed += 1
        out[s] = (secs, missed)
    return out


print("4. TIME TO FIRST FLAG (median seconds from the first event of the attack)")
print(f"{'Scenario':<22}" + "".join(f"{name:>24}" for name, _ in DET))
delays = {c: delay_stats(c) for _, c in DET}
for s in SCENARIOS:
    line = f"{s:<22}"
    for _, c in DET:
        secs, missed = delays[c][s]
        cell = f"{np.median(secs):.1f}s" if secs else "never"
        if secs and missed:
            cell += f" ({missed} missed)"
        line += f"{cell:>24}"
    print(line)
print()

# ---------- chart ----------
os.makedirs(FIGURE_DIR, exist_ok=True)
fig, axes = plt.subplots(1, 2, figsize=(13, 5))

x = np.arange(len(SCENARIOS))
w = 0.2
for j, (name, c) in enumerate(DET):
    rates = [det[(s, c)][0] / det[(s, c)][1] for s in SCENARIOS]
    axes[0].bar(x + (j - 1.5) * w, rates, w, label=name)
axes[0].set_xticks(x)
axes[0].set_xticklabels([s.replace("_", " ") for s in SCENARIOS])
axes[0].set_ylim(0, 1.05)
axes[0].set_ylabel("Share of attack runs detected")
axes[0].set_title("Detection by attack type (held-out data)")
axes[0].legend(fontsize=8, loc="lower left")

names = [n for n, _ in DET]
rates = np.array([fa[c][0] / fa[c][1] for _, c in DET])
lows = np.array([fa[c][2] for _, c in DET])
highs = np.array([fa[c][3] for _, c in DET])
axes[1].bar(range(len(DET)), rates,
            yerr=[np.maximum(rates - lows, 0), np.maximum(highs - rates, 0)],
            capsize=5, color="tab:red")
axes[1].set_xticks(range(len(DET)))
axes[1].set_xticklabels(names, rotation=15, ha="right")
axes[1].set_ylabel("Share of normal sessions flagged")
axes[1].set_title("False alarms (bars show 95% confidence intervals)")

plt.tight_layout()
fig_path = os.path.join(FIGURE_DIR, "evaluation.png")
plt.savefig(fig_path, dpi=150)
print("Chart saved to", fig_path)

# ---------- summary file ----------
os.makedirs(RESULTS_DIR, exist_ok=True)
rows = []
for name, c in DET:
    k, n, lo, hi = overall[c]
    fk, fn, flo, fhi, fev = fa[c]
    p, r, f = event_scores[c]
    rows.append({
        "detector": name,
        "attack_runs_detected": k, "attack_runs": n,
        "detection_rate": round(k / n, 3), "detection_ci_low": round(lo, 3), "detection_ci_high": round(hi, 3),
        "normal_sessions_flagged": fk, "normal_sessions": fn,
        "false_alarm_rate": round(fk / fn, 3), "false_alarm_ci_low": round(flo, 3), "false_alarm_ci_high": round(fhi, 3),
        "normal_events_flagged_rate": round(fev, 4),
        "event_precision": round(p, 3), "event_recall": round(r, 3), "event_f1": round(f, 3),
    })
summary_path = os.path.join(RESULTS_DIR, "evaluation_summary.csv")
pd.DataFrame(rows).to_csv(summary_path, index=False)
print("Summary saved to", summary_path)