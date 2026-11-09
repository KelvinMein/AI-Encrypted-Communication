"""Matches live anomaly flags to the simulator's scenario windows (most recent run only)."""
import os

import pandas as pd
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT, "backend", ".env"))
engine = create_engine(os.getenv("DATABASE_URL"))

labels = pd.read_csv(os.path.join(ROOT, "ai", "data", "scenario_labels.csv"))
labels["start_utc"] = pd.to_datetime(labels["start_utc"], utc=True)
labels["end_utc"] = pd.to_datetime(labels["end_utc"], utc=True)

# The most recent run is everything from the last "setup" row onwards
last_setup = labels.index[labels["scenario"] == "setup"].max()
run = labels.loc[last_setup:].reset_index(drop=True)

flags = pd.read_sql(
    text("SELECT id, subject, anomaly_score, reason, flagged_at FROM anomaly_flags "
         "WHERE flagged_at >= :t ORDER BY flagged_at"),
    engine,
    params={"t": run["start_utc"].min().to_pydatetime()},
)
flags["flagged_at"] = pd.to_datetime(flags["flagged_at"], utc=True)


def which(ts):
    for _, w in run.iterrows():
        if w["start_utc"] <= ts <= w["end_utc"]:
            return pd.Series([w["scenario"], w["label"]])
    return pd.Series(["between windows", "none"])


print("Total flags in this run:", len(flags))
if len(flags):
    flags[["scenario", "label"]] = flags["flagged_at"].apply(which)

print()
print("Attack windows and whether they were flagged:")
for _, w in run[run["label"] == "attack"].iterrows():
    n = 0
    if len(flags):
        n = int(((flags["flagged_at"] >= w["start_utc"]) & (flags["flagged_at"] <= w["end_utc"])).sum())
    print(f"  {w['scenario']:<22} {'FLAGGED' if n else 'MISSED':<8} ({n} flags)")

print()
if len(flags):
    false_alarms = flags[flags["label"] == "normal"]
    print("Flags raised during NORMAL traffic (false alarms):", len(false_alarms))
    if len(false_alarms):
        out = false_alarms[["subject", "anomaly_score", "reason"]].copy()
        out["reason"] = out["reason"].str[:70]
        print(out.to_string(index=False))
    other = flags[flags["label"] == "none"]
    print()
    print("Flags outside every window (setup phase or gaps):", len(other))