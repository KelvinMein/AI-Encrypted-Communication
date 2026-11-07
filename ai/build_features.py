"""Turns labelled events into per-user, per-window features for the anomaly detector.

Input:  ai/data/labelled_events.csv
Output: ai/data/features.csv  (one row per user per 10-second window)
"""
import os

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IN_FILE = os.path.join(ROOT, "ai", "data", "labelled_events.csv")
OUT_FILE = os.path.join(ROOT, "ai", "data", "features.csv")
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

events = pd.read_csv(IN_FILE)
events["occurred_at"] = pd.to_datetime(events["occurred_at"], utc=True)
events["window"] = events["occurred_at"].dt.floor(f"{WINDOW_SECONDS}s")

# Helper columns so everything can be counted in one pass
events["is_msg"] = events["event_type"] == "message_sent"
events["is_fail"] = events["event_type"] == "login_failure"
events["is_login_ok"] = events["event_type"] == "login_success"
events["is_connect"] = events["event_type"] == "ws_connect"
events["is_attack"] = events["label"] == "attack"
events["msg_size"] = events["size_bytes"].where(events["is_msg"])
events["msg_recipient"] = events["recipient_email"].where(events["is_msg"])

# Per user, per window
rows = events.groupby(["email", "window"]).agg(
    msg_count=("is_msg", "sum"),
    distinct_recipients=("msg_recipient", "nunique"),
    avg_msg_size=("msg_size", "mean"),
    max_msg_size=("msg_size", "max"),
    failed_logins=("is_fail", "sum"),
    login_successes=("is_login_ok", "sum"),
    ws_connects=("is_connect", "sum"),
    attack_events=("is_attack", "sum"),
    total_events=("id", "count"),
).reset_index()
rows[["avg_msg_size", "max_msg_size"]] = rows[["avg_msg_size", "max_msg_size"]].fillna(0)

# Network-wide, per window: catches attacks spread across many accounts
fails = events[events["is_fail"]]
global_feats = fails.groupby("window").agg(
    global_failed_logins=("id", "count"),
    global_distinct_failed_emails=("email", "nunique"),
).reset_index()
rows = rows.merge(global_feats, on="window", how="left")
rows[["global_failed_logins", "global_distinct_failed_emails"]] = (
    rows[["global_failed_logins", "global_distinct_failed_emails"]].fillna(0)
)

# A row is an attack if most of its events came from an attack window
rows["label"] = (rows["attack_events"] * 2 > rows["total_events"]).map(
    {True: "attack", False: "normal"}
)
mixed = ((rows["attack_events"] > 0) & (rows["attack_events"] < rows["total_events"])).sum()

rows.to_csv(OUT_FILE, index=False)

print("Feature rows:", len(rows))
print("Rows whose window mixed normal and attack events:", int(mixed))
print()
print("Rows per label:")
print(rows["label"].value_counts())
print()
print("Average of each feature by label:")
print(rows.groupby("label")[FEATURES].mean().round(1).T)
print()
print("Saved to", OUT_FILE)