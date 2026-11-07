"""Exports metadata_logs from PostgreSQL and labels each row using the simulator's scenario windows.

Output: ai/data/labelled_events.csv
"""
import os

import pandas as pd
from dotenv import load_dotenv
from sqlalchemy import create_engine

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT, "backend", ".env"))

DATABASE_URL = os.getenv("DATABASE_URL")
LABEL_FILE = os.path.join(ROOT, "ai", "data", "scenario_labels.csv")
OUT_FILE = os.path.join(ROOT, "ai", "data", "labelled_events.csv")

engine = create_engine(DATABASE_URL)

events = pd.read_sql(
    """
    SELECT id, event_type, status, email, recipient_email, size_bytes,
           ip_address, occurred_at
    FROM metadata_logs
    WHERE email LIKE 'sim.%%'
    ORDER BY occurred_at
    """,
    engine,
)
events["occurred_at"] = pd.to_datetime(events["occurred_at"], utc=True)
print("Simulated events read from the database:", len(events))

windows = pd.read_csv(LABEL_FILE)
windows["start_utc"] = pd.to_datetime(windows["start_utc"], utc=True)
windows["end_utc"] = pd.to_datetime(windows["end_utc"], utc=True)

events["scenario"] = None
events["label"] = None
for _, w in windows.iterrows():
    mask = (events["occurred_at"] >= w["start_utc"]) & (events["occurred_at"] <= w["end_utc"])
    events.loc[mask, "scenario"] = w["scenario"]
    events.loc[mask, "label"] = w["label"]

# Keep only rows that fell inside a normal or attack window (drops setup and unmatched rows)
labelled = events[events["label"].isin(["normal", "attack"])].copy()
print("Rows dropped (setup or outside any window):", len(events) - len(labelled))

labelled.to_csv(OUT_FILE, index=False)
print("Saved", len(labelled), "labelled events to", OUT_FILE)
print()
print("Rows per label:")
print(labelled["label"].value_counts())
print()
print("Rows per scenario:")
print(labelled["scenario"].value_counts())