"""Live anomaly detector: scores a user's last 10 seconds of metadata with the hybrid model.

Uses the same nine features as ai/train_live.py, computed over a sliding 10-second
window at every event. Flags are written to the anomaly_flags table.
"""
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import pandas as pd

from app.models.metadata_log import MetadataLog
from app.models.anomaly_flag import AnomalyFlag

# backend/app/detector.py -> project root is two folders above "app"
MODEL_FILE = Path(__file__).resolve().parents[2] / "ai" / "models" / "hybrid_live_model.joblib"

WINDOW_SECONDS = 10      # how far back to look
DEDUPE_SECONDS = 10      # don't raise the same flag again within this time
MIN_GAP_SECONDS = 0.5    # score each user at most this often
SCORED_EVENTS = {"message_sent", "login_failure", "login_success", "ws_connect"}

_bundle = None
_last_scored = {}


def _load():
    global _bundle
    if _bundle is None:
        _bundle = joblib.load(MODEL_FILE)
        print(f"[detector] model loaded from {MODEL_FILE}")
    return _bundle


def compute_features(db, email):
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=WINDOW_SECONDS)
    rows = (
        db.query(
            MetadataLog.event_type,
            MetadataLog.email,
            MetadataLog.recipient_email,
            MetadataLog.size_bytes,
        )
        .filter(MetadataLog.occurred_at >= cutoff)
        .all()
    )

    mine = [r for r in rows if r.email == email]
    msgs = [r for r in mine if r.event_type == "message_sent"]
    sizes = [r.size_bytes for r in msgs if r.size_bytes is not None]
    all_fails = [r for r in rows if r.event_type == "login_failure"]

    return {
        "msg_count": len(msgs),
        "distinct_recipients": len({r.recipient_email for r in msgs if r.recipient_email}),
        "avg_msg_size": (sum(sizes) / len(sizes)) if sizes else 0.0,
        "max_msg_size": max(sizes) if sizes else 0,
        "failed_logins": sum(1 for r in mine if r.event_type == "login_failure"),
        "login_successes": sum(1 for r in mine if r.event_type == "login_success"),
        "ws_connects": sum(1 for r in mine if r.event_type == "ws_connect"),
        "global_failed_logins": len(all_fails),
        "global_distinct_failed_emails": len({r.email for r in all_fails if r.email}),
    }


def check_event(db, log_id, event_type, email):
    if email is None or event_type not in SCORED_EVENTS:
        return

    now = time.monotonic()
    last = _last_scored.get(email)
    if last is not None and now - last < MIN_GAP_SECONDS:
        return
    _last_scored[email] = now

    bundle = _load()
    model, feature_names, limits = bundle["model"], bundle["features"], bundle["limits"]

    feats = compute_features(db, email)
    X = pd.DataFrame([feats], columns=feature_names)
    score = float(model.score_samples(X)[0])

    iforest_flag = score < model.offset_
    hits = [f for f, limit in limits.items() if feats[f] > limit]
    if not iforest_flag and not hits:
        return

    # Credential stuffing touches many accounts once each, so group it as one network flag
    if event_type == "login_failure" and feats["global_distinct_failed_emails"] >= 10:
        subject = "network"
    else:
        subject = email

    since = datetime.now(timezone.utc) - timedelta(seconds=DEDUPE_SECONDS)
    already = (
        db.query(AnomalyFlag.id)
        .filter(AnomalyFlag.subject == subject, AnomalyFlag.flagged_at >= since)
        .first()
    )
    if already:
        return

    reasons = [f"{f} = {feats[f]:g} exceeds learned limit {limits[f]:.0f}" for f in hits]
    if iforest_flag:
        reasons.append(f"unusual combination of behaviour (Isolation Forest score {score:.2f})")

    db.add(AnomalyFlag(
        log_id=log_id,
        subject=subject,
        email=email,
        anomaly_score=score,
        reason="; ".join(reasons),
        features=json.dumps(feats),
    ))
    db.commit()
    print(f"[detector] FLAG {subject}: {'; '.join(reasons)}")