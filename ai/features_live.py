"""Shared feature code for the live-style detector (used by train_live.py and evaluate.py).

Features are computed over a sliding 10-second window ending at each event, the same way
backend/app/detector.py computes them. Each scenario run is treated as its own episode:
the window never reaches back into the previous scenario. The simulator leaves only a
3-second gap between scenarios, shorter than the 10-second window, so without this the
first normal events after an attack would carry that attack's failed logins in their features.
"""
import numpy as np
import pandas as pd

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
COUNT_FEATURES = [
    "msg_count",
    "failed_logins",
    "login_successes",
    "ws_connects",
    "global_failed_logins",
    "global_distinct_failed_emails",
]
SCORED = {"message_sent", "login_failure", "login_success", "ws_connect"}


def add_runs(ev):
    """Sort events by time and number the runs (a new run starts whenever the scenario changes)."""
    ev = ev.sort_values(["occurred_at", "id"]).reset_index(drop=True)
    ev["run"] = (ev["scenario"] != ev["scenario"].shift()).cumsum()
    return ev


def build_live_features(ev):
    """One feature row per scored event. ev must come from add_runs()."""
    ts = (ev["occurred_at"] - ev["occurred_at"].iloc[0]).dt.total_seconds().to_numpy()
    etype = ev["event_type"].to_numpy()
    email = ev["email"].to_numpy()
    recip = ev["recipient_email"].to_numpy()
    size = pd.to_numeric(ev["size_bytes"], errors="coerce").to_numpy(dtype=float)
    run_arr = ev["run"].to_numpy()
    scen_arr = ev["scenario"].to_numpy()
    label_arr = ev["label"].to_numpy()
    time_arr = ev["occurred_at"].to_numpy()
    pos_in_run = ev.groupby("run").cumcount().to_numpy()

    rows = []
    for i in range(len(ev)):
        if etype[i] not in SCORED:
            continue
        run_start = i - int(pos_in_run[i])
        lo = max(int(np.searchsorted(ts, ts[i] - WINDOW_SECONDS, side="left")), run_start)
        idx = np.arange(lo, i + 1)

        t_win, e_win = etype[idx], email[idx]
        mine = e_win == email[i]
        msgs = mine & (t_win == "message_sent")
        sizes = size[idx][msgs]
        sizes = sizes[~np.isnan(sizes)]
        fails = t_win == "login_failure"

        rows.append({
            "run": int(run_arr[i]),
            "scenario": scen_arr[i],
            "label": label_arr[i],
            "email": email[i],
            "occurred_at": time_arr[i],
            "t": float(ts[i]),
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
    return pd.DataFrame(rows)