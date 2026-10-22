"""Traffic simulator: generates labelled normal and attack traffic against the running backend.

Writes ai/data/scenario_labels.csv, one row per scenario run, with the start and end time
and a label (normal / attack / setup). Week 8 joins these time windows with metadata_logs.
"""
import argparse
import base64
import csv
import json
import os
import random
import threading
import time
import uuid
from datetime import datetime, timezone

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from websockets.sync.client import connect

BASE = "http://127.0.0.1:8000"
WS_BASE = "ws://127.0.0.1:8000"
PASSWORD = "SimPass123!"

NORMAL_USERS = [f"sim.user{i}@example.com" for i in range(1, 7)]
ATTACKER = "sim.attacker@example.com"
SINK = "sim.sink@example.com"  # receives attack traffic and never connects
ALL_ACCOUNTS = NORMAL_USERS + [ATTACKER, SINK]

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
LABEL_FILE = os.path.join(DATA_DIR, "scenario_labels.csv")


# ---------- helpers ----------

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def b64_random(n):
    return base64.b64encode(os.urandom(n)).decode()


def fake_public_key():
    """A real, valid P-256 public key (raw format) so simulated users look like real ones."""
    key = ec.generate_private_key(ec.SECP256R1())
    raw = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return base64.b64encode(raw).decode()


def make_payload(to_email):
    return {
        "to": to_email,
        "ciphertext": b64_random(random.randint(20, 200)),
        "nonce": b64_random(12),
        "signature": b64_random(64),
        "msg_id": str(uuid.uuid4()),
        "timestamp": int(time.time() * 1000),
    }


def register(email):
    return requests.post(
        f"{BASE}/register", json={"email": email, "password": PASSWORD}, timeout=15
    ).status_code


def login(email, password):
    r = requests.post(
        f"{BASE}/login", json={"email": email, "password": password}, timeout=15
    )
    return r.json()["access_token"] if r.status_code == 200 else None


def upload_keys(token):
    requests.post(
        f"{BASE}/upload-key",
        headers={"Authorization": f"Bearer {token}"},
        json={"public_key": fake_public_key(), "signing_key": fake_public_key()},
        timeout=15,
    )


def record_label(scenario, label, actors, start, end):
    os.makedirs(DATA_DIR, exist_ok=True)
    new_file = not os.path.exists(LABEL_FILE)
    with open(LABEL_FILE, "a", newline="") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["scenario", "label", "actors", "start_utc", "end_utc"])
        w.writerow([scenario, label, ";".join(actors), start, end])


def timed(name, label, fn):
    print(f"Running {name} ({label})...")
    start = utc_now()
    actors = fn()
    time.sleep(1)  # let the server finish logging disconnects before the window closes
    end = utc_now()
    record_label(name, label, actors, start, end)
    time.sleep(2)  # gap so scenario windows never overlap


# ---------- scenarios ----------

def run_setup():
    for email in ALL_ACCOUNTS:
        register(email)  # a 400 just means it already exists
        token = login(email, PASSWORD)
        if token:
            upload_keys(token)
    return ALL_ACCOUNTS


def normal_session(email, speed):
    if random.random() < 0.15:  # an occasional typo, like a real user
        login(email, "wrong-password")
        time.sleep(random.uniform(1, 2) * speed)

    token = login(email, PASSWORD)
    if not token:
        return
    upload_keys(token)
    others = [u for u in NORMAL_USERS if u != email]

    with connect(f"{WS_BASE}/ws/{token}") as ws:
        stop = threading.Event()

        def drain():
            while not stop.is_set():
                try:
                    ws.recv(timeout=0.5)
                except TimeoutError:
                    continue
                except Exception:
                    break

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()

        for _ in range(random.randint(5, 12)):
            ws.send(json.dumps(make_payload(random.choice(others))))
            time.sleep(random.uniform(0.8, 3.5) * speed)

        stop.set()
        reader.join(timeout=2)


def make_run_normal(speed):
    def run_normal():
        threads = [
            threading.Thread(target=normal_session, args=(email, speed))
            for email in NORMAL_USERS
        ]
        for t in threads:
            t.start()
            time.sleep(random.uniform(0.2, 1.5) * speed)
        for t in threads:
            t.join()
        return NORMAL_USERS
    return run_normal


def run_brute_force():
    target = random.choice(NORMAL_USERS)
    for i in range(40):
        login(target, f"guess{i}")
        time.sleep(0.05)
    return [target]


def run_flooding():
    token = login(ATTACKER, PASSWORD)
    upload_keys(token)
    with connect(f"{WS_BASE}/ws/{token}") as ws:
        for _ in range(150):
            ws.send(json.dumps(make_payload(SINK)))
            time.sleep(0.01)
    return [ATTACKER]


def run_replay_burst():
    token = login(ATTACKER, PASSWORD)
    upload_keys(token)
    payload = make_payload(SINK)  # one captured message, re-sent over and over
    with connect(f"{WS_BASE}/ws/{token}") as ws:
        for _ in range(40):
            ws.send(json.dumps(payload))
            time.sleep(0.05)
    return [ATTACKER]


def run_credential_stuffing():
    emails = [f"sim.ghost{i}@example.com" for i in range(30)]
    for e in emails:
        login(e, "Password123")
        time.sleep(0.05)
    return emails


# ---------- main ----------

def main():
    parser = argparse.ArgumentParser(description="Generate labelled normal and attack traffic.")
    parser.add_argument("--rounds", type=int, default=3, help="how many full rounds to run")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="multiplier for pauses in normal traffic (smaller = faster)")
    args = parser.parse_args()

    try:
        requests.get(BASE + "/", timeout=5)
    except Exception:
        print("Backend not reachable at", BASE, "- start it first, then run this again.")
        return

    run_normal = make_run_normal(args.speed)
    schedule = [
        ("normal", "normal", run_normal),
        ("brute_force", "attack", run_brute_force),
        ("normal", "normal", run_normal),
        ("flooding", "attack", run_flooding),
        ("normal", "normal", run_normal),
        ("replay_burst", "attack", run_replay_burst),
        ("normal", "normal", run_normal),
        ("credential_stuffing", "attack", run_credential_stuffing),
    ]

    timed("setup", "setup", run_setup)
    for r in range(1, args.rounds + 1):
        print(f"--- Round {r}/{args.rounds} ---")
        for name, label, fn in schedule:
            timed(name, label, fn)

    print("Done. Labels saved to", LABEL_FILE)


if __name__ == "__main__":
    main()