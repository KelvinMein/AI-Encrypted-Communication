"""Shared test setup.

Every test runs against a separate database (encrypted_comm_test_db), never the real one.
The environment is configured BEFORE the app is imported, because app/database.py and
app/auth.py read their settings at import time.
"""
import os
import re
import time
from pathlib import Path

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

BACKEND_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BACKEND_DIR / ".env")

real_url = os.getenv("DATABASE_URL")
if not real_url:
    raise RuntimeError("DATABASE_URL is missing from backend/.env")

TEST_DB = "encrypted_comm_test_db"
test_url = re.sub(r"/[^/]+$", "/" + TEST_DB, real_url)

try:
    with create_engine(test_url).connect() as _conn:
        _conn.execute(text("SELECT 1"))
except Exception as exc:
    raise RuntimeError(
        f"Cannot connect to the test database '{TEST_DB}'. Create it once with:\n"
        f'  psql -U postgres -c "CREATE DATABASE {TEST_DB};"\n({exc.__class__.__name__})'
    ) from None

os.environ["DATABASE_URL"] = test_url
os.environ["SECRET_KEY"] = "pytest-only-secret-key-0123456789abcdef0123456789abcdef"
os.environ["ADMIN_EMAILS"] = "admin.test@example.com"
os.environ["RATE_LIMIT"] = "on"

from fastapi.testclient import TestClient  # noqa: E402
from app import detector, ratelimit  # noqa: E402
from app.database import engine  # noqa: E402
from app.main import app  # noqa: E402

PASSWORD = "TestPass123!"


@pytest.fixture(autouse=True)
def clean_state():
    """Empty every table and reset in-memory state before each test."""
    with engine.begin() as conn:
        conn.execute(text("SET LOCAL lock_timeout = '5s'"))
        conn.execute(
            text("TRUNCATE TABLE anomaly_flags, messages, metadata_logs, users RESTART IDENTITY CASCADE")
        )
    ratelimit.account_limiter._events.clear()
    ratelimit.ip_limiter._events.clear()
    detector._last_scored.clear()
    yield


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def register(client):
    def _register(email, password=PASSWORD):
        return client.post("/register", json={"email": email, "password": password})
    return _register


@pytest.fixture
def login(client):
    def _login(email, password=PASSWORD):
        return client.post("/login", json={"email": email, "password": password})
    return _login


@pytest.fixture
def make_user(register, login):
    """Registers a user, logs in, and returns the access token."""
    def _make(email, password=PASSWORD):
        assert register(email, password).status_code == 200
        r = login(email, password)
        assert r.status_code == 200
        return r.json()["access_token"]
    return _make


@pytest.fixture
def auth():
    def _auth(token):
        return {"Authorization": f"Bearer {token}"}
    return _auth


@pytest.fixture
def query():
    """Runs a SELECT against the test database and returns a list of dicts."""
    def _query(sql, **params):
        with engine.connect() as conn:
            return [dict(r._mapping) for r in conn.execute(text(sql), params)]
    return _query


@pytest.fixture
def wait_for():
    """Polls until predicate() returns something truthy (the server works in the background)."""
    def _wait(predicate, timeout=5.0, interval=0.05):
        end = time.time() + timeout
        while time.time() < end:
            result = predicate()
            if result:
                return result
            time.sleep(interval)
        return predicate()
    return _wait


@pytest.fixture
def ws_payload():
    """A relay message as the browser would send it (random-looking ciphertext)."""
    def _make(to, n=1, ciphertext="Q0lQSEVSVEVYVA=="):
        return {
            "to": to,
            "ciphertext": ciphertext,
            "nonce": "bm9uY2U=",
            "signature": "c2lnbmF0dXJl",
            "msg_id": f"msg-{n}",
            "timestamp": 1700000000000,
        }
    return _make