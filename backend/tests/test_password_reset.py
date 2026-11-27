import re

import pytest
from sqlalchemy import text

from app.database import engine
from app.routes import password_routes

NEW = "BrandNewPass456!"
OLD = "TestPass123!"  # the default password used by the register fixture


@pytest.fixture(autouse=True)
def fresh_limiters():
    for limiter in (
        password_routes.reset_limiter,
        password_routes.reset_ip_limiter,
        password_routes.bad_token_limiter,
    ):
        limiter._events.clear()
    yield


@pytest.fixture
def outbox(monkeypatch):
    sent = []
    monkeypatch.setattr(
        "app.mailer.send_email",
        lambda to, subject, body: sent.append({"to": to, "subject": subject, "body": body}),
    )
    return sent


def token_from(mail):
    return re.search(r"reset=([A-Za-z0-9_-]+)", mail["body"]).group(1)


def forgot(client, email):
    return client.post("/forgot-password", json={"email": email})


def reset(client, token, password=NEW):
    return client.post("/reset-password", json={"token": token, "new_password": password})


def test_unknown_email_gets_the_same_reply_and_no_email(client, register, outbox):
    register("alice@example.com")
    known = forgot(client, "alice@example.com")
    unknown = forgot(client, "nobody@example.com")
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json()  # does not reveal which emails exist
    assert len(outbox) == 1 and outbox[0]["to"] == "alice@example.com"


def test_email_contains_a_reset_link(client, register, outbox):
    register("alice@example.com")
    forgot(client, "alice@example.com")
    assert "reset=" in outbox[0]["body"]


def test_token_is_stored_only_as_a_hash(client, register, outbox, query):
    register("alice@example.com")
    forgot(client, "alice@example.com")
    token = token_from(outbox[0])
    stored = query("SELECT token_hash FROM password_resets")[0]["token_hash"]
    assert stored != token and token not in stored and len(stored) == 64


def test_reset_changes_the_password(client, register, login, outbox):
    register("alice@example.com")
    forgot(client, "alice@example.com")
    assert reset(client, token_from(outbox[0])).status_code == 200
    assert login("alice@example.com", NEW).status_code == 200
    assert login("alice@example.com", OLD).status_code == 401


def test_a_link_works_only_once(client, register, outbox):
    register("alice@example.com")
    forgot(client, "alice@example.com")
    token = token_from(outbox[0])
    assert reset(client, token).status_code == 200
    assert reset(client, token, "AnotherPass789!").status_code == 400


def test_expired_link_is_rejected(client, register, login, outbox):
    register("alice@example.com")
    forgot(client, "alice@example.com")
    with engine.begin() as conn:
        conn.execute(text("UPDATE password_resets SET expires_at = now() - interval '1 minute'"))
    assert reset(client, token_from(outbox[0])).status_code == 400
    assert login("alice@example.com", OLD).status_code == 200  # password unchanged


def test_a_new_request_cancels_the_earlier_link(client, register, outbox):
    register("alice@example.com")
    forgot(client, "alice@example.com")
    forgot(client, "alice@example.com")
    first, second = token_from(outbox[0]), token_from(outbox[1])
    assert reset(client, first).status_code == 400
    assert reset(client, second).status_code == 200


def test_short_password_is_rejected_without_using_up_the_link(client, register, outbox):
    register("alice@example.com")
    forgot(client, "alice@example.com")
    token = token_from(outbox[0])
    r = reset(client, token, "short")
    assert r.status_code == 400 and "at least" in r.json()["detail"].lower()
    assert reset(client, token).status_code == 200


def test_made_up_token_is_rejected(client):
    assert reset(client, "not-a-real-token").status_code == 400


def test_reset_requests_are_rate_limited_and_equally_for_unknown_emails(client, register, outbox):
    register("alice@example.com")
    known = [forgot(client, "alice@example.com").status_code for _ in range(7)]
    assert known == [200] * 5 + [429] * 2
    unknown = [forgot(client, "ghost@example.com").status_code for _ in range(7)]
    assert unknown == [200] * 5 + [429] * 2  # same behaviour, so nothing is revealed


def test_reset_lifts_a_login_lockout(client, register, login, outbox):
    register("alice@example.com")
    for i in range(5):
        login("alice@example.com", f"wrong{i}")
    assert login("alice@example.com").status_code == 429
    forgot(client, "alice@example.com")
    assert reset(client, token_from(outbox[0])).status_code == 200
    assert login("alice@example.com", NEW).status_code == 200


def test_reset_is_recorded_in_the_activity_log(client, register, outbox, query):
    register("alice@example.com")
    forgot(client, "alice@example.com")
    reset(client, token_from(outbox[0]))
    events = {r["event_type"] for r in query("SELECT event_type FROM metadata_logs")}
    assert {"password_reset_requested", "password_reset_completed"} <= events