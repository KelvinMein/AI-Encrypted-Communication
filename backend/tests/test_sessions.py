from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt
from starlette.websockets import WebSocketDisconnect

from app.auth import ALGORITHM, SECRET_KEY
from app.routes import password_routes

PASSWORD = "TestPass123!"
CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
SAFARI_IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"


@pytest.fixture(autouse=True)
def fresh_reset_limiters():
    for limiter in (password_routes.reset_limiter, password_routes.reset_ip_limiter, password_routes.bad_token_limiter):
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


def login_from(client, email, device, ua=CHROME_WIN, password=PASSWORD):
    r = client.post(
        "/login",
        json={"email": email, "password": password, "device_id": device},
        headers={"user-agent": ua},
    )
    assert r.status_code == 200
    return r.json()["access_token"]


def sessions(client, auth, token):
    return client.get("/sessions", headers=auth(token)).json()


def notes(client, auth, token):
    return client.get("/security/notifications", headers=auth(token)).json()


def test_sessions_need_a_login(client):
    assert client.get("/sessions").status_code == 401


def test_a_token_without_a_session_is_rejected(register, client, auth):
    register("alice@example.com")
    token = jwt.encode(
        {"sub": "alice@example.com", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        SECRET_KEY, algorithm=ALGORITHM,
    )
    assert client.get("/sessions", headers=auth(token)).status_code == 401


def test_the_first_login_is_trusted_and_not_notified(register, client, auth, outbox):
    register("alice@example.com")
    token = login_from(client, "alice@example.com", "dev-1")
    rows = sessions(client, auth, token)
    assert len(rows) == 1 and rows[0]["current"] and rows[0]["confirmed"]
    assert notes(client, auth, token)["unread"] == 0 and outbox == []


def test_a_login_from_a_new_device_is_flagged_and_notified(register, client, auth, outbox):
    register("alice@example.com")
    first = login_from(client, "alice@example.com", "dev-1")
    login_from(client, "alice@example.com", "dev-2", ua=SAFARI_IPHONE)

    other = next(s for s in sessions(client, auth, first) if not s["current"])
    assert other["confirmed"] is False and "iOS" in other["device"]
    n = notes(client, auth, first)
    assert n["unconfirmed"] == 1 and n["unread"] >= 1
    assert len(outbox) == 1 and outbox[0]["to"] == "alice@example.com"


def test_returning_to_a_known_device_is_not_flagged(register, client, auth, outbox):
    register("alice@example.com")
    login_from(client, "alice@example.com", "dev-1")
    token = login_from(client, "alice@example.com", "dev-1")
    assert all(s["confirmed"] for s in sessions(client, auth, token))
    assert outbox == []


def test_confirming_a_device_trusts_it_from_then_on(register, client, auth, outbox):
    register("alice@example.com")
    first = login_from(client, "alice@example.com", "dev-1")
    login_from(client, "alice@example.com", "dev-2", ua=SAFARI_IPHONE)
    flagged = next(s for s in sessions(client, auth, first) if not s["current"])

    assert client.post(f"/sessions/{flagged['id']}/confirm", headers=auth(first)).status_code == 200
    login_from(client, "alice@example.com", "dev-2", ua=SAFARI_IPHONE)  # the same device again
    assert len(outbox) == 1  # no second email
    assert all(s["confirmed"] for s in sessions(client, auth, first))


def test_signing_out_another_session_ends_it(register, client, auth, outbox):
    register("alice@example.com")
    first = login_from(client, "alice@example.com", "dev-1")
    second = login_from(client, "alice@example.com", "dev-2")
    other = next(s for s in sessions(client, auth, first) if not s["current"])

    assert client.post(f"/sessions/{other['id']}/revoke", headers=auth(first)).status_code == 200
    assert client.get("/sessions", headers=auth(second)).status_code == 401
    assert client.get("/sessions", headers=auth(first)).status_code == 200


def test_the_current_session_cannot_be_revoked_with_revoke(register, client, auth, outbox):
    register("alice@example.com")
    token = login_from(client, "alice@example.com", "dev-1")
    mine = sessions(client, auth, token)[0]
    assert client.post(f"/sessions/{mine['id']}/revoke", headers=auth(token)).status_code == 400


def test_sign_out_all_other_sessions(register, client, auth, outbox):
    register("alice@example.com")
    first = login_from(client, "alice@example.com", "dev-1")
    second = login_from(client, "alice@example.com", "dev-2")
    third = login_from(client, "alice@example.com", "dev-3")
    assert client.post("/sessions/revoke-others", headers=auth(first)).status_code == 200
    assert client.get("/sessions", headers=auth(second)).status_code == 401
    assert client.get("/sessions", headers=auth(third)).status_code == 401
    assert client.get("/sessions", headers=auth(first)).status_code == 200


def test_logout_ends_the_session(register, client, auth):
    register("alice@example.com")
    token = login_from(client, "alice@example.com", "dev-1")
    assert client.post("/logout", headers=auth(token)).status_code == 200
    assert client.get("/sessions", headers=auth(token)).status_code == 401


def test_you_cannot_touch_someone_elses_session(register, client, auth, outbox):
    register("alice@example.com")
    register("bob@example.com")
    alice = login_from(client, "alice@example.com", "dev-a")
    bob = login_from(client, "bob@example.com", "dev-b")
    target = sessions(client, auth, alice)[0]["id"]
    assert client.post(f"/sessions/{target}/revoke", headers=auth(bob)).status_code == 404
    assert client.post(f"/sessions/{target}/confirm", headers=auth(bob)).status_code == 404


def test_a_password_reset_signs_out_every_device(register, client, auth, outbox):
    register("alice@example.com")
    first = login_from(client, "alice@example.com", "dev-1")
    second = login_from(client, "alice@example.com", "dev-2")
    outbox.clear()

    client.post("/forgot-password", json={"email": "alice@example.com"})
    reset_token = outbox[-1]["body"].split("reset=")[1].split()[0]
    assert client.post(
        "/reset-password", json={"token": reset_token, "new_password": "BrandNewPass456!"}
    ).status_code == 200

    assert client.get("/sessions", headers=auth(first)).status_code == 401
    assert client.get("/sessions", headers=auth(second)).status_code == 401
    fresh = login_from(client, "alice@example.com", "dev-1", password="BrandNewPass456!")
    assert any(i["kind"] == "password_reset" for i in notes(client, auth, fresh)["items"])


def test_a_revoked_session_cannot_open_a_live_connection(register, client, auth, outbox):
    register("alice@example.com")
    first = login_from(client, "alice@example.com", "dev-1")
    second = login_from(client, "alice@example.com", "dev-2")
    other = next(s for s in sessions(client, auth, first) if not s["current"])
    client.post(f"/sessions/{other['id']}/revoke", headers=auth(first))
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/{second}"):
            pass


def test_notifications_can_be_marked_as_read(register, client, auth, outbox):
    register("alice@example.com")
    first = login_from(client, "alice@example.com", "dev-1")
    login_from(client, "alice@example.com", "dev-2")
    assert notes(client, auth, first)["unread"] >= 1
    assert client.post("/security/notifications/read", headers=auth(first)).status_code == 200
    assert notes(client, auth, first)["unread"] == 0