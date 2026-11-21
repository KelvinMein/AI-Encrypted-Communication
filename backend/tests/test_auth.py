import base64
import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt

from app.auth import ALGORITHM, SECRET_KEY, hash_password

ADMIN = "admin.test@example.com"


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


# ---------- registration ----------

def test_root_is_up(client):
    assert client.get("/").status_code == 200


def test_register_returns_id_and_email_only(register):
    r = register("alice@example.com")
    assert r.status_code == 200
    assert set(r.json()) == {"id", "email"}


def test_password_is_stored_as_a_bcrypt_hash(register, query):
    register("alice@example.com", "TestPass123!")
    stored = query("SELECT hashed_password FROM users")[0]["hashed_password"]
    assert stored.startswith("$2")
    assert "TestPass123!" not in stored


def test_same_password_gives_different_hashes():
    assert hash_password("same-password") != hash_password("same-password")


def test_duplicate_email_is_rejected(register):
    assert register("alice@example.com").status_code == 200
    r = register("alice@example.com")
    assert r.status_code == 400
    assert "already" in r.json()["detail"].lower()


def test_invalid_email_is_rejected(register):
    assert register("not-an-email").status_code == 422


# ---------- login ----------

def test_login_returns_a_bearer_token(register, login):
    register("alice@example.com")
    r = login("alice@example.com")
    assert r.status_code == 200
    assert r.json()["token_type"] == "bearer"
    assert r.json()["access_token"]


def test_token_names_the_user_and_expires_in_about_an_hour(make_user):
    token = make_user("alice@example.com")
    claims = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert claims["sub"] == "alice@example.com"
    remaining = claims["exp"] - time.time()
    assert 55 * 60 < remaining <= 60 * 60 + 5


def test_wrong_password_is_rejected(register, login):
    register("alice@example.com")
    assert login("alice@example.com", "wrong-password").status_code == 401


def test_unknown_user_gets_the_same_error_as_a_wrong_password(register, login):
    register("alice@example.com")
    wrong = login("alice@example.com", "wrong-password")
    unknown = login("nobody@example.com", "wrong-password")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()  # does not reveal which emails exist


# ---------- token checks ----------

def test_protected_endpoint_needs_a_token(client):
    assert client.post("/upload-key", json={"public_key": "x"}).status_code == 401


def test_tampered_token_is_rejected(make_user, client, auth):
    token = make_user("alice@example.com")
    header, payload, sig = token.split(".")
    sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    bad = ".".join([header, payload, sig])
    r = client.post("/upload-key", json={"public_key": "x"}, headers=auth(bad))
    assert r.status_code == 401


def test_token_signed_with_another_key_is_rejected(register, client, auth):
    register("alice@example.com")
    forged = jwt.encode(
        {"sub": "alice@example.com", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        "some-other-key",
        algorithm=ALGORITHM,
    )
    r = client.post("/upload-key", json={"public_key": "x"}, headers=auth(forged))
    assert r.status_code == 401


def test_expired_token_is_rejected(register, client, auth):
    register("alice@example.com")
    expired = jwt.encode(
        {"sub": "alice@example.com", "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    r = client.post("/upload-key", json={"public_key": "x"}, headers=auth(expired))
    assert r.status_code == 401


def test_unsigned_token_is_rejected(register, client, auth):
    register("alice@example.com")
    unsigned = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': 'alice@example.com', 'exp': int(time.time()) + 300})}."
    r = client.post("/upload-key", json={"public_key": "x"}, headers=auth(unsigned))
    assert r.status_code == 401


# ---------- administrator access ----------

def test_flags_need_a_login(client):
    assert client.get("/flags").status_code == 401


@pytest.mark.parametrize(
    "method,path",
    [("get", "/flags"), ("get", "/logs"), ("post", "/flags/1/review")],
)
def test_ordinary_users_cannot_use_admin_endpoints(make_user, client, auth, method, path):
    token = make_user("alice@example.com")
    r = getattr(client, method)(path, headers=auth(token))
    assert r.status_code == 403


def test_admin_can_read_flags_and_logs(make_user, client, auth):
    token = make_user(ADMIN)
    flags = client.get("/flags", headers=auth(token))
    logs = client.get("/logs", headers=auth(token))
    assert flags.status_code == 200 and isinstance(flags.json(), list)
    assert logs.status_code == 200 and isinstance(logs.json(), list)


def test_admin_is_not_granted_to_a_case_variant_of_the_admin_email(register, login, client, auth):
    assert register(ADMIN).status_code == 200  # the real administrator
    variant = "Admin.Test@example.com"
    if register(variant).status_code != 200:
        pytest.skip("a case variant cannot be registered, so there is nothing to exploit")
    token = login(variant).json()["access_token"]
    r = client.get("/flags", headers=auth(token))
    assert r.status_code == 403


# ---------- public keys ----------

def test_uploaded_keys_are_stored_and_listed(make_user, client, auth):
    token = make_user("alice@example.com")
    r = client.post(
        "/upload-key", json={"public_key": "PUB-A", "signing_key": "SIG-A"}, headers=auth(token)
    )
    assert r.status_code == 200
    users = client.get("/users").json()
    assert users == [{"email": "alice@example.com", "public_key": "PUB-A", "signing_key": "SIG-A"}]


def test_user_list_never_exposes_password_hashes(make_user, client, auth):
    token = make_user("alice@example.com")
    client.post("/upload-key", json={"public_key": "PUB", "signing_key": "SIG"}, headers=auth(token))
    text = client.get("/users").text
    assert "hashed_password" not in text
    assert "$2b$" not in text


def test_user_list_only_includes_users_who_uploaded_keys(register, client):
    register("nokey@example.com")
    assert client.get("/users").json() == []


def test_key_upload_only_changes_the_callers_own_record(make_user, client, auth):
    alice = make_user("alice@example.com")
    make_user("bob@example.com")
    client.post("/upload-key", json={"public_key": "PUB-A", "signing_key": "SIG-A"}, headers=auth(alice))
    emails = {u["email"] for u in client.get("/users").json()}
    assert emails == {"alice@example.com"}