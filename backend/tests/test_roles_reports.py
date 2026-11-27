import pytest
from starlette.websockets import WebSocketDisconnect

ADMIN = "admin.test@example.com"


def reg(client, email, username, accept=True, password="TestPass123!"):
    return client.post(
        "/register",
        json={"email": email, "username": username, "password": password, "accept_terms": accept},
    )


def send(client, token, payloads, wait_for, query, total):
    with client.websocket_connect(f"/ws/{token}") as ws:
        for p in payloads:
            ws.send_json(p)
        assert wait_for(lambda: len(query("SELECT 1 FROM messages")) >= total)


def report(client, auth, token, msg_id="msg-1", reason="insult", **extra):
    return client.post("/reports", json={"msg_id": msg_id, "reason": reason, **extra}, headers=auth(token))


def user_id(client, auth, admin, username):
    rows = client.get("/admin/users", headers=auth(admin)).json()
    return next(r["id"] for r in rows if r["username"] == username)


@pytest.fixture
def scene(make_user, client, ws_payload, wait_for, query):
    """An administrator exists, and alice has sent bob three messages."""
    admin = make_user(ADMIN)
    alice = make_user("alice@example.com")
    bob = make_user("bob@example.com")
    send(client, alice, [ws_payload("bob", n=i) for i in (1, 2, 3)], wait_for, query, 3)
    return {"admin": admin, "alice": alice, "bob": bob}


# ---------- registration: usernames and rules ----------

def test_registration_requires_agreeing_to_the_rules(client):
    r = reg(client, "a@example.com", "andrew", accept=False)
    assert r.status_code == 400 and "rules" in r.json()["detail"].lower()


def test_rules_acceptance_is_recorded(client, query):
    assert reg(client, "a@example.com", "andrew").status_code == 200
    row = query("SELECT terms_accepted_at, terms_version FROM users")[0]
    assert row["terms_accepted_at"] is not None and row["terms_version"]


@pytest.mark.parametrize("bad", ["ab", "has space", "bad@name", "x" * 21, "admin", "Support"])
def test_invalid_or_reserved_usernames_are_rejected(client, bad):
    assert reg(client, "a@example.com", bad).status_code == 400


def test_usernames_are_unique_ignoring_case(client):
    assert reg(client, "a@example.com", "Andrew").status_code == 200
    r = reg(client, "b@example.com", "andrew")
    assert r.status_code == 400 and "taken" in r.json()["detail"].lower()


def test_short_password_is_rejected_at_registration(client):
    assert reg(client, "a@example.com", "andrew", password="short").status_code == 400


def test_login_returns_username_and_role(register, login):
    register(ADMIN)
    register("alice@example.com")
    assert login(ADMIN).json()["role"] == "admin"
    body = login("alice@example.com").json()
    assert body["role"] == "user" and body["username"] == "alice"


# ---------- reports ----------

def test_a_receiver_can_report_a_message(client, scene, auth):
    r = report(client, auth, scene["bob"], details="rude", evidence_text="some insult")
    assert r.status_code == 200
    rows = client.get("/admin/reports", headers=auth(scene["admin"])).json()
    assert len(rows) == 1
    assert rows[0]["reporter"] == "bob" and rows[0]["reported"] == "alice"
    assert rows[0]["evidence_text"] == "some insult" and rows[0]["status"] == "open"


def test_a_report_without_evidence_text_is_allowed(client, scene, auth):
    assert report(client, auth, scene["bob"]).status_code == 200
    assert client.get("/admin/reports", headers=auth(scene["admin"])).json()[0]["evidence_text"] is None


def test_you_cannot_report_a_message_you_did_not_receive(client, scene, auth, make_user):
    carol = make_user("carol@example.com")
    assert report(client, auth, scene["alice"]).status_code == 400   # alice sent it
    assert report(client, auth, carol).status_code == 400            # carol never got it
    assert report(client, auth, scene["bob"], msg_id="nope").status_code == 400


def test_a_message_can_only_be_reported_once_per_person(client, scene, auth):
    assert report(client, auth, scene["bob"]).status_code == 200
    assert report(client, auth, scene["bob"]).status_code == 400


def test_an_unknown_reason_is_rejected(client, scene, auth):
    assert report(client, auth, scene["bob"], reason="because").status_code == 400


def test_reports_are_rate_limited(client, scene, auth, ws_payload, wait_for, query):
    send(client, scene["alice"], [ws_payload("bob", n=i) for i in (4, 5, 6)], wait_for, query, 6)
    codes = [report(client, auth, scene["bob"], msg_id=f"msg-{i}").status_code for i in range(1, 7)]
    assert codes == [200] * 5 + [429]


def test_reports_need_a_login(client):
    assert client.post("/reports", json={"msg_id": "x", "reason": "insult"}).status_code == 401


@pytest.mark.parametrize("method,path", [
    ("get", "/admin/reports"), ("get", "/admin/users"),
    ("post", "/admin/reports/1/dismiss"), ("post", "/admin/users/1/deactivate"),
    ("post", "/admin/users/1/reactivate"), ("post", "/admin/users/1/role"),
])
def test_ordinary_users_cannot_use_admin_tools(client, scene, auth, method, path):
    kwargs = {"json": {"role": "admin"}} if path.endswith("/role") else {"json": {}}
    r = getattr(client, method)(path, headers=auth(scene["bob"]), **(kwargs if method == "post" else {}))
    assert r.status_code == 403


# ---------- administrator actions ----------

def test_admin_can_dismiss_a_report(client, scene, auth):
    report(client, auth, scene["bob"])
    rid = client.get("/admin/reports", headers=auth(scene["admin"])).json()[0]["id"]
    r = client.post(f"/admin/reports/{rid}/dismiss", json={"note": "not abusive"}, headers=auth(scene["admin"]))
    assert r.status_code == 200
    assert client.get("/admin/reports", headers=auth(scene["admin"])).json()[0]["status"] == "dismissed"
    again = client.post(f"/admin/reports/{rid}/dismiss", json={}, headers=auth(scene["admin"]))
    assert again.status_code == 400


def test_deactivating_blocks_login_ends_old_tokens_and_resolves_reports(client, scene, auth, login):
    report(client, auth, scene["bob"])
    uid = user_id(client, auth, scene["admin"], "alice")
    r = client.post(f"/admin/users/{uid}/deactivate", json={"reason": "abuse"}, headers=auth(scene["admin"]))
    assert r.status_code == 200

    assert login("alice@example.com").status_code == 403
    old = client.post("/upload-key", json={"public_key": "x"}, headers=auth(scene["alice"]))
    assert old.status_code == 403
    assert client.get("/admin/reports", headers=auth(scene["admin"])).json()[0]["status"] == "actioned"


def test_a_deactivated_user_cannot_connect(client, scene, auth):
    uid = user_id(client, auth, scene["admin"], "alice")
    client.post(f"/admin/users/{uid}/deactivate", json={"reason": "abuse"}, headers=auth(scene["admin"]))
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/{scene['alice']}"):
            pass


def test_a_wrong_password_does_not_reveal_that_an_account_is_deactivated(client, scene, auth, login):
    uid = user_id(client, auth, scene["admin"], "alice")
    client.post(f"/admin/users/{uid}/deactivate", json={"reason": "abuse"}, headers=auth(scene["admin"]))
    assert login("alice@example.com", "wrong-password").status_code == 401


def test_deactivated_users_disappear_from_the_contact_list(client, scene, auth):
    client.post("/upload-key", json={"public_key": "P", "signing_key": "S"}, headers=auth(scene["alice"]))
    assert len(client.get("/users", headers=auth(scene["bob"])).json()) == 1
    uid = user_id(client, auth, scene["admin"], "alice")
    client.post(f"/admin/users/{uid}/deactivate", json={"reason": "abuse"}, headers=auth(scene["admin"]))
    assert client.get("/users", headers=auth(scene["bob"])).json() == []


def test_admins_cannot_be_deactivated_and_cannot_deactivate_themselves(client, scene, auth):
    me = user_id(client, auth, scene["admin"], "admin.test")
    assert client.post(f"/admin/users/{me}/deactivate", json={}, headers=auth(scene["admin"])).status_code == 400
    bob = user_id(client, auth, scene["admin"], "bob")
    client.post(f"/admin/users/{bob}/role", json={"role": "admin"}, headers=auth(scene["admin"]))
    assert client.post(f"/admin/users/{bob}/deactivate", json={}, headers=auth(scene["admin"])).status_code == 400


def test_reactivating_restores_login(client, scene, auth, login):
    uid = user_id(client, auth, scene["admin"], "alice")
    client.post(f"/admin/users/{uid}/deactivate", json={"reason": "abuse"}, headers=auth(scene["admin"]))
    assert login("alice@example.com").status_code == 403
    assert client.post(f"/admin/users/{uid}/reactivate", headers=auth(scene["admin"])).status_code == 200
    assert login("alice@example.com").status_code == 200


def test_roles_can_be_changed_and_take_effect(client, scene, auth, login):
    bob = user_id(client, auth, scene["admin"], "bob")
    assert client.get("/flags", headers=auth(scene["bob"])).status_code == 403
    client.post(f"/admin/users/{bob}/role", json={"role": "admin"}, headers=auth(scene["admin"]))
    assert client.get("/flags", headers=auth(scene["bob"])).status_code == 200
    me = user_id(client, auth, scene["admin"], "admin.test")
    assert client.post(f"/admin/users/{me}/role", json={"role": "user"}, headers=auth(scene["admin"])).status_code == 400