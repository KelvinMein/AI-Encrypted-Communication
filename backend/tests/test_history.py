MARKER = "TUFSS0VSMTIzNDU2"  # recognisable stand-in for ciphertext


def send(client, token, payload, wait_for, query):
    with client.websocket_connect(f"/ws/{token}") as ws:
        ws.send_json(payload)
        assert wait_for(lambda: query("SELECT 1 FROM messages"))


def test_history_needs_a_login(client):
    assert client.get("/messages").status_code == 401


def test_history_returns_only_the_callers_own_messages(make_user, client, auth, ws_payload, wait_for, query):
    alice = make_user("alice@example.com")
    bob = make_user("bob@example.com")
    carol = make_user("carol@example.com")
    send(client, alice, ws_payload("bob@example.com", ciphertext=MARKER), wait_for, query)

    assert len(client.get("/messages", headers=auth(alice)).json()) == 1
    assert len(client.get("/messages", headers=auth(bob)).json()) == 1
    assert client.get("/messages", headers=auth(carol)).json() == []


def test_history_is_ciphertext_only(make_user, client, auth, ws_payload, wait_for, query):
    alice = make_user("alice@example.com")
    make_user("bob@example.com")
    send(client, alice, ws_payload("bob@example.com", ciphertext=MARKER), wait_for, query)

    rows = client.get("/messages", headers=auth(alice)).json()
    assert rows[0]["ciphertext"] == MARKER
    assert rows[0]["from"] == "alice@example.com"
    assert rows[0]["to"] == "bob@example.com"
    assert not ({"text", "plaintext", "content", "body"} & set(rows[0]))


def test_history_survives_the_recipient_logging_in_later(make_user, client, auth, ws_payload, wait_for, query):
    alice = make_user("alice@example.com")
    bob = make_user("bob@example.com")
    send(client, alice, ws_payload("bob@example.com", ciphertext=MARKER), wait_for, query)

    # Bob has never connected, so the message is still undelivered but already in his history
    rows = client.get("/messages", headers=auth(bob)).json()
    assert len(rows) == 1 and rows[0]["delivered"] is False