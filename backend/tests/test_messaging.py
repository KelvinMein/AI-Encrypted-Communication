import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt
from starlette.websockets import WebSocketDisconnect

from app.auth import ALGORITHM, SECRET_KEY

MARKER = "TUFSS0VSMTIzNDU2"  # base64 of "MARKER123456", a recognisable stand-in for ciphertext


def test_websocket_rejects_an_invalid_token(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/not-a-real-token"):
            pass


def test_websocket_rejects_a_valid_token_for_an_unknown_user(client):
    token = jwt.encode(
        {"sub": "ghost@example.com", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/{token}"):
            pass


def test_message_reaches_an_online_recipient(make_user, client, ws_payload):
    alice = make_user("alice@example.com")
    bob = make_user("bob@example.com")
    sent = ws_payload("bob@example.com", ciphertext=MARKER)
    with client.websocket_connect(f"/ws/{alice}") as wa, client.websocket_connect(f"/ws/{bob}") as wb:
        wa.send_json(sent)
        got = wb.receive_json()
    assert got["from"] == "alice@example.com"
    assert got["ciphertext"] == MARKER
    assert got["signature"] == sent["signature"]
    assert got["offline"] is False


def test_message_to_an_offline_user_is_stored_then_delivered(make_user, client, query, wait_for, ws_payload):
    alice = make_user("alice@example.com")
    bob = make_user("bob@example.com")

    with client.websocket_connect(f"/ws/{alice}") as wa:
        wa.send_json(ws_payload("bob@example.com", ciphertext=MARKER))
        rows = wait_for(lambda: query("SELECT delivered, ciphertext FROM messages"))
        assert len(rows) == 1
        assert rows[0]["delivered"] is False
        assert rows[0]["ciphertext"] == MARKER  # stored exactly as sent

    with client.websocket_connect(f"/ws/{bob}") as wb:
        got = wb.receive_json()

    assert got["offline"] is True
    assert got["from"] == "alice@example.com"
    assert got["ciphertext"] == MARKER
    assert wait_for(lambda: [r for r in query("SELECT delivered FROM messages") if r["delivered"]])


def test_message_to_an_unknown_recipient_is_not_stored(make_user, client, query, wait_for, ws_payload):
    alice = make_user("alice@example.com")
    with client.websocket_connect(f"/ws/{alice}") as wa:
        wa.send_json(ws_payload("nobody@example.com"))
        logged = wait_for(lambda: query("SELECT 1 FROM metadata_logs WHERE event_type = 'message_failed'"))
    assert logged
    assert query("SELECT 1 FROM messages") == []


def test_database_has_no_plaintext_or_private_key_columns(query):
    columns = {
        r["column_name"]
        for r in query("SELECT column_name FROM information_schema.columns WHERE table_schema = 'public'")
    }
    assert not (columns & {"plaintext", "content", "body", "text", "message", "private_key"})


def test_activity_log_records_size_but_never_content(make_user, client, query, wait_for, ws_payload):
    alice = make_user("alice@example.com")
    make_user("bob@example.com")
    with client.websocket_connect(f"/ws/{alice}") as wa:
        wa.send_json(ws_payload("bob@example.com", ciphertext=MARKER))
        rows = wait_for(lambda: query("SELECT * FROM metadata_logs WHERE event_type = 'message_sent'"))

    assert rows and rows[0]["size_bytes"] > 0
    assert rows[0]["recipient_email"] == "bob@example.com"

    everything = json.dumps(query("SELECT * FROM metadata_logs"), default=str)
    assert MARKER not in everything
    assert base64.b64decode(MARKER).decode() not in everything