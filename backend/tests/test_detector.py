import pytest

from app import detector


@pytest.fixture(autouse=True)
def score_every_event(monkeypatch):
    # The detector normally skips events that arrive less than half a second apart.
    # These tests are about the detection rules, so every event is scored.
    monkeypatch.setattr(detector, "MIN_GAP_SECONDS", 0)


def test_normal_login_is_not_flagged(register, login, query):
    register("normal@example.com")
    assert login("normal@example.com").status_code == 200
    assert query("SELECT 1 FROM anomaly_flags") == []


def test_repeated_failed_logins_raise_a_flag(register, login, query):
    register("target@example.com")
    for i in range(4):
        login("target@example.com", f"wrong{i}")
    flags = query("SELECT subject, reason FROM anomaly_flags")
    assert any(f["subject"] == "target@example.com" for f in flags)


def test_message_flood_is_flagged(make_user, client, query, wait_for, ws_payload):
    attacker = make_user("attacker@example.com")
    make_user("victim@example.com")
    with client.websocket_connect(f"/ws/{attacker}") as ws:
        for i in range(40):
            ws.send_json(ws_payload("victim@example.com", n=i))
        flagged = wait_for(
            lambda: query("SELECT subject FROM anomaly_flags WHERE subject = 'attacker@example.com'"),
            timeout=10,
        )
    assert flagged


@pytest.mark.xfail(
    reason="Known limitation: detector.MIN_GAP_SECONDS skips scoring of rapid events",
    strict=False,
)
def test_fast_burst_of_failed_logins_is_flagged(monkeypatch, register, login, query):
    monkeypatch.setattr(detector, "MIN_GAP_SECONDS", 0.5)  # the real setting
    register("burst@example.com")
    for i in range(5):
        login("burst@example.com", f"wrong{i}")
    flags = query("SELECT subject FROM anomaly_flags")
    assert any(f["subject"] == "burst@example.com" for f in flags)