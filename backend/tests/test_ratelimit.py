def test_blocks_after_five_failed_logins(register, login):
    register("victim@example.com")
    codes = [login("victim@example.com", f"wrong{i}").status_code for i in range(8)]
    assert codes == [401] * 5 + [429] * 3


def test_block_tells_the_user_how_long_to_wait(register, login):
    register("victim@example.com")
    for i in range(5):
        login("victim@example.com", f"wrong{i}")
    r = login("victim@example.com", "wrong-again")
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) >= 1
    assert "try again" in r.json()["detail"].lower()


def test_correct_password_is_refused_during_a_lockout(register, login):
    register("victim@example.com")
    for i in range(5):
        login("victim@example.com", f"wrong{i}")
    assert login("victim@example.com").status_code == 429  # default password is the correct one


def test_lockout_applies_to_one_account_only(register, login):
    register("victim@example.com")
    register("other@example.com")
    for i in range(5):
        login("victim@example.com", f"wrong{i}")
    assert login("other@example.com").status_code == 200


def test_successful_login_resets_the_counter(register, login):
    register("alice@example.com")
    first = [login("alice@example.com", f"wrong{i}").status_code for i in range(4)]
    assert login("alice@example.com").status_code == 200
    second = [login("alice@example.com", f"wrong{i}").status_code for i in range(4)]
    assert first == [401] * 4 and second == [401] * 4


def test_address_wide_limit_stops_credential_stuffing(login):
    # 20 failures spread over 20 different accounts: each account stays under its own limit
    codes = [login(f"ghost{i}@example.com", "x").status_code for i in range(20)]
    assert codes == [401] * 20
    assert login("another@example.com", "x").status_code == 429


def test_rate_limit_can_be_switched_off(monkeypatch, register, login):
    monkeypatch.setenv("RATE_LIMIT", "off")
    register("victim@example.com")
    codes = [login("victim@example.com", f"wrong{i}").status_code for i in range(8)]
    assert codes == [401] * 8


def test_blocked_attempts_are_logged(register, login, query):
    register("victim@example.com")
    for i in range(8):
        login("victim@example.com", f"wrong{i}")
    n = query("SELECT count(*) AS n FROM metadata_logs WHERE event_type = 'login_blocked'")[0]["n"]
    assert n == 3