from sqlalchemy.exc import OperationalError

import app.migrate as migrate


def test_connect_retries_until_database_is_up(monkeypatch):
    calls = {"n": 0}
    real = migrate.engine.connect

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise OperationalError("connect", {}, Exception("failed to resolve host 'postgres.railway.internal'"))
        return real()

    monkeypatch.setattr(migrate.engine, "connect", flaky)
    monkeypatch.setattr("time.sleep", lambda s: None)
    with migrate._connect_with_retry(timeout=30) as conn:
        assert conn is not None
    assert calls["n"] == 3


def test_connect_gives_up_after_timeout(monkeypatch):
    def down():
        raise OperationalError("connect", {}, Exception("down"))

    monkeypatch.setattr(migrate.engine, "connect", down)
    monkeypatch.setattr("time.sleep", lambda s: None)
    try:
        migrate._connect_with_retry(timeout=0)
    except OperationalError:
        return
    raise AssertionError("expected OperationalError")
