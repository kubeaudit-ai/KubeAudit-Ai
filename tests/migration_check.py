"""Run in a subprocess with DATABASE_URL set. Verifies the startup migration on one database.

Scenario "legacy": build the pre-accounts schema (initial migration only), insert a user with a
plaintext API key, then run the startup migration and check the key was hashed and still matches.
Scenario "fresh": empty database straight to head. Scenario "cycle": head -> base -> head.
"""
import hashlib
import sys
import uuid

from alembic import command
from sqlalchemy import inspect, text

from app.database import engine
from app.migrate import INITIAL, _config, upgrade_database

scenario = sys.argv[1]
cfg = _config()

def tables():
    return set(inspect(engine).get_table_names())

with engine.begin() as c:  # start clean
    for t in ("scans", "login_tokens", "sessions", "audit_logs", "users", "alembic_version"):
        c.execute(text(f"DROP TABLE IF EXISTS {t} CASCADE" if engine.dialect.name == "postgresql" else f"DROP TABLE IF EXISTS {t}"))
    if engine.dialect.name == "postgresql":
        c.execute(text("DROP TYPE IF EXISTS plantier"))

if scenario == "legacy":
    command.upgrade(cfg, INITIAL)
    with engine.begin() as c:
        c.execute(text("DROP TABLE alembic_version"))  # as if created before migrations existed
        uid = uuid.uuid4()
        c.execute(text("INSERT INTO users (id, email, api_key, subscription_tier, subscription_status, created_at) "
                       "VALUES (:id, 'old@example.com', 'ka_live_legacykey1234', 'PRO', 'active', CURRENT_TIMESTAMP)"),
                  {"id": uid if engine.dialect.name == "postgresql" else uid.hex})
    upgrade_database()
    with engine.connect() as c:
        row = c.execute(text("SELECT api_key, api_key_hash, api_key_last4, subscription_tier FROM users")).one()
    assert row[0] is None, "plaintext key must be cleared"
    assert row[1] == hashlib.sha256(b"ka_live_legacykey1234").hexdigest(), "key hash"
    assert row[2] == "1234" and row[3] == "PRO"
    upgrade_database()  # idempotent
elif scenario == "fresh":
    upgrade_database()
elif scenario == "cycle":
    upgrade_database()
    command.downgrade(cfg, "base")
    assert "users" not in tables()
    upgrade_database()

assert {"users", "sessions", "login_tokens", "scans", "audit_logs"} <= tables(), tables()
from sqlalchemy import inspect as _i
assert {"google_id", "microsoft_id", "billing_interval"} <= {c["name"] for c in _i(engine).get_columns("users")}
with engine.connect() as c:
    v = c.execute(text("SELECT version_num FROM alembic_version")).scalar()
print(f"{engine.dialect.name} {scenario}: OK (version {v})")
