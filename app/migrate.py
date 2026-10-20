"""Bring the database schema up to date at startup.

Handles three starting points:
  * empty database             -> run every migration
  * created by create_all()    -> tables already match the models; stamp as current
  * created before migrations  -> stamp the initial revision, then upgrade
On Postgres an advisory lock stops two app instances migrating at once.
"""
import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text

from app.database import engine

log = logging.getLogger("kubeaudit.migrate")
ROOT = Path(__file__).resolve().parent.parent
INITIAL = "95d3fe74163a"
LOCK_ID = 7_340_112_031


def _config() -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    return cfg


def upgrade_database() -> None:
    cfg = _config()
    is_pg = engine.dialect.name == "postgresql"
    with engine.connect() as conn:
        if is_pg:
            conn.execute(text("SELECT pg_advisory_lock(:id)"), {"id": LOCK_ID})
        try:
            tables = set(inspect(conn).get_table_names())
            cfg.attributes["connection"] = conn
            if "alembic_version" not in tables and "users" in tables:
                if "sessions" in tables:
                    log.info("Schema created without migrations matches the models; stamping head.")
                    command.stamp(cfg, "head")
                else:
                    log.info("Existing pre-migration schema found; stamping %s.", INITIAL)
                    command.stamp(cfg, INITIAL)
            command.upgrade(cfg, "head")
            conn.commit()
        finally:
            if is_pg:
                conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": LOCK_ID})
                conn.commit()
