import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base

DATABASE_URL = (os.getenv("DATABASE_URL") or "").strip().strip('"').strip("'")
if "${{" in DATABASE_URL or (os.getenv("DATABASE_URL") is not None and not DATABASE_URL):
    raise RuntimeError(
        "DATABASE_URL is set but empty or still contains an unresolved reference like ${{Postgres.DATABASE_URL}}. "
        "On Railway, delete the variable and re-add it with New Variable > Add Reference > your Postgres service."
    )
DATABASE_URL = DATABASE_URL or "sqlite:///./kubeaudit.db"

# Hosting platforms hand out postgres:// or postgresql:// URLs; use the psycopg 3 driver.
for prefix in ("postgres://", "postgresql://"):
    if DATABASE_URL.startswith(prefix):
        DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len(prefix):]
        break

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
