import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, Enum, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utcnow() -> datetime:
    """Naive UTC timestamp (portable across SQLite and Postgres)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class PlanTier(str, enum.Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class User(Base):
    __tablename__ = "users"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=True)
    avatar_url = Column(String(512), nullable=True)
    github_id = Column(String(32), unique=True, nullable=True, index=True)

    # Legacy plaintext column, emptied by the accounts migration. Keys are stored hashed.
    api_key = Column(String(128), unique=True, nullable=True, index=True)
    api_key_hash = Column(String(64), unique=True, nullable=True, index=True)
    api_key_last4 = Column(String(8), nullable=True)

    stripe_customer_id = Column(String(128), unique=True, nullable=True)
    stripe_subscription_id = Column(String(128), nullable=True)
    subscription_tier = Column(Enum(PlanTier), default=PlanTier.FREE, nullable=False)
    subscription_status = Column(String(50), default="active", nullable=False)
    current_period_end = Column(DateTime, nullable=True)

    rule_settings = Column(JSON, nullable=True)  # {"disabled": ["KA014"], "severity": {"KA009": "high"}}
    created_at = Column(DateTime, default=utcnow, nullable=False)

    audits = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")

    @property
    def is_pro(self) -> bool:
        return self.subscription_tier in (PlanTier.PRO, PlanTier.ENTERPRISE) and \
            self.subscription_status in ("active", "trialing")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(Uuid, ForeignKey("users.id"), nullable=False, index=True)
    resource_count = Column(Integer, default=1, nullable=False)
    violations_detected = Column(Integer, default=0, nullable=False)
    timestamp = Column(DateTime, default=utcnow, nullable=False, index=True)

    user = relationship("User", back_populates="audits")


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_used_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="sessions")


class LoginToken(Base):
    """Single-use tokens: email magic links ("email") and post-OAuth exchange codes ("exchange")."""
    __tablename__ = "login_tokens"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    purpose = Column(String(16), nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), nullable=True, index=True)
    user_id = Column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    ip = Column(String(64), nullable=True, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(200), nullable=False)
    score = Column(Integer, nullable=False)
    grade = Column(String(2), nullable=False)
    resource_count = Column(Integer, nullable=False, default=0)
    counts = Column(JSON, nullable=False)    # {"critical": n, "high": n, "medium": n, "low": n}
    findings = Column(JSON, nullable=False)  # [{rule_id, severity, title, message, resource, container, file, line}]
    files = Column(JSON, nullable=True)      # [{"name", "text"}], only when the user chose to save the YAML
    share_id = Column(String(40), unique=True, nullable=True, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)

    user = relationship("User", back_populates="scans")
