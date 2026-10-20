"""Who is calling: browser sessions (Bearer token) and API keys (X-API-Key), plus monthly quotas."""
from datetime import timedelta
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session as DbSession

from app.config import get_settings
from app.database import get_db
from app.models import AuditLog, PlanTier, Session, User, utcnow
from app.security import new_api_key, new_token, token_hash


def generate_api_key(prefix: str = "ka_live_") -> str:
    """Kept for compatibility; prefer set_new_api_key()."""
    return new_api_key() if prefix == "ka_live_" else new_token(prefix, 32)


def set_new_api_key(user: User) -> str:
    """Give the user a new API key. Returns the full key; only its hash is stored."""
    key = new_api_key()
    user.api_key = None
    user.api_key_hash = token_hash(key)
    user.api_key_last4 = key[-4:]
    return key


def create_session(db: DbSession, user: User) -> str:
    token = new_token("kas_", 32)
    db.add(Session(user_id=user.id, token_hash=token_hash(token),
                   expires_at=utcnow() + timedelta(days=get_settings().session_days)))
    return token


def _bearer(authorization: Optional[str]) -> Optional[str]:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip() or None
    return None


def _user_from_session(db: DbSession, token: str) -> Optional[User]:
    s = db.query(Session).filter(Session.token_hash == token_hash(token)).first()
    if not s or s.expires_at <= utcnow():
        return None
    now = utcnow()
    if not s.last_used_at or now - s.last_used_at > timedelta(minutes=10):
        s.last_used_at = now
        db.commit()
    return s.user


def _user_from_api_key(db: DbSession, key: str) -> Optional[User]:
    return db.query(User).filter(User.api_key_hash == token_hash(key)).first()


def optional_session_user(authorization: Optional[str] = Header(None),
                          db: DbSession = Depends(get_db)) -> Optional[User]:
    token = _bearer(authorization)
    return _user_from_session(db, token) if token else None


def require_session_user(user: Optional[User] = Depends(optional_session_user)) -> User:
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in to continue.")
    return user


def require_pro(user: User = Depends(require_session_user)) -> User:
    if not user.is_pro:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "This is a Pro feature. Upgrade to use it.")
    return user


def get_current_user(x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
                     authorization: Optional[str] = Header(None),
                     db: DbSession = Depends(get_db)) -> User:
    """API callers: an API key, or a signed-in browser session."""
    if x_api_key:
        user = _user_from_api_key(db, x_api_key)
        if not user:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key.")
        return user
    token = _bearer(authorization)
    if token:
        user = _user_from_session(db, token)
        if user:
            return user
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing X-API-Key header")


def month_start():
    now = utcnow()
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def monthly_limit(user: User) -> int:
    s = get_settings()
    if user.subscription_tier == PlanTier.ENTERPRISE and user.is_pro:
        return 1_000_000
    return s.pro_monthly_scans if user.is_pro else s.free_monthly_scans


def monthly_usage(db: DbSession, user: User) -> int:
    return db.query(AuditLog).filter(AuditLog.user_id == user.id, AuditLog.timestamp >= month_start()).count()


def verify_quota(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)) -> User:
    limit = monthly_limit(user)
    if monthly_usage(db, user) >= limit:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"Monthly limit of {limit} API scans reached." + ("" if user.is_pro else " Upgrade to Pro for more."))
    return user
