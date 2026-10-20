import os
import secrets
from typing import Optional
from fastapi import Header, HTTPException, Depends, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, PlanTier, AuditLog

TIER_LIMITS = {
    PlanTier.FREE: 50,
    PlanTier.PRO: 2500,
    PlanTier.ENTERPRISE: 1000000,
}


def generate_api_key(prefix: str = "ka_live_") -> str:
    return f"{prefix}{secrets.token_urlsafe(32)}"


def get_current_user(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db)
) -> User:
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )

    user = db.query(User).filter(User.api_key == x_api_key).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key"
        )
    if user.subscription_status not in ["active", "trialing"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Subscription inactive. Please update billing."
        )
    return user


def verify_quota(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
    limit = TIER_LIMITS.get(user.subscription_tier, 50)
    current_count = db.query(AuditLog).filter(AuditLog.user_id == user.id).count()
    if current_count >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Tier limit of {limit} audits reached. Upgrade to Pro."
        )
    return user
