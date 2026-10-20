"""Stripe billing: Pro checkout ($9/month price set in STRIPE_PRICE_ID_PRO), customer portal, webhooks."""
import logging
from datetime import datetime, timezone
from typing import Optional

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DbSession

from app.auth import require_session_user
from app.config import get_settings
from app.database import get_db
from app.models import PlanTier, User

log = logging.getLogger("kubeaudit.billing")
router = APIRouter(prefix="/v1/billing", tags=["billing"])

PRO_STATUSES = {"active", "trialing", "past_due"}  # past_due keeps the record; is_pro checks active/trialing


def _stripe() -> None:
    s = get_settings()
    if not s.billing_enabled:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Billing is not configured yet.")
    stripe.api_key = s.stripe_secret_key


def _with_query(url: str, **params) -> str:
    from urllib.parse import urlencode
    return url + ("&" if "?" in url else "?") + urlencode(params)


@router.post("/checkout")
def create_checkout(user: User = Depends(require_session_user)):
    _stripe()
    s = get_settings()
    if user.is_pro:
        raise HTTPException(status.HTTP_409_CONFLICT, "You're already on Pro.")
    params = dict(
        mode="subscription",
        line_items=[{"price": s.stripe_price_id_pro, "quantity": 1}],
        client_reference_id=str(user.id),
        metadata={"user_id": str(user.id)},
        subscription_data={"metadata": {"user_id": str(user.id)}},
        allow_promotion_codes=True,
        success_url=_with_query(s.app_url, billing="success"),
        cancel_url=_with_query(s.app_url, billing="cancelled"),
    )
    if user.stripe_customer_id:
        params["customer"] = user.stripe_customer_id
    else:
        params["customer_email"] = user.email
    try:
        session = stripe.checkout.Session.create(**params)
    except stripe.StripeError as e:
        log.error("Stripe checkout failed: %s", e)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Couldn't start checkout. Please try again.")
    return {"url": session.url}


@router.post("/portal")
def create_portal(user: User = Depends(require_session_user)):
    _stripe()
    if not user.stripe_customer_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No billing account yet. Upgrade to Pro first.")
    try:
        portal = stripe.billing_portal.Session.create(customer=user.stripe_customer_id, return_url=get_settings().app_url)
    except stripe.StripeError as e:
        log.error("Stripe portal failed: %s", e)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Couldn't open billing. Please try again.")
    return {"url": portal.url}


def _get(obj, key, default=None):
    try:
        return obj[key]
    except (KeyError, TypeError, IndexError):
        return default


def _ts(value) -> Optional[datetime]:
    return datetime.fromtimestamp(int(value), tz=timezone.utc).replace(tzinfo=None) if value else None


def _find_user(db: DbSession, user_id: Optional[str], customer: Optional[str]) -> Optional[User]:
    import uuid
    if user_id:
        try:
            u = db.get(User, uuid.UUID(str(user_id)))
            if u:
                return u
        except ValueError:
            pass
    if customer:
        return db.query(User).filter(User.stripe_customer_id == customer).first()
    return None


def _apply_subscription(user: User, sub) -> None:
    st = _get(sub, "status")
    user.stripe_subscription_id = _get(sub, "id")
    user.subscription_status = st or user.subscription_status
    user.subscription_tier = PlanTier.PRO if st in PRO_STATUSES else PlanTier.FREE
    # Newer Stripe API versions put the period end on the subscription item.
    end = _get(sub, "current_period_end") or _get(_get(_get(_get(sub, "items"), "data", [{}]), 0, {}), "current_period_end")
    user.current_period_end = _ts(end)


@router.post("/webhook")
async def stripe_webhook(request: Request, db: DbSession = Depends(get_db)):
    s = get_settings()
    if not s.stripe_webhook_secret:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Billing webhook is not configured.")
    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(payload, request.headers.get("stripe-signature", ""), s.stripe_webhook_secret)
    except (ValueError, stripe.SignatureVerificationError):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid signature.")

    kind = event["type"]
    obj = event["data"]["object"]
    stripe.api_key = s.stripe_secret_key

    def current(sub_id):
        # Events can arrive out of order, so read the subscription's current state from Stripe.
        try:
            return stripe.Subscription.retrieve(sub_id)
        except stripe.StripeError as e:
            log.error("Could not load subscription %s: %s", sub_id, e)
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Stripe unavailable; retry later.")

    if kind == "checkout.session.completed" and _get(obj, "mode") == "subscription":
        user = _find_user(db, _get(obj, "client_reference_id") or _get(_get(obj, "metadata"), "user_id"), _get(obj, "customer"))
        if not user:
            log.warning("checkout.session.completed for unknown user")
            return {"received": True}
        user.stripe_customer_id = _get(obj, "customer") or user.stripe_customer_id
        if _get(obj, "subscription"):
            _apply_subscription(user, current(_get(obj, "subscription")))
        db.commit()

    elif kind in ("customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"):
        user = _find_user(db, _get(_get(obj, "metadata"), "user_id"), _get(obj, "customer"))
        if not user:
            log.warning("%s for unknown customer", kind)
            return {"received": True}
        if not user.stripe_customer_id:
            user.stripe_customer_id = _get(obj, "customer")
        # Ignore events about an older subscription once the user has a newer one.
        if user.stripe_subscription_id and _get(obj, "id") != user.stripe_subscription_id and kind != "customer.subscription.created":
            log.info("Ignoring %s for superseded subscription", kind)
            return {"received": True}
        sub = current(_get(obj, "id"))
        if _get(sub, "status") in ("canceled", "incomplete_expired"):
            user.subscription_tier = PlanTier.FREE
            user.subscription_status = "canceled"
            user.stripe_subscription_id = None
            user.current_period_end = None
        else:
            _apply_subscription(user, sub)
        db.commit()

    return {"received": True}
