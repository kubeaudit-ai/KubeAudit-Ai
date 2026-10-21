"""Sign in with Google and Microsoft (OpenID Connect).

The ID token is read from the provider's token endpoint over TLS, server to server, which
OpenID Connect allows in place of a signature check (Core 3.1.3.7). We still check the
issuer, audience and expiry.

Account linking rule: a provider login is joined to an existing account by email only when
the provider vouches for that email. Microsoft work/school accounts can show an email the
user never proved they own, so those are accepted only when Microsoft marks the domain as
verified (xms_edov); otherwise sign-in is refused with a clear message.
"""
import base64
import json
import logging
import secrets
import time
from typing import Literal, Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session as DbSession

from app.config import get_settings
from app.database import get_db
from app.models import User

log = logging.getLogger("kubeaudit.oauth")
router = APIRouter(prefix="/v1/auth", tags=["accounts"])

Provider = Literal["google", "microsoft"]
MS_CONSUMER_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad"  # personal Microsoft accounts (Outlook.com, Hotmail, Live)

PROVIDERS = {
    "google": {
        "label": "Google",
        "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "scope": "openid email profile",
        "extra": {"prompt": "select_account"},
    },
    "microsoft": {
        "label": "Microsoft",
        "authorize": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "scope": "openid email profile",
        "extra": {"prompt": "select_account", "response_mode": "query"},
    },
}


class OAuthError(Exception):
    """A sign-in problem to show the user."""


def _creds(provider: str):
    s = get_settings()
    return (s.google_client_id, s.google_client_secret) if provider == "google" else (s.microsoft_client_id, s.microsoft_client_secret)


def _enabled(provider: str) -> bool:
    s = get_settings()
    return s.google_enabled if provider == "google" else s.microsoft_enabled


def _cookie(provider: str) -> str:
    return f"ka_oauth_{provider}"


def _redirect_uri(provider: str) -> str:
    return f"{get_settings().api_url}/v1/auth/{provider}/callback"


def decode_id_token(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError) as e:
        raise OAuthError("The sign-in response was not readable. Please try again.") from e


def identity_from_claims(provider: str, claims: dict, client_id: str, now: Optional[float] = None) -> dict:
    """Validate ID token claims and return {id, email, name, picture}. Raises OAuthError."""
    now = time.time() if now is None else now
    aud = claims.get("aud")
    if not (aud == client_id or (isinstance(aud, list) and client_id in aud)):
        raise OAuthError("The sign-in response was for a different app.")
    if float(claims.get("exp", 0)) < now - 60:
        raise OAuthError("The sign-in response expired. Please try again.")
    iss = str(claims.get("iss", ""))

    if provider == "google":
        if iss not in ("https://accounts.google.com", "accounts.google.com"):
            raise OAuthError("Unexpected sign-in issuer.")
        email = str(claims.get("email") or "").lower()
        verified = claims.get("email_verified") in (True, "true")
        if not email or not verified:
            raise OAuthError("Your Google account needs a verified email address.")
        return {"id": str(claims["sub"]), "email": email, "name": claims.get("name"), "picture": claims.get("picture")}

    tid = str(claims.get("tid") or "")
    if not tid or iss != f"https://login.microsoftonline.com/{tid}/v2.0":
        raise OAuthError("Unexpected sign-in issuer.")
    email = str(claims.get("email") or "").lower()
    personal = tid == MS_CONSUMER_TENANT
    domain_verified = claims.get("xms_edov") in (True, "true", 1, "1")
    if not email:
        raise OAuthError("Your Microsoft account didn't share an email address. Try another sign-in option.")
    if not (personal or domain_verified):
        raise OAuthError("Microsoft couldn't confirm the email on this work or school account. "
                         "Sign in with an email link, GitHub or Google instead.")
    oid = claims.get("oid") or claims.get("sub")
    return {"id": f"{tid}:{oid}", "email": email, "name": claims.get("name"), "picture": None}


def link_user(db: DbSession, provider: str, ident: dict) -> User:
    """Find or create the user for a verified provider identity."""
    field = User.google_id if provider == "google" else User.microsoft_id
    user = db.query(User).filter(field == ident["id"]).first() or db.query(User).filter(User.email == ident["email"]).first()
    if user is None:
        user = User(email=ident["email"])
        db.add(user)
    setattr(user, f"{provider}_id", ident["id"])
    user.name = user.name or ident.get("name")
    user.avatar_url = user.avatar_url or ident.get("picture")
    db.flush()
    return user


def _fail(provider: str, message: str) -> RedirectResponse:
    from app.accounts import _with_query
    resp = RedirectResponse(_with_query(get_settings().app_url, login_error=message), status_code=302)
    resp.delete_cookie(_cookie(provider), path=f"/v1/auth/{provider}")
    return resp


@router.get("/{provider}/start")
def oauth_start(provider: Provider):
    if not _enabled(provider):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"{PROVIDERS[provider]['label']} sign-in is not configured.")
    s = get_settings()
    cid, _ = _creds(provider)
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(16)
    cfg = PROVIDERS[provider]
    url = cfg["authorize"] + "?" + urlencode({"client_id": cid, "redirect_uri": _redirect_uri(provider), "response_type": "code",
                                               "scope": cfg["scope"], "state": state, "nonce": nonce, **cfg["extra"]})
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(_cookie(provider), f"{state}.{nonce}", max_age=600, httponly=True, secure=s.api_url.startswith("https"),
                    samesite="lax", path=f"/v1/auth/{provider}")
    return resp


@router.get("/{provider}/callback")
def oauth_callback(provider: Provider, request: Request, code: str = "", state: str = "", error: str = "",
                   db: DbSession = Depends(get_db)):
    from app.accounts import _issue_exchange_code, _with_query
    label = PROVIDERS[provider]["label"]
    if error:
        return _fail(provider, f"{label} sign-in was cancelled.")
    stored = request.cookies.get(_cookie(provider), "")
    expected_state, _, nonce = stored.partition(".")
    if not code or not state or not expected_state or not secrets.compare_digest(state, expected_state):
        return _fail(provider, "Sign-in expired. Please try again.")
    cid, secret = _creds(provider)
    try:
        with httpx.Client(timeout=10) as http:
            tok = http.post(PROVIDERS[provider]["token"], headers={"Accept": "application/json"}, data={
                "client_id": cid, "client_secret": secret, "code": code, "grant_type": "authorization_code",
                "redirect_uri": _redirect_uri(provider)}).json()
    except (httpx.HTTPError, ValueError) as e:
        log.warning("%s token exchange failed: %s", provider, e)
        return _fail(provider, f"Couldn't reach {label}. Please try again.")
    if not tok.get("id_token"):
        log.warning("%s token exchange returned no id_token: %s", provider, tok.get("error"))
        return _fail(provider, f"{label} did not approve the sign-in. Please try again.")
    try:
        claims = decode_id_token(tok["id_token"])
        if nonce and claims.get("nonce") != nonce:
            raise OAuthError("Sign-in expired. Please try again.")
        ident = identity_from_claims(provider, claims, cid)
    except OAuthError as e:
        return _fail(provider, str(e))
    user = link_user(db, provider, ident)
    out = _issue_exchange_code(db, user)
    db.commit()
    resp = RedirectResponse(_with_query(get_settings().app_url, login=out), status_code=302)
    resp.delete_cookie(_cookie(provider), path=f"/v1/auth/{provider}")
    return resp
