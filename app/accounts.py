"""Accounts API: sign-in (GitHub, email magic link), profile, API keys, saved scans, sharing, rule settings."""
import logging
import re
import secrets
from datetime import timedelta
from typing import Dict, List, Literal, Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session as DbSession

from app.auth import (create_session, monthly_limit, monthly_usage, optional_session_user,
                      require_pro, require_session_user, set_new_api_key, _bearer)
from app.config import get_settings
from app.database import get_db
from app.emailer import EmailError, send_magic_link
from app.models import LoginToken, Scan, Session, User, utcnow
from app.rules import RULES
from app.security import new_token, token_hash

log = logging.getLogger("kubeaudit.accounts")
router = APIRouter(prefix="/v1", tags=["accounts"])

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
MAGIC_TTL = timedelta(minutes=15)
EXCHANGE_TTL = timedelta(minutes=2)
STATE_COOKIE = "ka_oauth_state"


def _with_query(url: str, **params) -> str:
    return url + ("&" if "?" in url else "?") + urlencode(params)


def _client_ip(request: Request) -> str:
    # The hosting proxy appends the real client address as the LAST X-Forwarded-For entry;
    # earlier entries come from the client and can be forged.
    fwd = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    return (fwd[-1] if fwd else (request.client.host if request.client else ""))[:64]


def _issue_exchange_code(db: DbSession, user: User) -> str:
    code = new_token("kac_", 24)
    db.add(LoginToken(purpose="exchange", token_hash=token_hash(code), user_id=user.id,
                      expires_at=utcnow() + EXCHANGE_TTL))
    return code


def _consume(db: DbSession, token: str, purpose: str) -> LoginToken:
    t = db.query(LoginToken).filter(LoginToken.token_hash == token_hash(token), LoginToken.purpose == purpose).first()
    if not t or t.used_at is not None or t.expires_at <= utcnow():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This sign-in link has expired or was already used. Request a new one.")
    t.used_at = utcnow()
    return t


def _user_payload(db: DbSession, user: User) -> dict:
    s = get_settings()
    return {
        "id": str(user.id), "email": user.email, "name": user.name, "avatar_url": user.avatar_url,
        "github": bool(user.github_id),
        "google": bool(user.google_id),
        "microsoft": bool(user.microsoft_id),
        "billing_interval": user.billing_interval,
        "yearly_enabled": s.yearly_enabled,
        "plan": "pro" if user.is_pro else "free",
        "subscription_status": user.subscription_status,
        "current_period_end": user.current_period_end.isoformat() + "Z" if user.current_period_end else None,
        "has_billing_account": bool(user.stripe_customer_id),
        "api_key_last4": user.api_key_last4,
        "usage": {"api_scans_this_month": monthly_usage(db, user), "monthly_limit": monthly_limit(user)},
        "rule_settings": user.rule_settings or {"disabled": [], "severity": {}},
        "billing_enabled": s.billing_enabled,
    }


# ---------------------------------------------------------------- providers

@router.get("/auth/providers")
def providers():
    s = get_settings()
    return {"github": s.github_enabled, "google": s.google_enabled, "microsoft": s.microsoft_enabled,
            "email": s.email_enabled, "billing": s.billing_enabled, "yearly": s.yearly_enabled}


# ---------------------------------------------------------------- GitHub OAuth

@router.get("/auth/github/start")
def github_start():
    s = get_settings()
    if not s.github_enabled:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GitHub sign-in is not configured.")
    state = secrets.token_urlsafe(24)
    url = "https://github.com/login/oauth/authorize?" + urlencode({
        "client_id": s.github_client_id,
        "redirect_uri": f"{s.api_url}/v1/auth/github/callback",
        "scope": "read:user user:email",
        "state": state,
        "allow_signup": "true",
    })
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(STATE_COOKIE, state, max_age=600, httponly=True, secure=s.api_url.startswith("https"),
                    samesite="lax", path="/v1/auth/github")
    return resp


def _fail_redirect(message: str) -> RedirectResponse:
    resp = RedirectResponse(_with_query(get_settings().app_url, login_error=message), status_code=302)
    resp.delete_cookie(STATE_COOKIE, path="/v1/auth/github")
    return resp


@router.get("/auth/github/callback")
def github_callback(request: Request, code: str = "", state: str = "", error: str = "", db: DbSession = Depends(get_db)):
    s = get_settings()
    if error:
        return _fail_redirect("GitHub sign-in was cancelled.")
    expected = request.cookies.get(STATE_COOKIE)
    if not code or not state or not expected or not secrets.compare_digest(state, expected):
        return _fail_redirect("Sign-in expired. Please try again.")
    try:
        with httpx.Client(timeout=10) as http:
            tok = http.post("https://github.com/login/oauth/access_token", headers={"Accept": "application/json"}, data={
                "client_id": s.github_client_id, "client_secret": s.github_client_secret, "code": code,
                "redirect_uri": f"{s.api_url}/v1/auth/github/callback"}).json()
            access = tok.get("access_token")
            if not access:
                return _fail_redirect("GitHub did not approve the sign-in. Please try again.")
            gh = {"Authorization": f"Bearer {access}", "Accept": "application/vnd.github+json"}
            profile = http.get("https://api.github.com/user", headers=gh).json()
            emails = http.get("https://api.github.com/user/emails", headers=gh).json()
    except (httpx.HTTPError, ValueError) as e:
        log.warning("GitHub OAuth failed: %s", e)
        return _fail_redirect("Couldn't reach GitHub. Please try again.")

    gid = str(profile.get("id") or "")
    verified = [e for e in emails if isinstance(e, dict) and e.get("verified")] if isinstance(emails, list) else []
    primary = next((e["email"] for e in verified if e.get("primary")), None) or (verified[0]["email"] if verified else None)
    if not gid or not primary:
        return _fail_redirect("Your GitHub account needs a verified email address.")
    primary = primary.lower()

    user = db.query(User).filter(User.github_id == gid).first() or db.query(User).filter(User.email == primary).first()
    if user is None:
        user = User(email=primary)
        db.add(user)
    user.github_id = gid
    user.name = user.name or profile.get("name") or profile.get("login")
    user.avatar_url = profile.get("avatar_url") or user.avatar_url
    db.flush()
    code_out = _issue_exchange_code(db, user)
    db.commit()
    resp = RedirectResponse(_with_query(s.app_url, login=code_out), status_code=302)
    resp.delete_cookie(STATE_COOKIE, path="/v1/auth/github")
    return resp


class CodeIn(BaseModel):
    code: str = Field(min_length=10, max_length=200)


@router.post("/auth/exchange")
def exchange(body: CodeIn, db: DbSession = Depends(get_db)):
    t = _consume(db, body.code, "exchange")
    user = db.get(User, t.user_id)
    if not user:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Account not found.")
    token = create_session(db, user)
    db.commit()
    return {"token": token, "user": _user_payload(db, user)}


# ---------------------------------------------------------------- email magic link

class EmailIn(BaseModel):
    email: str = Field(max_length=255)

    @field_validator("email")
    @classmethod
    def valid(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_RE.match(v):
            raise ValueError("Enter a valid email address.")
        return v


@router.post("/auth/email/start", status_code=202)
def email_start(body: EmailIn, request: Request, db: DbSession = Depends(get_db)):
    s = get_settings()
    if not s.email_enabled:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Email sign-in is not configured.")
    ip = _client_ip(request)
    hour_ago = utcnow() - timedelta(hours=1)
    recent = db.query(LoginToken).filter(LoginToken.purpose == "email", LoginToken.created_at >= hour_ago)
    if recent.filter(LoginToken.email == body.email).count() >= 5 or (ip and recent.filter(LoginToken.ip == ip).count() >= 20):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many sign-in emails. Try again in an hour.")
    token = new_token("kam_", 32)
    db.add(LoginToken(purpose="email", token_hash=token_hash(token), email=body.email, ip=ip,
                      expires_at=utcnow() + MAGIC_TTL))
    db.commit()
    try:
        # The link opens the web app, which then confirms with a POST. Email scanners that
        # pre-open links therefore can't use up the token.
        send_magic_link(body.email, _with_query(s.app_url, magic=token))
    except EmailError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e))
    return {"sent": True}


class MagicIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)


@router.post("/auth/email/verify")
def email_verify(body: MagicIn, db: DbSession = Depends(get_db)):
    t = _consume(db, body.token, "email")
    user = db.query(User).filter(User.email == t.email).first()
    if user is None:
        user = User(email=t.email)
        db.add(user)
        db.flush()
    token = create_session(db, user)
    db.commit()
    return {"token": token, "user": _user_payload(db, user)}


@router.post("/auth/logout", status_code=204)
def logout(request: Request, db: DbSession = Depends(get_db)):
    token = _bearer(request.headers.get("authorization"))
    if token:
        db.query(Session).filter(Session.token_hash == token_hash(token)).delete()
        db.commit()
    return Response(status_code=204)


# ---------------------------------------------------------------- profile + API key

@router.get("/me")
def me(user: User = Depends(require_session_user), db: DbSession = Depends(get_db)):
    return _user_payload(db, user)


@router.post("/me/api-key")
def regenerate_api_key(user: User = Depends(require_session_user), db: DbSession = Depends(get_db)):
    key = set_new_api_key(user)
    db.commit()
    return {"api_key": key, "api_key_last4": user.api_key_last4}


@router.delete("/me", status_code=204)
def delete_account(user: User = Depends(require_session_user), db: DbSession = Depends(get_db)):
    if user.stripe_subscription_id and user.subscription_status in ("active", "trialing", "past_due"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Cancel your subscription in Manage billing before deleting your account.")
    db.delete(user)
    db.commit()
    return Response(status_code=204)


# ---------------------------------------------------------------- rule settings (Pro)

class RuleSettingsIn(BaseModel):
    disabled: List[str] = Field(default_factory=list, max_length=len(RULES))
    severity: Dict[str, Literal["critical", "high", "medium", "low"]] = Field(default_factory=dict)

    @field_validator("disabled")
    @classmethod
    def known(cls, v):
        bad = [r for r in v if r not in RULES]
        if bad:
            raise ValueError(f"Unknown rule IDs: {', '.join(bad)}")
        return sorted(set(v))

    @field_validator("severity")
    @classmethod
    def known_sev(cls, v):
        bad = [r for r in v if r not in RULES]
        if bad:
            raise ValueError(f"Unknown rule IDs: {', '.join(bad)}")
        return {k: s for k, s in v.items() if s != RULES[k].severity}


@router.put("/me/settings")
def save_settings(body: RuleSettingsIn, user: User = Depends(require_pro), db: DbSession = Depends(get_db)):
    user.rule_settings = {"disabled": body.disabled, "severity": body.severity}
    db.commit()
    return user.rule_settings


# ---------------------------------------------------------------- saved scans (Pro)

WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1}
MAX_TEXT = 1_000_000
MAX_FILES = 20


class FindingIn(BaseModel):
    rule_id: str = Field(max_length=10)
    severity: Literal["critical", "high", "medium", "low"]
    message: str = Field(max_length=1000)
    resource: str = Field(max_length=300)
    container: Optional[str] = Field(default=None, max_length=300)
    file: str = Field(max_length=255)
    line: int = Field(ge=1, le=10_000_000)


class FileIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    text: str = Field(max_length=MAX_TEXT)


class ScanIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    findings: List[FindingIn] = Field(default_factory=list, max_length=5000)
    resource_count: int = Field(ge=0, le=100_000, default=0)
    files: Optional[List[FileIn]] = Field(default=None, max_length=MAX_FILES)


def _score(findings: List[dict]):
    counts = {k: 0 for k in WEIGHT}
    for f in findings:
        counts[f["severity"]] += 1
    score = max(0, 100 - sum(counts[k] * WEIGHT[k] for k in WEIGHT))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return score, grade, counts


def _apply_settings(findings: List[dict], settings: Optional[dict]) -> List[dict]:
    settings = settings or {}
    disabled = set(settings.get("disabled") or [])
    sev = settings.get("severity") or {}
    out = []
    for f in findings:
        if f["rule_id"] in disabled:
            continue
        out.append({**f, "severity": sev.get(f["rule_id"], f["severity"])})
    return out


def _rescan(files: List[FileIn]):
    """Authoritative findings computed on the server from the submitted YAML."""
    import yaml
    from app.scanner import Config, scan_text
    findings, resources = [], 0
    for f in files:
        if "{{" in f.text:
            continue
        try:
            located, n = scan_text(f.text, f.name, Config())
        except yaml.YAMLError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{f.name} is not valid YAML.")
        resources += n
        for x in located:
            findings.append({"rule_id": x.finding.rule.id, "severity": x.finding.severity, "message": x.finding.message,
                             "resource": x.finding.resource, "container": x.finding.container,
                             "file": x.file, "line": x.line})
    return findings, resources


def _scan_out(s: Scan, full: bool = False) -> dict:
    out = {"id": str(s.id), "title": s.title, "score": s.score, "grade": s.grade, "counts": s.counts,
           "resource_count": s.resource_count, "created_at": s.created_at.isoformat() + "Z",
           "shared": bool(s.share_id), "share_id": s.share_id, "has_files": bool(s.files),
           "verified": bool(s.files)}
    if full:
        out["findings"] = [{**f, "title": RULES[f["rule_id"]].title if f["rule_id"] in RULES else f["rule_id"]} for f in s.findings]
        out["files"] = s.files or []
    return out


@router.post("/scans", status_code=201)
def save_scan(body: ScanIn, user: User = Depends(require_pro), db: DbSession = Depends(get_db)):
    if body.files:
        findings, resources = _rescan(body.files)
    else:
        findings = [f.model_dump() for f in body.findings if f.rule_id in RULES]
        resources = body.resource_count
    findings = _apply_settings(findings, user.rule_settings)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (order[f["severity"]], f["file"], f["line"], f["rule_id"]))
    score, grade, counts = _score(findings)
    scan = Scan(user_id=user.id, title=body.title.strip(), score=score, grade=grade, resource_count=resources,
                counts=counts, findings=findings,
                files=[f.model_dump() for f in body.files] if body.files else None)
    db.add(scan)
    db.commit()
    return _scan_out(scan, full=True)


@router.get("/scans")
def list_scans(limit: int = 50, offset: int = 0, user: User = Depends(require_pro), db: DbSession = Depends(get_db)):
    limit = max(1, min(limit, 100))
    q = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.created_at.desc())
    return {"total": q.count(), "items": [_scan_out(s) for s in q.offset(max(0, offset)).limit(limit).all()]}


def _own_scan(db: DbSession, user: User, scan_id: str) -> Scan:
    import uuid
    try:
        sid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
    s = db.get(Scan, sid)
    if not s or s.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
    return s


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, user: User = Depends(require_pro), db: DbSession = Depends(get_db)):
    return _scan_out(_own_scan(db, user, scan_id), full=True)


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str, user: User = Depends(require_pro), db: DbSession = Depends(get_db)):
    db.delete(_own_scan(db, user, scan_id))
    db.commit()
    return Response(status_code=204)


@router.post("/scans/{scan_id}/share")
def share_scan(scan_id: str, user: User = Depends(require_pro), db: DbSession = Depends(get_db)):
    s = _own_scan(db, user, scan_id)
    if not s.share_id:
        s.share_id = secrets.token_urlsafe(18)
        db.commit()
    return {"share_id": s.share_id}


@router.delete("/scans/{scan_id}/share", status_code=204)
def unshare_scan(scan_id: str, user: User = Depends(require_pro), db: DbSession = Depends(get_db)):
    s = _own_scan(db, user, scan_id)
    s.share_id = None
    db.commit()
    return Response(status_code=204)


@router.get("/shared/{share_id}")
def shared_report(share_id: str, db: DbSession = Depends(get_db)):
    s = db.query(Scan).filter(Scan.share_id == share_id).first() if 10 <= len(share_id) <= 40 else None
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "This report link doesn't exist or was turned off.")
    out = _scan_out(s, full=True)
    out.pop("share_id", None)
    out["files"] = [{"name": f["name"]} for f in (s.files or [])]  # never expose the YAML itself
    out["owner"] = s.user.name or "A KubeAudit AI user"
    return out
