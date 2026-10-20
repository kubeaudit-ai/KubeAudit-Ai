"""Sign-in, sessions, API keys, Pro features, sharing and Stripe billing."""
import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app import billing as billing_mod
from app.config import get_settings
from app.database import SessionLocal
from app.main import app
from app.models import AuditLog, LoginToken, PlanTier, Scan, Session, User, utcnow

client = TestClient(app)
OUTBOX = Path(os.environ["EMAIL_BACKEND"][5:])
INSECURE = Path(__file__).parent / "fixtures" / "repo" / "k8s" / "insecure.yaml"


@pytest.fixture(autouse=True)
def settings(monkeypatch):
    monkeypatch.setenv("APP_URL", "https://app.example/KubeAudit/")
    monkeypatch.setenv("API_URL", "https://api.example")
    monkeypatch.setenv("CORS_ORIGINS", "https://app.example")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def last_link(email):
    lines = [json.loads(l) for l in OUTBOX.read_text().splitlines()] if OUTBOX.exists() else []
    return [l for l in lines if l["to"] == email.lower()][-1]["link"]


def sign_in(email=None):
    email = email or f"user-{uuid.uuid4().hex[:8]}@example.com"
    ip = f"10.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}"
    assert client.post("/v1/auth/email/start", json={"email": email}, headers={"X-Forwarded-For": ip}).status_code == 202
    token = parse_qs(urlparse(last_link(email)).query)["magic"][0]
    r = client.post("/v1/auth/email/verify", json={"token": token})
    assert r.status_code == 200, r.text
    return r.json()["token"], email


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def make_pro(email):
    db = SessionLocal()
    u = db.query(User).filter(User.email == email).one()
    u.subscription_tier, u.subscription_status = PlanTier.PRO, "active"
    db.commit(); db.close()


# ---------------------------------------------------------------- email sign-in

def test_magic_link_sign_in_flow():
    token, email = sign_in()
    link = last_link(email)
    assert link.startswith("https://app.example/KubeAudit/?magic=")
    me = client.get("/v1/me", headers=auth(token)).json()
    assert me["email"] == email and me["plan"] == "free" and me["usage"]["monthly_limit"] == 50


def test_magic_link_is_single_use_and_expires():
    email = f"once-{uuid.uuid4().hex[:6]}@example.com"
    client.post("/v1/auth/email/start", json={"email": email})
    tok = parse_qs(urlparse(last_link(email)).query)["magic"][0]
    assert client.post("/v1/auth/email/verify", json={"token": tok}).status_code == 200
    assert client.post("/v1/auth/email/verify", json={"token": tok}).status_code == 400

    client.post("/v1/auth/email/start", json={"email": email})
    tok2 = parse_qs(urlparse(last_link(email)).query)["magic"][0]
    db = SessionLocal()
    for t in db.query(LoginToken).filter(LoginToken.email == email, LoginToken.used_at.is_(None)):
        t.expires_at = utcnow() - timedelta(seconds=1)
    db.commit(); db.close()
    r = client.post("/v1/auth/email/verify", json={"token": tok2})
    assert r.status_code == 400 and "expired" in r.json()["detail"]


def test_ip_rate_limit_uses_proxy_address():
    real = "198.51.100.7"
    codes = [client.post("/v1/auth/email/start", json={"email": f"ip{i}-{uuid.uuid4().hex[:4]}@example.com"},
                         headers={"X-Forwarded-For": f"203.0.113.{i}, {real}"}).status_code for i in range(21)]
    assert codes == [202] * 20 + [429]  # forging the first entry doesn't help


def test_email_validation_and_rate_limit():
    assert client.post("/v1/auth/email/start", json={"email": "not-an-email"}).status_code == 422
    email = f"spam-{uuid.uuid4().hex[:6]}@example.com"
    codes = [client.post("/v1/auth/email/start", json={"email": email}).status_code for _ in range(6)]
    assert codes == [202] * 5 + [429]


def test_email_is_case_insensitive_one_account():
    token1, email = sign_in(f"Case-{uuid.uuid4().hex[:6]}@Example.com")
    token2, _ = sign_in(email.lower())
    assert client.get("/v1/me", headers=auth(token1)).json()["id"] == client.get("/v1/me", headers=auth(token2)).json()["id"]


# ---------------------------------------------------------------- sessions

def test_me_requires_valid_session_and_logout_revokes():
    assert client.get("/v1/me").status_code == 401
    assert client.get("/v1/me", headers=auth("kas_nope")).status_code == 401
    token, _ = sign_in()
    assert client.get("/v1/me", headers=auth(token)).status_code == 200
    assert client.post("/v1/auth/logout", headers=auth(token)).status_code == 204
    assert client.get("/v1/me", headers=auth(token)).status_code == 401


def test_expired_session_rejected():
    token, email = sign_in()
    db = SessionLocal()
    for s in db.query(Session).join(User).filter(User.email == email):
        s.expires_at = utcnow() - timedelta(seconds=1)
    db.commit(); db.close()
    assert client.get("/v1/me", headers=auth(token)).status_code == 401


def test_tokens_are_stored_hashed():
    token, email = sign_in()
    db = SessionLocal()
    stored = [s.token_hash for s in db.query(Session).join(User).filter(User.email == email)]
    db.close()
    assert token not in stored and hashlib.sha256(token.encode()).hexdigest() in stored


# ---------------------------------------------------------------- GitHub OAuth

class FakeResp:
    def __init__(self, data): self._d = data
    def json(self): return self._d


class FakeGitHub:
    profile = {"id": 4242, "login": "octo", "name": "Octo Cat", "avatar_url": "https://avatars.example/o.png"}
    emails = [{"email": "octo@example.com", "verified": True, "primary": True}]
    def __init__(self, *a, **k): pass
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def post(self, url, **k):
        assert url == "https://github.com/login/oauth/access_token"
        assert k["data"]["code"] == "good-code"
        return FakeResp({"access_token": "gho_test"})
    def get(self, url, **k):
        return FakeResp(self.profile if url.endswith("/user") else self.emails)


@pytest.fixture
def github(monkeypatch):
    monkeypatch.setenv("GITHUB_CLIENT_ID", "cid")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "secret")
    get_settings.cache_clear()
    import app.accounts as acc
    monkeypatch.setattr(acc.httpx, "Client", FakeGitHub)


def github_login(state="s1"):
    c = TestClient(app, follow_redirects=False, base_url="https://testserver")  # cookie is Secure
    start = c.get("/v1/auth/github/start")
    assert start.status_code == 302
    q = parse_qs(urlparse(start.headers["location"]).query)
    assert q["redirect_uri"] == ["https://api.example/v1/auth/github/callback"]
    real_state = q["state"][0]
    return c, real_state


def test_email_sign_in_hidden_until_configured(monkeypatch):
    monkeypatch.setenv("EMAIL_BACKEND", "resend")
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    get_settings.cache_clear()
    assert client.get("/v1/auth/providers").json()["email"] is False
    assert client.post("/v1/auth/email/start", json={"email": "a@example.com"}).status_code == 503


def test_github_not_configured():
    assert client.get("/v1/auth/github/start", follow_redirects=False).status_code == 503
    assert client.get("/v1/auth/providers").json() == {"github": False, "email": True, "billing": False}


def test_github_sign_in_and_exchange(github):
    c, state = github_login()
    cb = c.get(f"/v1/auth/github/callback?code=good-code&state={state}")
    assert cb.status_code == 302
    loc = urlparse(cb.headers["location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == "https://app.example/KubeAudit/"
    code = parse_qs(loc.query)["login"][0]
    r = c.post("/v1/auth/exchange", json={"code": code})
    assert r.status_code == 200
    me = r.json()["user"]
    assert me["email"] == "octo@example.com" and me["github"] is True and me["name"] == "Octo Cat"
    assert c.post("/v1/auth/exchange", json={"code": code}).status_code == 400  # single use


def test_github_state_mismatch_rejected(github):
    c, _ = github_login()
    cb = c.get("/v1/auth/github/callback?code=good-code&state=forged")
    assert cb.status_code == 302 and "login_error" in cb.headers["location"]
    fresh = TestClient(app, follow_redirects=False, base_url="https://testserver")  # no state cookie at all
    cb2 = fresh.get("/v1/auth/github/callback?code=good-code&state=whatever")
    assert "login_error" in cb2.headers["location"]


def test_github_links_existing_email_account(github, monkeypatch):
    email = f"link-{uuid.uuid4().hex[:6]}@example.com"
    token, _ = sign_in(email)
    before = client.get("/v1/me", headers=auth(token)).json()["id"]
    monkeypatch.setattr(FakeGitHub, "profile", {**FakeGitHub.profile, "id": 777001})
    monkeypatch.setattr(FakeGitHub, "emails", [{"email": email, "verified": True, "primary": True}])
    c, state = github_login()
    code = parse_qs(urlparse(c.get(f"/v1/auth/github/callback?code=good-code&state={state}").headers["location"]).query)["login"][0]
    assert c.post("/v1/auth/exchange", json={"code": code}).json()["user"]["id"] == before


def test_github_requires_verified_email(github, monkeypatch):
    monkeypatch.setattr(FakeGitHub, "profile", {**FakeGitHub.profile, "id": 999})
    monkeypatch.setattr(FakeGitHub, "emails", [{"email": "x@example.com", "verified": False, "primary": True}])
    c, state = github_login()
    assert "login_error" in c.get(f"/v1/auth/github/callback?code=good-code&state={state}").headers["location"]


# ---------------------------------------------------------------- API keys + quota

def test_api_key_regenerate_and_use():
    token, _ = sign_in()
    k1 = client.post("/v1/me/api-key", headers=auth(token)).json()["api_key"]
    assert client.post("/audit", json={"manifest": "apiVersion: v1\nkind: Pod\nmetadata: {name: p}"}, headers={"X-API-Key": k1}).status_code == 200
    k2 = client.post("/v1/me/api-key", headers=auth(token)).json()["api_key"]
    assert client.post("/audit", json={"manifest": "apiVersion: v1\nkind: Pod"}, headers={"X-API-Key": k1}).status_code == 401
    assert client.post("/audit", json={"manifest": "apiVersion: v1\nkind: Pod"}, headers={"X-API-Key": k2}).status_code == 200
    me = client.get("/v1/me", headers=auth(token)).json()
    assert me["api_key_last4"] == k2[-4:] and me["usage"]["api_scans_this_month"] == 2


def test_quota_counts_only_this_month():
    token, email = sign_in()
    key = client.post("/v1/me/api-key", headers=auth(token)).json()["api_key"]
    db = SessionLocal()
    u = db.query(User).filter(User.email == email).one()
    last_month = utcnow().replace(day=1) - timedelta(days=3)
    for _ in range(60):
        db.add(AuditLog(user_id=u.id, timestamp=last_month))
    db.commit(); db.close()
    assert client.post("/audit", json={"manifest": "apiVersion: v1\nkind: Pod"}, headers={"X-API-Key": key}).status_code == 200


# ---------------------------------------------------------------- Pro features

def test_pro_features_require_pro():
    token, _ = sign_in()
    assert client.get("/v1/scans", headers=auth(token)).status_code == 402
    assert client.put("/v1/me/settings", json={"disabled": []}, headers=auth(token)).status_code == 402


def test_save_scan_with_yaml_is_rescanned_on_server():
    token, email = sign_in(); make_pro(email)
    forged = [{"rule_id": "KA015", "severity": "low", "message": "x", "resource": "Pod/x", "file": "a.yaml", "line": 1}]
    r = client.post("/v1/scans", headers=auth(token), json={
        "title": "Release 1.2", "findings": forged, "files": [{"name": "insecure.yaml", "text": INSECURE.read_text()}]})
    assert r.status_code == 201, r.text
    body = r.json()
    from app.scanner import Config, scan_text
    expected, _ = scan_text(INSECURE.read_text(), "insecure.yaml", Config())
    assert len(body["findings"]) == len(expected) and body["verified"] is True
    assert body["counts"]["critical"] >= 1 and body["score"] == 0
    sev = [f["severity"] for f in body["findings"]]
    assert sev == sorted(sev, key=["critical", "high", "medium", "low"].index)  # most severe first


def test_saved_scan_without_yaml_uses_client_findings():
    token, email = sign_in(); make_pro(email)
    f = {"rule_id": "KA009", "severity": "medium", "message": "img", "resource": "Pod/p", "file": "a.yaml", "line": 3}
    body = client.post("/v1/scans", headers=auth(token), json={"title": "t", "findings": [f], "resource_count": 1}).json()
    assert body["score"] == 96 and body["grade"] == "A" and body["verified"] is False and body["files"] == []


def test_rule_settings_validate_and_apply():
    token, email = sign_in(); make_pro(email)
    assert client.put("/v1/me/settings", json={"disabled": ["KA999"]}, headers=auth(token)).status_code == 422
    r = client.put("/v1/me/settings", json={"disabled": ["KA015", "KA014"], "severity": {"KA009": "high", "KA001": "critical"}}, headers=auth(token))
    assert r.json() == {"disabled": ["KA014", "KA015"], "severity": {"KA009": "high"}}
    findings = [{"rule_id": "KA009", "severity": "medium", "message": "m", "resource": "Pod/p", "file": "a", "line": 1},
                {"rule_id": "KA015", "severity": "low", "message": "m", "resource": "Pod/p", "file": "a", "line": 2}]
    body = client.post("/v1/scans", headers=auth(token), json={"title": "t", "findings": findings}).json()
    assert [(f["rule_id"], f["severity"]) for f in body["findings"]] == [("KA009", "high")]


def test_scan_history_is_private_and_deletable():
    t1, e1 = sign_in(); make_pro(e1)
    t2, e2 = sign_in(); make_pro(e2)
    sid = client.post("/v1/scans", headers=auth(t1), json={"title": "mine", "findings": []}).json()["id"]
    assert client.get(f"/v1/scans/{sid}", headers=auth(t2)).status_code == 404
    assert client.delete(f"/v1/scans/{sid}", headers=auth(t2)).status_code == 404
    assert client.get("/v1/scans", headers=auth(t1)).json()["total"] == 1
    assert client.get("/v1/scans", headers=auth(t2)).json()["total"] == 0
    assert client.delete(f"/v1/scans/{sid}", headers=auth(t1)).status_code == 204
    assert client.get(f"/v1/scans/{sid}", headers=auth(t1)).status_code == 404
    assert client.get("/v1/scans/not-a-uuid", headers=auth(t1)).status_code == 404


def test_share_link_hides_yaml_and_can_be_revoked():
    token, email = sign_in(); make_pro(email)
    sid = client.post("/v1/scans", headers=auth(token), json={
        "title": "prod", "files": [{"name": "insecure.yaml", "text": INSECURE.read_text()}]}).json()["id"]
    share = client.post(f"/v1/scans/{sid}/share", headers=auth(token)).json()["share_id"]
    assert client.post(f"/v1/scans/{sid}/share", headers=auth(token)).json()["share_id"] == share  # stable
    pub = client.get(f"/v1/shared/{share}")
    assert pub.status_code == 200
    data = pub.json()
    assert data["files"] == [{"name": "insecure.yaml"}] and "hunter2" not in pub.text and "email" not in data
    assert client.delete(f"/v1/scans/{sid}/share", headers=auth(token)).status_code == 204
    assert client.get(f"/v1/shared/{share}").status_code == 404


def test_delete_account():
    token, email = sign_in(); make_pro(email)
    client.post("/v1/scans", headers=auth(token), json={"title": "t", "findings": []})
    db = SessionLocal(); u = db.query(User).filter(User.email == email).one()
    u.stripe_subscription_id = "sub_live"; db.commit(); db.close()
    assert client.delete("/v1/me", headers=auth(token)).status_code == 409
    db = SessionLocal(); u = db.query(User).filter(User.email == email).one()
    u.stripe_subscription_id = None; db.commit(); uid = u.id; db.close()
    assert client.delete("/v1/me", headers=auth(token)).status_code == 204
    db = SessionLocal()
    assert db.get(User, uid) is None and db.query(Scan).filter(Scan.user_id == uid).count() == 0
    db.close()


# ---------------------------------------------------------------- billing

@pytest.fixture
def stripe_on(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_x")
    monkeypatch.setenv("STRIPE_PRICE_ID_PRO", "price_pro")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
    get_settings.cache_clear()
    subs = {}

    class Obj(dict):
        def __getattr__(self, k): return self[k]

    def create(**kw):
        create.last = kw
        return Obj(url="https://checkout.stripe.example/s")
    monkeypatch.setattr(billing_mod.stripe.checkout.Session, "create", staticmethod(create))
    monkeypatch.setattr(billing_mod.stripe.billing_portal.Session, "create",
                        staticmethod(lambda **kw: Obj(url="https://portal.stripe.example/p")))
    monkeypatch.setattr(billing_mod.stripe.Subscription, "retrieve", staticmethod(lambda sid: subs[sid]))
    return {"create": create, "subs": subs}


def send_event(event, secret="whsec_test"):
    payload = json.dumps(event)
    t = int(time.time())
    sig = hmac.new(secret.encode(), f"{t}.{payload}".encode(), hashlib.sha256).hexdigest()
    return client.post("/v1/billing/webhook", content=payload, headers={"stripe-signature": f"t={t},v1={sig}", "content-type": "application/json"})


def evt(kind, obj):
    return {"id": "evt_" + uuid.uuid4().hex, "object": "event", "type": kind, "data": {"object": obj}}


def test_checkout_not_configured():
    token, _ = sign_in()
    assert client.post("/v1/billing/checkout", headers=auth(token)).status_code == 503


def test_checkout_session(stripe_on):
    token, email = sign_in()
    r = client.post("/v1/billing/checkout", headers=auth(token))
    assert r.json() == {"url": "https://checkout.stripe.example/s"}
    kw = stripe_on["create"].last
    uid = client.get("/v1/me", headers=auth(token)).json()["id"]
    assert kw["client_reference_id"] == uid and kw["customer_email"] == email
    assert kw["subscription_data"]["metadata"]["user_id"] == uid and kw["line_items"][0]["price"] == "price_pro"
    assert kw["success_url"] == "https://app.example/KubeAudit/?billing=success"
    assert client.post("/v1/billing/portal", headers=auth(token)).status_code == 400  # no customer yet


def test_webhook_rejects_bad_signature(stripe_on):
    assert send_event(evt("checkout.session.completed", {}), secret="whsec_wrong").status_code == 400


def test_full_subscription_lifecycle(stripe_on):
    token, _ = sign_in()
    uid = client.get("/v1/me", headers=auth(token)).json()["id"]
    end = int(time.time()) + 30 * 86400
    stripe_on["subs"]["sub_1"] = {"id": "sub_1", "status": "active", "customer": "cus_1",
                                  "items": {"data": [{"current_period_end": end}]}, "metadata": {"user_id": uid}}
    # Out of order: subscription.created (sent as 'incomplete') arrives after checkout completed.
    assert send_event(evt("checkout.session.completed", {"mode": "subscription", "client_reference_id": uid,
                                                          "customer": "cus_1", "subscription": "sub_1", "payment_status": "paid"})).status_code == 200
    assert send_event(evt("customer.subscription.created", {"id": "sub_1", "status": "incomplete", "customer": "cus_1",
                                                             "metadata": {"user_id": uid}})).status_code == 200
    me = client.get("/v1/me", headers=auth(token)).json()
    assert me["plan"] == "pro" and me["usage"]["monthly_limit"] == 2500 and me["current_period_end"]
    assert client.get("/v1/scans", headers=auth(token)).status_code == 200
    assert client.post("/v1/billing/portal", headers=auth(token)).json()["url"].startswith("https://portal")
    assert client.post("/v1/billing/checkout", headers=auth(token)).status_code == 409

    stripe_on["subs"]["sub_1"] = {**stripe_on["subs"]["sub_1"], "status": "past_due"}
    send_event(evt("customer.subscription.updated", {"id": "sub_1", "customer": "cus_1", "metadata": {}}))
    assert client.get("/v1/me", headers=auth(token)).json()["plan"] == "free"

    stripe_on["subs"]["sub_1"] = {**stripe_on["subs"]["sub_1"], "status": "active"}
    send_event(evt("customer.subscription.updated", {"id": "sub_1", "customer": "cus_1", "metadata": {}}))
    assert client.get("/v1/me", headers=auth(token)).json()["plan"] == "pro"

    stripe_on["subs"]["sub_1"] = {**stripe_on["subs"]["sub_1"], "status": "canceled"}
    send_event(evt("customer.subscription.deleted", {"id": "sub_1", "customer": "cus_1", "metadata": {}}))
    me = client.get("/v1/me", headers=auth(token)).json()
    assert me["plan"] == "free" and me["subscription_status"] == "canceled"
    assert client.get("/v1/scans", headers=auth(token)).status_code == 402


def test_unpaid_checkout_does_not_grant_pro(stripe_on):
    token, _ = sign_in()
    uid = client.get("/v1/me", headers=auth(token)).json()["id"]
    stripe_on["subs"]["sub_2"] = {"id": "sub_2", "status": "incomplete", "customer": "cus_2", "metadata": {"user_id": uid}}
    send_event(evt("checkout.session.completed", {"mode": "subscription", "client_reference_id": uid,
                                                  "customer": "cus_2", "subscription": "sub_2", "payment_status": "unpaid"}))
    assert client.get("/v1/me", headers=auth(token)).json()["plan"] == "free"


# ---------------------------------------------------------------- CORS

def test_cors_allows_only_the_web_app():
    ok = client.options("/v1/me", headers={"Origin": "https://msharsha565-create.github.io", "Access-Control-Request-Method": "GET",
                                           "Access-Control-Request-Headers": "authorization"})
    assert ok.headers.get("access-control-allow-origin") == "https://msharsha565-create.github.io"
    bad = client.options("/v1/me", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in bad.headers
