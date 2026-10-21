"""Google and Microsoft sign-in, account-linking safety, and the yearly plan."""
import base64
import json
import time
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

import app.oauth as oauth
from app import billing as billing_mod
from app.config import get_settings
from app.main import app
from app.oauth import MS_CONSUMER_TENANT, OAuthError, identity_from_claims

GOOGLE_ISS = "https://accounts.google.com"


def jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    for k, v in {"APP_URL": "https://app.example/KubeAudit/", "API_URL": "https://api.example",
                 "GOOGLE_CLIENT_ID": "g-cid", "GOOGLE_CLIENT_SECRET": "g-sec",
                 "MICROSOFT_CLIENT_ID": "m-cid", "MICROSOFT_CLIENT_SECRET": "m-sec"}.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ---------------------------------------------------------------- claim rules

def g_claims(**kw):
    base = {"iss": GOOGLE_ISS, "aud": "g-cid", "exp": time.time() + 300, "sub": "g-123",
            "email": "Person@Gmail.com", "email_verified": True, "name": "Pat", "picture": "https://p.example/a.png"}
    return {**base, **kw}


def m_claims(**kw):
    tid = kw.pop("tid", MS_CONSUMER_TENANT)
    base = {"iss": f"https://login.microsoftonline.com/{tid}/v2.0", "aud": "m-cid", "exp": time.time() + 300,
            "tid": tid, "oid": "oid-1", "sub": "s-1", "email": "pat@outlook.com", "name": "Pat"}
    return {**base, **kw}


def test_google_claims_accepted_and_lowercased():
    ident = identity_from_claims("google", g_claims(), "g-cid")
    assert ident["email"] == "person@gmail.com" and ident["id"] == "g-123"


@pytest.mark.parametrize("bad", [{"aud": "other"}, {"exp": time.time() - 3600}, {"iss": "https://evil.example"},
                                 {"email_verified": False}, {"email": ""}])
def test_google_bad_claims_rejected(bad):
    with pytest.raises(OAuthError):
        identity_from_claims("google", g_claims(**bad), "g-cid")


def test_microsoft_personal_account_accepted():
    ident = identity_from_claims("microsoft", m_claims(), "m-cid")
    assert ident["email"] == "pat@outlook.com" and ident["id"] == f"{MS_CONSUMER_TENANT}:oid-1"


def test_microsoft_work_account_needs_verified_domain():
    work = "11111111-2222-3333-4444-555555555555"
    with pytest.raises(OAuthError, match="couldn't confirm the email"):
        identity_from_claims("microsoft", m_claims(tid=work, email="ceo@victim.example"), "m-cid")
    ident = identity_from_claims("microsoft", m_claims(tid=work, email="dev@corp.example", xms_edov=True), "m-cid")
    assert ident["id"] == f"{work}:oid-1"


def test_microsoft_issuer_must_match_tenant():
    with pytest.raises(OAuthError):
        identity_from_claims("microsoft", m_claims(iss="https://login.microsoftonline.com/other/v2.0"), "m-cid")


# ---------------------------------------------------------------- full flow

class FakeResp:
    def __init__(self, d): self._d = d
    def json(self): return self._d


def fake_client(claims_for):
    class C:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def post(self, url, data=None, **k):
            assert data["grant_type"] == "authorization_code" and data["code"] == "the-code"
            return FakeResp({"id_token": jwt(claims_for())})
    return C


def run_flow(monkeypatch, provider, claims):
    c = TestClient(app, follow_redirects=False, base_url="https://testserver")
    start = c.get(f"/v1/auth/{provider}/start")
    assert start.status_code == 302
    q = parse_qs(urlparse(start.headers["location"]).query)
    assert q["redirect_uri"] == [f"https://api.example/v1/auth/{provider}/callback"] and q["scope"] == ["openid email profile"]
    nonce = q["nonce"][0]
    monkeypatch.setattr(oauth.httpx, "Client", fake_client(lambda: {**claims, "nonce": nonce}))
    cb = c.get(f"/v1/auth/{provider}/callback?code=the-code&state={q['state'][0]}")
    loc = urlparse(cb.headers["location"])
    params = parse_qs(loc.query)
    if "login" not in params:
        return c, None, params.get("login_error", [""])[0]
    r = c.post("/v1/auth/exchange", json={"code": params["login"][0]})
    return c, r.json()["user"], None


def test_google_sign_in(monkeypatch):
    email = f"g{uuid.uuid4().hex[:6]}@gmail.com"
    _, user, err = run_flow(monkeypatch, "google", g_claims(sub=uuid.uuid4().hex, email=email))
    assert err is None and user["email"] == email and user["google"] is True


def test_microsoft_sign_in_and_same_email_links_one_account(monkeypatch):
    email = f"m{uuid.uuid4().hex[:6]}@outlook.com"
    _, u1, _ = run_flow(monkeypatch, "microsoft", m_claims(oid=uuid.uuid4().hex, email=email))
    _, u2, _ = run_flow(monkeypatch, "google", g_claims(sub=uuid.uuid4().hex, email=email))
    assert u1["id"] == u2["id"] and u2["google"] and u2["microsoft"]


def test_unverified_work_email_cannot_take_over_account(monkeypatch):
    victim = f"v{uuid.uuid4().hex[:6]}@gmail.com"
    _, owner, _ = run_flow(monkeypatch, "google", g_claims(sub=uuid.uuid4().hex, email=victim))
    _, user, err = run_flow(monkeypatch, "microsoft", m_claims(tid="aaaaaaaa-0000-0000-0000-000000000000", email=victim))
    assert user is None and "couldn't confirm" in err


def test_nonce_and_state_are_checked(monkeypatch):
    c = TestClient(app, follow_redirects=False, base_url="https://testserver")
    q = parse_qs(urlparse(c.get("/v1/auth/google/start").headers["location"]).query)
    monkeypatch.setattr(oauth.httpx, "Client", fake_client(lambda: {**g_claims(), "nonce": "replayed"}))
    cb = c.get(f"/v1/auth/google/callback?code=the-code&state={q['state'][0]}")
    assert "login_error" in cb.headers["location"]
    cb2 = c.get("/v1/auth/google/callback?code=the-code&state=forged")
    assert "login_error" in cb2.headers["location"]


def test_unknown_or_unconfigured_provider(monkeypatch):
    c = TestClient(app, follow_redirects=False)
    assert c.get("/v1/auth/yahoo/start").status_code == 422
    monkeypatch.delenv("MICROSOFT_CLIENT_SECRET")
    get_settings.cache_clear()
    assert c.get("/v1/auth/microsoft/start").status_code == 503
    assert c.get("/v1/auth/providers").json()["microsoft"] is False


# ---------------------------------------------------------------- yearly plan

@pytest.fixture
def stripe_on(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_x")
    monkeypatch.setenv("STRIPE_PRICE_ID_PRO", "price_month")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
    get_settings.cache_clear()
    calls = []

    class Obj(dict):
        def __getattr__(self, k): return self[k]
    monkeypatch.setattr(billing_mod.stripe.checkout.Session, "create",
                        staticmethod(lambda **kw: calls.append(kw) or Obj(url="https://checkout.example")))
    return calls


def bearer(monkeypatch):
    c = TestClient(app, follow_redirects=False, base_url="https://testserver")
    q = parse_qs(urlparse(c.get("/v1/auth/google/start").headers["location"]).query)
    claims = g_claims(sub=uuid.uuid4().hex, email=f"b{uuid.uuid4().hex[:6]}@gmail.com", nonce=q["nonce"][0])
    monkeypatch.setattr(oauth.httpx, "Client", fake_client(lambda: claims))
    code = parse_qs(urlparse(c.get(f"/v1/auth/google/callback?code=the-code&state={q['state'][0]}").headers["location"]).query)["login"][0]
    return {"Authorization": f"Bearer {c.post('/v1/auth/exchange', json={'code': code}).json()['token']}"}


def test_monthly_and_yearly_prices(monkeypatch, stripe_on):
    h = bearer(monkeypatch)
    c = TestClient(app)
    assert c.post("/v1/billing/checkout", headers=h, json={"plan": "yearly"}).status_code == 400  # not configured
    assert c.get("/v1/auth/providers").json()["yearly"] is False
    monkeypatch.setenv("STRIPE_PRICE_ID_PRO_YEARLY", "price_year")
    get_settings.cache_clear()
    assert c.get("/v1/auth/providers").json()["yearly"] is True
    assert c.post("/v1/billing/checkout", headers=h, json={"plan": "yearly"}).status_code == 200
    assert stripe_on[-1]["line_items"][0]["price"] == "price_year"
    assert "14-day money-back" in stripe_on[-1]["custom_text"]["submit"]["message"]
    assert c.post("/v1/billing/checkout", headers=h).status_code == 200  # no body = monthly
    assert stripe_on[-1]["line_items"][0]["price"] == "price_month"
    assert c.post("/v1/billing/checkout", headers=h, json={"plan": "weekly"}).status_code == 422


def test_billing_interval_recorded(monkeypatch, stripe_on):
    from app.database import SessionLocal
    from app.models import User
    h = bearer(monkeypatch)
    uid = TestClient(app).get("/v1/me", headers=h).json()["id"]
    db = SessionLocal()
    u = db.get(User, uuid.UUID(uid))
    billing_mod._apply_subscription(u, {"id": "sub_y", "status": "active",
                                         "items": {"data": [{"price": {"recurring": {"interval": "year"}}, "current_period_end": 2000000000}]}})
    db.commit(); db.close()
    me = TestClient(app).get("/v1/me", headers=h).json()
    assert me["billing_interval"] == "year" and me["plan"] == "pro"
