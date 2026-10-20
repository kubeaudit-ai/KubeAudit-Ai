import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine, SessionLocal
from app.models import User, PlanTier, AuditLog
from app.auth import set_new_api_key

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    db.query(AuditLog).filter(AuditLog.user.has(User.email == "ci_test@kubeaudit.local")).delete(synchronize_session=False)
    db.query(User).filter(User.email == "ci_test@kubeaudit.local").delete()

    user = User(
        email="ci_test@kubeaudit.local",
        subscription_tier=PlanTier.FREE,
        subscription_status="active"
    )
    user.plain_key = set_new_api_key(user)
    db.add(user)
    db.commit()
    db.refresh(user)
    yield user
    db.close()

def test_missing_api_key_rejected():
    res = client.post("/audit", json={"manifest": "apiVersion: v1\nkind: Pod"})
    assert res.status_code == 401

def test_authenticated_audit_and_logging(setup_db):
    user = setup_db
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: secured-pod
  namespace: prod
spec:
  securityContext:
    runAsNonRoot: true
  containers:
  - name: app
    image: nginx:1.25.0
    securityContext:
      privileged: false
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
    resources:
      limits:
        cpu: "500m"
        memory: "512Mi"
      requests:
        cpu: "100m"
        memory: "128Mi"
"""
    res = client.post("/audit", json={"manifest": manifest}, headers={"X-API-Key": user.plain_key})
    assert res.status_code == 200
    assert res.json()["valid"] is True

    db = SessionLocal()
    assert db.query(AuditLog).filter(AuditLog.user_id == user.id).count() == 1
    db.close()

def test_quota_exhaustion_429(setup_db):
    user = setup_db
    db = SessionLocal()
    for _ in range(50):
        db.add(AuditLog(user_id=user.id, resource_count=1, violations_detected=0))
    db.commit()
    db.close()

    res = client.post("/audit", json={"manifest": "apiVersion: v1\nkind: Pod"}, headers={"X-API-Key": user.plain_key})
    assert res.status_code == 429
    assert "Monthly limit of 50" in res.json()["detail"]
