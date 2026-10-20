import os
import tempfile

# Each test run gets its own throwaway database, created by the real migrations.
_DB = os.path.join(tempfile.mkdtemp(prefix="kubeaudit-test-"), "test.db")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_DB}")
os.environ.setdefault("EMAIL_BACKEND", "file:" + os.path.join(os.path.dirname(_DB), "outbox.jsonl"))

import pytest  # noqa: E402

from app.database import SessionLocal  # noqa: E402
from app.migrate import upgrade_database  # noqa: E402
from app.models import PlanTier, User  # noqa: E402
from app.security import token_hash  # noqa: E402

CI_KEY = "ka_live_mock_ci_test_key"


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    upgrade_database()
    db = SessionLocal()
    if not db.query(User).filter(User.email == "test_audit@kubeaudit.local").first():
        db.add(User(email="test_audit@kubeaudit.local", api_key_hash=token_hash(CI_KEY), api_key_last4=CI_KEY[-4:],
                    subscription_tier=PlanTier.PRO, subscription_status="active"))
        db.commit()
    db.close()
    yield
