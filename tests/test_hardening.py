import pytest
from app.images import is_unpinned_image
from app.ai_advisor import JSONPatchOp, guard_ai_patches
from fastapi.testclient import TestClient
from app.main import app


@pytest.mark.parametrize("image,unpinned", [
    ("nginx", True),
    ("nginx:latest", True),
    ("nginx:1.25.0", False),
    ("registry:5000/img", True),
    ("registry:5000/img:1.2", False),
    ("registry:5000/img:latest", True),
    ("nginx@sha256:abc", False),
    ("nginx:1.25@sha256:abc", False),
    ("", True),
])
def test_is_unpinned_image(image, unpinned):
    assert is_unpinned_image(image) is unpinned


def test_audit_without_api_key_is_rejected_even_if_test_user_exists():
    # conftest provisions test_audit@kubeaudit.local; it must not act as a fallback.
    res = TestClient(app).post("/audit", json={"manifest": "apiVersion: v1\nkind: Pod"})
    assert res.status_code == 401


def _op(op, path, value=None):
    return JSONPatchOp(op=op, path=path, value=value)


def test_ai_patch_guard_allows_only_hardening_on_existing_container():
    containers = [{"name": "a", "securityContext": {}}]
    good = _op("add", "/spec/containers/0/securityContext/privileged", False)
    patches = [
        good,
        _op("add", "/spec/containers/0/securityContext/privileged", True),      # loosens
        _op("remove", "/spec/containers/0/securityContext/privileged"),          # remove op
        _op("replace", "/spec/containers/0/image", "evil:1"),                    # image
        _op("add", "/spec/containers/0/command", ["sh"]),                        # command
        _op("add", "/spec/containers/5/securityContext/privileged", False),      # no such container
        _op("add", "/metadata/labels/x", "y"),                                   # unrelated path
        _op("add", "/spec/containers/0/securityContext/capabilities", {"add": ["ALL"]}),
    ]
    assert guard_ai_patches(patches, "/spec", containers) == [good.model_dump(exclude_none=True)]


def test_ai_patch_guard_rejects_when_security_context_missing():
    containers = [{"name": "a"}]
    p = _op("add", "/spec/containers/0/securityContext/privileged", False)
    assert guard_ai_patches([p], "/spec", containers) == []


def test_mutate_never_rewrites_images():
    import base64, json
    review = {"request": {"uid": "u", "object": {
        "kind": "Pod", "metadata": {"name": "p", "namespace": "d"},
        "spec": {"containers": [{"name": "c", "image": "busybox"}]}}}}
    data = TestClient(app).post("/mutate", json=review).json()
    patches = json.loads(base64.b64decode(data["response"]["patch"]))
    assert all(not p["path"].endswith("/image") for p in patches)
