"""The webhook and fixers must never invent image tags (e.g. busybox:1.0.0)."""
import base64
import json

import yaml
from fastapi.testclient import TestClient

from app.cli import remediate_document
from app.main import app
from app.policy_engine import policy_engine

client = TestClient(app, headers={"X-API-Key": "ka_live_mock_ci_test_key"})


def _review(image):
    return {"request": {"uid": "u1", "object": {
        "kind": "Pod", "metadata": {"name": "p", "namespace": "apps"},
        "spec": {"containers": [{"name": "c", "image": image}]}}}}


def test_mutate_never_patches_images():
    for image in ("busybox", "nginx:latest", "registry.local:5000/team/api"):
        data = client.post("/mutate", json=_review(image)).json()
        patches = json.loads(base64.b64decode(data["response"]["patch"]))
        assert patches, "security patches should still be applied"
        assert not any(p["path"].endswith("/image") for p in patches), image


def test_fix_endpoint_keeps_images_and_still_reports_them():
    manifest = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: apps}\nspec:\n  containers:\n    - {name: c, image: busybox}\n"
    fixed = client.post("/fix", json={"manifest": manifest}).json()
    doc = yaml.safe_load(fixed["remediated_manifest"])
    assert doc["spec"]["containers"][0]["image"] == "busybox"
    issues = client.post("/audit", json={"manifest": fixed["remediated_manifest"]}).json()["issues"]
    assert [i["rule"] for i in issues] == ["AvoidLatestTag"]


def test_cli_fix_keeps_images():
    doc = {"kind": "Pod", "spec": {"containers": [{"name": "c", "image": "busybox"}]}}
    remediate_document(doc, [])
    assert doc["spec"]["containers"][0]["image"] == "busybox"


def test_policy_engine_handles_registry_ports_and_digests():
    def flagged(image):
        obj = {"kind": "Pod", "spec": {"containers": [{"name": "c", "image": image}]}}
        return any(v["rule"] == "AvoidLatestTag" for v in policy_engine.evaluate(obj))
    assert flagged("registry.local:5000/team/api")
    assert not flagged("registry.local:5000/team/api:1.2")
    assert not flagged("nginx@sha256:abc")
    assert flagged("nginx:latest")
