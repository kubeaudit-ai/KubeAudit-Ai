import pytest
from app.policy_engine import policy_engine

def test_policy_engine_evaluates_insecure_deployment():
    insecure = {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "web",
                            "image": "nginx",
                            "securityContext": {"privileged": True},
                            "resources": {}
                        }
                    ]
                }
            }
        }
    }
    violations = policy_engine.evaluate(insecure)
    rules = [v["rule"] for v in violations]
    assert "RunAsNonRoot" in rules
    assert "PrivilegedContainer" in rules
    assert "MissingResourceLimits" in rules

def test_policy_engine_evaluates_compliant_deployment():
    compliant = {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {
                    "securityContext": {"runAsNonRoot": True},
                    "containers": [
                        {
                            "name": "web",
                            "image": "nginx:alpine",
                            "securityContext": {
                                "privileged": False,
                                "readOnlyRootFilesystem": True,
                                "allowPrivilegeEscalation": False
                            },
                            "resources": {
                                "limits": {"cpu": "500m", "memory": "512Mi"},
                                "requests": {"cpu": "100m", "memory": "128Mi"}
                            }
                        }
                    ]
                }
            }
        }
    }
    violations = policy_engine.evaluate(compliant)
    assert len(violations) == 0
