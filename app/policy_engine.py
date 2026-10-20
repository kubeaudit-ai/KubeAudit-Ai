from typing import Any, Dict, List

from app.images import is_unpinned_image


class PolicyEngine:
    """Built-in Python policy checks (not an OPA/Rego evaluator)."""

    def evaluate(self, manifest: Any) -> List[Dict[str, str]]:
        if not isinstance(manifest, dict):
            return []

        violations: List[Dict[str, str]] = []
        kind = manifest.get("kind", "")
        spec = manifest.get("spec", {})

        pod_spec = None
        if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
            pod_spec = spec.get("template", {}).get("spec", {})
        elif kind == "Pod":
            pod_spec = spec

        if pod_spec is not None and isinstance(pod_spec, dict):
            sec_ctx = pod_spec.get("securityContext") or {}
            if not sec_ctx.get("runAsNonRoot"):
                violations.append({
                    "rule": "RunAsNonRoot",
                    "severity": "High",
                    "message": "Pod securityContext must enforce runAsNonRoot: true",
                    "remediation": "Configure spec.securityContext.runAsNonRoot: true."
                })

            containers = pod_spec.get("containers", [])
            for c in containers:
                if not isinstance(c, dict):
                    continue
                c_name = c.get("name", "unnamed")
                c_sec = c.get("securityContext") or {}
                if c_sec.get("privileged") is True:
                    violations.append({
                        "rule": "PrivilegedContainer",
                        "severity": "Critical",
                        "message": f"Container '{c_name}' must not run in privileged mode",
                        "remediation": f"Set securityContext.privileged: false on container '{c_name}'."
                    })
                if not c_sec.get("readOnlyRootFilesystem"):
                    violations.append({
                        "rule": "ReadOnlyRootFilesystem",
                        "severity": "Medium",
                        "message": f"Container '{c_name}' does not configure readOnlyRootFilesystem: true",
                        "remediation": f"Set securityContext.readOnlyRootFilesystem: true on container '{c_name}'."
                    })
                if c_sec.get("allowPrivilegeEscalation") is True:
                    violations.append({
                        "rule": "AllowPrivilegeEscalation",
                        "severity": "High",
                        "message": f"Container '{c_name}' allows privilege escalation",
                        "remediation": f"Set securityContext.allowPrivilegeEscalation: false on container '{c_name}'."
                    })

                image = c.get("image", "")
                if is_unpinned_image(image):
                    violations.append({
                        "rule": "AvoidLatestTag",
                        "severity": "Medium",
                        "message": f"Container '{c_name}' uses the ':latest' image tag or omitted tag.",
                        "remediation": f"Pin container '{c_name}' image to an immutable tag or SHA256 digest."
                    })

                res = c.get("resources") or {}
                limits = res.get("limits") or {}
                if not limits.get("cpu") or not limits.get("memory"):
                    violations.append({
                        "rule": "MissingResourceLimits",
                        "severity": "High",
                        "message": f"Container '{c_name}' lacks CPU or Memory limits",
                        "remediation": f"Configure resources.limits for container '{c_name}'."
                    })

        return violations

policy_engine = PolicyEngine()
