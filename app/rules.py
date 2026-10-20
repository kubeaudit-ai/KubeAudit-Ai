"""KubeAudit rule set.

Pure functions over parsed Kubernetes objects: no I/O, no web framework, no DB.
Every finding carries a ``path`` (keys/indices into the object) so callers can
map it back to a line in the source file.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

Path = Tuple[Any, ...]

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
IGNORE_ANNOTATION = "kubeaudit.ai/ignore"


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str  # critical | high | medium | low
    title: str
    remediation: str
    fix: str = ""  # YAML snippet showing the secure setting
    docs: str = ""


@dataclass
class Finding:
    rule: Rule
    message: str
    path: Path
    resource: str  # Kind/name
    container: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def severity(self) -> str:
        return self.rule.severity


_K8S = "https://kubernetes.io/docs"
RULES: Dict[str, Rule] = {r.id: r for r in [
    Rule("KA001", "PrivilegedContainer", "critical",
         "Container runs in privileged mode",
         "Privileged containers have full access to the host. Remove `privileged: true`.",
         "securityContext:\n  privileged: false",
         f"{_K8S}/concepts/security/pod-security-standards/#baseline"),
    Rule("KA002", "AllowPrivilegeEscalation", "high",
         "Container allows privilege escalation",
         "Set `allowPrivilegeEscalation: false` so processes can't gain more privileges than their parent.",
         "securityContext:\n  allowPrivilegeEscalation: false",
         f"{_K8S}/concepts/security/pod-security-standards/#restricted"),
    Rule("KA003", "RunAsNonRoot", "high",
         "Container may run as root",
         "Set `runAsNonRoot: true` on the pod or container, and use an image with a non-root user.",
         "securityContext:\n  runAsNonRoot: true\n  runAsUser: 10001",
         f"{_K8S}/concepts/security/pod-security-standards/#restricted"),
    Rule("KA004", "HostNamespaces", "high",
         "Pod shares host namespaces",
         "Remove `hostNetwork`, `hostPID` and `hostIPC` unless the workload is a node agent that truly needs them.",
         "hostNetwork: false\nhostPID: false\nhostIPC: false",
         f"{_K8S}/concepts/security/pod-security-standards/#baseline"),
    Rule("KA005", "HostPathVolume", "high",
         "Pod mounts a hostPath volume",
         "hostPath mounts expose the node filesystem. Use a PersistentVolumeClaim, configMap, secret or emptyDir instead.",
         "volumes:\n  - name: data\n    emptyDir: {}",
         f"{_K8S}/concepts/storage/volumes/#hostpath"),
    Rule("KA006", "DangerousCapabilities", "high",
         "Container adds dangerous Linux capabilities",
         "Remove capabilities such as SYS_ADMIN, NET_ADMIN or ALL from `capabilities.add`.",
         "securityContext:\n  capabilities:\n    drop: [\"ALL\"]",
         f"{_K8S}/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container"),
    Rule("KA007", "HardcodedSecretEnv", "high",
         "Secret value hard-coded in an environment variable",
         "Move the value into a Secret and reference it with `valueFrom.secretKeyRef`. Rotate the exposed value.",
         "env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: app-secrets\n        key: db-password",
         f"{_K8S}/concepts/configuration/secret/#using-secrets-as-environment-variables"),
    Rule("KA008", "RBACWildcard", "high",
         "RBAC rule grants wildcard access",
         "Replace `*` in verbs, resources or apiGroups with the specific values the workload needs.",
         "rules:\n  - apiGroups: [\"\"]\n    resources: [\"configmaps\"]\n    verbs: [\"get\", \"list\"]",
         f"{_K8S}/concepts/security/rbac-good-practices/"),
    Rule("KA009", "ImageNotPinned", "medium",
         "Image uses `latest` or no tag",
         "Pin the image to a specific version tag, or better, a `@sha256:` digest, so deploys are reproducible.",
         "image: registry.example.com/app:1.4.2",
         f"{_K8S}/concepts/containers/images/#image-names"),
    Rule("KA010", "ReadOnlyRootFilesystem", "medium",
         "Root filesystem is writable",
         "Set `readOnlyRootFilesystem: true` and mount an emptyDir for paths the app must write to.",
         "securityContext:\n  readOnlyRootFilesystem: true",
         f"{_K8S}/tasks/configure-pod-container/security-context/"),
    Rule("KA011", "MissingMemoryLimit", "medium",
         "Container has no memory limit",
         "Set `resources.limits.memory` so one container can't exhaust node memory.",
         "resources:\n  limits:\n    memory: 512Mi",
         f"{_K8S}/concepts/configuration/manage-resources-containers/"),
    Rule("KA012", "DropAllCapabilities", "low",
         "Container does not drop all capabilities",
         "Drop all capabilities and add back only what the process needs.",
         "securityContext:\n  capabilities:\n    drop: [\"ALL\"]",
         f"{_K8S}/concepts/security/pod-security-standards/#restricted"),
    Rule("KA013", "MissingResourceRequests", "low",
         "Container has no CPU or memory requests",
         "Set `resources.requests` so the scheduler can place the pod correctly.",
         "resources:\n  requests:\n    cpu: 100m\n    memory: 128Mi",
         f"{_K8S}/concepts/configuration/manage-resources-containers/"),
    Rule("KA014", "MissingProbes", "low",
         "Long-running container has no readiness or liveness probe",
         "Add a readinessProbe (and usually a livenessProbe) so Kubernetes only routes traffic to healthy pods.",
         "readinessProbe:\n  httpGet:\n    path: /healthz\n    port: 8080",
         f"{_K8S}/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/"),
    Rule("KA015", "AutomountServiceAccountToken", "low",
         "Service account token is mounted automatically",
         "Set `automountServiceAccountToken: false` unless the pod calls the Kubernetes API.",
         "automountServiceAccountToken: false",
         f"{_K8S}/tasks/configure-pod-container/configure-service-account/"),
]}

DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "BPF", "PERFMON", "DAC_READ_SEARCH"}
SECRET_NAME = re.compile(r"(PASSW(OR)?D|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL)", re.I)
LONG_RUNNING = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController"}

# kind -> path from object root to the pod spec
POD_SPEC_PATHS: Dict[str, Path] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "ReplicationController": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}


def _get(obj: Any, path: Path) -> Any:
    for part in path:
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list) and isinstance(part, int) and part < len(obj):
            obj = obj[part]
        else:
            return None
    return obj


def _d(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def image_is_pinned(image: str) -> bool:
    if not image:
        return False
    if "@sha256:" in image:
        return True
    last = image.rsplit("/", 1)[-1]  # ignore registry host:port
    if ":" not in last:
        return False
    return last.split(":", 1)[1] not in ("", "latest")


def ignored_rules(obj: Dict[str, Any]) -> set:
    raw = _d(_d(obj.get("metadata")).get("annotations")).get(IGNORE_ANNOTATION, "")
    return {r.strip().upper() for r in str(raw).split(",") if r.strip()}


def _iter_containers(pod_spec: Dict[str, Any], base: Path) -> Iterator[Tuple[Dict[str, Any], Path, str]]:
    for group in ("initContainers", "containers", "ephemeralContainers"):
        for i, c in enumerate(pod_spec.get(group) or []):
            if isinstance(c, dict):
                yield c, base + (group, i), group


def _check_pod(obj: Dict[str, Any], kind: str, resource: str) -> List[Finding]:
    base = POD_SPEC_PATHS[kind]
    pod_spec = _get(obj, base)
    if not isinstance(pod_spec, dict):
        return []
    out: List[Finding] = []
    pod_sc = _d(pod_spec.get("securityContext"))

    for flag in ("hostNetwork", "hostPID", "hostIPC"):
        if pod_spec.get(flag) is True:
            out.append(Finding(RULES["KA004"], f"{resource} sets `{flag}: true`.", base + (flag,), resource))

    for i, vol in enumerate(pod_spec.get("volumes") or []):
        if isinstance(vol, dict) and "hostPath" in vol:
            hp = _d(vol.get("hostPath")).get("path", "?")
            out.append(Finding(RULES["KA005"], f"{resource} mounts host path `{hp}` (volume `{vol.get('name', i)}`).",
                               base + ("volumes", i, "hostPath"), resource))

    if pod_spec.get("automountServiceAccountToken") is not False:
        out.append(Finding(RULES["KA015"], f"{resource} mounts its service account token automatically.",
                           base + ("automountServiceAccountToken",), resource))

    pod_non_root = pod_sc.get("runAsNonRoot") is True or (
        isinstance(pod_sc.get("runAsUser"), int) and pod_sc.get("runAsUser") > 0)

    for c, cpath, group in _iter_containers(pod_spec, base):
        name = c.get("name", "unnamed")
        label = f"container `{name}`" if group == "containers" else f"{group[:-1]} `{name}`"
        sc = _d(c.get("securityContext"))
        caps = _d(sc.get("capabilities"))
        res = _d(c.get("resources"))
        F = lambda rid, msg, p: out.append(Finding(RULES[rid], msg, p, resource, name))  # noqa: E731

        if sc.get("privileged") is True:
            F("KA001", f"{label} in {resource} runs privileged.", cpath + ("securityContext", "privileged"))
        if sc.get("allowPrivilegeEscalation") is not False:
            F("KA002", f"{label} in {resource} does not set `allowPrivilegeEscalation: false`.",
              cpath + ("securityContext", "allowPrivilegeEscalation"))
        c_non_root = sc.get("runAsNonRoot") is True or (isinstance(sc.get("runAsUser"), int) and sc.get("runAsUser") > 0)
        if not (pod_non_root or c_non_root) or sc.get("runAsNonRoot") is False or sc.get("runAsUser") == 0:
            F("KA003", f"{label} in {resource} may run as root.", cpath + ("securityContext", "runAsNonRoot"))
        added = {str(x).upper() for x in caps.get("add") or []}
        bad = sorted(added & DANGEROUS_CAPS)
        if bad:
            F("KA006", f"{label} in {resource} adds {', '.join(bad)}.", cpath + ("securityContext", "capabilities", "add"))
        if "ALL" not in {str(x).upper() for x in caps.get("drop") or []}:
            F("KA012", f"{label} in {resource} does not drop ALL capabilities.",
              cpath + ("securityContext", "capabilities", "drop"))
        image = str(c.get("image", ""))
        if not image_is_pinned(image):
            F("KA009", f"{label} in {resource} uses image `{image or '<none>'}` without a pinned version.", cpath + ("image",))
        if sc.get("readOnlyRootFilesystem") is not True:
            F("KA010", f"{label} in {resource} has a writable root filesystem.",
              cpath + ("securityContext", "readOnlyRootFilesystem"))
        if group == "ephemeralContainers":
            continue  # resources/probes are not allowed on ephemeral containers
        if not _d(res.get("limits")).get("memory"):
            F("KA011", f"{label} in {resource} has no memory limit.", cpath + ("resources", "limits", "memory"))
        req = _d(res.get("requests"))
        if not req.get("cpu") or not req.get("memory"):
            F("KA013", f"{label} in {resource} is missing CPU or memory requests.", cpath + ("resources", "requests"))
        if group == "containers" and kind in LONG_RUNNING and not (c.get("readinessProbe") or c.get("livenessProbe")):
            F("KA014", f"{label} in {resource} has no readiness or liveness probe.", cpath)
        for j, env in enumerate(c.get("env") or []):
            if not isinstance(env, dict):
                continue
            val = env.get("value")
            if isinstance(val, str) and val.strip() and SECRET_NAME.search(str(env.get("name", ""))):
                F("KA007", f"{label} in {resource} sets `{env.get('name')}` to a literal value.",
                  cpath + ("env", j, "value"))
    return out


def _check_rbac(obj: Dict[str, Any], resource: str) -> List[Finding]:
    out = []
    for i, rule in enumerate(obj.get("rules") or []):
        if not isinstance(rule, dict):
            continue
        wild = [k for k in ("verbs", "resources", "apiGroups") if "*" in (rule.get(k) or [])]
        if wild:
            out.append(Finding(RULES["KA008"], f"{resource} rule {i + 1} uses `*` in {', '.join(wild)}.",
                               ("rules", i), resource))
    return out


def check_object(obj: Dict[str, Any]) -> List[Finding]:
    """Run every rule against one Kubernetes object."""
    if not isinstance(obj, dict):
        return []
    kind = str(obj.get("kind", ""))
    name = _d(obj.get("metadata")).get("name", "unnamed")
    resource = f"{kind}/{name}"
    findings: List[Finding] = []
    if kind in POD_SPEC_PATHS:
        findings += _check_pod(obj, kind, resource)
    if kind in ("Role", "ClusterRole"):
        findings += _check_rbac(obj, resource)
    skip = ignored_rules(obj)
    if "ALL" in skip:
        return []
    return [f for f in findings if f.rule.id not in skip and f.rule.name.upper() not in skip]


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 99)
