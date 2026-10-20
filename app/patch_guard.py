"""Guardrails for AI-suggested JSON patches.

LLM output is never trusted in the admission path. A suggested patch is only
kept when it:
  * is an ``add`` or ``replace`` (never ``remove``),
  * targets a known security/resource field on a container or pod that exists,
  * sets a value of the right type that moves the field in the *secure* direction.

Anything else is dropped and logged. AI mutation is off unless
``AI_MUTATIONS_ENABLED=true``.
"""
import logging
import os
import re
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("kubeaudit.patch_guard")

QUANTITY = re.compile(r"^[0-9]+(\.[0-9]+)?(m|Ki|Mi|Gi|Ti|k|M|G|T)?$")

# field suffix -> validator(value) returning True if the value is acceptable
_CONTAINER_FIELDS = {
    "securityContext/privileged": lambda v: v is False,
    "securityContext/allowPrivilegeEscalation": lambda v: v is False,
    "securityContext/readOnlyRootFilesystem": lambda v: v is True,
    "securityContext/runAsNonRoot": lambda v: v is True,
    "securityContext/runAsUser": lambda v: isinstance(v, int) and not isinstance(v, bool) and v > 0,
    "resources/limits/cpu": lambda v: isinstance(v, str) and bool(QUANTITY.match(v)),
    "resources/limits/memory": lambda v: isinstance(v, str) and bool(QUANTITY.match(v)),
    "resources/requests/cpu": lambda v: isinstance(v, str) and bool(QUANTITY.match(v)),
    "resources/requests/memory": lambda v: isinstance(v, str) and bool(QUANTITY.match(v)),
}
_POD_FIELDS = {
    "securityContext/runAsNonRoot": lambda v: v is True,
    "securityContext/runAsUser": lambda v: isinstance(v, int) and not isinstance(v, bool) and v > 0,
    "automountServiceAccountToken": lambda v: v is False,
}

_POD_PREFIXES = ("/spec/template/spec", "/spec/jobTemplate/spec/template/spec", "/spec")
_CONTAINER_RE = re.compile(r"^/(containers|initContainers)/(\d+)/(.+)$")


def ai_mutations_enabled() -> bool:
    return os.getenv("AI_MUTATIONS_ENABLED", "false").lower() in ("1", "true", "yes")


def _pod_spec_for(obj: Dict[str, Any], prefix: str):
    node: Any = obj
    for part in prefix.strip("/").split("/"):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, dict) else None


def check_patch(obj: Dict[str, Any], patch: Dict[str, Any]) -> Tuple[bool, str]:
    op, path, value = patch.get("op"), patch.get("path", ""), patch.get("value")
    if op not in ("add", "replace"):
        return False, f"op '{op}' not allowed"
    if not isinstance(path, str) or not path.startswith("/"):
        return False, "invalid path"

    for prefix in _POD_PREFIXES:
        if not path.startswith(prefix + "/"):
            continue
        pod_spec = _pod_spec_for(obj, prefix)
        if pod_spec is None or "containers" not in pod_spec:
            continue
        rest = path[len(prefix):]
        m = _CONTAINER_RE.match(rest)
        if m:
            group, idx, field = m.group(1), int(m.group(2)), m.group(3)
            containers = pod_spec.get(group) or []
            if idx >= len(containers):
                return False, "container index out of range"
            check = _CONTAINER_FIELDS.get(field)
            if check is None:
                return False, f"field '{field}' not allowed"
            return (True, "ok") if check(value) else (False, f"unsafe value for '{field}'")
        field = rest.lstrip("/")
        check = _POD_FIELDS.get(field)
        if check is None:
            return False, f"field '{field}' not allowed"
        return (True, "ok") if check(value) else (False, f"unsafe value for '{field}'")
    return False, "path outside pod spec"


def _exists(obj: Any, path: str) -> bool:
    node = obj
    for part in path.strip("/").split("/"):
        if isinstance(node, list):
            if not part.isdigit() or int(part) >= len(node):
                return False
            node = node[int(part)]
        elif isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return False
    return True


def _parent_available(obj: Dict[str, Any], path: str, earlier: List[Dict[str, Any]]) -> bool:
    parent = path.rsplit("/", 1)[0]
    if _exists(obj, parent):
        return True
    # created by an earlier patch (the parent itself, or an ancestor carrying a dict value)
    return any(parent == p.get("path") or parent.startswith(p.get("path", "") + "/") for p in earlier
               if p.get("op") == "add")


def filter_ai_patches(obj: Dict[str, Any], suggested: List[Dict[str, Any]],
                      existing: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return only the AI patches that pass every guard and don't duplicate existing paths."""
    taken = {p.get("path") for p in existing}
    accepted = []
    for patch in suggested:
        ok, reason = check_patch(obj, patch)
        if not ok:
            logger.warning("Rejected AI patch %s: %s", patch.get("path"), reason)
            continue
        if patch["path"] in taken:
            continue
        if not _parent_available(obj, patch["path"], existing + accepted):
            logger.warning("Rejected AI patch %s: parent path does not exist", patch["path"])
            continue
        taken.add(patch["path"])
        accepted.append(patch)
    return accepted
