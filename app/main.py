import logging
logger = logging.getLogger("kubeaudit.main")
from contextlib import asynccontextmanager
from fastapi import Depends

from app.database import get_db
from app.auth import verify_quota
from app.models import User, AuditLog
from sqlalchemy.orm import Session


from app.database import init_db
from app.billing import router as billing_router
from app.auth import get_current_user, verify_quota
from app.models import User, AuditLog
from app.database import get_db
from sqlalchemy.orm import Session

import base64
import json
import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
import yaml
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from app.policy_engine import policy_engine
from app.images import is_unpinned_image


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan, title="KubeAudit AI", version="1.0.0")

AUDIT_REQUESTS = Counter(
    "kubeaudit_requests_total",
    "Total audit and admission requests processed",
    ["endpoint", "status"]
)
POLICY_VIOLATIONS = Counter(
    "kubeaudit_policy_violations_total",
    "Total policy violations detected by rule",
    ["rule", "severity"]
)
ADMISSION_DURATION = Histogram(
    "kubeaudit_admission_duration_seconds",
    "Latency of admission decisions in seconds",
    ["webhook_type"]
)

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/metrics")
def get_metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

class AuditRequest(BaseModel):
    manifest: str

class Issue(BaseModel):
    severity: str
    rule: str
    message: str
    remediation: Optional[str] = None

class AuditResponse(BaseModel):
    valid: bool
    issues: List[Issue]

class FixResponse(BaseModel):
    remediated_manifest: str
    applied_fixes: List[str]

from app.ai_advisor import ai_advisor, guard_ai_patches, AI_PATCHES_ENABLED

class AdviseRequest(BaseModel):
    manifest: str

class AdviseResponse(BaseModel):
    available: bool
    violations: List[str]
    advice: str

@app.post("/advise")
@app.post("/v1/advise", response_model=AdviseResponse)
def advise_manifest(payload: AdviseRequest):
    try:
        docs = list(yaml.safe_load_all(payload.manifest))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML payload: {str(e)}")

    valid_docs = [d for d in docs if isinstance(d, dict)]
    violations = []
    for d in valid_docs:
        issues = analyze_manifest(d)
        violations.extend([f"{i.rule}: {i.message}" for i in issues])

    advice = ai_advisor.explain_violations(payload.manifest, violations)
    return AdviseResponse(
        available=ai_advisor.is_available(),
        violations=violations,
        advice=advice
    )


def inspect_container_list(containers: List[Dict[str, Any]], container_type: str) -> List[Issue]:
    issues = []
    for container in containers:
        c_name = container.get("name", "unnamed")
        image = container.get("image", "")

        if is_unpinned_image(image):
            issues.append(Issue(
                severity="Medium",
                rule="AvoidLatestTag",
                message=f"{container_type} '{c_name}' uses the ':latest' image tag or omitted tag.",
                remediation=f"Pin container '{c_name}' image to an immutable tag or SHA256 digest."
            ))

        resources = container.get("resources", {})
        limits = resources.get("limits", {})
        requests = resources.get("requests", {})

        if not limits.get("cpu") or not limits.get("memory"):
            issues.append(Issue(
                severity="High",
                rule="MissingResourceLimits",
                message=f"{container_type} '{c_name}' lacks explicit CPU or Memory limits.",
                remediation="Configure resources.limits: { cpu: '500m', memory: '512Mi' }."
            ))

        if not requests.get("cpu") or not requests.get("memory"):
            issues.append(Issue(
                severity="Low",
                rule="MissingResourceRequests",
                message=f"{container_type} '{c_name}' lacks explicit CPU or Memory requests.",
                remediation="Configure resources.requests: { cpu: '100m', memory: '128Mi' }."
            ))

        c_sec_ctx = container.get("securityContext", {})
        if c_sec_ctx.get("privileged", False):
            issues.append(Issue(
                severity="Critical",
                rule="PrivilegedContainer",
                message=f"{container_type} '{c_name}' runs in privileged mode.",
                remediation="Set securityContext.privileged: false and drop unnecessary capabilities."
            ))

        if not c_sec_ctx.get("readOnlyRootFilesystem", False):
            issues.append(Issue(
                severity="Medium",
                rule="ReadOnlyRootFilesystem",
                message=f"{container_type} '{c_name}' does not configure 'readOnlyRootFilesystem: true'.",
                remediation="Set securityContext.readOnlyRootFilesystem: true."
            ))

        if c_sec_ctx.get("allowPrivilegeEscalation", True):
            issues.append(Issue(
                severity="High",
                rule="AllowPrivilegeEscalation",
                message=f"{container_type} '{c_name}' allows privilege escalation.",
                remediation="Set securityContext.allowPrivilegeEscalation: false."
            ))
    return issues

def analyze_manifest(doc: Dict[str, Any]) -> List[Issue]:
    issues = []
    kind = doc.get("kind", "")
    metadata = doc.get("metadata", {})
    spec = doc.get("spec", {})

    if not metadata.get("namespace") and kind not in ["Namespace", "ClusterRole", "ClusterRoleBinding"]:
        issues.append(Issue(
            severity="Medium",
            rule="RequireNamespace",
            message=f"{kind} '{metadata.get('name', 'unnamed')}' does not specify an explicit namespace.",
            remediation=f"Add metadata.namespace to '{metadata.get('name', 'unnamed')}'."
        ))

    pod_spec = None
    if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
        pod_spec = spec.get("template", {}).get("spec", {})
    elif kind == "Pod":
        pod_spec = spec

    if pod_spec:
        sec_ctx = pod_spec.get("securityContext", {})
        if not sec_ctx.get("runAsNonRoot"):
            issues.append(Issue(
                severity="High",
                rule="RunAsNonRoot",
                message="Pod specification does not enforce 'runAsNonRoot: true'.",
                remediation="Configure spec.securityContext.runAsNonRoot: true."
            ))

        issues.extend(inspect_container_list(pod_spec.get("containers", []), "Container"))
        issues.extend(inspect_container_list(pod_spec.get("initContainers", []), "InitContainer"))
        issues.extend(inspect_container_list(pod_spec.get("ephemeralContainers", []), "EphemeralContainer"))

    return issues

def patch_container(container: Dict[str, Any], fixes: List[str]):
    c_name = container.get("name", "unnamed")
    sec_ctx = container.setdefault("securityContext", {})
    if sec_ctx.get("privileged", False):
        sec_ctx["privileged"] = False
        fixes.append(f"Disabled privileged mode on container '{c_name}'")
    if not sec_ctx.get("readOnlyRootFilesystem", False):
        sec_ctx["readOnlyRootFilesystem"] = True
        fixes.append(f"Enforced readOnlyRootFilesystem on container '{c_name}'")
    if sec_ctx.get("allowPrivilegeEscalation", True):
        sec_ctx["allowPrivilegeEscalation"] = False
        fixes.append(f"Disabled allowPrivilegeEscalation on container '{c_name}'")

    resources = container.setdefault("resources", {})
    limits = resources.setdefault("limits", {})
    requests = resources.setdefault("requests", {})

    if not limits.get("cpu"):
        limits["cpu"] = "500m"
        fixes.append(f"Added default CPU limit (500m) on container '{c_name}'")
    if not limits.get("memory"):
        limits["memory"] = "512Mi"
        fixes.append(f"Added default Memory limit (512Mi) on container '{c_name}'")
    if not requests.get("cpu"):
        requests["cpu"] = "100m"
        fixes.append(f"Added default CPU request (100m) on container '{c_name}'")
    if not requests.get("memory"):
        requests["memory"] = "128Mi"
        fixes.append(f"Added default Memory request (128Mi) on container '{c_name}'")

def remediate_document(doc: Dict[str, Any], fixes: List[str]):
    kind = doc.get("kind", "")
    metadata = doc.setdefault("metadata", {})
    spec = doc.setdefault("spec", {})

    if not metadata.get("namespace") and kind not in ["Namespace", "ClusterRole", "ClusterRoleBinding"]:
        metadata["namespace"] = "default"
        fixes.append(f"Assigned namespace 'default' to {kind} '{metadata.get('name', 'unnamed')}'")

    pod_spec = None
    if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
        template = spec.setdefault("template", {})
        pod_spec = template.setdefault("spec", {})
    elif kind == "Pod":
        pod_spec = spec

    if pod_spec:
        sec_ctx = pod_spec.setdefault("securityContext", {})
        if not sec_ctx.get("runAsNonRoot"):
            sec_ctx["runAsNonRoot"] = True
            fixes.append("Enforced spec.securityContext.runAsNonRoot: true")

        for c in pod_spec.get("containers", []):
            patch_container(c, fixes)
        for c in pod_spec.get("initContainers", []):
            patch_container(c, fixes)
        for c in pod_spec.get("ephemeralContainers", []):
            patch_container(c, fixes)

def generate_pod_spec_patches(pod_spec: Dict[str, Any], path_prefix: str) -> List[Dict[str, Any]]:
    patches = []

    sec_ctx = pod_spec.get("securityContext")
    if sec_ctx is None:
        patches.append({
            "op": "add",
            "path": f"{path_prefix}/securityContext",
            "value": {"runAsNonRoot": True, "runAsUser": 10001}
        })
    else:
        if not sec_ctx.get("runAsNonRoot"):
            patches.append({"op": "add", "path": f"{path_prefix}/securityContext/runAsNonRoot", "value": True})
        if "runAsUser" not in sec_ctx:
            patches.append({"op": "add", "path": f"{path_prefix}/securityContext/runAsUser", "value": 10001})

    containers = pod_spec.get("containers", [])
    for idx, container in enumerate(containers):
        c_prefix = f"{path_prefix}/containers/{idx}"
        c_sec = container.get("securityContext")
        if c_sec is None:
            patches.append({
                "op": "add",
                "path": f"{c_prefix}/securityContext",
                "value": {
                    "privileged": False,
                    "readOnlyRootFilesystem": True,
                    "allowPrivilegeEscalation": False
                }
            })
        else:
            if c_sec.get("privileged", False):
                patches.append({"op": "replace", "path": f"{c_prefix}/securityContext/privileged", "value": False})
            if not c_sec.get("readOnlyRootFilesystem", False):
                patches.append({"op": "add", "path": f"{c_prefix}/securityContext/readOnlyRootFilesystem", "value": True})
            if c_sec.get("allowPrivilegeEscalation", True):
                patches.append({"op": "add", "path": f"{c_prefix}/securityContext/allowPrivilegeEscalation", "value": False})

        res = container.get("resources")
        default_limits = {"cpu": "500m", "memory": "512Mi"}
        default_requests = {"cpu": "100m", "memory": "128Mi"}

        if res is None:
            patches.append({
                "op": "add",
                "path": f"{c_prefix}/resources",
                "value": {"limits": default_limits, "requests": default_requests}
            })
        else:
            if "limits" not in res:
                patches.append({"op": "add", "path": f"{c_prefix}/resources/limits", "value": default_limits})
            else:
                if "cpu" not in res["limits"]:
                    patches.append({"op": "add", "path": f"{c_prefix}/resources/limits/cpu", "value": "500m"})
                if "memory" not in res["limits"]:
                    patches.append({"op": "add", "path": f"{c_prefix}/resources/limits/memory", "value": "512Mi"})

            if "requests" not in res:
                patches.append({"op": "add", "path": f"{c_prefix}/resources/requests", "value": default_requests})
            else:
                if "cpu" not in res["requests"]:
                    patches.append({"op": "add", "path": f"{c_prefix}/resources/requests/cpu", "value": "100m"})
                if "memory" not in res["requests"]:
                    patches.append({"op": "add", "path": f"{c_prefix}/resources/requests/memory", "value": "128Mi"})

    return patches

@app.post("/audit")
async def audit_endpoint(
    payload: dict,
    user: User = Depends(verify_quota),
    db: Session = Depends(get_db)
):
    manifest = payload.get("manifest")
    if not manifest:
        raise HTTPException(status_code=400, detail="Missing 'manifest' in request body")

    import yaml
    from app.policy_engine import policy_engine

    try:
        if isinstance(manifest, str):
            doc = yaml.safe_load(manifest)
        else:
            doc = manifest
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML/JSON manifest: {str(e)}")

    if not isinstance(doc, dict):
        raise HTTPException(status_code=400, detail="Manifest does not contain valid YAML object definitions.")
    issues = policy_engine.evaluate(doc)
    is_valid = len(issues) == 0

    # Record persistent audit entry against the authenticated user
    audit_entry = AuditLog(
        user_id=user.id,
        resource_count=1,
        violations_detected=len(issues)
    )
    db.add(audit_entry)
    db.commit()

    return {"valid": is_valid, "issues": issues}
@app.post("/fix", response_model=FixResponse)
def fix_manifest(payload: AuditRequest):
    try:
        documents = list(yaml.safe_load_all(payload.manifest))
    except Exception as e:
        AUDIT_REQUESTS.labels(endpoint="fix", status="error").inc()
        raise HTTPException(status_code=400, detail=f"Invalid YAML payload: {str(e)}")

    valid_docs = [doc for doc in documents if isinstance(doc, dict)]
    if not valid_docs:
        AUDIT_REQUESTS.labels(endpoint="fix", status="error").inc()
        raise HTTPException(status_code=400, detail="Manifest does not contain valid YAML object definitions.")

    applied_fixes = []
    for doc in valid_docs:
        remediate_document(doc, applied_fixes)

    remediated_yaml = yaml.dump_all(valid_docs, sort_keys=False)
    AUDIT_REQUESTS.labels(endpoint="fix", status="success").inc()
    return FixResponse(remediated_manifest=remediated_yaml, applied_fixes=applied_fixes)

@app.post("/validate")
async def validate_admission(request: Request):
    start_time = time.time()
    try:
        body = await request.json()
    except Exception:
        AUDIT_REQUESTS.labels(endpoint="validate", status="error").inc()
        raise HTTPException(status_code=400, detail="Invalid JSON in admission request")

    req = body.get("request", {})
    uid = req.get("uid", "")
    object_spec = req.get("object", {})

    if "kind" not in object_spec and "kind" in req:
        object_spec["kind"] = req["kind"].get("kind")
        object_spec["apiVersion"] = req["kind"].get("version")

    if not object_spec:
        AUDIT_REQUESTS.labels(endpoint="validate", status="allowed").inc()
        ADMISSION_DURATION.labels(webhook_type="validate").observe(time.time() - start_time)
        return JSONResponse(content={
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {"uid": uid, "allowed": True}
        })

    issues = analyze_manifest(object_spec)
    rego_violations = policy_engine.evaluate(object_spec)
    for rv in rego_violations:
        if not any(i.rule == rv["rule"] for i in issues):
            issues.append(Issue(severity=rv["severity"], rule=rv["rule"], message=rv["message"]))
            
    # AI Security Audit Enrichment
    try:
        if ai_advisor.is_available():
            violation_dicts = [{"rule": i.rule, "severity": i.severity, "message": i.message} for i in issues]
            ai_report = await ai_advisor.audit_manifest(object_spec, violations=violation_dicts)
        for finding in (ai_report.findings if "ai_report" in locals() else []):
            if not any(i.rule == finding.rule_id for i in issues):
                issues.append(Issue(severity=finding.severity, rule=finding.rule_id, message=finding.description))
    except Exception as e:
        logger.warning(f"AI validation enrichment error: {e}")

    critical_or_high = [i for i in issues if i.severity in ["Critical", "High"]]

    if critical_or_high:
        for i in critical_or_high:
            POLICY_VIOLATIONS.labels(rule=i.rule, severity=i.severity).inc()
        AUDIT_REQUESTS.labels(endpoint="validate", status="rejected").inc()
        ADMISSION_DURATION.labels(webhook_type="validate").observe(time.time() - start_time)
        rejection_reasons = "; ".join([f"{i.rule}: {i.message}" for i in critical_or_high])
        return JSONResponse(content={
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": False,
                "status": {
                    "code": 403,
                    "message": f"KubeAudit AI policy violations: {rejection_reasons}"
                }
            }
        })

    AUDIT_REQUESTS.labels(endpoint="validate", status="allowed").inc()
    ADMISSION_DURATION.labels(webhook_type="validate").observe(time.time() - start_time)
    return JSONResponse(content={
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {"uid": uid, "allowed": True}
    })

@app.post("/mutate")
async def mutate_admission(request: Request):
    start_time = time.time()
    try:
        body = await request.json()
    except Exception:
        AUDIT_REQUESTS.labels(endpoint="mutate", status="error").inc()
        raise HTTPException(status_code=400, detail="Invalid JSON in admission request")

    req = body.get("request", {})
    uid = req.get("uid", "")
    object_spec = req.get("object", {})

    if not object_spec:
        AUDIT_REQUESTS.labels(endpoint="mutate", status="allowed").inc()
        ADMISSION_DURATION.labels(webhook_type="mutate").observe(time.time() - start_time)
        return JSONResponse(content={
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {"uid": uid, "allowed": True}
        })

    kind = object_spec.get("kind", "")
    spec = object_spec.get("spec", {})
    patches = []

    metadata = object_spec.get("metadata", {})
    if not metadata.get("namespace") and kind not in ["Namespace", "ClusterRole", "ClusterRoleBinding"]:
        patches.append({"op": "add", "path": "/metadata/namespace", "value": "default"})

    if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
        pod_spec = spec.get("template", {}).get("spec", {})
        if pod_spec:
            patches.extend(generate_pod_spec_patches(pod_spec, "/spec/template/spec"))
    elif kind == "Pod":
        patches.extend(generate_pod_spec_patches(spec, "/spec"))

    # AI Mutation Enrichment (opt-in; model output passes a strict allow-list)
    if AI_PATCHES_ENABLED:
        pod_spec_path = "/spec/template/spec" if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"] else "/spec"
        pod_spec_obj = spec.get("template", {}).get("spec", {}) if pod_spec_path != "/spec" else spec
        if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job", "Pod"]:
            try:
                ai_report = await ai_advisor.audit_manifest(object_spec)
                containers = pod_spec_obj.get("containers", [])
                for patch_dict in guard_ai_patches(ai_report.suggested_patches, pod_spec_path, containers):
                    if patch_dict not in patches:
                        patches.append(patch_dict)
            except Exception as e:
                logger.warning(f"AI mutation enrichment error: {e}")

    response: Dict[str, Any] = {"uid": uid, "allowed": True}

    if patches:
        patch_json = json.dumps(patches)
        patch_base64 = base64.b64encode(patch_json.encode("utf-8")).decode("utf-8")
        response["patchType"] = "JSONPatch"
        response["patch"] = patch_base64
        AUDIT_REQUESTS.labels(endpoint="mutate", status="mutated").inc()
    else:
        AUDIT_REQUESTS.labels(endpoint="mutate", status="unmodified").inc()

    ADMISSION_DURATION.labels(webhook_type="mutate").observe(time.time() - start_time)
    return JSONResponse(content={
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": response
    })

# Register commercial billing routes
app.include_router(billing_router)



