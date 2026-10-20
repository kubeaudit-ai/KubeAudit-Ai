"""Output formats for scan results: text, json, sarif, markdown."""
from __future__ import annotations

import json
from collections import OrderedDict
from typing import Dict, List, Optional

from app.rules import RULES, Rule
from app.scanner import Located, ScanResult

try:
    from importlib.metadata import version as _pkg_version
    TOOL_VERSION = _pkg_version("kubeaudit-ai")
except Exception:  # pragma: no cover - not installed
    TOOL_VERSION = "0.0.0"

COMMENT_MARKER = "<!-- kubeaudit-ai-report -->"
SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "2.0"}


def _loc(x: Located) -> str:
    return f"{x.file}:{x.line}" if not x.rendered_from_helm else f"{x.file} (rendered)"


# ---------------------------------------------------------------- text

def to_text(result: ScanResult, color: bool = False) -> str:
    c = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[2m", "end": "\033[0m"}
    if not color:
        c = {k: "" for k in c}
    lines: List[str] = []
    for x in result.findings:
        f = x.finding
        sev = f.severity
        lines.append(f"{c[sev]}{SEV_LABEL[sev].upper():8}{c['end']} {f.rule.id} {_loc(x)}  {f.message}")
        lines.append(f"         fix: {f.rule.remediation}")
    for w in result.warnings:
        lines.append(f"WARNING  {w}")
    counts = result.counts()
    summary = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low"))
    lines.append("")
    lines.append(f"Scanned {result.resources_scanned} resources in {result.files_scanned} files/charts: "
                 f"{len(result.findings)} findings ({summary}).")
    return "\n".join(lines)


# ---------------------------------------------------------------- json

def to_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": {"name": "kubeaudit-ai", "version": TOOL_VERSION},
        "summary": {"files": result.files_scanned, "resources": result.resources_scanned,
                    "findings": len(result.findings), **result.counts()},
        "findings": [{
            "rule_id": x.finding.rule.id,
            "rule": x.finding.rule.name,
            "severity": x.finding.severity,
            "title": x.finding.rule.title,
            "message": x.finding.message,
            "resource": x.finding.resource,
            "container": x.finding.container,
            "file": x.file,
            "line": x.line,
            "rendered_from_helm": x.rendered_from_helm,
            "remediation": x.finding.rule.remediation,
            "fix": x.finding.rule.fix,
        } for x in result.findings],
        "warnings": result.warnings,
    }, indent=2)


# ---------------------------------------------------------------- sarif

def _sarif_rule(r: Rule) -> Dict:
    return {
        "id": r.id,
        "name": r.name,
        "shortDescription": {"text": r.title},
        "fullDescription": {"text": r.remediation},
        "helpUri": r.docs,
        "help": {"text": f"{r.remediation}\n\n{r.fix}",
                 "markdown": f"{r.remediation}\n\n```yaml\n{r.fix}\n```"},
        "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
        "properties": {"security-severity": SECURITY_SEVERITY[r.severity],
                       "tags": ["security", "kubernetes"], "precision": "high"},
    }


def to_sarif(result: ScanResult) -> str:
    rules = list(RULES.values())
    index = {r.id: i for i, r in enumerate(rules)}
    results = []
    for x in result.findings:
        f = x.finding
        results.append({
            "ruleId": f.rule.id,
            "ruleIndex": index[f.rule.id],
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": x.file, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, x.line)},
            }}],
            "partialFingerprints": {"kubeauditResource/v1": f"{f.rule.id}:{x.file}:{f.resource}:{f.container or ''}"},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "KubeAudit AI",
                "informationUri": "https://github.com/msharsha565-create/KubeAudit-Ai",
                "semanticVersion": TOOL_VERSION,
                "rules": [_sarif_rule(r) for r in rules],
            }},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
            "results": results,
        }],
    }, indent=2)


# ---------------------------------------------------------------- markdown (PR comment)

def to_markdown(result: ScanResult, link_base: Optional[str] = None, fail_on: str = "high",
                max_findings: int = 50) -> str:
    counts = result.counts()
    failed = result.failed(fail_on)
    out = [COMMENT_MARKER, "## 🛡️ KubeAudit AI"]
    if not result.findings:
        out.append(f"✅ No issues found in {result.resources_scanned} Kubernetes resources.")
    else:
        status = "❌ **Blocking issues found**" if failed else "⚠️ Issues found (not blocking)"
        out.append(f"{status} — {len(result.findings)} findings in {result.resources_scanned} resources.\n")
        out.append("| Severity | Count |\n|---|---:|")
        for s in ("critical", "high", "medium", "low"):
            if counts[s]:
                out.append(f"| {SEV_ICON[s]} {SEV_LABEL[s]} | {counts[s]} |")
        out.append("")

        by_file: "OrderedDict[str, List[Located]]" = OrderedDict()
        for x in result.findings[:max_findings]:
            by_file.setdefault(x.file, []).append(x)
        for file, items in by_file.items():
            out.append(f"### `{file}`")
            for x in items:
                f = x.finding
                where = f"line {x.line}" if not x.rendered_from_helm else "Helm template"
                if link_base and not x.rendered_from_helm:
                    where = f"[{where}]({link_base.rstrip('/')}/{x.file}#L{x.line})"
                out.append(f"- {SEV_ICON[f.severity]} **{f.rule.id} · {f.rule.title}** ({where})  \n"
                           f"  {f.message}")
                out.append(f"  <details><summary>How to fix</summary>\n\n  {f.rule.remediation}\n\n"
                           f"  ```yaml\n" + "\n".join("  " + ln for ln in f.rule.fix.splitlines()) +
                           "\n  ```\n  </details>")
            out.append("")
        if len(result.findings) > max_findings:
            out.append(f"_…and {len(result.findings) - max_findings} more. "
                       f"See the full list in the Security tab or the job log._\n")
    if result.warnings:
        out.append("<details><summary>Warnings</summary>\n")
        out.extend(f"- {w}" for w in result.warnings[:20])
        out.append("\n</details>")
    out.append("\n<sub>Silence a rule on one resource with the annotation "
               "`kubeaudit.ai/ignore: \"KA010\"`, or repo-wide in `.kubeaudit.yaml`.</sub>")
    return "\n".join(out)


FORMATS = {"text": to_text, "json": to_json, "sarif": to_sarif, "markdown": to_markdown}
