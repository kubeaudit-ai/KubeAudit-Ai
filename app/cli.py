import argparse
import sys
from pathlib import Path
import yaml
import json
import urllib.request
import urllib.error

from app.policy_engine import policy_engine


def remediate_document(doc: dict, all_fixes: list = None):
    """Remediates common security issues in-place in a manifest dictionary."""
    if all_fixes is None:
        all_fixes = []

    kind = doc.get("kind", "")
    spec = doc.get("spec", {})

    pod_spec = None
    if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
        pod_spec = spec.setdefault("template", {}).setdefault("spec", {})
    elif kind == "Pod":
        pod_spec = spec

    if pod_spec is not None:
        # Enforce runAsNonRoot
        sec_ctx = pod_spec.setdefault("securityContext", {})
        if not sec_ctx.get("runAsNonRoot"):
            sec_ctx["runAsNonRoot"] = True
            all_fixes.append("Set spec.securityContext.runAsNonRoot: true")

        # Container fixes
        for c in pod_spec.get("containers", []):
            name = c.get("name", "container")
            c_sec = c.setdefault("securityContext", {})
            if c_sec.get("privileged"):
                c_sec["privileged"] = False
                all_fixes.append(f"Set container '{name}' securityContext.privileged: false")
            if not c_sec.get("readOnlyRootFilesystem"):
                c_sec["readOnlyRootFilesystem"] = True
                all_fixes.append(f"Set container '{name}' securityContext.readOnlyRootFilesystem: true")
            if c_sec.get("allowPrivilegeEscalation") is not False:
                c_sec["allowPrivilegeEscalation"] = False
                all_fixes.append(f"Set container '{name}' securityContext.allowPrivilegeEscalation: false")

            # Images are never rewritten (the right version can't be guessed);
            # `kubeaudit scan` reports unpinned images for a human to pin.

            # Limits / requests
            res = c.setdefault("resources", {})
            limits = res.setdefault("limits", {})
            if "cpu" not in limits:
                limits["cpu"] = "500m"
                all_fixes.append(f"Set resources.limits.cpu for '{name}'")
            if "memory" not in limits:
                limits["memory"] = "512Mi"
                all_fixes.append(f"Set resources.limits.memory for '{name}'")
    return doc


def load_manifests(file_path: str):
    """Load YAML manifests from a file or stdin, unwrapping List kinds."""
    if file_path == "-":
        raw = sys.stdin.read()
    else:
        p = Path(file_path)
        if not p.is_file():
            print(f"Error: File '{file_path}' not found.", file=sys.stderr)
            sys.exit(1)
        raw = p.read_text()

    docs = []
    for doc in yaml.safe_load_all(raw):
        if not doc or not isinstance(doc, dict):
            continue
        if doc.get("kind") == "List" and "items" in doc:
            docs.extend([item for item in doc["items"] if isinstance(item, dict)])
        else:
            docs.append(doc)
    return docs


def audit_file(file_path: str, exit_on_fail: bool = True):
    documents = load_manifests(file_path)
    valid_docs = [d for d in documents if isinstance(d, dict)]
    total_violations = []

    for doc in valid_docs:
        kind = doc.get("kind", "Unknown")
        name = doc.get("metadata", {}).get("name", "unnamed")
        namespace = doc.get("metadata", {}).get("namespace", "default")
        issues = policy_engine.evaluate(doc)
        if issues:
            print(f"\\n[FAILED] {kind}/{name} (namespace: {namespace}) in {file_path}:")
            for issue in issues:
                rule = issue.get("rule", "PolicyViolation")
                severity = issue.get("severity", "Medium")
                message = issue.get("message", "Violation detected")
                fix = issue.get("remediation")
                print(f"  - [{severity}] {rule}: {message}")
                if fix:
                    print(f"    Fix: {fix}")
            total_violations.extend(issues)
        else:
            print(f"[PASSED] {kind}/{name} (namespace: {namespace})")

    if total_violations and exit_on_fail:
        print(f"\\nTotal security policy violations: {len(total_violations)}")
        sys.exit(1)
    elif not total_violations:
        print(f"\\nAll manifests in {file_path} conform to security policies.")
    return 0


def audit_remote(file_path: str, host: str, api_key: str):
    import requests
    docs = load_manifests(file_path)
    valid_docs = [d for d in docs if isinstance(d, dict)]
    total_violations = 0

    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    base_url = host.rstrip("/")

    for doc in valid_docs:
        kind = doc.get("kind", "Unknown")
        name = doc.get("metadata", {}).get("name", "unnamed")
        namespace = doc.get("metadata", {}).get("namespace", "default")

        manifest_str = yaml.dump(doc)
        resp = requests.post(
            f"{base_url}/audit",
            headers=headers,
            json={"manifest": manifest_str}
        )

        if resp.status_code == 429:
            print(f"\\n[QUOTA EXCEEDED] {resp.json().get('detail')}")
            sys.exit(1)
        elif resp.status_code != 200:
            print(f"\\n[ERROR {resp.status_code}] {resp.text}")
            sys.exit(1)

        data = resp.json()
        issues = data.get("issues", [])
        if issues:
            print(f"\\n[FAILED] {kind}/{name} (namespace: {namespace}) [SaaS Audit]:")
            for issue in issues:
                rule = issue.get("rule", "PolicyViolation")
                severity = issue.get("severity", "Medium")
                message = issue.get("message", "Violation detected")
                print(f"  - [{severity}] {rule}: {message}")
            total_violations += len(issues)
        else:
            print(f"[PASSED] {kind}/{name} (namespace: {namespace}) [SaaS Audit]")

    if total_violations:
        print(f"\\nTotal security policy violations: {total_violations}")
        sys.exit(1)
    else:
        print("\\nAll manifests conform to security policies.")
    return 0


def fix_file(file_path: str):
    path = Path(file_path)
    if not path.is_file():
        print(f"Error: File '{file_path}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(path, "r") as f:
        documents = list(yaml.safe_load_all(f.read()))

    valid_docs = [d for d in documents if isinstance(d, dict)]
    all_fixes = []

    for doc in valid_docs:
        remediate_document(doc, all_fixes)

    with open(path, "w") as f:
        yaml.dump_all(valid_docs, f, sort_keys=False)

    print(f"Successfully remediated {file_path}:")
    for fix in all_fixes:
        print(f"  - {fix}")
    return 0


def run_advise(args):
    path = Path(args.manifest)
    if not path.is_file():
        print(f"Error: File '{args.manifest}' not found.", file=sys.stderr)
        sys.exit(1)

    manifest_yaml = path.read_text()
    url = f"{args.host.rstrip('/')}/advise"
    req = urllib.request.Request(
        url,
        data=json.dumps({"manifest": manifest_yaml}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"Advice from {data.get('source', 'engine')}:")
            print(data.get("advice", data.get("remediation", "")))
            return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def run_scan(args) -> int:
    from app.scanner import Config, scan
    from app import reporters

    root = Path(args.root).resolve()
    cfg = Config.load(root, args.config)
    if args.fail_on:
        cfg.fail_on = args.fail_on
    if args.min_severity:
        cfg.min_severity = args.min_severity
    if args.ignore:
        cfg.ignore += [r.strip().upper() for r in args.ignore.split(",") if r.strip()]

    paths = list(args.paths)
    if args.files_from:
        src = sys.stdin if args.files_from == "-" else open(args.files_from)
        with src:
            paths += [ln.strip() for ln in src if ln.strip()]
    if args.files_from and not paths:
        from app.scanner import ScanResult
        print("No files to scan.")
        result = ScanResult([], 0, 0, [])
    else:
        result = scan(paths or ["."], root, cfg)

    def render(fmt: str) -> str:
        if fmt == "markdown":
            return reporters.to_markdown(result, link_base=args.link_base, fail_on=cfg.fail_on)
        if fmt == "text":
            return reporters.to_text(result, color=sys.stdout.isatty() and not args.output)
        return reporters.FORMATS[fmt](result)

    text = render(args.format)
    if args.files_from and not paths:
        text = ""
    if args.output:
        Path(args.output).write_text(text + "\n")
    elif text:
        print(text)
    for fmt, dest in (("sarif", args.sarif), ("markdown", args.markdown), ("json", args.json)):
        if dest:
            Path(dest).write_text(render(fmt) + "\n")

    if result.failed(cfg.fail_on):
        if args.format == "text" and not args.output:
            print(f"\nFailing: found issues at or above '{cfg.fail_on}' severity.")
        return 1
    return 0


def run_rules(args) -> int:
    from app.rules import RULES
    for r in RULES.values():
        print(f"{r.id}  {r.severity.upper():8} {r.name:30} {r.title}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="kubeaudit",
        description="KubeAudit AI manifest security scanner and auto-fixer"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser("audit", help="Audit Kubernetes YAML manifests against security policies")
    audit_parser.add_argument("file", help="Path to Kubernetes YAML manifest or '-' for stdin")
    audit_parser.add_argument("--key", help="KubeAudit SaaS API Key (X-API-Key)", default=None)
    audit_parser.add_argument("--host", help="KubeAudit SaaS Host URL", default="http://127.0.0.1:8000")

    fix_parser = subparsers.add_parser("fix", help="Auto-remediate Kubernetes YAML manifests in place")
    fix_parser.add_argument("file", help="Path to Kubernetes YAML manifest")

    p_advise = subparsers.add_parser("advise", help="AI-assisted remediation advice")
    p_advise.add_argument("manifest", help="Path to Kubernetes YAML manifest file")
    p_advise.add_argument("--host", default="https://kubeaudit-ai-production.up.railway.app", help="KubeAudit API base URL")
    p_advise.set_defaults(func=run_advise)

    p_scan = subparsers.add_parser("scan", help="Scan files, directories and Helm charts offline (no server needed)")
    p_scan.add_argument("paths", nargs="*", help="Files or directories to scan (default: current directory)")
    p_scan.add_argument("--format", "-f", choices=["text", "json", "sarif", "markdown"], default="text")
    p_scan.add_argument("--output", "-o", help="Write the main report to this file instead of stdout")
    p_scan.add_argument("--sarif", help="Also write a SARIF report to this path")
    p_scan.add_argument("--markdown", help="Also write a Markdown (PR comment) report to this path")
    p_scan.add_argument("--json", help="Also write a JSON report to this path")
    p_scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                        help="Exit 1 when a finding at or above this severity exists (default: high)")
    p_scan.add_argument("--min-severity", choices=["critical", "high", "medium", "low"],
                        help="Hide findings below this severity (default: low)")
    p_scan.add_argument("--ignore", help="Comma-separated rule IDs or names to skip")
    p_scan.add_argument("--config", help="Path to config file (default: .kubeaudit.yaml in --root)")
    p_scan.add_argument("--root", default=".", help="Repository root; report paths are relative to it")
    p_scan.add_argument("--files-from", help="Read extra paths (one per line) from this file, or '-' for stdin")
    p_scan.add_argument("--link-base", help="URL prefix for file links in Markdown, e.g. https://github.com/o/r/blob/<sha>")
    p_scan.set_defaults(func=run_scan)

    p_rules = subparsers.add_parser("rules", help="List all rules")
    p_rules.set_defaults(func=run_rules)

    args = parser.parse_args(argv)
    if hasattr(args, "func"):
        res = args.func(args)
        return res if res is not None else 0
    if args.command == "audit":
        if getattr(args, "key", None):
            res = audit_remote(args.file, args.host, args.key)
            return res if res is not None else 0
        res = audit_file(args.file)
        return res if res is not None else 0
    elif args.command == "fix":
        res = fix_file(args.file)
        return res if res is not None else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
