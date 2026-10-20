"""Repository scanner: finds Kubernetes YAML and Helm charts, runs rules, maps findings to lines."""
from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

from app.rules import RULES, Finding, check_object, severity_at_least

YAML_SUFFIXES = {".yaml", ".yml"}
_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)  # C parser when available (much faster)
MAX_FILE_BYTES = 5 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".terraform", "vendor"}
CONFIG_NAMES = (".kubeaudit.yaml", ".kubeaudit.yml")


@dataclass
class Config:
    ignore: List[str] = field(default_factory=list)       # rule ids or names
    exclude: List[str] = field(default_factory=list)      # glob patterns (relative paths)
    fail_on: str = "high"                                  # critical|high|medium|low|none
    min_severity: str = "low"                              # hide findings below this
    helm_values: Dict[str, List[str]] = field(default_factory=dict)  # chart dir -> values files

    @classmethod
    def load(cls, root: Path, explicit: Optional[str] = None) -> "Config":
        path = Path(explicit) if explicit else next((root / n for n in CONFIG_NAMES if (root / n).is_file()), None)
        if not path or not path.is_file():
            return cls()
        data = yaml.safe_load(path.read_text()) or {}
        helm = data.get("helm") or {}
        values = {k: (v if isinstance(v, list) else [v]) for k, v in (helm.get("values") or {}).items()}
        return cls(
            ignore=[str(x).upper() for x in data.get("ignore") or []],
            exclude=[str(x) for x in data.get("exclude") or []],
            fail_on=str(data.get("fail_on", data.get("fail-on", "high"))).lower(),
            min_severity=str(data.get("min_severity", data.get("min-severity", "low"))).lower(),
            helm_values=values,
        )


@dataclass
class Located:
    finding: Finding
    file: str          # path relative to root, POSIX style
    line: int
    rendered_from_helm: bool = False


@dataclass
class ScanResult:
    findings: List[Located]
    files_scanned: int
    resources_scanned: int
    warnings: List[str]

    def counts(self) -> Dict[str, int]:
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            c[f.finding.severity] += 1
        return c

    def failed(self, fail_on: str) -> bool:
        if fail_on == "none":
            return False
        return any(severity_at_least(f.finding.severity, fail_on) for f in self.findings)


# ---------------------------------------------------------------- line mapping

def _line_for(node: Optional[yaml.Node], path: Tuple[Any, ...]) -> int:
    """Return the 1-based line of the deepest node along ``path`` that exists."""
    if node is None:
        return 1
    best = node.start_mark.line + 1
    for part in path:
        nxt = None
        if isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                if isinstance(k, yaml.ScalarNode) and k.value == part:
                    nxt, best = v, k.start_mark.line + 1
                    break
        elif isinstance(node, yaml.SequenceNode) and isinstance(part, int) and part < len(node.value):
            nxt = node.value[part]
            best = nxt.start_mark.line + 1
        if nxt is None:
            break
        node = nxt
    return best


def _parse(text: str) -> List[Tuple[Dict[str, Any], Optional[yaml.Node], Tuple[Any, ...]]]:
    """Parse multi-doc YAML into (object, node, path-prefix) triples, unwrapping `kind: List`."""
    nodes = list(yaml.compose_all(text, Loader=_Loader))
    docs = list(yaml.load_all(text, Loader=_Loader))
    out = []
    for node, doc in zip(nodes, docs):
        if not isinstance(doc, dict):
            continue
        if doc.get("kind") == "List" and isinstance(doc.get("items"), list):
            for i, item in enumerate(doc["items"]):
                if isinstance(item, dict) and item.get("kind"):
                    out.append((item, node, ("items", i)))
        elif doc.get("apiVersion") and doc.get("kind"):
            out.append((doc, node, ()))
    return out


# ---------------------------------------------------------------- discovery

def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _excluded(rel: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/") + "/*") for p in patterns)


def _owning_chart(p: Path, root: Path) -> Optional[Path]:
    """Return the Helm chart directory that contains ``p``, if any (stops at ``root``)."""
    root = root.resolve()
    for d in [p.resolve().parent, *p.resolve().parent.parents]:
        if (d / "Chart.yaml").is_file():
            return d
        if d == root or root not in d.parents:
            break
    return None


def discover(paths: List[str], root: Path, cfg: Config,
             warnings: Optional[List[str]] = None) -> Tuple[List[Path], List[Path]]:
    """Return (plain YAML files, Helm chart directories)."""
    files: List[Path] = []
    charts: List[Path] = []
    for raw in paths:
        p = Path(raw)
        if not p.is_absolute():
            p = root / p
        if p.is_file():
            chart = _owning_chart(p, root)
            if chart is not None:
                charts.append(chart)
            elif p.suffix in YAML_SUFFIXES:
                files.append(p)
            continue
        if not p.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(p):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            d = Path(dirpath)
            if "Chart.yaml" in filenames:
                charts.append(d)
                dirnames[:] = []  # chart contents are covered by rendering
                continue
            files.extend(d / f for f in sorted(filenames) if Path(f).suffix in YAML_SUFFIXES)

    def keep(x: Path) -> bool:
        return not _excluded(_rel(x, root), cfg.exclude)

    if warnings is not None:
        for raw in paths:
            p = Path(raw) if Path(raw).is_absolute() else root / raw
            if p.exists() and not keep(p):
                warnings.append(f"{_rel(p, root)}: excluded by the `exclude` setting in your config, not scanned")

    # drop raw files that live inside a chart dir we will render
    chart_set = [c.resolve() for c in charts]
    files = [f for f in files if keep(f) and not any(c in f.resolve().parents for c in chart_set)]
    seen, uniq = set(), []
    for c in charts:
        if keep(c) and c.resolve() not in seen:
            seen.add(c.resolve())
            uniq.append(c)
    return sorted(set(files)), uniq


# ---------------------------------------------------------------- scanning

def _apply(obj_findings: List[Finding], cfg: Config) -> List[Finding]:
    return [f for f in obj_findings
            if f.rule.id not in cfg.ignore and f.rule.name.upper() not in cfg.ignore
            and severity_at_least(f.rule.severity, cfg.min_severity)]


def scan_text(text: str, rel: str, cfg: Config) -> Tuple[List[Located], int]:
    located, count = [], 0
    for obj, node, prefix in _parse(text):
        count += 1
        for f in _apply(check_object(obj), cfg):
            located.append(Located(f, rel, _line_for(node, prefix + tuple(f.path))))
    return located, count


def render_chart(chart: Path, values: List[str]) -> Tuple[Optional[str], Optional[str]]:
    helm = shutil.which("helm")
    if not helm:
        return None, "helm not found on PATH"
    cmd = [helm, "template", "kubeaudit-scan", str(chart)]
    for v in values:
        cmd += ["-f", str(chart / v) if not Path(v).is_absolute() else v]
    try:
        if (chart / "Chart.lock").exists() or "dependencies:" in (chart / "Chart.yaml").read_text():
            subprocess.run([helm, "dependency", "build", str(chart)], capture_output=True, timeout=120)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, str(e)
    if proc.returncode != 0:
        return None, (proc.stderr or proc.stdout).strip().splitlines()[-1] if (proc.stderr or proc.stdout) else "helm template failed"
    return proc.stdout, None


def _split_helm(output: str) -> List[Tuple[str, str]]:
    """Split `helm template` output into (source template path, yaml text) chunks."""
    chunks, source, buf = [], None, []
    for line in output.splitlines(keepends=True):
        if line.startswith("---"):
            if buf:
                chunks.append((source, "".join(buf)))
            source, buf = None, []
            continue
        if line.startswith("# Source: "):
            source = line[len("# Source: "):].strip()
        buf.append(line)
    if buf:
        chunks.append((source, "".join(buf)))
    return [(s, t) for s, t in chunks if s]


def scan(paths: List[str], root: Path, cfg: Config) -> ScanResult:
    findings: List[Located] = []
    warnings: List[str] = []
    files, charts = discover(paths or ["."], root, cfg, warnings)
    resources = 0

    for f in files:
        rel = _rel(f, root)
        try:
            if f.stat().st_size > MAX_FILE_BYTES:
                warnings.append(f"{rel}: larger than 5 MB, skipped")
                continue
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            warnings.append(f"{rel}: could not read ({e})")
            continue
        if "{{" in text:
            continue  # unrendered template outside a chart; nothing reliable to check
        try:
            located, n = scan_text(text, rel, cfg)
        except yaml.YAMLError as e:
            mark = getattr(e, "problem_mark", None)
            warnings.append(f"{rel}:{mark.line + 1 if mark else 1}: invalid YAML, skipped")
            continue
        findings += located
        resources += n

    for chart in charts:
        rel_chart = _rel(chart, root)
        values = cfg.helm_values.get(rel_chart, [])
        out, err = render_chart(chart, values)
        if err:
            warnings.append(f"{rel_chart}: Helm chart not rendered ({err})")
            continue
        for source, text in _split_helm(out):
            # "<chart-name>/templates/x.yaml" -> "<chart dir>/templates/x.yaml"
            sub = source.split("/", 1)[1] if "/" in source else source
            rel = f"{rel_chart}/{sub}" if rel_chart not in ("", ".") else sub
            try:
                located, n = scan_text(text, rel, cfg)
            except yaml.YAMLError:
                warnings.append(f"{rel}: rendered output is not valid YAML, skipped")
                continue
            for loc in located:
                loc.line = 1  # rendered output lines don't map to the template source
                loc.rendered_from_helm = True
            findings += located
            resources += n

    findings.sort(key=lambda x: (-_sev(x), x.file, x.line, x.finding.rule.id))
    return ScanResult(findings, len(files) + len(charts), resources, warnings)


def _sev(x: Located) -> int:
    from app.rules import SEVERITY_ORDER
    return SEVERITY_ORDER[x.finding.severity]


__all__ = ["Config", "Located", "ScanResult", "scan", "scan_text", "discover", "RULES"]
