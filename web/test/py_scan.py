"""Scan YAML files with the Python engine and print per-file results as JSON (parity reference)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import yaml  # noqa: E402
from app.scanner import Config, scan_text  # noqa: E402

root = Path(sys.argv[1]).resolve()
out = {}
for f in sorted(root.rglob("*")):
    if f.suffix not in (".yaml", ".yml") or not f.is_file() or ".git" in f.parts:
        continue
    rel = f.relative_to(root).as_posix()
    try:
        text = f.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        continue
    if "{{" in text:
        continue
    try:
        located, n = scan_text(text, rel, Config())
    except yaml.YAMLError:
        out[rel] = {"error": True}
        continue
    except Exception as e:  # keep going; record the crash
        out[rel] = {"error": True, "crash": repr(e)}
        continue
    out[rel] = {"resources": n, "findings": sorted(
        [x.finding.rule.id, x.line, x.finding.resource, x.finding.container, x.finding.message] for x in located)}
json.dump(out, sys.stdout)
