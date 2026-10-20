"""Check fixer output: auto-fixable findings gone, everything else unchanged, YAML still valid."""
import copy
import json
import sys
from pathlib import Path

import yaml

before = json.load(open(sys.argv[1])); after = json.load(open(sys.argv[2]))
src, fixed = Path(sys.argv[3]), Path(sys.argv[4])
AUTO = {"KA001", "KA002", "KA003", "KA010", "KA011", "KA012", "KA013", "KA015"}
POD = {"Pod": ["spec"], "Deployment": ["spec", "template", "spec"], "StatefulSet": ["spec", "template", "spec"],
       "DaemonSet": ["spec", "template", "spec"], "ReplicaSet": ["spec", "template", "spec"],
       "ReplicationController": ["spec", "template", "spec"], "Job": ["spec", "template", "spec"],
       "CronJob": ["spec", "jobTemplate", "spec", "template", "spec"]}


def strip(obj):
    """Remove only the fields the fixer is allowed to change."""
    if not isinstance(obj, dict):
        return obj
    targets = obj.get("items") if obj.get("kind") == "List" and isinstance(obj.get("items"), list) else [obj]
    for o in targets:
        if not isinstance(o, dict) or o.get("kind") not in POD:
            continue
        node = o
        for p in POD[o["kind"]]:
            node = node.get(p) if isinstance(node, dict) else None
        if not isinstance(node, dict):
            continue
        node.pop("automountServiceAccountToken", None)
        node.pop("securityContext", None)
        for g in ("initContainers", "containers", "ephemeralContainers"):
            for c in node.get(g) or []:
                if isinstance(c, dict):
                    c.pop("securityContext", None)
                    c.pop("resources", None)
    return obj


left, invalid, changed_manual, changed_other = {}, 0, [], []
for f, a in after.items():
    if a.get("error"):
        invalid += 1
        print("NOW INVALID:", f)
        continue
    b = before[f]
    for x in a["findings"]:
        if x[0] in AUTO:
            left[x[0]] = left.get(x[0], 0) + 1
    bm = sorted((x[0], x[2], x[3]) for x in b["findings"] if x[0] not in AUTO)
    am = sorted((x[0], x[2], x[3]) for x in a["findings"] if x[0] not in AUTO)
    if bm != am:
        changed_manual.append(f)
    s1 = [strip(copy.deepcopy(d)) for d in yaml.safe_load_all((src / f).read_text())]
    s2 = [strip(copy.deepcopy(d)) for d in yaml.safe_load_all((fixed / f).read_text())]
    if s1 != s2:
        changed_other.append(f)
tb = sum(len(before[f]["findings"]) for f in after)
ta = sum(len(v["findings"]) for v in after.values() if not v.get("error"))
print(f"files: {len(after)} | findings before: {tb} -> after: {ta}")
print(f"auto-fixable findings left: {left or 0}")
print(f"invalid YAML after fix: {invalid} | manual findings changed: {len(changed_manual)} | other fields changed: {len(changed_other)}")
for f in (changed_manual + changed_other)[:8]:
    print("  ", f)
sys.exit(1 if (left or invalid or changed_manual or changed_other) else 0)
