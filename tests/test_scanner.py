import json
import os
import stat
import textwrap
from pathlib import Path

import pytest

from app import reporters
from app.cli import main as cli_main
from app.rules import RULES, check_object, image_is_pinned
from app.scanner import Config, scan, scan_text

FIXTURE = Path(__file__).parent / "fixtures" / "repo"


def ids(findings):
    return {f.rule.id for f in findings}


@pytest.mark.parametrize("image,pinned", [
    ("nginx", False),
    ("nginx:latest", False),
    ("nginx:1.27", True),
    ("registry.local:5000/team/api", False),
    ("registry.local:5000/team/api:2.1.0", True),
    ("ghcr.io/a/b@sha256:abc", True),
    ("", False),
])
def test_image_pinning(image, pinned):
    assert image_is_pinned(image) is pinned


def test_insecure_fixture_hits_expected_rules():
    cfg = Config.load(FIXTURE)
    result = scan(["k8s/insecure.yaml"], FIXTURE, cfg)
    got = {x.finding.rule.id for x in result.findings}
    for rid in ("KA001", "KA002", "KA003", "KA004", "KA005", "KA006", "KA007", "KA008", "KA009"):
        assert rid in got, rid
    assert "KA015" not in got  # ignored in .kubeaudit.yaml
    assert result.failed("high")


def test_line_numbers_point_at_the_field():
    cfg = Config()
    result = scan(["k8s/insecure.yaml"], FIXTURE, cfg)
    lines = {x.finding.rule.id: x.line for x in result.findings
             if x.finding.resource in ("Deployment/api", "ClusterRole/god-mode")}
    assert lines["KA004"] == 9    # hostNetwork: true
    assert lines["KA005"] == 12   # hostPath:
    assert lines["KA007"] == 19   # value: hunter2
    assert lines["KA001"] == 21   # privileged: true
    assert lines["KA009"] == 16   # image:
    assert lines["KA008"] == 30   # first rule item


def test_cronjob_containers_are_checked():
    cfg = Config()
    result = scan(["k8s/insecure.yaml"], FIXTURE, cfg)
    assert any(x.finding.resource == "CronJob/nightly" and x.finding.rule.id == "KA009" for x in result.findings)


def test_secure_fixture_is_clean_and_non_k8s_yaml_is_ignored():
    result = scan(["k8s/secure.yaml", "k8s/not-k8s.yaml"], FIXTURE, Config())
    assert result.findings == []
    assert result.resources_scanned == 2  # Deployment + ConfigMap; compose-style file skipped


def test_exclude_patterns_and_directory_walk():
    cfg = Config.load(FIXTURE)
    result = scan(["k8s"], FIXTURE, cfg)
    assert not any(x.file.startswith("k8s/ignored/") for x in result.findings)


def test_annotation_suppression():
    obj = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "p", "annotations": {"kubeaudit.ai/ignore": "KA001, ReadOnlyRootFilesystem"}},
        "spec": {"containers": [{"name": "c", "image": "x:1", "securityContext": {"privileged": True}}]},
    }
    got = ids(check_object(obj))
    assert "KA001" not in got and "KA010" not in got and "KA002" in got
    obj["metadata"]["annotations"]["kubeaudit.ai/ignore"] = "all"
    assert check_object(obj) == []


def test_pod_level_non_root_satisfies_containers_unless_overridden():
    base = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p"},
            "spec": {"securityContext": {"runAsNonRoot": True},
                     "containers": [{"name": "a", "image": "a:1"},
                                    {"name": "b", "image": "b:1", "securityContext": {"runAsUser": 0}}]}}
    root = [f for f in check_object(base) if f.rule.id == "KA003"]
    assert [f.container for f in root] == ["b"]


def test_list_kind_is_unwrapped():
    text = textwrap.dedent("""\
        apiVersion: v1
        kind: List
        items:
          - apiVersion: v1
            kind: Pod
            metadata: {name: p}
            spec:
              containers:
                - name: c
                  image: c
                  securityContext: {privileged: true}
        """)
    located, n = scan_text(text, "list.yaml", Config())
    assert n == 1
    priv = [x for x in located if x.finding.rule.id == "KA001"]
    assert priv and priv[0].line == 11


def test_invalid_yaml_becomes_warning(tmp_path):
    (tmp_path / "bad.yaml").write_text("apiVersion: v1\nkind: Pod\n  bad: [indent\n")
    result = scan(["."], tmp_path, Config())
    assert result.findings == [] and any("invalid YAML" in w for w in result.warnings)


def test_sarif_is_well_formed():
    result = scan(["k8s/insecure.yaml"], FIXTURE, Config())
    sarif = json.loads(reporters.to_sarif(result))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert len(run["tool"]["driver"]["rules"]) == len(RULES)
    r0 = run["results"][0]
    assert r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "k8s/insecure.yaml"
    assert r0["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert all(rule_ids[r["ruleIndex"]] == r["ruleId"] for r in run["results"])


def test_markdown_has_marker_links_and_summary():
    result = scan(["k8s/insecure.yaml"], FIXTURE, Config())
    md = reporters.to_markdown(result, link_base="https://github.com/o/r/blob/abc")
    assert md.startswith(reporters.COMMENT_MARKER)
    assert "Blocking issues found" in md
    assert "https://github.com/o/r/blob/abc/k8s/insecure.yaml#L21" in md
    clean = reporters.to_markdown(scan(["k8s/secure.yaml"], FIXTURE, Config()))
    assert "No issues found" in clean


def test_cli_exit_codes_and_outputs(tmp_path, capsys):
    sarif = tmp_path / "out.sarif"
    md = tmp_path / "out.md"
    code = cli_main(["scan", "k8s/insecure.yaml", "--root", str(FIXTURE), "--sarif", str(sarif), "--markdown", str(md)])
    assert code == 1
    assert json.loads(sarif.read_text())["runs"][0]["results"]
    assert md.read_text().startswith(reporters.COMMENT_MARKER)
    assert cli_main(["scan", "k8s/insecure.yaml", "--root", str(FIXTURE), "--fail-on", "none"]) == 0
    assert cli_main(["scan", "k8s/secure.yaml", "--root", str(FIXTURE)]) == 0
    capsys.readouterr()


def test_cli_files_from_empty_list_is_success(tmp_path, capsys):
    empty = tmp_path / "files.txt"
    empty.write_text("")
    js = tmp_path / "r.json"
    assert cli_main(["scan", "--root", str(FIXTURE), "--files-from", str(empty), "--json", str(js)]) == 0
    assert "No files to scan" in capsys.readouterr().out
    assert json.loads(js.read_text())["summary"]["findings"] == 0


@pytest.fixture
def fake_helm(tmp_path, monkeypatch):
    """A stand-in `helm` binary that emits rendered output the way `helm template` does."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "helm"
    script.write_text(textwrap.dedent("""\
        #!/bin/sh
        if [ "$1" = "dependency" ]; then exit 0; fi
        cat <<'YAML'
        ---
        # Source: web/templates/deployment.yaml
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: kubeaudit-scan-web
        spec:
          template:
            spec:
              containers:
                - name: web
                  image: "nginx:latest"
        YAML
        """))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")


def test_helm_chart_rendering_maps_to_template(fake_helm):
    result = scan(["charts"], FIXTURE, Config())
    files = {x.file for x in result.findings}
    assert files == {"charts/web/templates/deployment.yaml"}
    assert all(x.rendered_from_helm for x in result.findings)
    assert "KA009" in {x.finding.rule.id for x in result.findings}


def test_changed_template_file_scans_its_chart(fake_helm):
    result = scan(["charts/web/templates/deployment.yaml"], FIXTURE, Config())
    assert result.findings and result.findings[0].file == "charts/web/templates/deployment.yaml"


def test_missing_helm_is_a_warning_not_a_crash(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    result = scan(["charts"], FIXTURE, Config())
    assert result.findings == [] and any("helm not found" in w for w in result.warnings)


def test_explicit_path_excluded_by_config_warns(tmp_path):
    (tmp_path / "skip").mkdir()
    (tmp_path / "skip" / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n    - {name: c, image: c}\n")
    cfg = Config(exclude=["skip/*"])
    result = scan(["skip/pod.yaml"], tmp_path, cfg)
    assert result.findings == []
    assert any("excluded by the `exclude` setting" in w for w in result.warnings)
