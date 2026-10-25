# CLI

The same scanner as the GitHub Action, for any CI system or your own machine. It needs Python 3.10+ and works offline. Install Helm too if you want charts rendered.

## Install

```bash
pip install "git+https://github.com/kubeaudit-ai/KubeAudit-Ai"
```

## Use

```bash
kubeaudit scan .                                   # scan the current folder
kubeaudit scan k8s/ charts/my-app                  # specific paths
kubeaudit scan . --fail-on critical                # only fail on critical
kubeaudit scan . --ignore KA014,KA015              # skip rules
kubeaudit scan . --format sarif -o results.sarif   # SARIF for code scanning
kubeaudit scan . --format json -o report.json      # machine-readable
kubeaudit rules                                    # list all rules
```

**Exit codes:** `0` = nothing at or above `--fail-on`, `1` = something was found at or above it.

## Options

| Option | What it does |
|---|---|
| `--format, -f` | `text` (default), `json`, `sarif`, `markdown` |
| `--output, -o` | Write the main report to a file instead of the screen |
| `--sarif`, `--json`, `--markdown` | Also write that report to the given path |
| `--fail-on` | `critical`, `high` (default), `medium`, `low`, `none` |
| `--min-severity` | Hide findings below this level |
| `--ignore` | Comma-separated rule IDs or names |
| `--config` | Path to a config file (default: `.kubeaudit.yaml` in `--root`) |
| `--root` | Repository root; report paths are relative to it |
| `--files-from` | Read extra paths, one per line, from a file or `-` for stdin |
| `--link-base` | URL prefix for file links in Markdown reports |

## In other CI systems

**GitLab CI**

```yaml
kubeaudit:
  image: python:3.12-slim
  script:
    - pip install "git+https://github.com/kubeaudit-ai/KubeAudit-Ai"
    - kubeaudit scan . --format sarif -o gl-kubeaudit.sarif
  artifacts:
    when: always
    paths: [gl-kubeaudit.sarif]
```

**pre-commit hook** (`.git/hooks/pre-commit`)

```bash
#!/bin/sh
git diff --cached --name-only --diff-filter=ACM | grep -E '\.ya?ml$' | kubeaudit scan --files-from - --fail-on high
```

**Only changed files in any CI:**

```bash
git diff --name-only origin/main...HEAD | kubeaudit scan --files-from -
```
