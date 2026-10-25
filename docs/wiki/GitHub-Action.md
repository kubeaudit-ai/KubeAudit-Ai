# GitHub Action

Scans the manifests and Helm charts in a pull request, posts one summary comment with fixes, uploads results to GitHub code scanning, and fails the check at the severity you choose.

## Setup

```yaml
name: KubeAudit
on: [pull_request]

permissions:
  contents: read
  pull-requests: write     # needed for the PR comment
  security-events: write   # needed for the code scanning upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: kubeaudit-ai/KubeAudit-Ai@v1.2.2
        with:
          fail-on: high
          only-changed: true
```

The comment is updated in place on every push instead of adding a new one. Findings also appear inline in the PR's **Files changed** tab through code scanning.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Files or directories to scan, space-separated |
| `only-changed` | `false` | On PRs, scan only changed files (and the Helm charts they belong to) |
| `fail-on` | `high` | Fail the check at or above this severity: `critical`, `high`, `medium`, `low`, `none` |
| `min-severity` | `low` | Hide findings below this severity |
| `ignore` | | Comma-separated rule IDs or names to skip, e.g. `KA014,KA015` |
| `config` | | Path to a `.kubeaudit.yaml` (defaults to the repo root's) |
| `comment` | `true` | Post or update one summary comment on the PR |
| `comment-key` | workflow + job | Keeps separate KubeAudit jobs on one PR from overwriting each other's comment |
| `sarif` | `true` | Upload to code scanning |
| `setup-helm` | `true` | Install Helm to render charts; set `false` if it's already on the runner |
| `github-token` | `github.token` | Token used to read PR files and write the comment |

## Outputs

| Output | Meaning |
|---|---|
| `findings` | Total number of findings |
| `critical` | Number of critical findings |
| `high` | Number of high findings |
| `sarif-file` | Path to the SARIF report |
| `report-file` | Path to the Markdown report |

Example, using an output in a later step:

```yaml
      - uses: kubeaudit-ai/KubeAudit-Ai@v1.2.2
        id: kubeaudit
        with:
          fail-on: none
      - run: echo "KubeAudit found ${{ steps.kubeaudit.outputs.findings }} issues"
```

## Common setups

**Report only, never block:** `fail-on: none`

**Scan one folder:** `path: k8s/`

**Helm values per environment:** list the values files in `.kubeaudit.yaml` (see [[Configuration]]) so the chart is rendered the way you deploy it.

**Two scans on one PR** (say, staging and prod): give each job its own `comment-key` so each keeps its own comment.

## Troubleshooting

- **No comment appears:** the workflow needs `pull-requests: write`. PRs from forks get a read-only token, so the comment is skipped; the check and job log still work.
- **Code scanning upload fails:** add `security-events: write`. Private repos also need GitHub Advanced Security; otherwise set `sarif: false`.
- **A file isn't scanned:** check `exclude` in `.kubeaudit.yaml`. The job log prints a warning when a path you asked for is excluded.
