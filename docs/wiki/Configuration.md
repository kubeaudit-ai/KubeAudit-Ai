# Configuration

## `.kubeaudit.yaml`

Put this file in the root of your repo. The Action and CLI pick it up automatically.

```yaml
fail_on: high                  # critical | high | medium | low | none
min_severity: low              # hide findings below this
ignore: [KA015]                # rule IDs or names to skip everywhere
exclude:                       # paths not to scan (glob patterns)
  - "examples/*"
  - "test/fixtures/*"
helm:
  values:
    charts/my-app: [values-prod.yaml]   # values files to render each chart with
```

How the file combines with other settings:

- **`ignore`**: rules from the file, the Action's `ignore` input and the CLI's `--ignore` are all skipped (the lists add up).
- **`fail_on` / `min_severity`**: on the CLI, the file's value is used unless you pass `--fail-on` / `--min-severity`. The GitHub Action always passes its `fail-on` and `min-severity` inputs (default `high` and `low`), so in the Action set the threshold with those inputs rather than in the file.
- **`exclude`** and **`helm`** come only from the file.

## Ignore one resource

Add an annotation to the resource itself. This is the best choice for a real exception, because the reason sits next to the code:

```yaml
metadata:
  annotations:
    kubeaudit.ai/ignore: "KA004,KA005"   # node agent that needs host access
```

Use `"all"` to skip every rule for that resource.

## Helm charts

Any folder with a `Chart.yaml` is rendered with `helm template` before scanning, so values that become `privileged: true` or `image: …:latest` are caught. Findings in rendered charts are labelled "Helm template" instead of a line number.

Use `helm.values` to render with the values files you actually deploy with.

## In the web app (Pro)

Signed-in Pro users can switch rules off and change their severity under **Account → Rule settings**. Those settings apply to scans in the web app. The Action and CLI keep using `.kubeaudit.yaml`.
