# Getting Started

Pick the path that fits. Each takes a couple of minutes.

## 1. Try it in your browser (30 seconds)

1. Open **[kubeaudit-ai.github.io](https://kubeaudit-ai.github.io/)**.
2. Paste a Kubernetes YAML file, drop files onto the editor, or pick an example from **Examples…**.
3. Findings appear as you type, each marked on its line. Click one to see why it matters and how to fix it.
4. Open the **Fixed YAML** tab for a hardened copy of your file, ready to copy or download.

Nothing is uploaded. See [[Web App]].

## 2. Check every pull request (2 minutes)

Create `.github/workflows/kubeaudit.yml` in your repo:

```yaml
name: KubeAudit
on: [pull_request]

permissions:
  contents: read
  pull-requests: write     # PR comment
  security-events: write   # code scanning upload

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

Open a pull request that touches a manifest. You'll get one comment listing each finding with its line and fix, and the check fails if anything is high or critical. See [[GitHub Action]].

## 3. Run it locally

```bash
pip install "git+https://github.com/kubeaudit-ai/KubeAudit-Ai"
kubeaudit scan .
```

See [[CLI]].

## 4. Protect a cluster

```bash
helm repo add kubeaudit https://kubeaudit-ai.github.io/KubeAudit-Ai/
helm repo update
helm upgrade --install kubeaudit kubeaudit/kubeaudit-ai -n kubeaudit --create-namespace
```

See [[Helm and Admission Webhook]].

## Next

- Too noisy? Turn rules off or raise the threshold: [[Configuration]]
- What every rule checks: [[Rules]]
