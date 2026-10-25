# KubeAudit AI

**Catch Kubernetes security misconfigurations in pull requests, before they reach a cluster.**

KubeAudit AI scans Kubernetes YAML and Helm charts, points to the exact line of each problem, and shows the fix. One rule engine runs in four places:

| Where | Best for | Page |
|---|---|---|
| 🌐 **Web app**, [kubeaudit-ai.github.io](https://kubeaudit-ai.github.io/) | Checking a file right now, no install | [[Web App]] |
| ⚙️ **GitHub Action** | Every pull request, with a comment on the exact lines | [[GitHub Action]] |
| 💻 **CLI** | GitLab, Jenkins, pre-commit, your laptop | [[CLI]] |
| ⛵ **Admission webhook** (Helm) | Blocking or fixing insecure pods inside the cluster | [[Helm and Admission Webhook]] |

## Start here

- New? → [[Getting Started]]
- What does each finding mean? → [[Rules]]
- Silence a rule or set a threshold → [[Configuration]]
- Accounts, Pro, refunds → [[Plans and Billing]]
- Calling the API with your key → [[API]]
- Questions → [[FAQ]]

## Why KubeAudit AI

- 📍 **Line-accurate findings** in one PR comment and in GitHub code scanning (SARIF)
- 🛠️ **A fix for every finding**, plus a one-click hardened file in the web app
- ⛵ **Helm-aware**: charts are rendered with `helm template` before scanning
- 🔒 **Private**: the Action and CLI run on your runner; the web app scans in your browser
- ✅ **Deterministic**: no LLM decides what's insecure, so the same YAML always gets the same result

Found a bug or a false positive? [Open an issue](https://github.com/kubeaudit-ai/KubeAudit-Ai/issues/new) with a small manifest that shows it.
