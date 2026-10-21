# KubeAudit AI

**Catch Kubernetes security misconfigurations in pull requests, before they reach a cluster.**

KubeAudit AI scans Kubernetes YAML and Helm charts, points to the exact line of each problem, and shows the fix. It runs as a GitHub Action, a CLI, or an in-cluster admission webhook.

- 🔍 15 rules covering privileged containers, root users, host access, hard-coded secrets, RBAC wildcards, unpinned images, and resource limits
- 📍 Line-accurate findings in PR comments and in GitHub code scanning (SARIF)
- ⛵ Helm charts are rendered with `helm template` before scanning, so templated values are checked too
- 🧩 Works offline. The scanner needs only Python and PyYAML, and no code leaves your runner

## Web app

**Open it: https://msharsha565-create.github.io/KubeAudit-Ai/**

Paste or drop Kubernetes YAML and get a security score, each problem marked on its line with the fix, and a one-click hardened file. It runs entirely in your browser (nothing is uploaded), works offline, and can be installed on a phone or desktop from the browser menu ("Install app" / "Add to Home Screen").

The web app uses a JavaScript port of the same rule engine. CI checks that both engines report identical findings, and that the auto-fixer removes every fixable issue without changing anything else in the file.

### Accounts and Pro

Sign in with GitHub or email to get an API key. **Pro ($9/month)** adds saved scan history, shareable report links,
custom rule settings and 2,500 API scans a month. Scanning itself always stays in your browser; an account stores
only what you choose to save. Setup for the server: [docs/ACCOUNTS_SETUP.md](docs/ACCOUNTS_SETUP.md).

## GitHub Action

Add `.github/workflows/kubeaudit.yml`:

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
      - uses: msharsha565-create/KubeAudit-Ai@v1.1.2
        with:
          fail-on: high        # critical | high | medium | low | none
          only-changed: true   # scan just the files this PR touches
```

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Files or directories to scan, space-separated |
| `only-changed` | `false` | On PRs, scan only changed files (and the Helm charts they belong to) |
| `fail-on` | `high` | Fail the check at or above this severity |
| `min-severity` | `low` | Hide findings below this severity |
| `ignore` | | Comma-separated rule IDs to skip |
| `comment` | `true` | Post or update one summary comment on the PR |
| `comment-key` | workflow/job | Keeps separate KubeAudit jobs from overwriting each other's PR comment |
| `sarif` | `true` | Upload to code scanning (private repos need GitHub Advanced Security) |
| `setup-helm` | `true` | Install Helm to render charts |

Outputs: `findings`, `critical`, `high`, `sarif-file`, `report-file`.

## CLI

```bash
pip install "git+https://github.com/msharsha565-create/KubeAudit-Ai"
kubeaudit scan .                       # human-readable, exit 1 on high+ findings
kubeaudit scan k8s/ --format sarif -o results.sarif
kubeaudit scan . --fail-on critical --ignore KA014,KA015
kubeaudit rules                        # list all rules
```

## Rules

| ID | Severity | Name | Checks for |
|---|---|---|---|
| KA001 | Critical | PrivilegedContainer | Container runs in privileged mode |
| KA002 | High | AllowPrivilegeEscalation | Container allows privilege escalation |
| KA003 | High | RunAsNonRoot | Container may run as root |
| KA004 | High | HostNamespaces | Pod shares host namespaces |
| KA005 | High | HostPathVolume | Pod mounts a hostPath volume |
| KA006 | High | DangerousCapabilities | Container adds dangerous Linux capabilities |
| KA007 | High | HardcodedSecretEnv | Secret value hard-coded in an environment variable |
| KA008 | High | RBACWildcard | RBAC rule grants wildcard access |
| KA009 | Medium | ImageNotPinned | Image uses latest or no tag |
| KA010 | Medium | ReadOnlyRootFilesystem | Root filesystem is writable |
| KA011 | Medium | MissingMemoryLimit | Container has no memory limit |
| KA012 | Low | DropAllCapabilities | Container does not drop all capabilities |
| KA013 | Low | MissingResourceRequests | Container has no CPU or memory requests |
| KA014 | Low | MissingProbes | Long-running container has no readiness or liveness probe |
| KA015 | Low | AutomountServiceAccountToken | Service account token is mounted automatically |

Workloads checked: Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJob, including init and ephemeral containers. RBAC checks cover Role and ClusterRole.

## Configuration

Put `.kubeaudit.yaml` in the repo root:

```yaml
fail_on: high
min_severity: low
ignore: [KA015]                 # rule IDs or names
exclude: ["examples/*", "test/fixtures/*"]
helm:
  values:
    charts/my-app: [values-prod.yaml]   # values files per chart
```

Skip rules on one resource with an annotation:

```yaml
metadata:
  annotations:
    kubeaudit.ai/ignore: "KA004,KA005"   # or "all"
```

## In-cluster admission webhook

The same project ships a validating and mutating admission webhook for pods.

- **FastAPI service (`app/main.py`)** with `/audit`, `/fix`, `/validate` and `/mutate` endpoints, plus `/health` and Prometheus `/metrics`.
- **Mutating webhook:** on pod creation it adds a non-root security context, turns off privilege escalation and privileged mode, and adds default CPU and memory limits and requests. Images are never rewritten; unpinned images are reported instead.
- **Validating webhook:** denies pods that still have critical or high findings.
- **TLS:** the Helm chart generates its own CA and serving certificate (`tls.autoGenerate: true`) and injects the CA into both webhook configurations. cert-manager is not required.
- **Safe defaults:** `kube-system`, `kube-public`, `kube-node-lease` and the `kubeaudit` namespace are excluded. The webhook itself runs non-root with a read-only root filesystem.

### Install from the Helm repository

```bash
helm repo add kubeaudit https://msharsha565-create.github.io/KubeAudit-Ai/
helm repo update
helm upgrade --install kubeaudit kubeaudit/kubeaudit-ai -n kubeaudit --create-namespace
kubectl rollout status deployment/kubeaudit-kubeaudit-ai -n kubeaudit --timeout=180s
```

### Local development with kind

These are the same steps CI runs on every push.

```bash
kind create cluster --name kubeaudit
docker build --provenance=false -t kubeaudit-ai:latest .
kind load docker-image kubeaudit-ai:latest --name kubeaudit

helm upgrade --install kubeaudit charts/kubeaudit-ai/ \
  --namespace kubeaudit --create-namespace \
  --set image.repository=kubeaudit-ai \
  --set image.tag=latest \
  --set image.pullPolicy=Never

kubectl rollout status deployment/kubeaudit-kubeaudit-ai -n kubeaudit --timeout=180s
```

### See the mutation happen

Apply the deliberately insecure sample. The webhook patches the **pods** it creates, so inspect a pod rather than the Deployment:

```bash
kubectl apply -f manifests/sample-deployment.yaml
POD=$(kubectl get pod -n default -l app=demo-api -o jsonpath='{.items[0].metadata.name}')

kubectl get pod "$POD" -n default -o jsonpath='{.spec.securityContext.runAsNonRoot}{"\n"}'
kubectl get pod "$POD" -n default -o jsonpath='{.spec.containers[0].securityContext}{"\n"}'
kubectl get pod "$POD" -n default -o jsonpath='{.spec.containers[0].resources}{"\n"}'
```

If the pod is not created, `kubectl get events -n default` shows the validating webhook's reason for denying it.
