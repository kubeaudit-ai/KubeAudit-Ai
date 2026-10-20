# KubeAudit AI

**Catch Kubernetes security misconfigurations in pull requests, before they reach a cluster.**

KubeAudit AI scans Kubernetes YAML and Helm charts, points to the exact line of each problem, and shows the fix. It runs as a GitHub Action, a CLI, or an in-cluster admission webhook.

- 🔍 15 rules covering privileged containers, root users, host access, hard-coded secrets, RBAC wildcards, unpinned images, and resource limits
- 📍 Line-accurate findings in PR comments and in GitHub code scanning (SARIF)
- ⛵ Helm charts are rendered with `helm template` before scanning, so templated values are checked too
- 🧩 Works offline. The scanner needs only Python and PyYAML, and no code leaves your runner

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
      - uses: actions/checkout@v4
      - uses: msharsha565-create/KubeAudit-Ai@v0.5.0
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

The same project also ships a validating and mutating admission webhook. The sections below cover deploying it.

---

## Architecture Overview

* **FastAPI Core (`app/main.py`)**: Implements `/audit`, `/fix`, `/validate`, and `/mutate` endpoints.
* **Automated TLS (`cert-manager`*)*: Issues self-signed cluster certificates and leverages `cert-manager.io/inject-ca-from` to populate the admission webhook `caBundle`$ynamically.
* **Self-Healing Webhook**:
  * **Validating Webhook**: Intercepts admission requests and denies non-compliant deployments (`runAsNonRoot: false`, privileged containers, missing resource limits).
  * **Mutating Webhook**: Transparently patches insecure manifests during creation (pins `:alpine` tags, injects non-root security contexts, and applies default CPU/memory limits).
* **Helm Packaging (`charts/kubeaudit-ai`*)*: Complete Helm v2 deployment with automated `helm test` health verification.

---

## Local Development & Cluster Setup

### Prerequisites
* Docker
* `kind` (Kubernetes in Docker)
* `kubectl`
* `helm` (v3+)

### 1. Build Application Image
To ensure compatibility with containerd CRI in `kind`, disable BuildKit provenance attestations:
```bash
docker build --provenance=false -t kubeaudit-ai:latest .
```

### 2. Sideload Images into Kind
```bash
for img in \
  quay.io/jetstack/cert-manager-controller:v1.16.1 \
  quay.io/jetstack/cert-manager-cainjector:v1.16.1 \
  quay.io/jetstack/cert-manager-webhook:v1.16.1 \
  kubeaudit-ai:latest; do
    docker save "$img" | docker exec -i kubeaudit-test-control-plane ctr -n k8s.io images import -
done
```

### 3. Deploy cert-manager
```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.1/cert-manager.yaml
kubectl wait --namespace cert-manager --for_condition=ready pod --all --timeout=90s
```

### 4. Deploy KubeAudit AI via Helm
```bash
helm upgrade --install kubeaudit charts/kubeaudit-ai/ \
  --namespace kubeaudit \
  --create-namespace

kubectl wait --namespace kubeaudit \
  --for=condition=ready pod \
  --selector=app=kubeaudit \
  --timeout=60s
```

---

## Verification & Testing

### Run Automated In-Cluster Helm Test
```bash
helm test kubeaudit -n kubeaudit --timeout 60s
```

### Verify Dynamic Manifest Mutation
Deploy an unpatched, insecure manifest:
```bash
kubectl apply -f manifests/sample-deployment.yaml
```

Verify that the mutating webhook auto-injected security constraints:
```bash
# Verify container image pinned:
kubectl get deployment demo-api -n default -o jsonpath='{.spec.template.spec.containers[0].image}'

# Verify non-root enforcement:
kubectl get deployment demo-api -n default -o jsonpath='{.spec.template.spec.securityContext.runAsNonRoot}'

# Verify resource limits injected:
kubectl get deployment demo-api -n default -o jsonpath='{.spec.template.spec.containers[0].resources}'
```

## Helm Installation

KubeAudit AI can be installed directly from the GitHub Pages Helm repository:

```bash
helm repo add kubeaudit https://msharsha565-create.github.io/KubeAudit-Ai/
helm repo update
helm upgrade --install kubeaudit kubeaudit/kubeaudit-ai -n kubeaudit --create-namespace
```
