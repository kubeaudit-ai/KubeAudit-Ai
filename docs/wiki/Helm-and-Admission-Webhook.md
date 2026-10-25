# Helm and Admission Webhook

Run the same rules inside your cluster as an admission webhook for pods.

- **Validating:** denies pods that still have critical or high findings.
- **Mutating:** when a pod is created, adds a non-root security context, turns off privilege escalation and privileged mode, and adds default CPU and memory requests and limits. **Images are never rewritten**; unpinned images are reported instead.

## Install

```bash
helm repo add kubeaudit https://kubeaudit-ai.github.io/KubeAudit-Ai/
helm repo update
helm upgrade --install kubeaudit kubeaudit/kubeaudit-ai -n kubeaudit --create-namespace
kubectl rollout status deployment/kubeaudit-kubeaudit-ai -n kubeaudit --timeout=180s
```

> **Moved:** the Helm repo used to be at `msharsha565-create.github.io/KubeAudit-Ai`. If you added it before, run
> `helm repo remove kubeaudit` and add it again with the address above.

## What's built in

- **TLS with no cert-manager:** the chart creates its own CA and serving certificate (`tls.autoGenerate: true`) and injects the CA into both webhook configurations.
- **Safe defaults:** `kube-system`, `kube-public`, `kube-node-lease` and the `kubeaudit` namespace are excluded, so the webhook can't block the cluster's own components.
- **Hardened itself:** runs non-root with a read-only root filesystem.
- **Endpoints:** `/audit`, `/fix`, `/validate`, `/mutate`, `/health` and Prometheus `/metrics`.

## See it work

The webhook changes the **pods** a Deployment creates, not the Deployment itself, so look at a pod:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubeaudit-ai/KubeAudit-Ai/main/manifests/sample-deployment.yaml
POD=$(kubectl get pod -n default -l app=demo-api -o jsonpath='{.items[0].metadata.name}')
kubectl get pod "$POD" -n default -o jsonpath='{.spec.containers[0].securityContext}{"\n"}'
```

If no pod appears, the validating webhook denied it. `kubectl get events -n default` shows why.

## Remove

```bash
helm uninstall kubeaudit -n kubeaudit
kubectl delete namespace kubeaudit
```

## Local testing with kind

```bash
kind create cluster --name kubeaudit
docker build --provenance=false -t kubeaudit-ai:latest .
kind load docker-image kubeaudit-ai:latest --name kubeaudit
helm upgrade --install kubeaudit charts/kubeaudit-ai/ -n kubeaudit --create-namespace \
  --set image.repository=kubeaudit-ai --set image.tag=latest --set image.pullPolicy=Never
```
