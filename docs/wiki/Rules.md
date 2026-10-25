# Rules

KubeAudit AI has 15 rules, based on the Kubernetes Pod Security Standards. Every rule is deterministic: the same YAML always gives the same findings.

| ID | Severity | What it catches |
|---|---|---|
| [KA001](#ka001) | 🔴 Critical | Container runs in privileged mode |
| [KA002](#ka002) | 🟠 High | Container allows privilege escalation |
| [KA003](#ka003) | 🟠 High | Container may run as root |
| [KA004](#ka004) | 🟠 High | Pod shares host namespaces |
| [KA005](#ka005) | 🟠 High | Pod mounts a hostPath volume |
| [KA006](#ka006) | 🟠 High | Container adds dangerous Linux capabilities |
| [KA007](#ka007) | 🟠 High | Secret value hard-coded in an environment variable |
| [KA008](#ka008) | 🟠 High | RBAC rule grants wildcard access |
| [KA009](#ka009) | 🟡 Medium | Image uses `latest` or no tag |
| [KA010](#ka010) | 🟡 Medium | Root filesystem is writable |
| [KA011](#ka011) | 🟡 Medium | Container has no memory limit |
| [KA012](#ka012) | ⚪ Low | Container does not drop all capabilities |
| [KA013](#ka013) | ⚪ Low | Container has no CPU or memory requests |
| [KA014](#ka014) | ⚪ Low | Long-running container has no readiness or liveness probe |
| [KA015](#ka015) | ⚪ Low | Service account token is mounted automatically |

Workloads checked: Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job and CronJob, including init and ephemeral containers. RBAC rules (KA008) check Role and ClusterRole.

**Severity and the score.** The web app's score is 100 − 25 per critical − 10 per high − 4 per medium − 1 per low. The GitHub Action fails at `high` and above by default (`fail-on`).

## KA001
**Container runs in privileged mode** · 🔴 Critical · `PrivilegedContainer`

Privileged containers have full access to the host. Remove `privileged: true`.

Fix:

```yaml
securityContext:
  privileged: false
```

Reference: https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline

## KA002
**Container allows privilege escalation** · 🟠 High · `AllowPrivilegeEscalation`

Set `allowPrivilegeEscalation: false` so processes can't gain more privileges than their parent.

Fix:

```yaml
securityContext:
  allowPrivilegeEscalation: false
```

Reference: https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted

## KA003
**Container may run as root** · 🟠 High · `RunAsNonRoot`

Set `runAsNonRoot: true` on the pod or container, and use an image with a non-root user.

Fix:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
```

Reference: https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted

## KA004
**Pod shares host namespaces** · 🟠 High · `HostNamespaces`

Remove `hostNetwork`, `hostPID` and `hostIPC` unless the workload is a node agent that truly needs them.

Fix:

```yaml
hostNetwork: false
hostPID: false
hostIPC: false
```

Reference: https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline

## KA005
**Pod mounts a hostPath volume** · 🟠 High · `HostPathVolume`

hostPath mounts expose the node filesystem. Use a PersistentVolumeClaim, configMap, secret or emptyDir instead.

Fix:

```yaml
volumes:
  - name: data
    emptyDir: {}
```

Reference: https://kubernetes.io/docs/concepts/storage/volumes/#hostpath

## KA006
**Container adds dangerous Linux capabilities** · 🟠 High · `DangerousCapabilities`

Remove capabilities such as SYS_ADMIN, NET_ADMIN or ALL from `capabilities.add`.

Fix:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
```

Reference: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container

## KA007
**Secret value hard-coded in an environment variable** · 🟠 High · `HardcodedSecretEnv`

Move the value into a Secret and reference it with `valueFrom.secretKeyRef`. Rotate the exposed value.

Fix:

```yaml
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: app-secrets
        key: db-password
```

Reference: https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables

## KA008
**RBAC rule grants wildcard access** · 🟠 High · `RBACWildcard`

Replace `*` in verbs, resources or apiGroups with the specific values the workload needs.

Fix:

```yaml
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
```

Reference: https://kubernetes.io/docs/concepts/security/rbac-good-practices/

## KA009
**Image uses `latest` or no tag** · 🟡 Medium · `ImageNotPinned`

Pin the image to a specific version tag, or better, a `@sha256:` digest, so deploys are reproducible.

Fix:

```yaml
image: registry.example.com/app:1.4.2
```

Reference: https://kubernetes.io/docs/concepts/containers/images/#image-names

## KA010
**Root filesystem is writable** · 🟡 Medium · `ReadOnlyRootFilesystem`

Set `readOnlyRootFilesystem: true` and mount an emptyDir for paths the app must write to.

Fix:

```yaml
securityContext:
  readOnlyRootFilesystem: true
```

Reference: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/

## KA011
**Container has no memory limit** · 🟡 Medium · `MissingMemoryLimit`

Set `resources.limits.memory` so one container can't exhaust node memory.

Fix:

```yaml
resources:
  limits:
    memory: 512Mi
```

Reference: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/

## KA012
**Container does not drop all capabilities** · ⚪ Low · `DropAllCapabilities`

Drop all capabilities and add back only what the process needs.

Fix:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
```

Reference: https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted

## KA013
**Container has no CPU or memory requests** · ⚪ Low · `MissingResourceRequests`

Set `resources.requests` so the scheduler can place the pod correctly.

Fix:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
```

Reference: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/

## KA014
**Long-running container has no readiness or liveness probe** · ⚪ Low · `MissingProbes`

Add a readinessProbe (and usually a livenessProbe) so Kubernetes only routes traffic to healthy pods.

Fix:

```yaml
readinessProbe:
  httpGet:
    path: /healthz
    port: 8080
```

Reference: https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/

## KA015
**Service account token is mounted automatically** · ⚪ Low · `AutomountServiceAccountToken`

Set `automountServiceAccountToken: false` unless the pod calls the Kubernetes API.

Fix:

```yaml
automountServiceAccountToken: false
```

Reference: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/

## Turning rules off

For one resource, add an annotation:

```yaml
metadata:
  annotations:
    kubeaudit.ai/ignore: "KA014,KA015"   # or "all"
```

For the whole repo, list them in `.kubeaudit.yaml` (`ignore: [KA015]`), or pass `ignore: KA014,KA015` to the Action or `--ignore` to the CLI. Pro accounts can also switch rules off or change their severity in the web app (Account → Rule settings).
