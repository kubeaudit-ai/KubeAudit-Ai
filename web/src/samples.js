// Example manifests for the "Examples" menu. Clearly fictional names.
export const SAMPLES = [
  {
    id: "payments",
    name: "payments-api.yaml",
    label: "Payments API (insecure)",
    text: `# Example: a payments service with common mistakes.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  namespace: payments
spec:
  replicas: 3
  selector:
    matchLabels:
      app: payments-api
  template:
    metadata:
      labels:
        app: payments-api
    spec:
      containers:
        - name: api
          image: acme/payments-api:latest
          ports:
            - containerPort: 8080
          env:
            - name: STRIPE_SECRET_KEY
              value: sk_live_example_do_not_commit
            - name: LOG_LEVEL
              value: info
          securityContext:
            privileged: true
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly-settlement
  namespace: payments
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: settle
              image: acme/settlement-runner
              resources:
                limits:
                  memory: 256Mi
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: payments-operator
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
`,
  },
  {
    id: "agent",
    name: "node-agent.yaml",
    label: "Monitoring agent (host access)",
    text: `# Example: a node monitoring agent that reaches into the host.
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-agent
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: node-agent
  template:
    metadata:
      labels:
        app: node-agent
    spec:
      hostNetwork: true
      hostPID: true
      volumes:
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
        - name: proc
          hostPath:
            path: /proc
      containers:
        - name: agent
          image: example/node-agent:2.4.1
          securityContext:
            capabilities:
              add: ["SYS_ADMIN", "NET_ADMIN"]
          volumeMounts:
            - name: docker-sock
              mountPath: /var/run/docker.sock
            - name: proc
              mountPath: /host/proc
              readOnly: true
`,
  },
  {
    id: "hardened",
    name: "web-hardened.yaml",
    label: "Hardened web app (passes)",
    text: `# Example: a web app that follows every KubeAudit rule.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: storefront-web
  namespace: storefront
spec:
  replicas: 2
  selector:
    matchLabels:
      app: storefront-web
  template:
    metadata:
      labels:
        app: storefront-web
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: web
          image: ghcr.io/example/storefront-web:3.2.0
          ports:
            - containerPort: 8080
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8080
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: storefront-db
                  key: password
          resources:
            limits:
              memory: 256Mi
            requests:
              cpu: 100m
              memory: 128Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
`,
  },
];
