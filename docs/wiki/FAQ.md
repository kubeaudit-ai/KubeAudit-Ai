# FAQ

**Where's the AI?**
Detection is deliberately *not* an LLM. Security checks have to be reproducible and auditable: the same manifest gets the same findings on every run, on every machine, offline. The "AI" is the problem KubeAudit is built for: more and more Kubernetes YAML is written by AI coding assistants, and that YAML often runs privileged, as root, on `:latest`. KubeAudit is the guardrail that catches it in the PR, whoever or whatever wrote it.

**Does my YAML leave my machine?**
No. The Action and CLI run on your runner or laptop, and the web app scans in your browser. Only Pro features you choose to use (saved history, share links) store anything.

**Is it really free?**
Yes. The scanner, Action, CLI, webhook and web app are free. Pro is for people who want saved history, share links, custom rule settings and more API scans.

**Does a shared report show my YAML?**
No. A share link shows the findings, rule IDs and severity only, never the file contents, so secrets in your YAML stay private.

**How is it different from Trivy, Polaris or kube-score?**
They're excellent and broader. KubeAudit AI focuses on the pull request: one comment with the exact line and the fix for each problem, plus a one-click hardened file in the browser. It works well alongside them, for example KubeAudit for manifests and Trivy for image vulnerabilities.

**A finding is wrong for my case. What do I do?**
Silence it on that one resource with `kubeaudit.ai/ignore: "KA0XX"` (see [[Configuration]]). If you think the rule itself is wrong, [open an issue](https://github.com/kubeaudit-ai/KubeAudit-Ai/issues/new) with a small manifest that shows it.

**Why doesn't the fixer change my image tag, secrets or probes?**
Those have no single safe answer: only you know the right version, where the secret lives, or which endpoint is healthy. They're marked **Needs your decision** with an example to copy.

**Does it scan Helm charts?**
Yes. Charts are rendered with `helm template` first, so problems that come from values are caught too.

**Which Kubernetes objects are checked?**
Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job and CronJob (including init and ephemeral containers), plus Role and ClusterRole for RBAC.

**I signed in before but I'm signed out now.**
The web app moved to [kubeaudit-ai.github.io](https://kubeaudit-ai.github.io/). Sign in once more there; your plan and saved scans are still in your account.

**How do I cancel or get a refund?**
See [[Plans and Billing]].

**How do I contact you?**
Email msharsha565@gmail.com, or [open an issue](https://github.com/kubeaudit-ai/KubeAudit-Ai/issues) for bugs and rule ideas.
