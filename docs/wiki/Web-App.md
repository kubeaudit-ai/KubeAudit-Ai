# Web App

**[kubeaudit-ai.github.io](https://kubeaudit-ai.github.io/)**: scan Kubernetes YAML in your browser, with no install and no upload.

## What you get

- **A security score** from 0 to 100 and a letter grade. Score = 100 − 25 per critical − 10 per high − 4 per medium − 1 per low.
- **"PR check" preview**: whether the GitHub Action would pass or fail this file at `fail-on: high`.
- **Findings marked on their lines.** Click a line or a finding to jump between them.
- **Fixed YAML**: a hardened copy with every safe fix applied. Your comments and formatting are kept, and nothing else in the file is changed. Fixes marked **Needs your decision** (image tags, secrets, probes, RBAC) are left for you, because only you know the right value.
- **Copy report** for pasting into a ticket or chat.

## Private by design

Scanning and fixing run entirely in your browser. Your YAML is never sent to a server. Your last files are kept only in this browser so you can pick up where you left off; **Clear** removes them.

## Install as an app

The site works offline and can be installed:

- **Desktop (Chrome / Edge):** the install icon in the address bar, or menu → *Install KubeAudit AI*.
- **iPhone / iPad (Safari):** Share → *Add to Home Screen*.
- **Android (Chrome):** menu → *Install app*.

## With an account

Sign in with **GitHub** or **Google** (top right) to get:

| | Free | Pro |
|---|:---:|:---:|
| Scanner, fixes, score | ✅ | ✅ |
| API key for CI | ✅ (50 API scans/month) | ✅ (2,500 API scans/month) |
| Saved scan history | | ✅ |
| Shareable report links | | ✅ |
| Custom rule settings | | ✅ |

**Saving** stores the scan's files and results in your account. **Sharing** creates a read-only link that shows the findings only, not your YAML, so secrets in your files aren't exposed. You can turn a share link off at any time.

See [[Plans and Billing]].
