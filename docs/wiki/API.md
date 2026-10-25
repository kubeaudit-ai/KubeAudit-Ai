# API

Use your API key to scan a manifest from a script or a CI system that can't run the CLI. In most cases the [[CLI]] or [[GitHub Action]] is simpler, because they run on your own machine with no key and no limit.

## Get a key

Sign in at [kubeaudit-ai.github.io](https://kubeaudit-ai.github.io/) → open your account → **Create API key**. The key starts with `ka_live_` and is shown **once**, so copy it right away. **Replace key** makes a new key and turns off the old one.

Keep it secret: store it as a CI secret, never in your repo.

## Scan a manifest

```bash
curl -s https://kubeaudit-ai-production.up.railway.app/audit \
  -H "X-API-Key: $KUBEAUDIT_API_KEY" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --rawfile m deployment.yaml '{manifest: $m}')"
```

Response:

```json
{
  "valid": false,
  "issues": [
    {
      "rule": "PrivilegedContainer",
      "severity": "Critical",
      "message": "Container 'demo-web' must not run in privileged mode",
      "remediation": "Set securityContext.privileged: false on container 'demo-web'."
    }
  ]
}
```

`valid` is `true` when nothing was found.

## Limits

| Plan | API scans per month |
|---|---|
| Free | 50 |
| Pro | 2,500 |

Over the limit, the API answers `429` until the next month. Scans in the web app, the Action and the CLI don't count toward it.

## Errors

| Status | Meaning |
|---|---|
| `400` | Missing `manifest`, or it isn't valid YAML |
| `401` | Missing or wrong `X-API-Key` |
| `429` | Monthly limit reached |
