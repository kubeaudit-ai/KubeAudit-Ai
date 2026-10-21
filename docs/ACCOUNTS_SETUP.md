# Turning on accounts and payments

The web app works without any of this. Each step below switches on one feature, and the
app shows or hides the matching buttons on its own (`GET /v1/auth/providers`).

All settings are **environment variables on the Railway service** (Service → Variables).
Railway redeploys after you save them.

## 0. How Railway runs this app

The Railway service runs a published Docker image, `ghcr.io/msharsha565-create/kubeaudit-ai:<version>`.
Publishing a GitHub release `vX.Y.Z` builds image `X.Y.Z`. To update the server, set
**Settings → Source → Image** to the new tag and deploy.

## 1. Database (do this first)

Without a database, accounts are lost every time Railway redeploys.

1. In your Railway project: **New → Database → PostgreSQL**.
2. On the KubeAudit service: **Variables → New Variable → Add Reference** → your Postgres service →
   `DATABASE_URL`. Use **Add Reference** rather than typing, so the service name is right.
   If the logs say `failed to resolve host 'postgres.railway.internal'`, the private network wasn't ready;
   version 1.1.2+ waits up to 60 seconds for it. On older versions use `DATABASE_PUBLIC_URL` instead.
3. The app creates and updates its tables automatically when it starts.

## 2. Sign in with GitHub

1. Go to <https://github.com/settings/developers> → **OAuth Apps** → **New OAuth App**.
   - Application name: `KubeAudit AI`
   - Homepage URL: `https://msharsha565-create.github.io/KubeAudit-Ai/`
   - Authorization callback URL: `https://kubeaudit-ai-production.up.railway.app/v1/auth/github/callback`
2. Copy the **Client ID**, then **Generate a new client secret** and copy it.
3. Railway variables: `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`.

## 2b. Sign in with Google

1. Open <https://console.cloud.google.com/>, create a project (any name), then **APIs & Services → OAuth consent screen**:
   External, app name `KubeAudit AI`, your support email, authorized domain `github.io` is not needed. Add the scopes
   `openid`, `email`, `profile`. Publish the app (no Google review is needed for these basic scopes).
2. **APIs & Services → Credentials → Create credentials → OAuth client ID**, type **Web application**.
   - Authorized redirect URI: `https://kubeaudit-ai-production.up.railway.app/v1/auth/google/callback`
3. Railway variables: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` (plain values, no `${{ }}`).

## 2c. Sign in with Microsoft (Outlook, Hotmail, Live, Microsoft 365)

1. Open <https://portal.azure.com/> → **Microsoft Entra ID → App registrations → New registration**.
   - Name: `KubeAudit AI`
   - Supported account types: **Accounts in any organizational directory and personal Microsoft accounts**
   - Redirect URI: platform **Web**, `https://kubeaudit-ai-production.up.railway.app/v1/auth/microsoft/callback`
2. Copy the **Application (client) ID**. Then **Certificates & secrets → New client secret** and copy its **Value**
   (not the Secret ID). Note when it expires and set a reminder to replace it.
3. Optional, for work accounts: **Token configuration → Add optional claim → ID → `xms_edov`**. Without it, work and school
   accounts are asked to use another sign-in method, because Microsoft doesn't confirm their email otherwise. Personal
   Outlook/Hotmail accounts always work.
4. Railway variables: `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`.

## 3. Sign in with email

1. Create a free account at <https://resend.com>.
2. **Domains → Add domain** and add the DNS records it shows. Resend can only send to
   people other than you from a domain you own.
3. **API Keys → Create API key** (sending access).
4. Railway variables:
   - `RESEND_API_KEY` = the key
   - `EMAIL_FROM` = `KubeAudit AI <login@your-domain.com>`

## 4. Payments (Stripe, $9/month)

Do this in **test mode** first (toggle at the top of the Stripe dashboard), then repeat in live mode.

1. **Product catalog → Add product**: name `KubeAudit AI Pro`, **Recurring**, **$9.00 / month**.
   Copy the **price ID** (`price_...`). Then **Add another price** on the same product: **$90.00 / year**, and copy that
   price ID too. The app shows these amounts, so keep them at $9 and $90 (or tell me to change the app).
2. **Developers → API keys**: copy the **Secret key** (`sk_test_...`).
3. **Developers → Webhooks → Add endpoint**:
   - URL: `https://kubeaudit-ai-production.up.railway.app/v1/billing/webhook`
   - Events: `checkout.session.completed`, `customer.subscription.created`,
     `customer.subscription.updated`, `customer.subscription.deleted`
   - Copy the **Signing secret** (`whsec_...`).
4. **Settings → Billing → Customer portal**: turn it on, and set:
   - Cancellations: **allowed**, **at the end of the billing period** (this is what the Refund Policy promises).
   - Payment methods: customers can update them.
5. **Settings → Billing → Subscriptions and emails**: turn on **Send emails about upcoming renewals** (for yearly plans) and
   **Send emails for failed payments**. The Refund Policy promises a reminder before yearly renewals.
6. **Settings → Public details**: add your support email and links to
   `https://msharsha565-create.github.io/KubeAudit-Ai/terms.html`, `privacy.html` and `refund.html`.
7. Railway variables: `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID_PRO` (monthly), `STRIPE_PRICE_ID_PRO_YEARLY`, `STRIPE_WEBHOOK_SECRET`.
8. Test: sign in on the web app, **Upgrade to Pro**, pay with card `4242 4242 4242 4242`,
   any future date and any CVC. You should come back as Pro within a few seconds.

### Giving a refund

When someone asks within the 14-day window: Stripe dashboard → **Customers** → the customer → their payment → **Refund**,
then on their subscription choose **Cancel immediately**. The app moves them to the free plan automatically.

When that works, switch Stripe to live mode, create the same product, webhook and keys there,
and replace the three variables with the live values.

## Optional settings

| Variable | Default | What it does |
|---|---|---|
| `FREE_MONTHLY_SCANS` | `50` | API scans per month on the free plan |
| `PRO_MONTHLY_SCANS` | `2500` | API scans per month on Pro |
| `SESSION_DAYS` | `30` | How long a sign-in lasts |
| `APP_URL` | GitHub Pages URL | Where sign-in and checkout return to |
| `API_URL` | Railway URL | Public address of this API (used for the GitHub callback) |
| `CORS_ORIGINS` | GitHub Pages origin | Sites allowed to call the API from a browser |

## Check it

`https://kubeaudit-ai-production.up.railway.app/v1/auth/providers` shows which features are on, for example
`{"github": true, "google": true, "microsoft": true, "email": true, "billing": true, "yearly": true}`.
