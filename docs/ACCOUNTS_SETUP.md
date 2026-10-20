# Turning on accounts and payments

The web app works without any of this. Each step below switches on one feature, and the
app shows or hides the matching buttons on its own (`GET /v1/auth/providers`).

All settings are **environment variables on the Railway service** (Service → Variables).
Railway redeploys after you save them.

## 1. Database (do this first)

Without a database, accounts are lost every time Railway redeploys.

1. In your Railway project: **New → Database → PostgreSQL**.
2. On the KubeAudit service, add a variable `DATABASE_URL` with the value `${{Postgres.DATABASE_URL}}`
   (Railway fills in the real address).
3. The app creates and updates its tables automatically when it starts.

## 2. Sign in with GitHub

1. Go to <https://github.com/settings/developers> → **OAuth Apps** → **New OAuth App**.
   - Application name: `KubeAudit AI`
   - Homepage URL: `https://msharsha565-create.github.io/KubeAudit-Ai/`
   - Authorization callback URL: `https://kubeaudit-ai-production.up.railway.app/v1/auth/github/callback`
2. Copy the **Client ID**, then **Generate a new client secret** and copy it.
3. Railway variables: `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`.

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
   Copy the **price ID** (`price_...`).
2. **Developers → API keys**: copy the **Secret key** (`sk_test_...`).
3. **Developers → Webhooks → Add endpoint**:
   - URL: `https://kubeaudit-ai-production.up.railway.app/v1/billing/webhook`
   - Events: `checkout.session.completed`, `customer.subscription.created`,
     `customer.subscription.updated`, `customer.subscription.deleted`
   - Copy the **Signing secret** (`whsec_...`).
4. **Settings → Billing → Customer portal**: turn it on (lets people cancel or change their card).
5. Railway variables: `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID_PRO`, `STRIPE_WEBHOOK_SECRET`.
6. Test: sign in on the web app, **Upgrade to Pro**, pay with card `4242 4242 4242 4242`,
   any future date and any CVC. You should come back as Pro within a few seconds.

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
`{"github": true, "email": true, "billing": true}`.
