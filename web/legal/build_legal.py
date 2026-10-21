"""Generate the Terms, Privacy and Refund pages (web/public/*.html) from one template."""
from pathlib import Path

OWNER = "Sai Harsha Vardhan Mylavarapu"
EMAIL = "msharsha565@gmail.com"
EFFECTIVE = "October 20, 2026"
SITE = "https://msharsha565-create.github.io/KubeAudit-Ai/"

CSS = """
:root{--bg:#eef1f3;--panel:#fbfcfc;--ink:#12202b;--ink-2:#4a5966;--line:#d5dde2;--accent:#0b6a86}
@media (prefers-color-scheme:dark){:root{--bg:#0b1218;--panel:#111b23;--ink:#dbe5ec;--ink-2:#93a4b2;--line:#24333f;--accent:#3fb3d3;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.65 "Hanken Grotesk",system-ui,-apple-system,"Segoe UI",sans-serif;
padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px));padding-block:24px 48px}
main{max-width:760px;margin:0 auto;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:28px clamp(18px,4vw,40px)}
a{color:var(--accent)}h1{font:800 clamp(30px,5vw,40px)/1.05 "Big Shoulders Display","Arial Narrow",sans-serif;text-transform:uppercase;margin:0 0 6px}
h2{font-size:19px;margin:28px 0 6px}p,li{max-width:68ch}.meta{color:var(--ink-2);font-size:14px;margin:0 0 20px}
nav{max-width:760px;margin:0 auto 14px;display:flex;gap:16px;flex-wrap:wrap;font-weight:600;font-size:14px}
.box{border:1px solid var(--line);border-radius:10px;padding:12px 16px;background:var(--bg)}
"""


def page(slug, title, body):
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>{title} · KubeAudit AI</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Big+Shoulders+Display:wght@800&family=Hanken+Grotesk:wght@400;600;700&display=swap">
<style>{CSS}</style></head>
<body>
<nav aria-label="Site"><a href="./">← KubeAudit AI</a><a href="terms.html">Terms</a><a href="privacy.html">Privacy</a><a href="refund.html">Refunds &amp; cancellation</a></nav>
<main>
<h1>{title}</h1>
<p class="meta">Effective {EFFECTIVE}. KubeAudit AI is operated by {OWNER} (“we”, “us”). Questions: <a href="mailto:{EMAIL}">{EMAIL}</a></p>
{body}
</main>
</body></html>
"""


TERMS = f"""
<p>These terms cover your use of KubeAudit AI: the web app at <a href="{SITE}">{SITE}</a>, the GitHub Action, the command-line tool,
the API and the admission webhook (together, the “Service”). By creating an account or using the Service you agree to them.</p>

<h2>1. Accounts</h2>
<p>You can sign in with GitHub, Google, Microsoft or an email link. Give us accurate information, keep your sign-in and API key private,
and tell us if you think someone else is using them. You are responsible for activity under your account and API key.
You must be at least 13 years old to use the Service.</p>

<h2>2. Plans and payment</h2>
<ul>
<li><strong>Free:</strong> unlimited scanning in your browser and 50 API scans a month.</li>
<li><strong>Pro:</strong> $9 per month or $90 per year, plus any tax. Pro adds saved scan history, shareable reports, custom rule settings
and 2,500 API scans a month.</li>
</ul>
<p>Payments are processed by Stripe. Pro is billed in advance and <strong>renews automatically</strong> at the end of each monthly or yearly
period until you cancel. If we change the price, we will email you at least 30 days before it applies to your next renewal.
If a payment fails, Pro features pause until the payment succeeds.</p>

<h2>3. Cancellation and refunds</h2>
<p>You can cancel anytime from your account (<em>Manage billing</em>). Pro stays on until the end of the period you already paid for,
and you won't be charged again. Refunds follow our <a href="refund.html">Refund &amp; Cancellation Policy</a>, including a
14-day money-back guarantee on your first payment.</p>

<h2>4. Your content</h2>
<p>You keep all rights to the YAML and other files you scan. Scanning in the web app happens in your browser and is not sent to us.
When you choose to save a scan, send YAML to the API, or create a share link, you allow us to store and process that content only to
provide the Service to you. Anyone with a share link can view that report (not your YAML); you can turn a link off at any time.</p>

<h2>5. Acceptable use</h2>
<p>Don't use the Service to break the law, to get around plan limits, to attack or overload our systems, to probe the security of the
Service without our permission, or to upload content you have no right to share. We may suspend accounts that do.</p>

<h2>6. The results are guidance</h2>
<p>KubeAudit AI checks configuration against a fixed set of rules and can suggest fixes. It does not guarantee that your systems are
secure, and automatic fixes can affect how your workloads run. Review findings and changes before you deploy them.</p>

<h2>7. Availability and changes</h2>
<p>We work to keep the Service available but don't promise it will be uninterrupted or error-free. We may change or discontinue features;
if we discontinue Pro, we will refund the unused part of any prepaid period.</p>

<h2>8. Disclaimer and limit of liability</h2>
<p>The Service is provided “as is”, without warranties of any kind, to the extent the law allows. Our total liability for any claim
relating to the Service is limited to the amount you paid us in the 12 months before the claim. We are not liable for indirect,
incidental or consequential damages, including lost profits or data, to the extent the law allows.</p>

<h2>9. Ending your use</h2>
<p>You can delete your account at any time from the account page. We may suspend or end accounts that break these terms; if we end a
paid account without cause, we will refund the unused part of the current period.</p>

<h2>10. Changes to these terms</h2>
<p>We may update these terms. For material changes we will post the new version here and email account holders before it takes effect.</p>

<h2>11. Law</h2>
<p>These terms are governed by the laws of the State of Georgia, USA, without regard to conflict-of-law rules, except where your local
consumer law gives you rights that can't be waived.</p>
"""

PRIVACY = f"""
<p>This policy explains what KubeAudit AI collects, why, and the choices you have. We don't sell your data, show ads, or use
tracking or analytics tools.</p>

<h2>Scanning in your browser</h2>
<p>When you paste, drop or upload YAML in the web app, it is scanned <strong>on your device</strong>. It is not sent to us unless you
click <em>Save</em>. The app keeps your last files and your sign-in token in your browser's local storage so you can pick up where you
left off; clearing your browser data removes them.</p>

<h2>What we store when you have an account</h2>
<ul>
<li><strong>Account details:</strong> email address, name and profile picture link, and the account ID from GitHub, Google or Microsoft if
you sign in with them.</li>
<li><strong>Sign-in records:</strong> session tokens, email sign-in links and your API key, stored only as one-way hashes. For email
sign-in we also keep the requesting IP address for an hour-long rate limit.</li>
<li><strong>API usage:</strong> the time of each API scan and the number of resources and issues found, to count your monthly limit.
The YAML you send to the API is scanned and not stored.</li>
<li><strong>Saved scans (Pro):</strong> the name, score and findings, and the YAML files if you choose to save them; plus share links
and your rule settings.</li>
<li><strong>Billing (Pro):</strong> your plan, billing period and Stripe customer and subscription IDs. Card details go directly to
Stripe; we never see or store them.</li>
</ul>

<h2>Services that process data for us</h2>
<ul>
<li><strong>Railway</strong> hosts the API and its database (United States).</li>
<li><strong>GitHub</strong> hosts the web app (GitHub Pages) and provides GitHub sign-in.</li>
<li><strong>Google</strong> and <strong>Microsoft</strong> provide sign-in when you choose them.</li>
<li><strong>Resend</strong> sends sign-in emails.</li>
<li><strong>Stripe</strong> processes payments and keeps billing records.</li>
<li><strong>jsDelivr</strong> and <strong>Google Fonts</strong> deliver code and fonts the web app loads, so they receive your IP address
when you open it.</li>
</ul>
<p>Each of these handles data under its own privacy policy. We share only what they need to do their job.</p>

<h2>Cookies</h2>
<p>We set one short-lived cookie during GitHub, Google or Microsoft sign-in to protect against forged sign-in requests. It is deleted
when sign-in finishes. We don't use advertising or tracking cookies.</p>

<h2>How long we keep data</h2>
<p>We keep your account data until you delete your account. Deleting it (account page → <em>Delete account</em>) removes your account,
saved scans, share links, sessions and API key from our database. Stripe keeps payment records as the law requires. Hosting providers
may keep server logs for a limited time.</p>

<h2>Your choices and rights</h2>
<p>You can see and change most of your data in the app, delete saved scans and share links at any time, and delete your account. To
request a copy of your data or ask a question, email <a href="mailto:{EMAIL}">{EMAIL}</a>. Depending on where you live (for example the
EU, UK or California), you may have additional rights, such as access, correction, deletion and objection; email us to use them.</p>

<h2>Security</h2>
<p>Connections use HTTPS, tokens and API keys are stored hashed, and shared reports never include your YAML. No system is perfectly
secure; if we learn of a breach that affects you, we will tell you.</p>

<h2>Children</h2>
<p>The Service is not meant for children under 13, and we don't knowingly collect their data.</p>

<h2>Changes</h2>
<p>We will post updates here and email account holders about material changes.</p>
"""

REFUND = f"""
<div class="box"><strong>Short version:</strong> cancel anytime; your first payment comes with a 14-day money-back guarantee;
after that we don't refund partial periods, but you keep Pro until your paid period ends.</div>

<h2>How to cancel</h2>
<p>Sign in, open your account (top right), and click <em>Manage billing</em> → <em>Cancel plan</em>. You can also email
<a href="mailto:{EMAIL}">{EMAIL}</a> from your account's email address and we'll cancel for you.</p>
<p>After you cancel, you won't be charged again. Pro stays on until the end of the monthly or yearly period you already paid for, then
your account moves to the free plan. Your saved scans stay in your account; to keep using them after Pro ends, export what you need
before then or upgrade again.</p>

<h2>14-day money-back guarantee</h2>
<p>If Pro isn't right for you, email <a href="mailto:{EMAIL}">{EMAIL}</a> within <strong>14 days of your first Pro payment</strong>
(monthly or yearly) from your account's email address, and we'll refund that payment in full. Pro ends when the refund is issued.</p>

<h2>Yearly renewals</h2>
<p>We email a reminder before a yearly plan renews. If it renews and you didn't mean to keep it, ask within
<strong>14 days of the renewal charge</strong> for a full refund of that renewal.</p>

<h2>Other cases</h2>
<ul>
<li>Outside those windows we don't refund partial months or years, but cancelling stops all future charges.</li>
<li>If you were charged by mistake (for example twice), or the Service was unavailable for a long time, contact us and we'll make it right.</li>
<li>If we discontinue Pro, we refund the unused part of any prepaid period.</li>
</ul>

<h2>How refunds are paid</h2>
<p>Refunds go back to the original payment method through Stripe. Banks usually show them within 5–10 business days.</p>

<h2>Before disputing a charge</h2>
<p>Please email us first; we answer billing questions within 2 business days and can usually resolve them faster than a bank dispute.</p>
"""

out = Path(__file__).resolve().parent.parent / "public"
for slug, title, body in (("terms", "Terms of Service", TERMS), ("privacy", "Privacy Policy", PRIVACY),
                          ("refund", "Refund &amp; Cancellation Policy", REFUND)):
    (out / f"{slug}.html").write_text(page(slug, title, body))
    print("wrote", out / f"{slug}.html")
