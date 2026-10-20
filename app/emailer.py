"""Sending sign-in emails through Resend (https://resend.com)."""
import html
import json
import logging
from pathlib import Path

import httpx

from app.config import get_settings

log = logging.getLogger("kubeaudit.email")


class EmailError(Exception):
    pass


def send_magic_link(to: str, link: str) -> None:
    s = get_settings()
    subject = "Your KubeAudit AI sign-in link"
    text = (f"Sign in to KubeAudit AI:\n\n{link}\n\n"
            "The link works once and expires in 15 minutes. "
            "If you didn't ask to sign in, you can ignore this email.\n")
    safe = html.escape(link, quote=True)
    body = f"""<div style="font-family:system-ui,sans-serif;max-width:480px;margin:auto;padding:24px;color:#12202b">
<h2 style="margin:0 0 12px">Sign in to KubeAudit AI</h2>
<p>Click the button to sign in. The link works once and expires in 15 minutes.</p>
<p style="margin:24px 0"><a href="{safe}" style="background:#0b6a86;color:#fff;padding:12px 18px;border-radius:8px;text-decoration:none;font-weight:600">Sign in</a></p>
<p style="color:#4a5966;font-size:13px">Or paste this link into your browser:<br>{safe}</p>
<p style="color:#4a5966;font-size:13px">If you didn't ask to sign in, you can ignore this email.</p></div>"""

    backend = s.email_backend
    if backend == "console":
        log.warning("EMAIL_BACKEND=console: sign-in link for %s: %s", to, link)
        return
    if backend.startswith("file:"):
        path = Path(backend[5:])
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as f:
            f.write(json.dumps({"to": to, "subject": subject, "link": link}) + "\n")
        return
    if not s.resend_api_key:
        raise EmailError("Email sign-in is not configured.")
    try:
        r = httpx.post("https://api.resend.com/emails", timeout=10,
                       headers={"Authorization": f"Bearer {s.resend_api_key}"},
                       json={"from": s.email_from, "to": [to], "subject": subject, "text": text, "html": body})
    except httpx.HTTPError as e:
        raise EmailError(f"Could not reach the email service: {e}") from e
    if r.status_code >= 300:
        log.error("Resend error %s: %s", r.status_code, r.text[:300])
        raise EmailError("The email service rejected the message.")
