"""Runtime settings, read from environment variables (set them in Railway)."""
import os
from functools import lru_cache


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


class Settings:
    def __init__(self) -> None:
        # Where the web app lives (sign-in redirects go here) and the public URL of this API.
        self.app_url = _env("APP_URL", "https://msharsha565-create.github.io/KubeAudit-Ai/")
        self.api_url = _env("API_URL", "https://kubeaudit-ai-production.up.railway.app").rstrip("/")
        origins = _env("CORS_ORIGINS", "https://msharsha565-create.github.io")
        self.cors_origins = [o.strip().rstrip("/") for o in origins.split(",") if o.strip()]

        self.github_client_id = _env("GITHUB_CLIENT_ID")
        self.github_client_secret = _env("GITHUB_CLIENT_SECRET")

        # Email: "resend" (needs RESEND_API_KEY). For development only: "console" (log the link)
        # or "file:/path". Email sign-in stays hidden until a real backend is configured.
        self.resend_api_key = _env("RESEND_API_KEY")
        self.email_from = _env("EMAIL_FROM", "KubeAudit AI <onboarding@resend.dev>")
        self.email_backend = _env("EMAIL_BACKEND", "resend")

        self.stripe_secret_key = _env("STRIPE_SECRET_KEY")
        self.stripe_webhook_secret = _env("STRIPE_WEBHOOK_SECRET")
        self.stripe_price_id_pro = _env("STRIPE_PRICE_ID_PRO")

        self.session_days = int(_env("SESSION_DAYS", "30"))
        self.free_monthly_scans = int(_env("FREE_MONTHLY_SCANS", "50"))
        self.pro_monthly_scans = int(_env("PRO_MONTHLY_SCANS", "2500"))

    @property
    def github_enabled(self) -> bool:
        return bool(self.github_client_id and self.github_client_secret)

    @property
    def email_enabled(self) -> bool:
        if self.email_backend == "resend":
            return bool(self.resend_api_key)
        return self.email_backend == "console" or self.email_backend.startswith("file:")

    @property
    def billing_enabled(self) -> bool:
        return bool(self.stripe_secret_key and self.stripe_price_id_pro)


@lru_cache
def get_settings() -> Settings:
    return Settings()
