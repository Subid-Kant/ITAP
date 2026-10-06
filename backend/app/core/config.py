"""
ITAP — Configuration Management
Central configuration using pydantic-settings for environment variable management.
Production-ready with comprehensive validation and sensible defaults.
"""
import os
import secrets
import logging
from pydantic_settings import BaseSettings
from typing import List, Optional

logger = logging.getLogger("itap.config")


class Settings(BaseSettings):
    # ── Application ─────────────────────────────
    APP_NAME: str = "ITAP"
    APP_VERSION: str = "2.0.0"
    APP_DESCRIPTION: str = (
        "Integrated Threat Assessment Platform — "
        "Autonomous Multi-Vector Intelligence & Incident Response"
    )

    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ENVIRONMENT: str = "development"  # development | staging | production

    # ── Database ────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./itap.db"
    REDIS_URL: str = "redis://localhost:6379/0"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_ECHO: bool = False  # Override DEBUG for DB to avoid log flooding
    # SQLite ignores foreign keys unless this pragma is set per connection, which
    # let parent rows be deleted ahead of their children without complaint. Keep it
    # on in dev so referential bugs surface now rather than after a Postgres move.
    DB_SQLITE_ENFORCE_FOREIGN_KEYS: bool = True

    # ── Security ────────────────────────────────
    SECRET_KEY: str = secrets.token_urlsafe(32)  # Regenerated each restart if not set
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480   # 8 hours
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"

    # Built-in user passwords (override in production .env)
    ADMIN_PASSWORD: str = "ITAP@Admin2025!"
    ANALYST_PASSWORD: str = "ITAP@Analyst2025!"
    VIEWER_PASSWORD: str = "ITAP@Viewer2025!"

    # NOTE: validation lives in model_post_init below. This class used to declare
    # both __init__ *and* model_post_init, each warning about a different default;
    # two code paths for one job, and pydantic v2 only guarantees model_post_init.

    # ── CORS ────────────────────────────────────
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:5174,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:5174"

    @property
    def cors_origins(self) -> List[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    # ── Rate Limiting ────────────────────────────
    RATE_LIMIT_REQUESTS: int = 200
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    # The IP limiter exempted loopback unconditionally, which made it dead code in
    # development. /auth/login now has its own per-account throttle (see
    # app.core.security.guard_login) independent of this switch.
    RATE_LIMIT_ALLOW_LOCALHOST: bool = True

    # ── OSINT API Keys ───────────────────────────
    SHODAN_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""
    ALIENVAULT_OTX_KEY: str = ""
    NVD_API_KEY: str = ""           # NVD API key (optional, higher rate limits)

    # ── Nmap Active Scanning ─────────────────────
    NMAP_PATH: str = r"C:\Program Files (x86)\Nmap\nmap.exe"

    # ── ML Configuration ─────────────────────────
    LSTM_MODEL_PATH: str = "ml_models/lstm_predictor.pth"
    AUTOENCODER_MODEL_PATH: str = "ml_models/autoencoder.pth"
    PREDICTION_WINDOW_HOURS: int = 72
    ANOMALY_THRESHOLD: float = 0.82
    ML_RANDOM_SEED: int = 42        # For reproducible simulations

    # ── MITRE ATT&CK ─────────────────────────────
    ATTACK_DATA_PATH: str = "data/mitre_attack.json"

    # ── Email Alerting ───────────────────────────
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "itap-alerts@yourorg.com"
    SMTP_FROM_NAME: str = "ITAP Security Platform"
    SMTP_USE_TLS: bool = True
    ALERT_TO_EMAILS: str = ""       # Comma-separated list of alert recipients

    # ── Webhook Alerting ─────────────────────────
    WEBHOOK_URLS: str = ""          # Comma-separated webhook URLs
    SLACK_WEBHOOK_URL: str = ""
    TEAMS_WEBHOOK_URL: str = ""

    # ── Machine Scanner (this host's own network inventory) ─────
    # The scanner reports the host's public IP and every remote endpoint it is
    # talking to, and resolves those through a third-party geolocation service.
    # That is dev-time convenience rather than core function, so it is opt-in.
    MACHINE_SCAN_ENABLED: bool = False
    MACHINE_SCAN_INTERVAL_SECONDS: int = 60

    # Base URL for the geolocation lookups. ip-api.com's free tier is HTTP-only
    # ("256-bit SSL encryption is not available for this free API" — their docs),
    # so this is configurable rather than hardcoded: point it at an HTTPS
    # endpoint when one is available. Private/loopback/link-local addresses are
    # never sent, whatever this is set to.
    GEOLOCATION_API_BASE: str = "http://ip-api.com"

    # ── WebSocket ────────────────────────────────
    WS_HEARTBEAT_INTERVAL: int = 30  # seconds

    class Config:
        env_file = ".env"
        case_sensitive = True

    def model_post_init(self, __context) -> None:
        """Post-initialization validation and warnings.

        The previous version compared the configured key against
        ``secrets.token_urlsafe(32)`` — a fresh random value on every call — so
        the comparison could never be true and the "SECRET_KEY not set" warning
        could never fire. It also only looked at ENVIRONMENT=production, which
        meant a development instance kept booting with the placeholder from
        ``.env.example`` and minting JWTs that anyone who has read the repo can
        forge (``jwt.encode({"role": "admin"}, "CHANGE_ME...")``).
        """
        # SECRET_KEY is a signing key, not a preference: fail fast everywhere
        # rather than run with a value that is published in this repository.
        if len(self.SECRET_KEY) < 32 or self.SECRET_KEY.startswith("CHANGE_ME"):
            raise RuntimeError(
                "SECRET_KEY is unset, is still the .env.example placeholder, or is "
                "shorter than 32 characters. Anyone who can read it can forge an "
                "admin JWT. Generate one and put it in backend/.env:\n"
                '  python -c "import secrets; print(secrets.token_urlsafe(64))"'
            )

        if self.ADMIN_PASSWORD == "ITAP@Admin2025!":
            logger.warning(
                "Using the default ADMIN_PASSWORD (ITAP@Admin2025!). "
                "Override ADMIN_PASSWORD in .env before exposing this instance."
            )
        if self.DEBUG:
            logger.warning(
                "DEBUG=True — debug logging, SQL echo and interactive /docs are enabled."
            )
        if self.ENVIRONMENT == "production":
            if self.DEBUG:
                logger.critical("DEBUG=True in production environment!")
            if "*" in self.ALLOWED_ORIGINS:
                logger.critical("ALLOWED_ORIGINS contains wildcard — insecure for production!")


settings = Settings()
