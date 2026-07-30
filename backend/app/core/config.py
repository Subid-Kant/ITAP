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

    # ── Security ────────────────────────────────
    SECRET_KEY: str = secrets.token_urlsafe(32)  # Regenerated each restart if not set
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480   # 8 hours
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"

    # Built-in user passwords (override in production .env)
    ADMIN_PASSWORD: str = "ITAP@Admin2025!"
    ANALYST_PASSWORD: str = "ITAP@Analyst2025!"
    VIEWER_PASSWORD: str = "ITAP@Viewer2025!"

    # ── CORS ────────────────────────────────────
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:5174,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:5174"

    @property
    def cors_origins(self) -> List[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    # ── Rate Limiting ────────────────────────────
    RATE_LIMIT_REQUESTS: int = 200
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # ── OSINT API Keys ───────────────────────────
    SHODAN_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""
    ALIENVAULT_OTX_KEY: str = ""
    NVD_API_KEY: str = ""           # NVD API key (optional, higher rate limits)

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

    # ── WebSocket ────────────────────────────────
    WS_HEARTBEAT_INTERVAL: int = 30  # seconds

    class Config:
        env_file = ".env"
        case_sensitive = True

    def model_post_init(self, __context) -> None:
        """Post-initialization validation and warnings."""
        if self.ENVIRONMENT == "production":
            if self.SECRET_KEY == secrets.token_urlsafe(32):
                logger.critical(
                    "SECRET_KEY not set in .env! Using insecure random key. "
                    "All sessions will be invalidated on restart."
                )
            if self.DEBUG:
                logger.warning("DEBUG=True in production environment!")
            if "*" in self.ALLOWED_ORIGINS:
                logger.critical("ALLOWED_ORIGINS contains wildcard — insecure for production!")


settings = Settings()
