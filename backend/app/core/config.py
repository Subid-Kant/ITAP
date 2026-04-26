"""
ITAP — Configuration Management
Central configuration using pydantic-settings for environment variable management.
"""
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "ITAP"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "Integrated Threat Assessment Platform — Autonomous Multi-Vector Intelligence"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://itap:itap@localhost:5432/itap_db"
    REDIS_URL: str = "redis://localhost:6379/0"

    # OSINT API Keys
    SHODAN_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""
    ALIENVAULT_OTX_KEY: str = ""

    # ML Configuration
    LSTM_MODEL_PATH: str = "ml_models/lstm_predictor.pth"
    AUTOENCODER_MODEL_PATH: str = "ml_models/autoencoder.pth"
    PREDICTION_WINDOW_HOURS: int = 72
    ANOMALY_THRESHOLD: float = 0.85

    # Security
    SECRET_KEY: str = "itap-secret-key-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    ALGORITHM: str = "HS256"

    # MITRE ATT&CK
    ATTACK_DATA_PATH: str = "data/mitre_attack.json"

    # Alerting
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    WEBHOOK_URLS: str = ""

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
