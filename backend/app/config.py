"""
Application configuration.
Reads from environment variables with sensible defaults for development.
This is the single source of truth for all settings across the app.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ─── App ───
    APP_NAME: str = "Cyber Threat Watch"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False  # opt-in only; never default-on (prevents SQL echo / verbose leakage)

    # ─── Database ───
    DATABASE_URL: str = "postgresql+asyncpg://cybershield:CHANGE_ME@localhost:5432/cybershield"

    # ─── Redis ───
    REDIS_URL: str = "redis://localhost:6379/0"

    # ─── Auth ───
    SECRET_KEY: str = "change-me-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ─── Initial admin bootstrap (production) ───
    # In non-development environments the app does NOT seed default test accounts.
    # If these are set, a single admin is created on first start; otherwise create
    # the first admin with scripts/create_admin.py.
    INITIAL_ADMIN_EMAIL: str = ""
    INITIAL_ADMIN_PASSWORD: str = ""

    # ─── Scraping ───
    SCRAPE_INTERVAL_MINUTES: int = 30

    # ─── Email / SMTP ───
    SMTP_HOST: str = "mailpit"
    SMTP_PORT: int = 1025
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "alerts@example.com"
    SMTP_FROM_NAME: str = "Cyber Threat Watch"
    SMTP_TLS: bool = False
    SMTP_ENABLED: bool = True
    MAX_EMAILS_PER_HOUR: int = 50

    @property
    def SYNC_DATABASE_URL(self) -> str:
        """Convert async database URL to sync for Celery tasks (psycopg2)."""
        return self.DATABASE_URL.replace("+asyncpg", "")

    class Config:
        env_file = ".env"
        case_sensitive = True


# Single instance used across the app
settings = Settings()