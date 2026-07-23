"""Typed application settings loaded from environment variables."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Provide validated configuration for the application and its services."""

    app_name: str = "Secure Authentication API"
    app_env: Literal["development", "testing", "production"] = "development"
    debug: bool = False

    database_url: str

    secret_key: SecretStr = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = Field(default=15, gt=0)
    refresh_token_expire_days: int = Field(default=7, gt=0)

    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_from_email: str = ""

    google_client_id: str = ""
    google_client_secret: SecretStr = SecretStr("")
    github_client_id: str = ""
    github_client_secret: SecretStr = SecretStr("")

    backend_cors_origins: str = "http://localhost:3000"

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[2] / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        """Require a PostgreSQL URL using the psycopg SQLAlchemy driver."""

        if not value.startswith("postgresql+psycopg://"):
            raise ValueError("DATABASE_URL must use postgresql+psycopg://")
        return value

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, value: SecretStr) -> SecretStr:
        """Reject secrets that contain only whitespace characters."""

        if not value.get_secret_value().strip():
            raise ValueError("SECRET_KEY must not be blank")
        return value

    @model_validator(mode="after")
    def validate_production_debug(self) -> "Settings":
        """Prevent debug mode from being enabled in production."""

        if self.app_env == "production" and self.debug:
            raise ValueError("DEBUG must be false when APP_ENV is production")
        return self

    @property
    def cors_origins(self) -> list[str]:
        """Return configured CORS origins as a normalized list of strings."""

        return [
            origin.strip()
            for origin in self.backend_cors_origins.split(",")
            if origin.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    """Create and cache the application settings instance."""

    return Settings()


settings = get_settings()
