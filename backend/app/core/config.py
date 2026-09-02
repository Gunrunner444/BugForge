from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_UNSAFE_DEFAULT_KEY = "change_me_in_production_please"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_name: str = "BugForge"
    version: str = "0.3.0"
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"

    # Database
    database_url: str = "postgresql+asyncpg://bugforge:bugforge_dev@localhost:5432/bugforge"

    # Security — must be overridden in production
    secret_key: str = _UNSAFE_DEFAULT_KEY

    # CORS
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:3001"]

    # Analysis limits
    max_file_size_bytes: int = 5 * 1024 * 1024  # 5 MB
    max_repo_files: int = 10_000
    analysis_timeout_seconds: int = 300

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        v = v.upper()
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return v

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str, info: object) -> str:
        # Prevent the default placeholder from being used in production
        env = getattr(getattr(info, "data", {}), "get", lambda k, d=None: d)("environment", "development")
        if v == _UNSAFE_DEFAULT_KEY and env == "production":
            raise ValueError(
                "SECRET_KEY must be set to a secure random value in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
