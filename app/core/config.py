"""Application configuration loaded via Pydantic settings."""

from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for Fayda MCP Bridge."""

    APP_ENV: str = "development"
    APP_NAME: str = "fayda-mcp-bridge"
    PUBLIC_BASE_URL: str = "https://bridge.example.com"
    LOG_LEVEL: str = "INFO"
    ALLOWED_HOSTS: List[str] = ["bridge.example.com", "localhost"]
    CORS_ORIGINS: List[str] = ["https://portal.example.com"]

    # Database settings (Neon PostgreSQL via async SQLAlchemy + psycopg)
    DATABASE_URL: str = "postgresql+psycopg://USER:PASS@HOST-pooler/DB?sslmode=require"
    DATABASE_MIGRATION_URL: str = "postgresql+psycopg://USER:PASS@HOST/DB?sslmode=require"
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 5

    # Redis settings
    REDIS_URL: str = "rediss://default:PASSWORD@HOST:6379/0"
    REDIS_KEY_PREFIX: str = "fayda_bridge:dev:"
    OIDC_SESSION_TTL_SECONDS: int = 600
    VERIFICATION_LINK_TTL_SECONDS: int = 600
    RESULT_TTL_SECONDS: int = 900
    RATE_LIMIT_PER_MINUTE: int = 30

    # MCP OAuth settings
    MCP_RESOURCE_URL: str = "https://bridge.example.com/mcp"
    MCP_AUTH_ISSUER: str = "https://auth.example.com/"
    MCP_AUTH_JWKS_URL: str = "https://auth.example.com/.well-known/jwks.json"
    MCP_REQUIRED_SCOPES: List[str] = ["verification:create", "verification:read"]

    # Fayda eSignet provider settings
    FAYDA_ENVIRONMENT: str = "sandbox"
    FAYDA_ISSUER_URL: str = "https://REPLACE_APPROVED_ISSUER"
    FAYDA_AUTHORIZATION_URL: str = "https://REPLACE_APPROVED_AUTH_ENDPOINT"
    FAYDA_TOKEN_URL: str = "https://REPLACE_APPROVED_TOKEN_ENDPOINT"
    FAYDA_USERINFO_URL: str = "https://REPLACE_APPROVED_USERINFO_ENDPOINT"
    FAYDA_JWKS_URL: str = "https://REPLACE_APPROVED_JWKS_ENDPOINT"
    FAYDA_REDIRECT_URI: str = "https://bridge.example.com/auth/fayda/callback"
    FAYDA_ALLOWED_ALGORITHMS: List[str] = ["RS256"]
    FAYDA_HTTP_TIMEOUT_SECONDS: int = 10
    FAYDA_CLIENT_ASSERTION_TTL_SECONDS: int = 120

    # Secrets backend
    SECRETS_BACKEND: str = "vault"
    SECRETS_BASE_URL: str = "https://vault.example.com"
    SECRETS_NAMESPACE: str = "fayda-bridge"

    # Retention & JWT parameters
    AUDIT_RETENTION_DAYS: int = 90
    RESULT_RETENTION_DAYS: int = 30
    JWT_CLOCK_SKEW_SECONDS: int = 60
    JWKS_CACHE_TTL_SECONDS: int = 300

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return cached Settings instance."""
    return Settings()
