"""Validated configuration for Fayda eSignet integration."""

import os
from typing import Any, List, Optional
from pydantic import BaseModel, Field


class FaydaConfig(BaseModel):
    """Configuration for Fayda eSignet relying-party integration."""

    client_id: str = Field(..., min_length=1, description="Registered Fayda client ID")
    redirect_uri: str = Field(..., min_length=1, description="Registered developer callback URL")
    issuer: str = Field(..., min_length=1, description="Fayda OIDC issuer URL")
    authorization_endpoint: str = Field(..., min_length=1, description="Fayda eSignet authorization endpoint")
    token_endpoint: str = Field(..., min_length=1, description="Fayda token endpoint")
    userinfo_endpoint: str = Field(..., min_length=1, description="Fayda UserInfo endpoint")
    jwks_uri: str = Field(..., min_length=1, description="Fayda JWKS endpoint for public key validation")

    # Optional local private key path or direct key material
    signing_key_path: Optional[str] = Field(default=None, description="Path to client private signing key")
    signing_key: Optional[str] = Field(default=None, repr=False, description="Direct client private signing key in PEM format")
    key_id: Optional[str] = Field(default=None, description="Key ID (kid) for JWS client assertion headers")

    def to_redacted_dict(self) -> dict[str, Any]:
        """Return configuration dictionary with all secret material redacted."""
        data = self.model_dump()
        if data.get("signing_key"):
            data["signing_key"] = "[REDACTED]"
        return data


    # Cryptographic & network settings
    allowed_algorithms: List[str] = Field(default_factory=lambda: ["RS256"])
    http_timeout_seconds: float = 10.0
    client_assertion_ttl_seconds: int = 120
    session_ttl_seconds: int = 600
    result_ttl_seconds: int = 900
    jwt_clock_skew_seconds: int = 60
    jwks_cache_ttl_seconds: int = 300
    jwks_refresh_after_seconds: int = Field(default=240, description="Seconds after which JWKS keys should be refreshed in the background")
    jwks_hard_ttl_seconds: int = Field(default=300, description="Hard TTL seconds before JWKS keys are considered hard-expired")
    jwks_hard_expiry_factor: float = Field(default=2.0, description="Multiplier on TTL to compute hard expiry")
    jwks_refresh_factor: float = Field(default=0.8, description="Multiplier on TTL to compute refresh_at")
    jwks_jitter_ratio: float = Field(default=0.05, description="Random jitter ratio applied to refresh_at")
    jwks_base_backoff_seconds: float = Field(default=1.0, description="Base exponential backoff seconds for failed JWKS refreshes")
    jwks_max_backoff_seconds: float = Field(default=60.0, description="Max backoff seconds for failed JWKS refreshes")
    jwks_stale_grace_seconds: float = Field(default=0.0, description="Grace period seconds past hard expiry where known keys may be used if refresh fails (default 0.0 = zero stale grace)")
    jwks_unknown_kid_cooldown_seconds: float = Field(default=30.0, description="Minimum seconds between synchronous refreshes triggered by unknown kids")
    jwks_negative_cache_ttl_seconds: float = Field(default=30.0, description="TTL in seconds for negative caching of unknown kids")
    storage_mode: str = Field(default="memory", description="Active storage backend: memory, redis-postgres, or redis")
    dob_source_calendar: str = Field(default="gregorian", description="Explicit calendar convention for DOB claim: 'gregorian' or 'ethiopic'")
    age_evaluation_timezone: str = Field(default="Africa/Addis_Ababa", description="Host evaluation timezone for age checks")
    february_29_anniversary: str = Field(default="march_1", description="Anniversary rule for Feb 29 birthdates in common years ('march_1' or 'february_28')")
    claims_locales: List[str] = Field(default_factory=lambda: ["en", "am", "om", "so", "ti", "sid", "wal"], description="Permitted/supported selection locales")

    @classmethod
    def from_env(cls, env_prefix: str = "FAYDA_", dotenv_path: Optional[str] = None) -> "FaydaConfig":
        """Explicit helper to load configuration from environment variables or .env file."""
        if dotenv_path:
            try:
                from dotenv import load_dotenv
                load_dotenv(dotenv_path)
            except ImportError:
                pass

        def get_val(*keys: str, default: str = "") -> str:
            for k in keys:
                v = os.environ.get(k)
                if v is not None and v != "":
                    return v
            return default

        client_id = get_val(f"{env_prefix}CLIENT_ID", "CLIENT_ID")
        redirect_uri = get_val(f"{env_prefix}REDIRECT_URI", "REDIRECT_URI")
        auth_endpoint = get_val(
            f"{env_prefix}AUTHORIZATION_URL",
            f"{env_prefix}AUTHORIZATION_ENDPOINT",
            "AUTHORIZATION_URL",
            "AUTHORIZATION_ENDPOINT",
        )
        token_endpoint = get_val(
            f"{env_prefix}TOKEN_URL",
            f"{env_prefix}TOKEN_ENDPOINT",
            "TOKEN_URL",
            "TOKEN_ENDPOINT",
        )
        userinfo_endpoint = get_val(
            f"{env_prefix}USERINFO_URL",
            f"{env_prefix}USERINFO_ENDPOINT",
            "USERINFO_URL",
            "USERINFO_ENDPOINT",
        )

        # Derive issuer if not explicit
        issuer = get_val(f"{env_prefix}ISSUER_URL", f"{env_prefix}ISSUER", "ISSUER_URL", "ISSUER")
        if not issuer and auth_endpoint:
            from urllib.parse import urlparse
            parsed = urlparse(auth_endpoint)
            issuer = f"{parsed.scheme}://{parsed.netloc}"

        # Derive jwks_uri if not explicit
        jwks_uri = get_val(f"{env_prefix}JWKS_URL", f"{env_prefix}JWKS_URI", "JWKS_URL", "JWKS_URI")
        if not jwks_uri and token_endpoint:
            if "/token" in token_endpoint:
                jwks_uri = token_endpoint.replace("/token", "/jwks")
            elif issuer:
                jwks_uri = f"{issuer}/v1/esignet/oauth/v2/jwks"

        # Resolve private key
        raw_key = get_val(
            f"{env_prefix}PRIVATE_KEY",
            f"{env_prefix}SIGNING_KEY",
            "PRIVATE_KEY",
            "SIGNING_KEY",
        )
        signing_key_path = get_val(f"{env_prefix}SIGNING_KEY_PATH", "SIGNING_KEY_PATH", default="") or None
        signing_key: Optional[str] = None
        key_id = get_val(f"{env_prefix}KEY_ID", "KEY_ID", default="") or None

        if raw_key:
            from fayda_mcp.secrets.keys import parse_private_key
            try:
                pem, parsed_kid = parse_private_key(raw_key)
                signing_key = pem
                if parsed_kid and not key_id:
                    key_id = parsed_kid
            except Exception:
                signing_key = raw_key
        elif signing_key_path and os.path.exists(signing_key_path):
            with open(signing_key_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            from fayda_mcp.secrets.keys import parse_private_key
            pem, parsed_kid = parse_private_key(content)
            signing_key = pem
            if parsed_kid and not key_id:
                key_id = parsed_kid

        exp_time = get_val(f"{env_prefix}EXPIRATION_TIME", "EXPIRATION_TIME", default="")
        ttl_seconds = int(exp_time) if exp_time and exp_time.isdigit() else 120

        algorithm = get_val(f"{env_prefix}ALGORITHM", "ALGORITHM", default="RS256")

        return cls(
            client_id=client_id,
            redirect_uri=redirect_uri,
            issuer=issuer,
            authorization_endpoint=auth_endpoint,
            token_endpoint=token_endpoint,
            userinfo_endpoint=userinfo_endpoint,
            jwks_uri=jwks_uri,
            signing_key_path=signing_key_path,
            signing_key=signing_key,
            key_id=key_id,
            allowed_algorithms=[algorithm],
            client_assertion_ttl_seconds=ttl_seconds,
            session_ttl_seconds=int(get_val(f"{env_prefix}SESSION_TTL_SECONDS", "SESSION_TTL_SECONDS", default="600")),
            result_ttl_seconds=int(get_val(f"{env_prefix}RESULT_TTL_SECONDS", "RESULT_TTL_SECONDS", default="900")),
            jwks_cache_ttl_seconds=int(get_val(f"{env_prefix}JWKS_CACHE_TTL_SECONDS", "JWKS_CACHE_TTL_SECONDS", default="300")),
            jwks_refresh_after_seconds=int(get_val(f"{env_prefix}JWKS_REFRESH_AFTER_SECONDS", "JWKS_REFRESH_AFTER_SECONDS", default="240")),
            jwks_hard_ttl_seconds=int(get_val(f"{env_prefix}JWKS_HARD_TTL_SECONDS", f"{env_prefix}JWKS_HARD_TTL", "JWKS_HARD_TTL_SECONDS", default="300")),
            jwks_hard_expiry_factor=float(get_val(f"{env_prefix}JWKS_HARD_EXPIRY_FACTOR", "JWKS_HARD_EXPIRY_FACTOR", default="2.0")),
            jwks_refresh_factor=float(get_val(f"{env_prefix}JWKS_REFRESH_FACTOR", "JWKS_REFRESH_FACTOR", default="0.8")),
            jwks_jitter_ratio=float(get_val(f"{env_prefix}JWKS_JITTER_RATIO", "JWKS_JITTER_RATIO", default="0.05")),
            jwks_base_backoff_seconds=float(get_val(f"{env_prefix}JWKS_BASE_BACKOFF_SECONDS", "JWKS_BASE_BACKOFF_SECONDS", default="1.0")),
            jwks_max_backoff_seconds=float(get_val(f"{env_prefix}JWKS_MAX_BACKOFF_SECONDS", "JWKS_MAX_BACKOFF_SECONDS", default="60.0")),
            jwks_stale_grace_seconds=float(get_val(f"{env_prefix}JWKS_STALE_GRACE_SECONDS", "JWKS_STALE_GRACE_SECONDS", default="0.0")),
            jwks_unknown_kid_cooldown_seconds=float(get_val(f"{env_prefix}JWKS_UNKNOWN_KID_COOLDOWN_SECONDS", "JWKS_UNKNOWN_KID_COOLDOWN_SECONDS", default="30.0")),
            jwks_negative_cache_ttl_seconds=float(get_val(f"{env_prefix}JWKS_NEGATIVE_CACHE_TTL_SECONDS", "JWKS_NEGATIVE_CACHE_TTL_SECONDS", default="30.0")),
            storage_mode=get_val(f"{env_prefix}STORAGE_MODE", "STORAGE_MODE", default="memory"),
            dob_source_calendar=get_val(f"{env_prefix}DOB_SOURCE_CALENDAR", "DOB_SOURCE_CALENDAR", default="gregorian"),
            age_evaluation_timezone=get_val(f"{env_prefix}AGE_EVALUATION_TIMEZONE", "AGE_EVALUATION_TIMEZONE", default="Africa/Addis_Ababa"),
            february_29_anniversary=get_val(f"{env_prefix}FEBRUARY_29_ANNIVERSARY", "FEBRUARY_29_ANNIVERSARY", default="march_1"),
            claims_locales=[
                loc.strip() for loc in get_val(f"{env_prefix}CLAIMS_LOCALES", "CLAIMS_LOCALES", default="en am om so ti sid wal").replace(",", " ").split() if loc.strip()
            ],
        )

    @classmethod
    def sandbox(
        cls,
        client_id: str,
        redirect_uri: str,
        signing_key_path: Optional[str] = None,
        **kwargs: Any,
    ) -> "FaydaConfig":
        """Convenience preset helper pre-populating Ethiopian Fayda eSignet sandbox endpoints."""
        return cls(
            client_id=client_id,
            redirect_uri=redirect_uri,
            issuer="https://esignet.sandbox.fayda.et",
            authorization_endpoint="https://esignet.sandbox.fayda.et/authorize",
            token_endpoint="https://esignet.sandbox.fayda.et/v1/esignet/oauth/v2/token",
            userinfo_endpoint="https://esignet.sandbox.fayda.et/v1/esignet/oidc/userinfo",
            jwks_uri="https://esignet.sandbox.fayda.et/v1/esignet/oauth/v2/jwks",
            signing_key_path=signing_key_path,
            **kwargs,
        )
