"""Validated configuration for Fayda eSignet integration."""

import os
import re
from typing import Any, List, Optional, Union
from pydantic import BaseModel, Field


def parse_expiration_time(
    raw_val: Union[str, int, float, None],
    unit_hint: Optional[str] = None,
    default_seconds: int = 120,
) -> int:
    """Parse and confirm expiration time unit into integer seconds.

    Supports:
    - String with units: '15m', '15min', '900s', '1h', etc.
    - Explicit unit_hint ('minutes', 'seconds', etc.)
    - Fayda Portal numeric default: Fayda exports EXPIRATION_TIME=15 (minutes).
      Values <= 60 without explicit unit designation are interpreted as minutes (val * 60).
      Values > 60 without unit designation are interpreted as seconds.
    """
    if raw_val is None:
        return default_seconds

    val_str = str(raw_val).strip()
    if not val_str:
        return default_seconds

    match = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]*)$", val_str.lower())
    if not match:
        return default_seconds

    clean_num = float(match.group(1))
    suffix_unit = match.group(2).strip()
    unit = suffix_unit or (unit_hint.lower().strip() if unit_hint else "")

    if unit in ("m", "min", "mins", "minute", "minutes"):
        return max(1, int(clean_num * 60))
    elif unit in ("s", "sec", "secs", "second", "seconds"):
        return max(1, int(clean_num))
    elif unit in ("h", "hr", "hrs", "hour", "hours"):
        return max(1, int(clean_num * 3600))
    elif unit in ("ms", "msec", "millis", "millisecond", "milliseconds"):
        return max(1, int(clean_num / 1000.0))
    else:
        # Confirm expiry unit: Fayda portal exports EXPIRATION_TIME=15 which represents 15 minutes.
        if clean_num <= 60:
            return max(1, int(clean_num * 60))
        return max(1, int(clean_num))


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
    algorithm: str = Field(default="RS256", description="JWS signing algorithm for client assertions")
    client_assertion_type: str = Field(
        default="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        description="Client assertion type",
    )
    acr_values: str = Field(
        default="mosip:idp:acr:generated-code",
        description="Fayda ACR authentication context class reference",
    )

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

    # QR verification settings (Task 19)
    qr_verification_enabled: bool = Field(
        default=False,
        description="Enable offline Fayda QR verification route. Default is False (disabled) for fail-closed security.",
    )
    qr_profile: str = Field(
        default="v4",
        description="Default/target QR format profile version (e.g. 'v4')",
    )
    qr_allowed_profiles: List[str] = Field(
        default_factory=lambda: ["v4"],
        description="Permitted QR specification profiles (e.g. ['v4'])",
    )
    qr_key_bundle_path: Optional[str] = Field(
        default=None,
        description="Path to operator-managed QR public key bundle or directory",
    )
    qr_public_key_pem: Optional[str] = Field(
        default=None,
        description="Inline operator-approved QR public key PEM string",
    )
    qr_max_text_size_bytes: int = Field(
        default=16384,
        description="Maximum permitted QR scanner text size in bytes (bounded memory protection, default 16KB)",
    )
    qr_dob_calendar: str = Field(
        default="gregorian",
        description="Default confirmed calendar convention for QR DOB claims ('gregorian' or 'ethiopic')",
    )
    qr_confirmed_calendars: List[str] = Field(
        default_factory=lambda: ["gregorian", "ethiopic"],
        description="List of recognized confirmed calendar systems for QR age predicates",
    )

    def load_qr_trust_store(self) -> Any:
        """Instantiate a QRTrustStore from configured bundle path or inline PEM."""
        from fayda_mcp.qr.trust import load_trust_store_from_config
        return load_trust_store_from_config(
            bundle_path=self.qr_key_bundle_path,
            inline_pem=self.qr_public_key_pem,
        )

    @classmethod
    def from_env(cls, env_prefix: str = "FAYDA_", dotenv_path: Optional[str] = None) -> "FaydaConfig":
        """Explicit helper to load configuration from environment variables or .env file.

        Priority order:
        1. FAYDA_ prefixed variables (e.g. FAYDA_CLIENT_ID, FAYDA_JWKS_URL)
        2. Standard/Portal variables (e.g. CLIENT_ID, PRIVATE_KEY, EXPIRATION_TIME)
        3. Trusted OIDC discovery for unresolved endpoints (issuer, jwks_uri)
        4. Safe domain-derived fallback endpoints
        """
        if dotenv_path:
            try:
                from dotenv import load_dotenv
                load_dotenv(dotenv_path, override=False)
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
            f"{env_prefix}AUTHORIZATION_ENDPOINT",
            f"{env_prefix}AUTHORIZATION_URL",
            "AUTHORIZATION_ENDPOINT",
            "AUTHORIZATION_URL",
        )
        token_endpoint = get_val(
            f"{env_prefix}TOKEN_ENDPOINT",
            f"{env_prefix}TOKEN_URL",
            "TOKEN_ENDPOINT",
            "TOKEN_URL",
        )
        userinfo_endpoint = get_val(
            f"{env_prefix}USERINFO_ENDPOINT",
            f"{env_prefix}USERINFO_URL",
            "USERINFO_ENDPOINT",
            "USERINFO_URL",
        )

        explicit_issuer = get_val(f"{env_prefix}ISSUER", f"{env_prefix}ISSUER_URL", "ISSUER", "ISSUER_URL")
        explicit_jwks_uri = get_val(f"{env_prefix}JWKS_URI", f"{env_prefix}JWKS_URL", "JWKS_URI", "JWKS_URL")

        # 4. Resolve issuer and JWKS URL through trusted OIDC discovery with explicit overrides
        discovered: Optional[dict[str, Any]] = None
        if not explicit_issuer or not explicit_jwks_uri:
            candidate_url = explicit_issuer or auth_endpoint or token_endpoint or userinfo_endpoint
            if candidate_url:
                try:
                    from fayda_mcp.oidc.discovery import discover_oidc_configuration
                    discovered = discover_oidc_configuration(candidate_url, timeout=2.5)
                except Exception:
                    discovered = None

        issuer = explicit_issuer or (discovered.get("issuer", "") if discovered else "")
        jwks_uri = explicit_jwks_uri or (discovered.get("jwks_uri", "") if discovered else "")

        if not auth_endpoint and discovered:
            auth_endpoint = discovered.get("authorization_endpoint", "")
        if not token_endpoint and discovered:
            token_endpoint = discovered.get("token_endpoint", "")
        if not userinfo_endpoint and discovered:
            userinfo_endpoint = discovered.get("userinfo_endpoint", "")

        # Safe fallback if discovery unavailable or offline
        if not issuer and (auth_endpoint or token_endpoint):
            from urllib.parse import urlparse
            parsed = urlparse(auth_endpoint or token_endpoint)
            if parsed.scheme and parsed.netloc:
                issuer = f"{parsed.scheme}://{parsed.netloc}"

        if not jwks_uri:
            if issuer:
                jwks_uri = f"{issuer}/.well-known/jwks.json"
            elif token_endpoint and "/token" in token_endpoint:
                jwks_uri = token_endpoint.replace("/token", "/jwks")

        # 2. Resolve private key from base64 RSA JWK, raw JWK, PEM, or file path
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
                # If raw_key was an existing file path, keep signing_key_path
                if not signing_key_path and isinstance(raw_key, str) and os.path.isfile(raw_key):
                    signing_key_path = raw_key
            except Exception:
                signing_key = raw_key
        elif signing_key_path:
            from fayda_mcp.secrets.keys import parse_private_key
            try:
                pem, parsed_kid = parse_private_key(signing_key_path)
                signing_key = pem
                if parsed_kid and not key_id:
                    key_id = parsed_kid
            except Exception:
                pass

        # 3. Support ALGORITHM and EXPIRATION_TIME with unit confirmation
        algorithm = get_val(f"{env_prefix}ALGORITHM", "ALGORITHM", default="RS256")
        client_assertion_type = get_val(
            f"{env_prefix}CLIENT_ASSERTION_TYPE",
            "CLIENT_ASSERTION_TYPE",
            default="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )

        exp_time_val = get_val(f"{env_prefix}EXPIRATION_TIME", "EXPIRATION_TIME", default="")
        exp_unit_hint = get_val(
            f"{env_prefix}EXPIRATION_UNIT",
            f"{env_prefix}EXPIRATION_TIME_UNIT",
            "EXPIRATION_UNIT",
            "EXPIRATION_TIME_UNIT",
            default="",
        ) or None

        ttl_seconds = parse_expiration_time(exp_time_val, unit_hint=exp_unit_hint, default_seconds=120)

        allowed_algs = [algorithm]
        if "RS256" not in allowed_algs:
            allowed_algs.append("RS256")

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
            algorithm=algorithm,
            client_assertion_type=client_assertion_type,
            allowed_algorithms=allowed_algs,
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
            acr_values=get_val(f"{env_prefix}ACR_VALUES", "ACR_VALUES", default="mosip:idp:acr:generated-code"),
            claims_locales=[
                loc.strip() for loc in get_val(f"{env_prefix}CLAIMS_LOCALES", "CLAIMS_LOCALES", default="en am om so ti sid wal").replace(",", " ").split() if loc.strip()
            ],
            qr_verification_enabled=get_val(
                f"{env_prefix}QR_VERIFICATION_ENABLED",
                f"{env_prefix}QR_ENABLED",
                "QR_VERIFICATION_ENABLED",
                "QR_ENABLED",
                default="false",
            ).strip().lower() in ("true", "1", "yes", "on", "enabled"),
            qr_profile=get_val(
                f"{env_prefix}QR_PROFILE",
                "QR_PROFILE",
                default="v4",
            ),
            qr_allowed_profiles=[
                p.strip()
                for p in get_val(
                    f"{env_prefix}QR_ALLOWED_PROFILES",
                    "QR_ALLOWED_PROFILES",
                    default="v4",
                ).replace(",", " ").split()
                if p.strip()
            ] or ["v4"],
            qr_max_text_size_bytes=int(
                get_val(
                    f"{env_prefix}QR_MAX_TEXT_SIZE_BYTES",
                    f"{env_prefix}QR_MAX_SIZE_BYTES",
                    "QR_MAX_TEXT_SIZE_BYTES",
                    "QR_MAX_SIZE_BYTES",
                    default="16384",
                )
            ),
            qr_dob_calendar=get_val(
                f"{env_prefix}QR_DOB_CALENDAR",
                f"{env_prefix}QR_CALENDAR",
                "QR_DOB_CALENDAR",
                "QR_CALENDAR",
                default="gregorian",
            ),
            qr_confirmed_calendars=[
                c.strip().lower()
                for c in get_val(
                    f"{env_prefix}QR_CONFIRMED_CALENDARS",
                    "QR_CONFIRMED_CALENDARS",
                    default="gregorian ethiopic",
                ).replace(",", " ").split()
                if c.strip()
            ] or ["gregorian", "ethiopic"],
            qr_key_bundle_path=get_val(f"{env_prefix}QR_KEY_BUNDLE_PATH", "QR_KEY_BUNDLE_PATH", default="") or None,
            qr_public_key_pem=get_val(f"{env_prefix}QR_PUBLIC_KEY_PEM", "QR_PUBLIC_KEY_PEM", default="") or None,
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
