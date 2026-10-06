"""Validated configuration for Fayda eSignet integration."""

import os
from typing import List, Optional
from pydantic import BaseModel, Field


class FaydaConfig(BaseModel):
    """Configuration for Fayda eSignet relying-party integration."""

    client_id: str = Field(..., description="Registered Fayda client ID")
    redirect_uri: str = Field(..., description="Registered developer callback URL")
    issuer: str = Field(..., description="Fayda OIDC issuer URL")
    authorization_endpoint: str = Field(..., description="Fayda eSignet authorization endpoint")
    token_endpoint: str = Field(..., description="Fayda token endpoint")
    userinfo_endpoint: str = Field(..., description="Fayda UserInfo endpoint")
    jwks_uri: str = Field(..., description="Fayda JWKS endpoint for public key validation")

    # Optional local private key path or key reference
    signing_key_path: Optional[str] = Field(None, description="Path to client private signing key")

    # Cryptographic & network settings
    allowed_algorithms: List[str] = Field(default_factory=lambda: ["RS256"])
    http_timeout_seconds: float = 10.0
    client_assertion_ttl_seconds: int = 120
    session_ttl_seconds: int = 600
    result_ttl_seconds: int = 900
    jwt_clock_skew_seconds: int = 60
    jwks_cache_ttl_seconds: int = 300

    @classmethod
    def from_env(cls, env_prefix: str = "FAYDA_") -> "FaydaConfig":
        """Explicit helper to load configuration from environment variables."""
        return cls(
            client_id=os.environ.get(f"{env_prefix}CLIENT_ID", ""),
            redirect_uri=os.environ.get(f"{env_prefix}REDIRECT_URI", ""),
            issuer=os.environ.get(f"{env_prefix}ISSUER_URL", ""),
            authorization_endpoint=os.environ.get(f"{env_prefix}AUTHORIZATION_URL", ""),
            token_endpoint=os.environ.get(f"{env_prefix}TOKEN_URL", ""),
            userinfo_endpoint=os.environ.get(f"{env_prefix}USERINFO_URL", ""),
            jwks_uri=os.environ.get(f"{env_prefix}JWKS_URL", ""),
            signing_key_path=os.environ.get(f"{env_prefix}SIGNING_KEY_PATH"),
            session_ttl_seconds=int(os.environ.get(f"{env_prefix}SESSION_TTL_SECONDS", "600")),
            result_ttl_seconds=int(os.environ.get(f"{env_prefix}RESULT_TTL_SECONDS", "900")),
        )
