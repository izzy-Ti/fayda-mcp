"""Token signature and claims validation."""

from typing import Any, Dict, List, Optional
import jwt
from jwt import PyJWKClient
from fayda_mcp.config import FaydaConfig
from fayda_mcp.exceptions import TokenValidationError


def validate_id_token(
    token_str: str,
    config: FaydaConfig,
    signing_key: Any,
    expected_nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate signed ID token with issuer, audience, expiry, and nonce checks."""
    try:
        claims = jwt.decode(
            token_str,
            signing_key,
            algorithms=config.allowed_algorithms,
            audience=config.client_id,
            issuer=config.issuer,
            leeway=config.jwt_clock_skew_seconds,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except Exception as exc:
        raise TokenValidationError(f"Invalid ID token signature or claims: {exc}") from exc

    if expected_nonce and claims.get("nonce") != expected_nonce:
        raise TokenValidationError("ID token nonce does not match original request nonce")

    return claims
