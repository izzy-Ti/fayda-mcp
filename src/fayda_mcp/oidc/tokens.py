"""Token signature and claims validation."""

from typing import Any, Dict, List, Optional
import jwt
from fayda_mcp.config import FaydaConfig
from fayda_mcp.exceptions import TokenValidationError


def validate_id_token(
    token_str: str,
    config: FaydaConfig,
    signing_key: Any,
    expected_nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate signed ID token with issuer, audience, expiry, and nonce checks per OIDC Core.

    Args:
        token_str: Encoded JWT string.
        config: Provider configuration.
        signing_key: Public key or PyJWK for signature verification.
        expected_nonce: Expected nonce bound to original request.

    Returns:
        Validated claims dictionary.

    Raises:
        TokenValidationError on forged, unsigned, expired, wrong issuer, wrong audience, or bad nonce.
    """
    if not token_str or not isinstance(token_str, str):
        raise TokenValidationError("ID token must be a non-empty string")

    # Reject unsigned tokens
    try:
        header = jwt.get_unverified_header(token_str)
    except Exception as exc:
        raise TokenValidationError(f"Malformed token header: {exc}") from exc

    alg = header.get("alg")
    if not alg or alg.lower() == "none":
        raise TokenValidationError("Unsigned JWT (alg=none) is strictly prohibited")

    if alg not in config.allowed_algorithms:
        raise TokenValidationError(
            f"Algorithm '{alg}' is not in allowed algorithms: {config.allowed_algorithms}"
        )

    try:
        claims = jwt.decode(
            token_str,
            signing_key,
            algorithms=config.allowed_algorithms,
            audience=config.client_id,
            issuer=config.issuer,
            leeway=config.jwt_clock_skew_seconds,
            options={
                "verify_signature": True,
                "require": ["exp", "iss", "aud", "sub"],
            },
        )
    except Exception as exc:
        raise TokenValidationError(f"Invalid ID token signature or claims: {exc}") from exc

    if not claims.get("sub"):
        raise TokenValidationError("ID token must contain non-empty 'sub' claim")

    if expected_nonce is not None:
        token_nonce = claims.get("nonce")
        if token_nonce != expected_nonce:
            raise TokenValidationError(
                f"ID token nonce '{token_nonce}' does not match expected nonce '{expected_nonce}'"
            )

    return claims


def validate_userinfo_response(
    userinfo: Any,
    config: FaydaConfig,
    expected_sub: str,
    signing_key: Optional[Any] = None,
) -> Dict[str, Any]:
    """Validate UserInfo response and ensure subject matches ID token subject.

    Args:
        userinfo: UserInfo dict or signed JWT string.
        config: Provider configuration.
        expected_sub: Subject from validated ID token.
        signing_key: Optional public key if UserInfo is a signed JWT.

    Returns:
        Validated UserInfo dictionary.

    Raises:
        TokenValidationError if subject does not match or JWT signature fails.
    """
    if isinstance(userinfo, str):
        # Signed UserInfo JWT
        if signing_key is None:
            raise TokenValidationError("Signing key required for signed UserInfo response")
        try:
            claims = jwt.decode(
                userinfo,
                signing_key,
                algorithms=config.allowed_algorithms,
                audience=config.client_id,
                issuer=config.issuer,
                leeway=config.jwt_clock_skew_seconds,
                options={"verify_signature": True, "require": ["sub"]},
            )
        except Exception as exc:
            raise TokenValidationError(f"Invalid UserInfo JWT: {exc}") from exc
    elif isinstance(userinfo, dict):
        claims = dict(userinfo)
    else:
        raise TokenValidationError(f"Unexpected UserInfo response type: {type(userinfo)}")

    userinfo_sub = claims.get("sub")
    if not userinfo_sub:
        raise TokenValidationError("UserInfo response must contain non-empty 'sub' claim")

    if userinfo_sub != expected_sub:
        raise TokenValidationError(
            f"UserInfo subject '{userinfo_sub}' does not match ID token subject '{expected_sub}'"
        )

    return claims
