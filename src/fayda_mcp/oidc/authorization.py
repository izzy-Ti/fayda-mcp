"""OIDC authorization URL, state, nonce, and PKCE parameters generation."""

import base64
import hashlib
import json
import secrets
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode
from fayda_mcp.config import FaydaConfig


def generate_secure_token(nbytes: int = 32) -> str:
    """Generate cryptographically secure URL-safe random string."""
    return secrets.token_urlsafe(nbytes)


def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256) per RFC 7636.

    Returns:
        tuple[code_verifier, code_challenge]
    """
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return verifier, challenge


def build_authorization_url(
    config: FaydaConfig,
    state: str,
    nonce: str,
    code_challenge: str,
    scopes: Optional[List[str]] = None,
    claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Construct Fayda eSignet authorization URL with query parameters."""
    if scopes is None:
        scopes = ["openid"]
    if "openid" not in scopes:
        scopes = ["openid"] + scopes

    params: Dict[str, str] = {
        "response_type": "code",
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    if claims:
        params["claims"] = json.dumps(claims)

    query_str = urlencode(params)
    sep = "&" if "?" in config.authorization_endpoint else "?"
    return f"{config.authorization_endpoint}{sep}{query_str}"
