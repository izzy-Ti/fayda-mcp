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
    acr_values: Optional[str] = None,
    claims_locales: Optional[str] = None,
    ui_locales: Optional[str] = None,
    display: Optional[str] = "page",
) -> str:
    """Construct Fayda eSignet authorization URL with query parameters matching official spec."""
    if scopes is None:
        scopes = ["openid", "profile", "email"]
    if "openid" not in scopes:
        scopes = ["openid"] + scopes

    acr_val = acr_values or getattr(config, "acr_values", "mosip:idp:acr:generated-code")
    c_loc = claims_locales or (config.claims_locales[0] if getattr(config, "claims_locales", None) else "en")
    u_loc = ui_locales or "en"

    params: Dict[str, str] = {
        "client_id": config.client_id,
        "response_type": "code",
        "redirect_uri": config.redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    if acr_val:
        params["acr_values"] = acr_val

    if claims:
        claims_copy = dict(claims)
        if "id_token" not in claims_copy:
            claims_copy["id_token"] = {}
        params["claims"] = json.dumps(claims_copy)

    if c_loc:
        params["claims_locales"] = c_loc
    if u_loc:
        params["ui_locales"] = u_loc
    if display:
        params["display"] = display

    query_str = urlencode(params)
    sep = "&" if "?" in config.authorization_endpoint else "?"
    return f"{config.authorization_endpoint}{sep}{query_str}"
