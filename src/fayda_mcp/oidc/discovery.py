"""Trusted OpenID Connect Discovery helper for Fayda eSignet.

Retrieves and validates metadata from standard OIDC discovery endpoints:
- {origin}/.well-known/openid-configuration
- {issuer}/.well-known/openid-configuration
- {origin}/.well-known/oauth-authorization-server (RFC 8414)

Enforces HTTPS on remote endpoints (unless localhost/127.0.0.1 for testing).
Explicit configuration variables always override discovered values.
Never skips cryptographic token validation.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import httpx


def _is_secure_host(parsed_url: Any) -> bool:
    """Check if URL uses HTTPS or is local development."""
    if parsed_url.scheme == "https":
        return True
    host = (parsed_url.hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1", "testserver")


def discover_oidc_configuration(
    candidate_url_or_issuer: str,
    timeout: float = 5.0,
    client: Optional[httpx.Client] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve and validate OIDC discovery metadata document.

    Args:
        candidate_url_or_issuer: URL of issuer, auth endpoint, or token endpoint.
        timeout: Timeout in seconds for discovery HTTP request.
        client: Optional existing httpx.Client instance.

    Returns:
        Validated dictionary of discovered endpoints, or None if discovery failed/offline.
    """
    if not candidate_url_or_issuer or not isinstance(candidate_url_or_issuer, str):
        return None

    raw = candidate_url_or_issuer.strip()
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"

    parsed = urlparse(raw)
    if not parsed.netloc:
        return None

    if not _is_secure_host(parsed):
        return None

    scheme = parsed.scheme
    netloc = parsed.netloc
    base_url = f"{scheme}://{netloc}"
    path = parsed.path.rstrip("/")

    # Construct discovery candidate endpoints in priority order
    candidate_urls: List[str] = [
        # Standard root discovery (used by Fayda eSignet: https://esignet.ida.fayda.et/.well-known/openid-configuration)
        f"{base_url}/.well-known/openid-configuration",
    ]

    # If a sub-path exists (e.g. /v1/esignet), also try path-scoped discovery
    if path and path != "/.well-known" and not path.startswith("/.well-known/"):
        candidate_urls.append(f"{base_url}{path}/.well-known/openid-configuration")

    # RFC 8414 OAuth 2.0 Authorization Server metadata
    candidate_urls.append(f"{base_url}/.well-known/oauth-authorization-server")

    close_client = False
    http_cli = client
    if http_cli is None:
        http_cli = httpx.Client(
            timeout=timeout,
            headers={"User-Agent": "fayda-mcp/0.1.0"},
            follow_redirects=True,
        )
        close_client = True

    try:
        for disc_url in candidate_urls:
            try:
                resp = http_cli.get(disc_url)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict):
                        issuer = data.get("issuer")
                        jwks_uri = data.get("jwks_uri")
                        # Must contain at least an issuer and jwks_uri
                        if issuer and jwks_uri:
                            # Verify discovered jwks_uri is also on secure host
                            parsed_jwks = urlparse(jwks_uri)
                            if not _is_secure_host(parsed_jwks):
                                continue
                            return data
            except Exception:
                continue
    finally:
        if close_client:
            http_cli.close()

    return None
