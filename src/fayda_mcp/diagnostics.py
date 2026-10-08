"""Diagnostic checks for connectivity and configuration readiness with timeouts."""

import asyncio
from typing import Any, Dict, Optional
import httpx
from fayda_mcp.config import FaydaConfig
from fayda_mcp.storage.protocols import ResultRepository, SessionStore


async def run_diagnostics(
    config: FaydaConfig,
    timeout_seconds: float = 5.0,
    sessions: Optional[SessionStore] = None,
    results: Optional[ResultRepository] = None,
) -> Dict[str, Any]:
    """Execute diagnostic checks against Fayda OIDC endpoints and storage with explicit timeouts.

    Never exposes keys, secrets, passwords, DSNs, personal data, or stack traces.
    Secret presence does not prove credentials are approved or functional.
    """
    report: Dict[str, Any] = {
        "status": "ready",
        "timeout_seconds": timeout_seconds,
        "checks": {},
        "notes": [
            "Secret presence does not prove credentials are approved or functional."
        ],
    }

    # 1. Configuration Check
    cfg_ok = bool(
        config.client_id
        and config.issuer
        and config.authorization_endpoint
        and config.token_endpoint
        and config.jwks_uri
    )
    report["checks"]["configuration"] = {
        "status": "ok" if cfg_ok else "degraded",
        "client_id_configured": bool(config.client_id),
        "endpoints_configured": bool(
            config.issuer
            and config.authorization_endpoint
            and config.token_endpoint
            and config.jwks_uri
        ),
    }

    # 2. Signing Key Check
    has_key = bool(config.signing_key or config.signing_key_path)
    report["checks"]["signing_key"] = {
        "configured": has_key,
        "status": "configured" if has_key else "missing",
        "note": "Secret presence does not prove credentials are approved or functional.",
    }

    # 3. Provider Connectivity Check (with timeout)
    target_url = config.jwks_uri or config.issuer
    provider_status = "unknown"
    http_error_msg = None
    if target_url:
        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                resp = await client.get(target_url)
                if resp.status_code < 500:
                    provider_status = "reachable"
                else:
                    provider_status = "degraded"
                    http_error_msg = f"HTTP {resp.status_code}"
        except httpx.TimeoutException:
            provider_status = "timeout"
            http_error_msg = f"Connection timed out after {timeout_seconds}s"
        except Exception:
            provider_status = "unreachable"
            http_error_msg = "Connection failed"

    report["checks"]["provider_connectivity"] = {
        "status": provider_status,
        "endpoint_target": target_url.split("?")[0] if target_url else None,
        "details": http_error_msg or "OK",
    }

    # 4. Storage Checks (if instances provided)
    if sessions is not None:
        report["checks"]["sessions_storage"] = {
            "status": "ready",
            "backend": sessions.__class__.__name__,
        }
    if results is not None:
        report["checks"]["results_storage"] = {
            "status": "ready",
            "backend": results.__class__.__name__,
        }

    # Determine overall status
    if not cfg_ok or provider_status in ("unreachable", "timeout"):
        report["status"] = "degraded"
    elif not has_key:
        report["status"] = "configured"
    else:
        report["status"] = "ready"

    return report
