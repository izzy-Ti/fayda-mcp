"""Explicit FastMCP tools for Fayda identity verification."""

from typing import List
from app.mcp.server import mcp_server
from app.schemas.verification import (
    StartVerificationResponse,
    VerificationStatusResponse,
    CancelVerificationResponse,
)
from app.schemas.results import VerificationResultResponse


@mcp_server.tool()
async def start_verification(
    purpose: str,
    checks: List[str],
    application_user_ref: str,
    idempotency_key: str,
) -> StartVerificationResponse:
    """Start an identity verification session for an end user.

    Creates a durable verification request and returns a short-lived link
    for the person to authenticate and consent via Fayda eSignet.

    Args:
        purpose: Business reason for the verification (e.g. "kyc_onboarding").
        checks: Permitted checks to perform (e.g. ["identity_verified", "age_over_18"]).
        application_user_ref: Opaque caller-assigned identifier for the user.
        idempotency_key: Unique caller idempotency key to prevent duplicate starts.
    """
    # Service implementation will be expanded in tasks B/C/D
    # Returns structured schema matching acceptance criteria
    return StartVerificationResponse(
        request_id=f"vr_{idempotency_key[:8]}",
        verification_url=f"https://bridge.example.com/verify/link_{idempotency_key[:8]}",
        expires_at="2026-10-06T13:15:00Z",
    )


@mcp_server.tool()
async def get_verification_status(request_id: str) -> VerificationStatusResponse:
    """Check the current lifecycle status of a verification request.

    Args:
        request_id: The verification request identifier.

    Returns:
        One of: pending, processing, verified, rejected, failed, expired, cancelled.
    """
    return VerificationStatusResponse(
        request_id=request_id,
        status="pending",
    )


@mcp_server.tool()
async def get_verification_result(request_id: str) -> VerificationResultResponse:
    """Retrieve verified claim outcomes and evidence metadata after completion.

    Only approved checks and non-PII boolean predicates are returned.
    Raw tokens and citizen identifiers remain protected.

    Args:
        request_id: The verification request identifier.
    """
    return VerificationResultResponse(
        request_id=request_id,
        status="verified",
        checks={"identity_verified": True},
        verified_at="2026-10-06T13:00:00Z",
        expires_at="2026-10-06T13:15:00Z",
        evidence_ref=f"ev_{request_id}",
        policy_version="v1",
    )


@mcp_server.tool()
async def cancel_verification(request_id: str) -> CancelVerificationResponse:
    """Cancel an unfinished verification request owned by the caller.

    Args:
        request_id: The verification request identifier.
    """
    return CancelVerificationResponse(
        request_id=request_id,
        status="cancelled",
    )
