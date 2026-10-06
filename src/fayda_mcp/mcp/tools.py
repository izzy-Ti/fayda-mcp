"""Thin typed FastMCP tool handlers."""

from typing import Any, Callable, List, Optional
from fayda_mcp.context import CallerContext
from fayda_mcp.schemas import (
    CancelVerificationResponse,
    StartVerificationResponse,
    VerificationResult,
    VerificationStatusResponse,
)
from fayda_mcp.service import FaydaVerificationService


def register_tools(
    server: Any,
    service: FaydaVerificationService,
    get_context: Optional[Callable[[], CallerContext]] = None,
) -> None:
    """Register explicit FastMCP verification tools onto a FastMCP server."""

    def _resolve_context() -> CallerContext:
        if get_context:
            return get_context()
        return CallerContext()

    @server.tool()
    async def start_verification(
        purpose: str,
        checks: List[str],
        application_user_ref: str,
        idempotency_key: str,
    ) -> StartVerificationResponse:
        """Initiate citizen identity verification via Fayda eSignet.

        Args:
            purpose: Approved business purpose for verification.
            checks: Permitted boolean checks to evaluate (e.g. ['identity_verified', 'age_over_18']).
            application_user_ref: Opaque host application reference for the user.
            idempotency_key: Unique caller key preventing duplicate starts.
        """
        ctx = _resolve_context()
        return await service.start_verification(
            context=ctx,
            purpose=purpose,
            checks=checks,
            application_user_ref=application_user_ref,
            idempotency_key=idempotency_key,
        )

    @server.tool()
    async def get_verification_status(request_id: str) -> VerificationStatusResponse:
        """Check status of a verification request.

        Args:
            request_id: Unique verification request identifier.
        """
        ctx = _resolve_context()
        return await service.get_verification_status(context=ctx, request_id=request_id)

    @server.tool()
    async def get_verification_result(request_id: str) -> VerificationResult:
        """Retrieve minimal verification outcome predicates.

        Args:
            request_id: Unique verification request identifier.
        """
        ctx = _resolve_context()
        return await service.get_verification_result(context=ctx, request_id=request_id)

    @server.tool()
    async def cancel_verification(request_id: str) -> CancelVerificationResponse:
        """Cancel an in-progress verification request.

        Args:
            request_id: Unique verification request identifier.
        """
        ctx = _resolve_context()
        return await service.cancel_verification(context=ctx, request_id=request_id)
