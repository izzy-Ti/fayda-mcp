"""Thin typed FastMCP tool handlers."""

from typing import Any, Callable, List, Optional
from fayda_mcp.context import (
    CallerAuthorizationAdapter,
    CallerContext,
    SimpleCallerAdapter,
)
from fayda_mcp.exceptions import AuthorizationError
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
    caller_adapter: Optional[Any] = None,
    get_context: Optional[Callable[[], CallerContext]] = None,
) -> None:
    """Register explicit FastMCP verification tools onto a FastMCP server.

    Args:
        server: FastMCP server instance.
        service: Initialized FaydaVerificationService.
        caller_adapter: Host-provided CallerAuthorizationAdapter or resolver.
        get_context: Legacy callable callback to resolve caller context.
    """
    if caller_adapter is not None:
        if isinstance(caller_adapter, CallerAuthorizationAdapter):
            adapter: CallerAuthorizationAdapter = caller_adapter
        elif callable(caller_adapter):
            adapter = SimpleCallerAdapter(context_resolver=caller_adapter)
        else:
            adapter = SimpleCallerAdapter()
    elif get_context is not None:
        adapter = SimpleCallerAdapter(context_resolver=get_context)
    else:
        adapter = SimpleCallerAdapter()

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
        ctx = await adapter.resolve_context(
            "start_verification",
            purpose=purpose,
            checks=checks,
            application_user_ref=application_user_ref,
        )
        allowed = await adapter.authorize(ctx, "verification:create", None)
        if not allowed:
            raise AuthorizationError(f"Caller '{ctx.principal_id}' denied authorization for 'verification:create'")

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
        ctx = await adapter.resolve_context("get_verification_status", request_id=request_id)
        allowed = await adapter.authorize(ctx, "verification:read", request_id)
        if not allowed:
            raise AuthorizationError(f"Caller '{ctx.principal_id}' denied authorization for 'verification:read'")

        return await service.get_verification_status(context=ctx, request_id=request_id)

    @server.tool()
    async def get_verification_result(request_id: str) -> VerificationResult:
        """Retrieve minimal verification outcome predicates.

        Args:
            request_id: Unique verification request identifier.
        """
        ctx = await adapter.resolve_context("get_verification_result", request_id=request_id)
        allowed = await adapter.authorize(ctx, "verification:read", request_id)
        if not allowed:
            raise AuthorizationError(f"Caller '{ctx.principal_id}' denied authorization for 'verification:read'")

        return await service.get_verification_result(context=ctx, request_id=request_id)

    @server.tool()
    async def cancel_verification(request_id: str) -> CancelVerificationResponse:
        """Cancel an in-progress verification request.

        Args:
            request_id: Unique verification request identifier.
        """
        ctx = await adapter.resolve_context("cancel_verification", request_id=request_id)
        allowed = await adapter.authorize(ctx, "verification:cancel", request_id)
        if not allowed:
            raise AuthorizationError(f"Caller '{ctx.principal_id}' denied authorization for 'verification:cancel'")

        return await service.cancel_verification(context=ctx, request_id=request_id)
