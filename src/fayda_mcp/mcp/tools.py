"""Thin typed FastMCP tool handlers."""

from typing import Any, Callable, Dict, List, Optional
from fayda_mcp.context import (
    CallerAuthorizationAdapter,
    CallerContext,
    SimpleCallerAdapter,
)
from fayda_mcp.exceptions import AuthorizationError, VerificationNotFoundError
from fayda_mcp.mcp.resources import (
    build_health_data,
    build_policy_checks_data,
    build_policy_purposes_data,
)
from fayda_mcp.qr.schemas import (
    QRAgentVerificationResult,
    QRVerificationResult,
    filter_agent_output,
)
from fayda_mcp.matching.schemas import (
    DetailsMatchResult,
    StartDetailsVerificationResponse,
)
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
    async def start_details_verification(
        expected_details_ref: str,
        purpose: str,
        application_user_ref: str,
        idempotency_key: str,
    ) -> StartDetailsVerificationResponse:
        """Initiate citizen identity verification with bound expected details matching.

        Resolves caller-owned expected details reference, binds it to the verification
        request, and returns the eSignet authorization URL for citizen consent.

        Args:
            expected_details_ref: Opaque reference to expected details created by host backend.
            purpose: Approved business purpose for verification (e.g. 'onboarding', 'kyc').
            application_user_ref: Opaque host application reference for the user.
            idempotency_key: Unique caller key preventing duplicate starts.
        """
        ctx = await adapter.resolve_context(
            "start_details_verification",
            expected_details_ref=expected_details_ref,
            purpose=purpose,
            application_user_ref=application_user_ref,
            idempotency_key=idempotency_key,
        )
        allowed = await adapter.authorize(ctx, "verification:create", None)
        if not allowed:
            raise AuthorizationError(f"Caller '{ctx.principal_id}' denied authorization for 'verification:create'")

        return await service.start_details_verification(
            context=ctx,
            expected_details_ref=expected_details_ref,
            purpose=purpose,
            application_user_ref=application_user_ref,
            idempotency_key=idempotency_key,
        )

    @server.tool()
    async def get_details_match_result(request_id: str) -> DetailsMatchResult:
        """Retrieve minimal citizen details match outcome by opaque request identifier.

        Returns matching_status ('matched', 'mismatched', 'unavailable', or 'pending'),
        tri-state field matches (true, false, null), comparison policy version ('details-v1'),
        checked timestamp, and safe reasons.
        Strictly excludes citizen demographics (names, DOBs), FANs, and provider tokens.

        Args:
            request_id: Unique verification request identifier.
        """
        ctx = await adapter.resolve_context("get_details_match_result", request_id=request_id)
        allowed = await adapter.authorize(ctx, "verification:read", request_id)
        if not allowed:
            raise AuthorizationError(f"Caller '{ctx.principal_id}' denied authorization for 'verification:read'")

        result = await service.get_details_match_result(request_id=request_id, context=ctx)
        if result is None:
            raise VerificationNotFoundError(f"Details verification request '{request_id}' not found")

        return result

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

    @server.tool()
    async def submit_qr_verification(
        qr_text: str,
        purpose: Optional[str] = None,
        application_user_ref: Optional[str] = None,
        checks: Optional[List[str]] = None,
        idempotency_key: Optional[str] = None,
        dob_calendar: Optional[str] = None,
    ) -> QRAgentVerificationResult:
        """Submit a Fayda QR code for offline verification and predicate evaluation.

        Returns minimal filtered agent output: status, method, checks, times, safe reasons.
        Strictly excludes demographics, photo, and signature.

        Args:
            qr_text: Raw scanned QR text string.
            purpose: Approved business purpose for verification.
            application_user_ref: Opaque host application reference for the user.
            checks: Permitted boolean checks to evaluate (e.g. ['credential_signature_valid', 'age_over_18']).
            idempotency_key: Unique caller key preventing duplicate submissions.
            dob_calendar: Optional DOB calendar system ('gregorian' or 'ethiopian').
        """
        ctx = await adapter.resolve_context(
            "submit_qr_verification",
            qr_text=qr_text,
            purpose=purpose,
            application_user_ref=application_user_ref,
            checks=checks,
            idempotency_key=idempotency_key,
            dob_calendar=dob_calendar,
        )
        allowed = await adapter.authorize(ctx, "verification:create", None)
        if not allowed:
            raise AuthorizationError(f"Caller '{ctx.principal_id}' denied authorization for 'verification:create'")

        raw_res = await service.submit_qr_verification(
            qr_text=qr_text,
            context=ctx,
            purpose=purpose,
            application_user_ref=application_user_ref,
            checks=checks,
            idempotency_key=idempotency_key,
            dob_calendar=dob_calendar,
        )
        if isinstance(raw_res, QRAgentVerificationResult):
            return raw_res
        return filter_agent_output(raw_res)

    @server.tool()
    async def get_qr_verification_result(request_id: str) -> QRAgentVerificationResult:
        """Retrieve minimal filtered QR verification result by opaque request identifier.

        Returns status, method, checks, times, and safe reasons.
        Strictly excludes demographics, photo, and signature.

        Args:
            request_id: Unique QR verification request identifier.
        """
        ctx = await adapter.resolve_context("get_qr_verification_result", request_id=request_id)
        allowed = await adapter.authorize(ctx, "verification:read", request_id)
        if not allowed:
            raise AuthorizationError(f"Caller '{ctx.principal_id}' denied authorization for 'verification:read'")

        result = await service.get_qr_verification_result(
            request_id=request_id,
            context=ctx,
            filter_output=True,
        )
        if result is None:
            raise VerificationNotFoundError(f"QR verification request '{request_id}' not found")
        if isinstance(result, QRAgentVerificationResult):
            return result
        return filter_agent_output(result)

    @server.tool()
    async def list_allowed_checks() -> Dict[str, Any]:
        """Return checks permitted by verification policy.

        Exposes supported checks, descriptions, required claims, required scopes,
        default requirement (required vs optional), and custom age threshold ranges.
        """
        ctx = await adapter.resolve_context("list_allowed_checks")
        allowed = await adapter.authorize(ctx, "verification:read", None)
        if not allowed:
            raise AuthorizationError(f"Caller '{ctx.principal_id}' denied authorization for 'verification:read'")

        return build_policy_checks_data(service.policy)

    @server.tool()
    async def list_verification_purposes() -> Dict[str, Any]:
        """Return approved business verification purposes and their constraints.

        Exposes allowed purposes (e.g. onboarding, kyc) and permissible age threshold ranges.
        """
        ctx = await adapter.resolve_context("list_verification_purposes")
        allowed = await adapter.authorize(ctx, "verification:read", None)
        if not allowed:
            raise AuthorizationError(f"Caller '{ctx.principal_id}' denied authorization for 'verification:read'")

        return build_policy_purposes_data(service.policy)

    @server.tool()
    async def check_service_health() -> Dict[str, Any]:
        """Return sanitized readiness state of Fayda MCP.

        Evaluates overall status (ready/configured/degraded), storage backends, and key configuration
        without exposing secrets, making outbound network calls, or performing migrations.
        """
        ctx = await adapter.resolve_context("check_service_health")
        allowed = await adapter.authorize(ctx, "verification:read", None)
        if not allowed:
            raise AuthorizationError(f"Caller '{ctx.principal_id}' denied authorization for 'verification:read'")

        return build_health_data(service)
