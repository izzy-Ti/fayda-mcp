"""Details matching service orchestrating backend submission, binding, and verification."""

from datetime import datetime, timedelta, timezone
import secrets
from typing import Any, Dict, Optional, Union

from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import (
    AuthorizationError,
    PolicyViolationError,
)
from fayda_mcp.matching.schemas import (
    DEFAULT_EXPECTED_DETAILS_TTL_SECONDS,
    DetailsAlreadyBoundError,
    DetailsCallerMismatchError,
    DetailsMatchingError,
    DetailsMatchingErrorCode,
    DetailsPurposeMismatchError,
    DetailsReferenceExpiredError,
    DetailsReferenceNotFoundError,
    DetailsUserMismatchError,
    ExpectedDetails,
    ExpectedDetailsRecord,
    ExpectedDetailsSubmission,
    ExpectedDetailsSubmissionResponse,
)
from fayda_mcp.matching.storage import (
    ExpectedDetailsStore,
    MemoryExpectedDetailsStore,
    SessionExpectedDetailsStore,
)
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.storage.protocols import SessionStore


def generate_expected_details_ref() -> str:
    """Generate a cryptographically random, opaque reference identifier.

    Strictly opaque; never encodes citizen demographics, dates, or identifiers.
    """
    return f"edr_{secrets.token_urlsafe(18)}"


class DetailsMatchingService:
    """Orchestrates caller-bound expected details submission, binding, and outcome retrieval."""

    def __init__(
        self,
        policy: Optional[VerificationPolicy] = None,
        store: Optional[ExpectedDetailsStore] = None,
        session_store: Optional[SessionStore] = None,
    ) -> None:
        self.policy = policy or VerificationPolicy()
        if store is not None:
            self.store = store
        elif session_store is not None:
            self.store = SessionExpectedDetailsStore(session_store)
        else:
            self.store = MemoryExpectedDetailsStore()

    async def submit_expected_details(
        self,
        application_user_ref: str,
        purpose: str,
        expected_details: Union[ExpectedDetails, Dict[str, Any]],
        context: Optional[CallerContext] = None,
        ttl_seconds: int = DEFAULT_EXPECTED_DETAILS_TTL_SECONDS,
    ) -> ExpectedDetailsSubmissionResponse:
        """Submit expected identity details from an authenticated host backend.

        Args:
            application_user_ref: Host application user identifier to bind.
            purpose: Approved business purpose for verification (e.g. 'onboarding', 'kyc').
            expected_details: Expected citizen details (full_name and/or date_of_birth).
            context: Authenticated CallerContext identifying caller principal and tenant.
            ttl_seconds: Time-to-live for the expected details record (default: 900s, min: 60s, max: 3600s).

        Returns:
            ExpectedDetailsSubmissionResponse containing opaque expected_details_ref and expiry.
        """
        ctx = context or CallerContext()

        # 1. Authorize caller
        permitted_scopes = {"verification:create", "details:create", "verification:*", "admin", "*"}
        if not any(scope in ctx.scopes for scope in permitted_scopes):
            raise AuthorizationError(
                f"Caller '{ctx.principal_id}' denied authorization for 'verification:create'"
            )

        # 2. Validate application_user_ref
        if not application_user_ref or not str(application_user_ref).strip():
            raise DetailsMatchingError(
                "application_user_ref must not be empty",
                DetailsMatchingErrorCode.INVALID_EXPECTATIONS,
            )

        # 3. Validate business purpose against active policy
        self.policy.validate_purpose(purpose)

        # 4. Parse & validate expected details
        if isinstance(expected_details, ExpectedDetails):
            details_model = expected_details
        elif isinstance(expected_details, dict):
            try:
                details_model = ExpectedDetails(**expected_details)
            except Exception as e:
                raise DetailsMatchingError(
                    f"Invalid expected details: {str(e)}",
                    DetailsMatchingErrorCode.INVALID_EXPECTATIONS,
                ) from e
        else:
            raise DetailsMatchingError(
                "expected_details must be an instance of ExpectedDetails or dict",
                DetailsMatchingErrorCode.INVALID_EXPECTATIONS,
            )

        # 5. Bound TTL
        clamped_ttl = max(60, min(3600, int(ttl_seconds)))
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=clamped_ttl)

        # 6. Generate opaque reference
        ref = generate_expected_details_ref()

        # 7. Create bound record
        record = ExpectedDetailsRecord(
            ref=ref,
            tenant_id=ctx.tenant_id,
            principal_id=ctx.principal_id,
            application_user_ref=str(application_user_ref).strip(),
            purpose=str(purpose).strip(),
            expected_details=details_model,
            created_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            bound_request_id=None,
        )

        # 8. Persist into expected details store with short TTL
        await self.store.save_expected_details(ref, record, clamped_ttl)

        return ExpectedDetailsSubmissionResponse(
            expected_details_ref=ref,
            expires_at=expires_at.isoformat(),
        )

    async def get_expected_details_record(
        self,
        ref: str,
        context: Optional[CallerContext] = None,
        validate_caller: bool = True,
    ) -> ExpectedDetailsRecord:
        """Retrieve and validate an expected details record by reference.

        Args:
            ref: Opaque expected details reference.
            context: Caller context requesting access.
            validate_caller: Whether to enforce that the caller matches the creator tenant/principal.

        Raises:
            DetailsReferenceNotFoundError: If the reference is not found.
            DetailsReferenceExpiredError: If the reference has expired.
            DetailsCallerMismatchError: If the caller does not match the bound creator.
        """
        if not ref or not ref.strip():
            raise DetailsReferenceNotFoundError("empty_reference")

        record = await self.store.get_expected_details(ref.strip())
        if record is None:
            raise DetailsReferenceNotFoundError(ref)

        # Check expiration timestamp
        try:
            exp_dt = datetime.fromisoformat(record.expires_at)
            if exp_dt <= datetime.now(timezone.utc):
                await self.store.delete_expected_details(ref)
                raise DetailsReferenceExpiredError(ref)
        except DetailsReferenceExpiredError:
            raise
        except Exception:
            pass

        # Validate caller ownership
        if validate_caller and context is not None:
            if context.tenant_id != record.tenant_id:
                raise DetailsCallerMismatchError(ref)
            # Principal isolation if not admin/wildcard
            if (
                context.principal_id != record.principal_id
                and "admin" not in context.scopes
                and "*" not in context.scopes
            ):
                raise DetailsCallerMismatchError(ref)

        return record

    async def bind_expected_details(
        self,
        ref: str,
        request_id: str,
        application_user_ref: str,
        purpose: str,
        context: Optional[CallerContext] = None,
    ) -> ExpectedDetailsRecord:
        """Bind an expected details reference to a verification request.

        Validates caller ownership, application user, purpose, and prevents replay binding.
        """
        record = await self.get_expected_details_record(ref, context=context, validate_caller=True)

        if record.bound_request_id is not None and record.bound_request_id != request_id:
            raise DetailsAlreadyBoundError(ref)

        if record.application_user_ref != application_user_ref:
            raise DetailsUserMismatchError(ref)

        if record.purpose != purpose:
            raise DetailsPurposeMismatchError(ref)

        # Mark as bound to this request
        updated_record = ExpectedDetailsRecord(
            ref=record.ref,
            tenant_id=record.tenant_id,
            principal_id=record.principal_id,
            application_user_ref=record.application_user_ref,
            purpose=record.purpose,
            expected_details=record.expected_details,
            created_at=record.created_at,
            expires_at=record.expires_at,
            bound_request_id=request_id,
        )

        # Calculate remaining TTL
        exp_dt = datetime.fromisoformat(record.expires_at)
        remaining_ttl = max(10, int((exp_dt - datetime.now(timezone.utc)).total_seconds()))
        await self.store.save_expected_details(ref, updated_record, remaining_ttl)

        return updated_record

    async def purge_expected_details(self, ref: str) -> bool:
        """Purge expected details record after matching is finalized."""
        return await self.store.delete_expected_details(ref)
