"""Details matching service orchestrating backend submission, binding, and verification."""

from datetime import datetime, timedelta, timezone
import secrets
from typing import Any, Dict, Optional, Union

from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import (
    AuthorizationError,
    PolicyViolationError,
)
from fayda_mcp.matching.crypto import DetailsEncryptor
from fayda_mcp.matching.normalization import evaluate_details_matching
from fayda_mcp.matching.schemas import (
    DEFAULT_COMPARISON_POLICY_VERSION,
    DEFAULT_EXPECTED_DETAILS_TTL_SECONDS,
    MAX_EXPECTED_DETAILS_TTL_SECONDS,
    MIN_EXPECTED_DETAILS_TTL_SECONDS,
    DetailsAlreadyBoundError,
    DetailsCallerMismatchError,
    DetailsMatchResult,
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
        encryptor: Optional[DetailsEncryptor] = None,
        encryption_key: Optional[Union[str, bytes]] = None,
    ) -> None:
        self.policy = policy or VerificationPolicy()
        self.encryptor = encryptor or DetailsEncryptor(key=encryption_key)

        if store is not None:
            self.store = store
        elif session_store is not None:
            self.store = SessionExpectedDetailsStore(
                session_store=session_store,
                encryptor=self.encryptor,
            )
        else:
            self.store = MemoryExpectedDetailsStore(encryptor=self.encryptor)

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

        # 5. Bound and enforce short TTL
        clamped_ttl = max(
            MIN_EXPECTED_DETAILS_TTL_SECONDS,
            min(MAX_EXPECTED_DETAILS_TTL_SECONDS, int(ttl_seconds)),
        )
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=clamped_ttl)

        # 6. Generate opaque reference
        ref = generate_expected_details_ref()

        # 7. Create bound record (retained details will be encrypted at rest by the store)
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

        # 8. Persist into expected details store with short TTL and authenticated encryption
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

        # Check expiration timestamp against UTC clock
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
        """Bind an expected details reference to caller, user, purpose, and request.

        Validates caller ownership, application user, purpose, and prevents replay binding.
        Enforces that the bound record cannot outlive its remaining TTL.
        """
        if not request_id or not str(request_id).strip():
            raise DetailsMatchingError(
                "request_id must not be empty when binding expected details",
                DetailsMatchingErrorCode.INVALID_EXPECTATIONS,
            )

        clean_request_id = str(request_id).strip()

        # 1. Retrieve record with caller validation and expiration check
        record = await self.get_expected_details_record(ref, context=context, validate_caller=True)

        # 2. Prevent replay binding to conflicting verification requests
        if record.bound_request_id is not None and record.bound_request_id != clean_request_id:
            raise DetailsAlreadyBoundError(ref)

        # 3. Verify application user binding
        if record.application_user_ref != str(application_user_ref).strip():
            raise DetailsUserMismatchError(ref)

        # 4. Verify purpose binding
        if record.purpose != str(purpose).strip():
            raise DetailsPurposeMismatchError(ref)

        # 5. Check remaining TTL
        exp_dt = datetime.fromisoformat(record.expires_at)
        now_dt = datetime.now(timezone.utc)
        remaining_ttl = int((exp_dt - now_dt).total_seconds())
        if remaining_ttl <= 0:
            await self.store.delete_expected_details(ref)
            raise DetailsReferenceExpiredError(ref)

        # 6. Idempotent check: already bound to this request
        if record.bound_request_id == clean_request_id:
            return record

        # 7. Mark as bound to this request and update persistence
        updated_record = ExpectedDetailsRecord(
            ref=record.ref,
            tenant_id=record.tenant_id,
            principal_id=record.principal_id,
            application_user_ref=record.application_user_ref,
            purpose=record.purpose,
            expected_details=record.expected_details,
            created_at=record.created_at,
            expires_at=record.expires_at,
            bound_request_id=clean_request_id,
        )

        await self.store.save_expected_details(ref, updated_record, max(1, remaining_ttl))
        return updated_record

    async def get_bound_expected_details_for_request(
        self,
        request_id: str,
        context: Optional[CallerContext] = None,
        validate_caller: bool = True,
    ) -> ExpectedDetailsRecord:
        """Retrieve the bound expected details record for an active verification request."""
        clean_request_id = str(request_id).strip()
        ref = await self.store.get_ref_by_request_id(clean_request_id)
        if not ref:
            raise DetailsReferenceNotFoundError(f"request:{clean_request_id}")

        return await self.get_expected_details_record(
            ref=ref,
            context=context,
            validate_caller=validate_caller,
        )

    async def purge_expected_details(self, ref: str) -> bool:
        """Purge expected details record after matching is finalized."""
        return await self.store.delete_expected_details(str(ref).strip())

    async def purge_bound_expected_details_for_request(self, request_id: str) -> bool:
        """Purge bound expected details record for a verification request after finalization."""
        clean_request_id = str(request_id).strip()
        ref = await self.store.get_ref_by_request_id(clean_request_id)
        if ref:
            return await self.store.delete_expected_details(ref)
        return False

    async def evaluate_details_for_request(
        self,
        request_id: str,
        claims: Dict[str, Any],
        provider_dob_calendar: str = "gregorian",
        expected_details_ref: Optional[str] = None,
        application_user_ref: Optional[str] = None,
        purpose: Optional[str] = None,
        expires_at: Optional[str] = None,
        identity_authenticated: bool = True,
    ) -> DetailsMatchResult:
        """Compare permitted validated claims with bound expected details.

        Strictly deterministic; extracts only permitted name/DOB claims.
        Stores minimal match outcomes and safe reasons, never raw claims.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        clean_request_id = str(request_id).strip()

        # 1. Resolve bound record
        record: Optional[ExpectedDetailsRecord] = None
        record_error_reason: Optional[str] = None

        if expected_details_ref:
            try:
                record = await self.get_expected_details_record(
                    ref=expected_details_ref,
                    validate_caller=False,
                )
            except DetailsReferenceExpiredError:
                record_error_reason = "details_reference_expired"
            except DetailsReferenceNotFoundError:
                record_error_reason = "details_reference_not_found"
            except Exception:
                record_error_reason = "details_reference_not_found"

        if record is None and not record_error_reason:
            try:
                record = await self.get_bound_expected_details_for_request(
                    request_id=clean_request_id,
                    validate_caller=False,
                )
            except DetailsReferenceExpiredError:
                record_error_reason = "details_reference_expired"
            except DetailsReferenceNotFoundError:
                record_error_reason = "details_reference_not_found"
            except Exception:
                record_error_reason = "details_reference_not_found"

        if record is None:
            safe_reason = record_error_reason or "details_reference_not_found"
            res = DetailsMatchResult(
                request_id=clean_request_id,
                verification_method="esignet",
                matching_status="unavailable",
                matches={},
                comparison_policy_version=DEFAULT_COMPARISON_POLICY_VERSION,
                required_fields=[],
                checked_at=now_iso,
                expires_at=expires_at,
                reasons={"details_matching": safe_reason},
                identity_authenticated=identity_authenticated,
                evidence_ref=f"ev_{clean_request_id}",
            )
            await self.store.save_match_result(clean_request_id, res, ttl_seconds=900)
            return res

        # 2. Verify bound application_user_ref and purpose
        if application_user_ref and record.application_user_ref != str(application_user_ref).strip():
            res = DetailsMatchResult(
                request_id=clean_request_id,
                verification_method="esignet",
                matching_status="unavailable",
                matches={},
                comparison_policy_version=DEFAULT_COMPARISON_POLICY_VERSION,
                required_fields=list(record.expected_details.required_fields or []) if record.expected_details else [],
                checked_at=now_iso,
                expires_at=expires_at or record.expires_at,
                reasons={"details_matching": "details_user_mismatch"},
                identity_authenticated=identity_authenticated,
                evidence_ref=f"ev_{clean_request_id}",
            )
            await self.store.save_match_result(clean_request_id, res, ttl_seconds=900)
            return res

        if purpose and record.purpose != str(purpose).strip():
            res = DetailsMatchResult(
                request_id=clean_request_id,
                verification_method="esignet",
                matching_status="unavailable",
                matches={},
                comparison_policy_version=DEFAULT_COMPARISON_POLICY_VERSION,
                required_fields=list(record.expected_details.required_fields or []) if record.expected_details else [],
                checked_at=now_iso,
                expires_at=expires_at or record.expires_at,
                reasons={"details_matching": "details_purpose_mismatch"},
                identity_authenticated=identity_authenticated,
                evidence_ref=f"ev_{clean_request_id}",
            )
            await self.store.save_match_result(clean_request_id, res, ttl_seconds=900)
            return res

        if not record.expected_details:
            res = DetailsMatchResult(
                request_id=clean_request_id,
                verification_method="esignet",
                matching_status="unavailable",
                matches={},
                comparison_policy_version=DEFAULT_COMPARISON_POLICY_VERSION,
                required_fields=[],
                checked_at=now_iso,
                expires_at=expires_at or record.expires_at,
                reasons={"details_matching": "missing_expected_details"},
                identity_authenticated=identity_authenticated,
                evidence_ref=f"ev_{clean_request_id}",
            )
            await self.store.save_match_result(clean_request_id, res, ttl_seconds=900)
            return res

        # 3. Deterministically evaluate expected details against validated permitted claims
        matches, reasons, overall_status = evaluate_details_matching(
            expected_details=record.expected_details,
            claims=claims,
            provider_dob_calendar=provider_dob_calendar,
        )

        res = DetailsMatchResult(
            request_id=clean_request_id,
            verification_method="esignet",
            matching_status=overall_status,
            matches=matches,
            comparison_policy_version=DEFAULT_COMPARISON_POLICY_VERSION,
            required_fields=list(record.expected_details.required_fields or matches.keys()),
            checked_at=now_iso,
            expires_at=expires_at or record.expires_at,
            reasons=reasons,
            identity_authenticated=identity_authenticated,
            evidence_ref=f"ev_{clean_request_id}",
        )

        # 4. Save minimal outcome
        await self.store.save_match_result(clean_request_id, res, ttl_seconds=900)
        return res

    async def save_match_result(
        self,
        request_id: str,
        result: DetailsMatchResult,
        ttl_seconds: int = 900,
    ) -> None:
        """Store evaluated minimal details match outcome with expiration TTL."""
        await self.store.save_match_result(
            request_id=str(request_id).strip(),
            result=result,
            ttl_seconds=ttl_seconds,
        )

    async def get_match_result(
        self,
        request_id: str,
    ) -> Optional[DetailsMatchResult]:
        """Retrieve evaluated minimal details match outcome by request_id."""
        return await self.store.get_match_result(str(request_id).strip())
