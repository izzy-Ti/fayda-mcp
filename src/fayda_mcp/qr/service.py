"""Fayda QR Verification Service orchestrator.

Orchestrates input validation, raw text preservation, parsing, detached RS256
signature verification, policy enforcement, privacy-filtered predicate evaluations,
and audit trail recording.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Sequence, Union
from uuid import uuid4

from fayda_mcp.claims import evaluate_checks
from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import AuthorizationError, IdempotencyConflictError
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.predicates import parse_age_check
from fayda_mcp.qr.decoder import decode_and_verify_qr
from fayda_mcp.qr.schemas import (
    QRAgentVerificationResult,
    QRErrorCode,
    QREvidence,
    QRVerificationRequest,
    QRVerificationResult,
    filter_agent_output,
)
from fayda_mcp.qr.signed_content import CONFIRMED_CALENDARS
from fayda_mcp.qr.trust import QRTrustStore, load_trust_store_from_config
from fayda_mcp.storage.protocols import AuditLogger, ResultRepository


class FaydaQRVerificationService:
    """Orchestrates offline Fayda National ID QR verification and policy evaluation."""

    def __init__(
        self,
        config: Optional[FaydaConfig] = None,
        trust_store: Optional[QRTrustStore] = None,
        policy: Optional[VerificationPolicy] = None,
        results: Optional[ResultRepository] = None,
        audit: Optional[AuditLogger] = None,
    ):
        self.config = config or FaydaConfig(
            client_id="default_qr_verifier",
            redirect_uri="https://localhost/callback",
            issuer="https://esignet.fayda.et",
            authorization_endpoint="https://esignet.fayda.et/authorize",
            token_endpoint="https://esignet.fayda.et/token",
            userinfo_endpoint="https://esignet.fayda.et/userinfo",
            jwks_uri="https://esignet.fayda.et/jwks",
        )
        self.trust_store = trust_store or load_trust_store_from_config(
            bundle_path=self.config.qr_key_bundle_path,
            inline_pem=self.config.qr_public_key_pem,
        )
        self.policy = policy
        self.results = results
        self.audit = audit

    def _evaluate_qr_checks(
        self,
        result: QRVerificationResult,
        requested_checks: List[str],
        calendar: str,
    ) -> tuple[Dict[str, Any], Dict[str, str]]:
        """Evaluate requested checks against decoded QR demographics and cryptographic status.

        Invariants:
        1. credential_signature_valid is True only when detached signature verifies against trusted key.
        2. Age predicates are evaluated ONLY from signed DOB with a confirmed calendar.
        3. When signature is invalid or unverified, all demographic/identity checks fail closed.
        4. Offline QR scanning never asserts live holder presence or identity.
        """
        checks: Dict[str, Any] = {}
        reasons: Dict[str, str] = {}

        is_cal_confirmed = (
            bool(calendar)
            and isinstance(calendar, str)
            and calendar.strip().lower() in CONFIRMED_CALENDARS
        )

        if not result.credential_signature_valid or not result.demographics:
            # When signature is invalid or unverified, all checks fail closed
            for ch in requested_checks:
                if ch == "credential_signature_valid":
                    checks[ch] = False
                    reasons[ch] = result.error_code or "signature_verification_failed"
                elif ch == "holder_authenticated":
                    checks[ch] = False
                    reasons[ch] = "qr_scan_does_not_authenticate_holder"
                elif ch == "identity_verified":
                    checks[ch] = False
                    reasons[ch] = "offline_qr_alone_cannot_assert_identity"
                else:
                    checks[ch] = "unavailable"
                    reasons[ch] = "credential_signature_unverified"
            return checks, reasons

        # Base invariant: credential_signature_valid is True
        if "credential_signature_valid" in requested_checks:
            checks["credential_signature_valid"] = True

        # Handle holder presence & identity invariants (QR-only evidence)
        if "holder_authenticated" in requested_checks:
            checks["holder_authenticated"] = False
            reasons["holder_authenticated"] = "qr_scan_does_not_authenticate_holder"

        if "identity_verified" in requested_checks:
            checks["identity_verified"] = False
            reasons["identity_verified"] = "offline_qr_alone_cannot_assert_identity"

        # Claims for predicate evaluation
        claims: Dict[str, Any] = {
            "sub": result.demographics.fan_normalized,
            "birthdate": result.demographics.dob_normalized,
            "gender": result.demographics.gender_normalized,
            "name": result.demographics.name_normalized,
            "fan": result.demographics.fan_normalized,
            "credential_signature_valid": True,
            "holder_authenticated": False,
        }

        # Evaluate remaining requested checks
        for ch in requested_checks:
            if ch in ("credential_signature_valid", "holder_authenticated", "identity_verified"):
                continue

            parsed_age = parse_age_check(ch)
            if parsed_age is not None:
                # Age checks require a confirmed calendar
                if not is_cal_confirmed:
                    checks[ch] = "unavailable"
                    reasons[ch] = "unconfirmed_calendar"
                    continue

                if not result.demographics.dob_normalized:
                    checks[ch] = "unavailable"
                    reasons[ch] = "invalid_or_partial_dob"
                    continue

                pred_results = evaluate_checks(
                    claims=claims,
                    requested_checks=[ch],
                    timezone_name=self.config.age_evaluation_timezone,
                    february_29_anniversary=self.config.february_29_anniversary,
                )
                checks.update(pred_results)
                continue

            if ch in ("phone_verified", "email_verified"):
                checks[ch] = "unavailable"
                reasons[ch] = "claim_not_present_in_qr"
                continue

            # General predicates evaluated via claims engine
            pred_results = evaluate_checks(
                claims=claims,
                requested_checks=[ch],
                timezone_name=self.config.age_evaluation_timezone,
                february_29_anniversary=self.config.february_29_anniversary,
            )
            checks.update(pred_results)

        return checks, reasons

    def verify_qr_sync(
        self,
        request: QRVerificationRequest,
        context: Optional[CallerContext] = None,
    ) -> QRVerificationResult:
        """Synchronously verify a Fayda QR code and evaluate requested checks."""
        # 1. Enforce tenant policy if configured
        if self.policy:
            if request.purpose:
                self.policy.validate_purpose(request.purpose)
            if request.checks:
                self.policy.validate_checks(request.checks)

        # 2. Determine calendar convention
        calendar_candidate = request.dob_calendar if request.dob_calendar is not None else (
            self.config.dob_source_calendar if self.config else "gregorian"
        )
        if calendar_candidate and isinstance(calendar_candidate, str) and calendar_candidate.strip().lower() in CONFIRMED_CALENDARS:
            confirmed_calendar = calendar_candidate.strip().lower()
        else:
            confirmed_calendar = "unconfirmed"

        # 3. Decode and verify cryptographic RS256 signature
        raw_result = decode_and_verify_qr(
            raw_text=request.qr_text,
            trust_store=self.trust_store,
            dob_calendar=confirmed_calendar,
            include_demographics=True,
        )

        # 4. Evaluate requested boolean predicates
        requested = request.checks or ["credential_signature_valid"]
        evaluated_checks, reasons = self._evaluate_qr_checks(
            result=raw_result,
            requested_checks=requested,
            calendar=confirmed_calendar,
        )

        # 5. Determine high-level outcome status
        if not raw_result.credential_signature_valid:
            status = raw_result.status
        else:
            # Valid signature: determine if all requested policy checks passed
            if all(v is True for v in evaluated_checks.values()):
                status = "verified"
            elif any(v is False for v in evaluated_checks.values()):
                status = "rejected"
            else:
                status = "incomplete"

        # 6. Apply privacy filtering: demographics unpopulated unless explicitly permitted
        demographics = raw_result.demographics if request.include_demographics else None

        # 7. Construct final evidence and verification result
        evidence = raw_result.evidence
        if evidence:
            evidence = evidence.model_copy(
                update={"checks_evaluated": evaluated_checks, "reasons": reasons}
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        verified_ts = evidence.verified_at if evidence and evidence.verified_at else now_iso
        times = {"verified_at": verified_ts}
        final_result = QRVerificationResult(
            request_id=f"qr_{uuid4().hex[:16]}",
            application_user_ref=request.application_user_ref,
            purpose=request.purpose,
            verified_at=verified_ts,
            times=times,
            method="qr_offline",
            policy_version=self.policy.version if self.policy else "v1",
            status=status,
            credential_signature_valid=raw_result.credential_signature_valid,
            holder_authenticated=False,
            evidence=evidence,
            demographics=demographics,
            checks=evaluated_checks,
            reasons=reasons,
            error=raw_result.error,
            error_code=raw_result.error_code,
        )

        return final_result

    def _result_from_record(self, record: Dict[str, Any]) -> QRVerificationResult:
        """Reconstruct a QRVerificationResult from a persisted repository record."""
        evidence_ref = record.get("evidence_ref")
        evidence = None
        if evidence_ref:
            evidence = QREvidence(
                evidence_type="qr_offline",
                credential_signature_valid=bool(record.get("credential_signature_valid", True)),
                holder_authenticated=False,
                identity_verified=False,
                qr_version=record.get("qr_version", 4),
                verified_at=record.get("verified_at"),
                key_thumbprint=record.get("key_thumbprint"),
                evidence_ref=evidence_ref,
                checks_evaluated=record.get("checks", {}),
                reasons=record.get("reasons", {}),
            )

        verified_at = record.get("verified_at")
        times = dict(record.get("times", {}))
        if verified_at and "verified_at" not in times:
            times["verified_at"] = verified_at
        if record.get("created_at") and "created_at" not in times:
            times["created_at"] = record.get("created_at")
        if record.get("expires_at") and "expires_at" not in times:
            times["expires_at"] = record.get("expires_at")

        return QRVerificationResult(
            request_id=record.get("request_id"),
            application_user_ref=record.get("application_user_ref"),
            purpose=record.get("purpose"),
            verified_at=verified_at,
            times=times,
            method="qr_offline",
            policy_version=record.get("policy_version"),
            status=record.get("status", "verified"),
            credential_signature_valid=bool(record.get("credential_signature_valid", True)),
            holder_authenticated=False,
            evidence=evidence,
            demographics=None,  # Demographics never persisted or exposed from storage
            checks=record.get("checks", {}),
            reasons=record.get("reasons", {}),
            error=record.get("error"),
            error_code=record.get("error_code"),
        )

    async def submit_qr_verification(
        self,
        qr_text: Union[str, QRVerificationRequest],
        context: Optional[CallerContext] = None,
        purpose: Optional[str] = None,
        application_user_ref: Optional[str] = None,
        checks: Optional[Sequence[str]] = None,
        idempotency_key: Optional[str] = None,
        dob_calendar: Optional[str] = None,
        include_demographics: bool = False,
    ) -> QRVerificationResult:
        """Submit a Fayda QR code for offline verification, binding caller, purpose, and application user.

        Workflow:
        1. Binds caller context (tenant_id, principal_id), business purpose, and host application user.
        2. Idempotency deduplication: retries with identical idempotency key return cached result;
           conflicting parameters raise IdempotencyConflictError.
        3. Parses unchanged scanner text and cryptographically verifies detached RS256 signature.
        4. Evaluates requested policy checks fail-closed under confirmed calendar.
        5. Persists minimal evidence in Neon / ResultRepository and records non-PII audit event.
        """
        ctx = context or CallerContext()

        if isinstance(qr_text, QRVerificationRequest):
            req_checks = list(checks) if checks is not None else qr_text.checks
            req_purpose = purpose or qr_text.purpose or "offline_verification"
            req_user = application_user_ref or qr_text.application_user_ref
            req_idemp = idempotency_key or qr_text.idempotency_key
            req_calendar = dob_calendar if dob_calendar is not None else qr_text.dob_calendar
            req_include_demo = include_demographics or qr_text.include_demographics
            raw_text = qr_text.qr_text
        else:
            req_checks = list(checks) if checks is not None else ["credential_signature_valid"]
            req_purpose = purpose or "offline_verification"
            req_user = application_user_ref
            req_idemp = idempotency_key
            req_calendar = dob_calendar
            req_include_demo = include_demographics
            raw_text = qr_text

        # 1. Idempotency lookup
        if req_idemp and self.results:
            existing = await self.results.find_by_idempotency_key(
                tenant_id=ctx.tenant_id,
                principal_id=ctx.principal_id,
                idempotency_key=req_idemp,
            )
            if existing:
                if (
                    existing.get("purpose") != req_purpose
                    or existing.get("application_user_ref") != req_user
                ):
                    raise IdempotencyConflictError(
                        f"Idempotency key '{req_idemp}' has already been used with different parameters"
                    )
                return self._result_from_record(existing)

        # 2. Build verified request model
        request = QRVerificationRequest(
            qr_text=raw_text,
            checks=req_checks,
            purpose=req_purpose,
            application_user_ref=req_user,
            idempotency_key=req_idemp,
            dob_calendar=req_calendar,
            include_demographics=req_include_demo,
        )

        # 3. Synchronously verify signature and evaluate policy
        result = self.verify_qr_sync(request, context=ctx)

        # Ensure binding attributes are populated
        req_id = result.request_id or f"qr_{uuid4().hex[:16]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        result = result.model_copy(
            update={
                "request_id": req_id,
                "application_user_ref": req_user,
                "purpose": req_purpose,
                "verified_at": result.verified_at or now_iso,
                "policy_version": self.policy.version if self.policy else "v1",
            }
        )

        # 4. Persist minimal evidence in ResultRepository (Neon / Memory)
        if self.results:
            ttl_seconds = self.config.result_ttl_seconds if self.config else 900
            record_data = {
                "request_id": req_id,
                "tenant_id": ctx.tenant_id,
                "principal_id": ctx.principal_id,
                "purpose": req_purpose,
                "application_user_ref": req_user,
                "idempotency_key": req_idemp,
                "status": result.status,
                "credential_signature_valid": result.credential_signature_valid,
                "holder_authenticated": False,
                "identity_verified": False,
                "checks": result.checks,
                "reasons": result.reasons,
                "times": result.times,
                "evidence_ref": result.evidence.evidence_ref if result.evidence else None,
                "key_thumbprint": result.evidence.key_thumbprint if result.evidence else None,
                "qr_version": result.evidence.qr_version if result.evidence else 4,
                "verified_at": result.verified_at,
                "policy_version": result.policy_version,
                "method": "qr_offline",
                "created_at": now_iso,
            }
            await self.results.save_request(
                request_id=req_id,
                data=record_data,
                ttl_seconds=ttl_seconds,
            )

        # 5. Persist audit log event
        if self.audit:
            evidence_ref = result.evidence.evidence_ref if result.evidence else None
            await self.audit.record_event(
                event_type="qr_verification",
                safe_metadata={
                    "request_id": req_id,
                    "tenant_id": ctx.tenant_id,
                    "principal_id": ctx.principal_id,
                    "purpose": req_purpose,
                    "application_user_ref": req_user,
                    "status": result.status,
                    "credential_signature_valid": result.credential_signature_valid,
                    "evidence_ref": evidence_ref,
                    "checks": result.checks,
                    "method": "qr_offline",
                },
            )

        return result

    def _authorize_caller(self, record: Dict[str, Any], context: CallerContext) -> None:
        """Enforce tenant and caller principal isolation."""
        if record.get("tenant_id") and record.get("tenant_id") != context.tenant_id:
            raise AuthorizationError("Access denied: tenant mismatch")

        record_principal = record.get("principal_id")
        if (
            record_principal
            and record_principal != "anonymous"
            and record_principal != context.principal_id
            and "verification:admin" not in context.scopes
            and "*" not in context.scopes
        ):
            raise AuthorizationError("Access denied: caller principal mismatch")

    async def get_qr_verification_result(
        self,
        request_id: str,
        context: Optional[CallerContext] = None,
        filter_output: bool = False,
    ) -> Optional[Union[QRVerificationResult, QRAgentVerificationResult]]:
        """Retrieve a stored QR verification result by request ID, enforcing caller ownership.

        Args:
            request_id: Unique opaque verification request identifier.
            context: Optional caller context for tenant and principal authorization.
            filter_output: If True, returns minimal QRAgentVerificationResult excluding demographics, photo, and signature.
        """
        if not self.results:
            return None
        rec = await self.results.get_request(request_id)
        if not rec:
            return None
        ctx = context or CallerContext()
        self._authorize_caller(rec, ctx)
        res = self._result_from_record(rec)
        if filter_output:
            return filter_agent_output(res)
        return res

    async def verify_qr(
        self,
        request: QRVerificationRequest,
        context: Optional[CallerContext] = None,
    ) -> QRVerificationResult:
        """Asynchronously verify a Fayda QR code, record audit events, and persist results."""
        return await self.submit_qr_verification(request, context=context)
