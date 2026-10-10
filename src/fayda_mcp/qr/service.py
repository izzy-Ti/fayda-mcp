"""Fayda QR Verification Service orchestrator.

Orchestrates input validation, raw text preservation, parsing, detached RS256
signature verification, policy enforcement, privacy-filtered predicate evaluations,
and audit trail recording.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fayda_mcp.claims import evaluate_checks
from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.predicates import parse_age_check
from fayda_mcp.qr.decoder import decode_and_verify_qr
from fayda_mcp.qr.schemas import (
    QRErrorCode,
    QREvidence,
    QRVerificationRequest,
    QRVerificationResult,
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

        final_result = QRVerificationResult(
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

    async def verify_qr(
        self,
        request: QRVerificationRequest,
        context: Optional[CallerContext] = None,
    ) -> QRVerificationResult:
        """Asynchronously verify a Fayda QR code, record audit events, and persist results."""
        result = self.verify_qr_sync(request, context=context)

        # Audit logging (no raw PII or secret material)
        if self.audit:
            tenant_id = context.tenant_id if context else "default"
            principal_id = context.principal_id if context else "anonymous"
            evidence_ref = result.evidence.evidence_ref if result.evidence else None
            await self.audit.record_event(
                event_type="qr_verification",
                safe_metadata={
                    "tenant_id": tenant_id,
                    "principal_id": principal_id,
                    "status": result.status,
                    "credential_signature_valid": result.credential_signature_valid,
                    "evidence_ref": evidence_ref,
                    "checks": result.checks,
                },
            )

        return result
