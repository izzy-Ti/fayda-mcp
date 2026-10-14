"""Core framework-neutral verification service."""

import asyncio
import datetime
import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Sequence, Union
import httpx
from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    IdempotencyConflictError,
    InvalidStateError,
    PolicyViolationError,
    ProviderError,
    TokenValidationError,
    VerificationNotFoundError,
)
from fayda_mcp.predicates import AgeThresholdRule


def compute_request_fingerprint(
    purpose: str, checks: Sequence[str], application_user_ref: str
) -> str:
    """Generate deterministic SHA-256 fingerprint of request parameters for idempotency checks."""
    payload = {
        "purpose": str(purpose),
        "checks": sorted(checks),
        "application_user_ref": str(application_user_ref or ""),
    }
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def compute_details_request_fingerprint(
    purpose: str, application_user_ref: str, expected_details_ref: str
) -> str:
    """Generate deterministic SHA-256 fingerprint for details verification requests."""
    payload = {
        "purpose": str(purpose),
        "application_user_ref": str(application_user_ref or ""),
        "expected_details_ref": str(expected_details_ref or ""),
        "verification_type": "details_matching",
    }
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


from fayda_mcp.matching.schemas import (
    DEFAULT_COMPARISON_POLICY_VERSION,
    DetailsAlreadyBoundError,
    DetailsCallerMismatchError,
    DetailsMatchResult,
    DetailsMatchingError,
    DetailsMatchingErrorCode,
    DetailsPurposeMismatchError,
    DetailsReferenceExpiredError,
    DetailsReferenceNotFoundError,
    DetailsUserMismatchError,
    StartDetailsVerificationResponse,
)
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.schemas import (
    CancelVerificationResponse,
    StartVerificationResponse,
    VerificationResult,
    VerificationStatusResponse,
)
from fayda_mcp.storage.protocols import AuditLogger, ResultRepository, SessionStore
from fayda_mcp.secrets.protocols import KeyProvider
from fayda_mcp.oidc.client import FaydaHttpClient
from fayda_mcp.oidc.authorization import (
    build_authorization_url,
    generate_pkce_pair,
    generate_secure_token,
)
from fayda_mcp.oidc.assertions import create_client_assertion
from fayda_mcp.oidc.tokens import validate_id_token, validate_userinfo_response
from fayda_mcp.oidc.jwks import JwksCache
from fayda_mcp.oidc.mapping import normalize_claims
from fayda_mcp.claims import evaluate_checks


class FaydaVerificationService:
    """Orchestrates end-to-end citizen verification with Fayda eSignet."""

    def __init__(
        self,
        config: FaydaConfig,
        sessions: SessionStore,
        results: ResultRepository,
        policy: Optional[VerificationPolicy] = None,
        key_provider: Optional[KeyProvider] = None,
        audit: Optional[AuditLogger] = None,
        http_client: Optional[httpx.AsyncClient] = None,
        qr_success_hook: Optional[Any] = None,
    ) -> None:
        self.config = config
        self.sessions = sessions
        self.results = results
        self.policy = policy or VerificationPolicy()
        self.key_provider = key_provider
        self.audit = audit
        self._http = FaydaHttpClient(config=config, client=http_client)
        self.jwks = JwksCache(config=config)
        from fayda_mcp.qr.service import FaydaQRVerificationService
        self.qr_service = FaydaQRVerificationService(
            config=self.config,
            policy=self.policy,
            results=self.results,
            audit=self.audit,
            success_hook=qr_success_hook,
        )
        from fayda_mcp.matching.service import DetailsMatchingService
        self.matching_service = DetailsMatchingService(
            policy=self.policy,
            session_store=self.sessions,
            encryption_key=self.config.details_encryption_key,
        )

    async def __aenter__(self) -> "FaydaVerificationService":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Cleanly close underlying HTTP clients and connections."""
        await self.jwks.aclose()
        await self._http.aclose()

    async def _get_private_key(self) -> Optional[str]:
        """Resolve client private signing key from KeyProvider, config, or configured file."""
        if self.key_provider:
            key = await self.key_provider.get_private_key()
            from fayda_mcp.secrets.keys import parse_private_key
            pem, kid = parse_private_key(key)
            if kid and not self.config.key_id:
                self.config.key_id = kid
            return pem
        if self.config.signing_key:
            return self.config.signing_key
        if self.config.signing_key_path:
            from fayda_mcp.secrets.file import FileKeyProvider
            from fayda_mcp.secrets.keys import parse_private_key
            raw = await FileKeyProvider(self.config.signing_key_path).get_private_key()
            pem, kid = parse_private_key(raw)
            if kid and not self.config.key_id:
                self.config.key_id = kid
            return pem
        return None

    async def start_verification(
        self,
        context: CallerContext,
        purpose: str,
        checks: Sequence[Union[str, AgeThresholdRule]],
        application_user_ref: str,
        idempotency_key: str,
        optional_checks: Optional[Sequence[Union[str, AgeThresholdRule]]] = None,
    ) -> StartVerificationResponse:
        """Start a verification flow, creating state, PKCE verifier, and authorization link.

        Idempotent: repeating the call with identical idempotency_key returns existing request.
        Reusing an idempotency key with different parameters raises IdempotencyConflictError.
        """
        # Separate any checks prefixed with 'optional:' or provided via optional_checks
        cleaned_checks: List[Union[str, AgeThresholdRule]] = []
        req_optional: List[str] = []
        if optional_checks:
            req_optional.extend(
                [c.check_name if isinstance(c, AgeThresholdRule) else str(c) for c in optional_checks]
            )

        for c in checks:
            if isinstance(c, str) and c.startswith("optional:"):
                clean_name = c[len("optional:"):]
                cleaned_checks.append(clean_name)
                req_optional.append(clean_name)
            else:
                cleaned_checks.append(c)

        # 1. Validate against policy before state creation or redirect
        resolved_checks = self.policy.validate_request(purpose=purpose, checks=cleaned_checks)
        required_list, optional_list = self.policy.partition_required_and_optional(
            resolved_checks, req_optional
        )

        # 2. Compute deterministic request fingerprint
        fingerprint = compute_request_fingerprint(
            purpose=purpose,
            checks=resolved_checks,
            application_user_ref=application_user_ref,
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = (now + datetime.timedelta(seconds=self.config.session_ttl_seconds)).isoformat()
        request_id = f"vr_{generate_secure_token(16)}"

        # 3. Reserve request through unique insert before initiating OIDC flow (state: initializing)
        reservation_data = {
            "request_id": request_id,
            "tenant_id": context.tenant_id,
            "principal_id": context.principal_id,
            "application_user_ref": application_user_ref,
            "idempotency_key": idempotency_key,
            "request_fingerprint": fingerprint,
            "purpose": purpose,
            "checks": resolved_checks,
            "required_checks": required_list,
            "optional_checks": optional_list,
            "status": "initializing",
            "expires_at": expires_at,
            "policy_version": self.policy.version,
        }

        reserved, existing_or_reserved = await self.results.reserve_request(
            request_id=request_id,
            data=reservation_data,
            ttl_seconds=self.config.result_ttl_seconds,
        )

        if not reserved:
            # An existing request with this idempotency key already exists
            existing_fp = existing_or_reserved.get("request_fingerprint")
            if existing_fp and existing_fp != fingerprint:
                raise IdempotencyConflictError(
                    f"Idempotency key '{idempotency_key}' has already been used with different parameters"
                )

            # Briefly retain sensitive authorization URL only while pending.
            # If the concurrent request is still initializing, wait briefly for it to reach pending.
            current_rec = existing_or_reserved
            if current_rec.get("status") == "initializing":
                for _ in range(40):
                    await asyncio.sleep(0.05)
                    poll_rec = await self.results.get_request(current_rec["request_id"])
                    if poll_rec and poll_rec.get("status") != "initializing":
                        current_rec = poll_rec
                        break

            auth_url = ""
            if current_rec.get("status") == "pending":
                auth_url = current_rec.get("authorization_url") or current_rec.get("auth_url") or ""

            if not auth_url and current_rec.get("status") not in ("verified", "processing"):
                # Regenerate fresh session and auth URL so retrying verification works reliably
                actual_req_id = current_rec["request_id"]
                state = generate_secure_token(32)
                nonce = generate_secure_token(32)
                code_verifier, code_challenge = generate_pkce_pair()
                scopes, claims_param = self.policy.resolve_scopes_and_claims(resolved_checks)
                auth_url = build_authorization_url(
                    config=self.config,
                    state=state,
                    nonce=nonce,
                    code_challenge=code_challenge,
                    scopes=scopes,
                    claims=claims_param,
                )
                session_data = {
                    "request_id": actual_req_id,
                    "tenant_id": context.tenant_id,
                    "principal_id": context.principal_id,
                    "application_user_ref": application_user_ref,
                    "nonce": nonce,
                    "code_verifier": code_verifier,
                    "purpose": purpose,
                    "checks": resolved_checks,
                    "required_checks": required_list,
                    "optional_checks": optional_list,
                    "expires_at": expires_at,
                    "browser_binding": context.browser_binding,
                }
                try:
                    await self.sessions.save_session(
                        state, session_data, ttl_seconds=self.config.session_ttl_seconds
                    )
                    pending_record = {
                        "request_id": actual_req_id,
                        "tenant_id": context.tenant_id,
                        "principal_id": context.principal_id,
                        "application_user_ref": application_user_ref,
                        "purpose": purpose,
                        "checks": resolved_checks,
                        "required_checks": required_list,
                        "optional_checks": optional_list,
                        "status": "pending",
                        "expires_at": expires_at,
                        "idempotency_key": idempotency_key,
                        "request_fingerprint": fingerprint,
                        "authorization_url": auth_url,
                        "policy_version": self.policy.version,
                    }
                    await self.results.save_request(
                        actual_req_id, pending_record, ttl_seconds=self.config.result_ttl_seconds
                    )
                except Exception:
                    pass

            exp_str = current_rec.get("expires_at")
            if not exp_str and current_rec.get("session_expires_at"):
                try:
                    exp_str = datetime.datetime.fromtimestamp(
                        float(current_rec["session_expires_at"]), tz=datetime.timezone.utc
                    ).isoformat()
                except Exception:
                    exp_str = str(current_rec["session_expires_at"])

            return StartVerificationResponse(
                request_id=current_rec["request_id"],
                authorization_url=auth_url,
                expires_at=exp_str or "",
            )

        # 4. We successfully reserved this request. Now build OIDC parameters
        actual_req_id = existing_or_reserved.get("request_id", request_id)
        state = generate_secure_token(32)
        nonce = generate_secure_token(32)
        code_verifier, code_challenge = generate_pkce_pair()

        scopes, claims_param = self.policy.resolve_scopes_and_claims(resolved_checks)
        auth_url = build_authorization_url(
            config=self.config,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            scopes=scopes,
            claims=claims_param,
        )

        # 5. Persist short-lived session in Redis / SessionStore
        session_data = {
            "request_id": actual_req_id,
            "tenant_id": context.tenant_id,
            "principal_id": context.principal_id,
            "application_user_ref": application_user_ref,
            "nonce": nonce,
            "code_verifier": code_verifier,
            "purpose": purpose,
            "checks": resolved_checks,
            "required_checks": required_list,
            "optional_checks": optional_list,
            "expires_at": expires_at,
            "browser_binding": context.browser_binding,
        }

        try:
            await self.sessions.save_session(
                state, session_data, ttl_seconds=self.config.session_ttl_seconds
            )
        except Exception as e:
            # Compensate failed Redis writes by transitioning DB status to failed
            await self.results.update_status(actual_req_id, "failed")
            raise ProviderError(f"Failed to persist verification session in Redis: {e}")

        # 6. Redis write succeeded -> transition initializing -> pending and store auth_url
        pending_record = {
            "request_id": actual_req_id,
            "tenant_id": context.tenant_id,
            "principal_id": context.principal_id,
            "application_user_ref": application_user_ref,
            "purpose": purpose,
            "checks": resolved_checks,
            "required_checks": required_list,
            "optional_checks": optional_list,
            "status": "pending",
            "expires_at": expires_at,
            "idempotency_key": idempotency_key,
            "request_fingerprint": fingerprint,
            "authorization_url": auth_url,
            "policy_version": self.policy.version,
        }
        await self.results.save_request(
            actual_req_id, pending_record, ttl_seconds=self.config.result_ttl_seconds
        )

        if self.audit:
            await self.audit.record_event(
                "verification_started",
                {
                    "request_id": actual_req_id,
                    "tenant_id": context.tenant_id,
                    "principal_id": context.principal_id,
                    "purpose": purpose,
                },
            )

        return StartVerificationResponse(
            request_id=actual_req_id,
            authorization_url=auth_url,
            expires_at=expires_at,
        )

    async def start_details_verification(
        self,
        context: CallerContext,
        expected_details_ref: str,
        purpose: str,
        application_user_ref: str,
        idempotency_key: str,
    ) -> StartDetailsVerificationResponse:
        """Initiate citizen identity verification with bound expected details matching.

        Reuses the existing eSignet authorization flow, resolving the caller-owned
        expected details reference, binding it to the generated request, and requesting
        the required OIDC claims (name, birthdate) based on expected details.
        """
        clean_ref = str(expected_details_ref or "").strip()
        clean_purpose = str(purpose or "").strip()
        clean_user = str(application_user_ref or "").strip()
        clean_idempotency = str(idempotency_key or "").strip()

        if not clean_ref:
            raise DetailsReferenceNotFoundError("empty_reference")
        if not clean_purpose:
            raise PolicyViolationError("purpose must not be empty")
        if not clean_user:
            raise DetailsMatchingError(
                "application_user_ref must not be empty",
                DetailsMatchingErrorCode.INVALID_EXPECTATIONS,
            )
        if not clean_idempotency:
            raise DetailsMatchingError(
                "idempotency_key must not be empty",
                DetailsMatchingErrorCode.INVALID_EXPECTATIONS,
            )

        # 1. Resolve and validate the owned expected details reference
        record = await self.matching_service.get_expected_details_record(
            ref=clean_ref,
            context=context,
            validate_caller=True,
        )

        # 2. Validate application user & purpose match
        if record.application_user_ref != clean_user:
            raise DetailsUserMismatchError(clean_ref)
        if record.purpose != clean_purpose:
            raise DetailsPurposeMismatchError(clean_ref)

        # 3. Validate purpose against verification policy
        self.policy.validate_purpose(clean_purpose)

        # 4. Compute deterministic fingerprint for details verification
        fingerprint = compute_details_request_fingerprint(
            purpose=clean_purpose,
            application_user_ref=clean_user,
            expected_details_ref=clean_ref,
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = (now + datetime.timedelta(seconds=self.config.session_ttl_seconds)).isoformat()
        request_id = f"vr_{generate_secure_token(16)}"

        # 5. Reserve request through unique insert before initiating OIDC flow
        reservation_data = {
            "request_id": request_id,
            "tenant_id": context.tenant_id,
            "principal_id": context.principal_id,
            "application_user_ref": clean_user,
            "idempotency_key": clean_idempotency,
            "request_fingerprint": fingerprint,
            "purpose": clean_purpose,
            "verification_method": "esignet",
            "verification_type": "details_matching",
            "expected_details_ref": clean_ref,
            "checks": ["identity_verified"],
            "required_checks": ["identity_verified"],
            "optional_checks": [],
            "status": "initializing",
            "expires_at": expires_at,
            "policy_version": self.policy.version,
            "comparison_policy_version": DEFAULT_COMPARISON_POLICY_VERSION,
        }

        reserved, existing_or_reserved = await self.results.reserve_request(
            request_id=request_id,
            data=reservation_data,
            ttl_seconds=self.config.result_ttl_seconds,
        )

        if not reserved:
            # Replay with idempotency key
            existing_fp = existing_or_reserved.get("request_fingerprint")
            if existing_fp and existing_fp != fingerprint:
                raise IdempotencyConflictError(
                    f"Idempotency key '{clean_idempotency}' has already been used with different parameters"
                )

            current_rec = existing_or_reserved
            if current_rec.get("status") == "initializing":
                for _ in range(40):
                    await asyncio.sleep(0.05)
                    poll_rec = await self.results.get_request(current_rec["request_id"])
                    if poll_rec and poll_rec.get("status") != "initializing":
                        current_rec = poll_rec
                        break

            auth_url = ""
            if current_rec.get("status") == "pending":
                auth_url = current_rec.get("authorization_url") or current_rec.get("auth_url") or ""

            actual_req_id = current_rec["request_id"]
            if not auth_url and current_rec.get("status") not in ("verified", "processing"):
                # Regenerate OIDC session and authorization URL for retry
                state = generate_secure_token(32)
                nonce = generate_secure_token(32)
                code_verifier, code_challenge = generate_pkce_pair()

                scopes, claims_param = self.policy.resolve_details_scopes_and_claims(
                    record.expected_details
                )
                auth_url = build_authorization_url(
                    config=self.config,
                    state=state,
                    nonce=nonce,
                    code_challenge=code_challenge,
                    scopes=scopes,
                    claims=claims_param,
                )
                session_data = {
                    "request_id": actual_req_id,
                    "tenant_id": context.tenant_id,
                    "principal_id": context.principal_id,
                    "application_user_ref": clean_user,
                    "nonce": nonce,
                    "code_verifier": code_verifier,
                    "purpose": clean_purpose,
                    "verification_method": "esignet",
                    "verification_type": "details_matching",
                    "expected_details_ref": clean_ref,
                    "checks": ["identity_verified"],
                    "required_checks": ["identity_verified"],
                    "optional_checks": [],
                    "expires_at": expires_at,
                    "browser_binding": context.browser_binding,
                }
                try:
                    await self.sessions.save_session(
                        state, session_data, ttl_seconds=self.config.session_ttl_seconds
                    )
                    pending_record = {
                        "request_id": actual_req_id,
                        "tenant_id": context.tenant_id,
                        "principal_id": context.principal_id,
                        "application_user_ref": clean_user,
                        "purpose": clean_purpose,
                        "verification_method": "esignet",
                        "verification_type": "details_matching",
                        "expected_details_ref": clean_ref,
                        "checks": ["identity_verified"],
                        "required_checks": ["identity_verified"],
                        "optional_checks": [],
                        "status": "pending",
                        "expires_at": expires_at,
                        "idempotency_key": clean_idempotency,
                        "request_fingerprint": fingerprint,
                        "authorization_url": auth_url,
                        "policy_version": self.policy.version,
                        "comparison_policy_version": DEFAULT_COMPARISON_POLICY_VERSION,
                    }
                    await self.results.save_request(
                        actual_req_id, pending_record, ttl_seconds=self.config.result_ttl_seconds
                    )
                except Exception:
                    pass

            exp_str = current_rec.get("expires_at")
            if not exp_str and current_rec.get("session_expires_at"):
                try:
                    exp_str = datetime.datetime.fromtimestamp(
                        float(current_rec["session_expires_at"]), tz=datetime.timezone.utc
                    ).isoformat()
                except Exception:
                    exp_str = str(current_rec["session_expires_at"])

            return StartDetailsVerificationResponse(
                request_id=actual_req_id,
                authorization_url=auth_url,
                expires_at=exp_str or "",
            )

        # 6. Reserved new request -> check replay conflict and bind reference
        actual_req_id = existing_or_reserved.get("request_id", request_id)

        if record.bound_request_id is not None and record.bound_request_id != actual_req_id:
            await self.results.update_status(actual_req_id, "failed")
            raise DetailsAlreadyBoundError(clean_ref)

        try:
            await self.matching_service.bind_expected_details(
                ref=clean_ref,
                request_id=actual_req_id,
                application_user_ref=clean_user,
                purpose=clean_purpose,
                context=context,
            )
        except Exception:
            await self.results.update_status(actual_req_id, "failed")
            raise

        state = generate_secure_token(32)
        nonce = generate_secure_token(32)
        code_verifier, code_challenge = generate_pkce_pair()

        scopes, claims_param = self.policy.resolve_details_scopes_and_claims(
            record.expected_details
        )
        auth_url = build_authorization_url(
            config=self.config,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            scopes=scopes,
            claims=claims_param,
        )

        session_data = {
            "request_id": actual_req_id,
            "tenant_id": context.tenant_id,
            "principal_id": context.principal_id,
            "application_user_ref": clean_user,
            "nonce": nonce,
            "code_verifier": code_verifier,
            "purpose": clean_purpose,
            "verification_method": "esignet",
            "verification_type": "details_matching",
            "expected_details_ref": clean_ref,
            "checks": ["identity_verified"],
            "required_checks": ["identity_verified"],
            "optional_checks": [],
            "expires_at": expires_at,
            "browser_binding": context.browser_binding,
        }

        try:
            await self.sessions.save_session(
                state, session_data, ttl_seconds=self.config.session_ttl_seconds
            )
        except Exception as e:
            await self.results.update_status(actual_req_id, "failed")
            raise ProviderError(f"Failed to persist verification session in Redis: {e}")

        pending_record = {
            "request_id": actual_req_id,
            "tenant_id": context.tenant_id,
            "principal_id": context.principal_id,
            "application_user_ref": clean_user,
            "purpose": clean_purpose,
            "verification_method": "esignet",
            "verification_type": "details_matching",
            "expected_details_ref": clean_ref,
            "checks": ["identity_verified"],
            "required_checks": ["identity_verified"],
            "optional_checks": [],
            "status": "pending",
            "expires_at": expires_at,
            "idempotency_key": clean_idempotency,
            "request_fingerprint": fingerprint,
            "authorization_url": auth_url,
            "policy_version": self.policy.version,
            "comparison_policy_version": DEFAULT_COMPARISON_POLICY_VERSION,
        }
        await self.results.save_request(actual_req_id, pending_record, ttl_seconds=self.config.result_ttl_seconds)

        if self.audit:
            await self.audit.record_event(
                "details_verification_started",
                {
                    "request_id": actual_req_id,
                    "tenant_id": context.tenant_id,
                    "principal_id": context.principal_id,
                    "purpose": clean_purpose,
                    "expected_details_ref": clean_ref,
                },
            )

        return StartDetailsVerificationResponse(
            request_id=actual_req_id,
            authorization_url=auth_url,
            expires_at=expires_at,
        )

    def _authorize_caller(self, record: Dict[str, Any], context: CallerContext) -> None:
        """Enforce tenant and caller principal isolation."""
        if record.get("tenant_id") != context.tenant_id:
            raise AuthorizationError("Access to verification request denied: tenant mismatch")

        record_principal = record.get("principal_id")
        if (
            record_principal
            and record_principal != "anonymous"
            and record_principal != context.principal_id
            and "verification:admin" not in context.scopes
            and "*" not in context.scopes
        ):
            raise AuthorizationError("Access to verification request denied: caller principal mismatch")

    async def get_verification_status(
        self,
        context: CallerContext,
        request_id: str,
    ) -> VerificationStatusResponse:
        """Retrieve the current lifecycle status for a request."""
        record = await self.results.get_request(request_id)
        if not record:
            raise VerificationNotFoundError(f"Verification request '{request_id}' not found")

        self._authorize_caller(record, context)

        status = record.get("status", "pending")
        if status == "pending":
            exp_val = record.get("session_expires_at") or record.get("expires_at")
            if exp_val is not None:
                try:
                    exp_ts = float(exp_val)
                except (ValueError, TypeError):
                    try:
                        from datetime import datetime
                        exp_ts = datetime.fromisoformat(str(exp_val)).timestamp()
                    except Exception:
                        exp_ts = 0.0
                if exp_ts > 0 and time.time() >= exp_ts:
                    status = "expired"

        return VerificationStatusResponse(
            request_id=request_id,
            status=status,
        )

    async def get_verification_result(
        self,
        context: CallerContext,
        request_id: str,
    ) -> VerificationResult:
        """Retrieve evaluated verification result."""
        record = await self.results.get_request(request_id)
        if not record:
            raise VerificationNotFoundError(f"Verification request '{request_id}' not found")

        self._authorize_caller(record, context)

        result = await self.results.get_result(request_id)
        if not result:
            if record.get("status") in ("verified", "rejected", "failed"):
                raise VerificationNotFoundError(f"Verification result for '{request_id}' has expired")
            return VerificationResult(
                request_id=request_id,
                status=record.get("status", "pending"),
                checks={},
            )

        return result

    async def cancel_verification(
        self,
        context: CallerContext,
        request_id: str,
    ) -> CancelVerificationResponse:
        """Cancel an in-progress verification request."""
        record = await self.results.get_request(request_id)
        if not record:
            raise VerificationNotFoundError(f"Verification request '{request_id}' not found")

        self._authorize_caller(record, context)

        current_status = record.get("status", "pending")
        if current_status in ("verified", "rejected", "failed"):
            raise InvalidStateError("Cannot cancel completed verification")

        await self.results.update_status(request_id, "cancelled")
        if self.audit:
            await self.audit.record_event(
                "verification_cancelled",
                {
                    "request_id": request_id,
                    "tenant_id": context.tenant_id,
                    "principal_id": context.principal_id,
                },
            )
        return CancelVerificationResponse(request_id=request_id, status="cancelled")

    async def complete_verification(
        self,
        code: str,
        state: str,
        browser_binding: Optional[str] = None,
    ) -> VerificationResult:
        """Atomically complete verification on callback, exchanging code and evaluating claims."""
        # 1. Consume state atomically (reused state fails)
        session_data = await self.sessions.consume_session(state)
        if not session_data:
            raise InvalidStateError("Verification state is invalid, expired, or already used")

        request_id = session_data["request_id"]
        checks = session_data.get("checks", ["identity_verified"])

        # 2. Verify request exists and is not cancelled or expired
        record = await self.results.get_request(request_id)
        if not record:
            raise VerificationNotFoundError(f"Verification request '{request_id}' not found")

        req_status = record.get("status", "pending")
        if req_status in ("cancelled", "expired"):
            raise InvalidStateError(f"Cannot complete verification: request is {req_status}")
        if req_status in ("verified", "rejected", "failed"):
            raise InvalidStateError("Verification request has already been finalized")

        exp_val = record.get("session_expires_at") or record.get("expires_at")
        if exp_val is not None:
            try:
                exp_ts = float(exp_val)
            except (ValueError, TypeError):
                try:
                    from datetime import datetime as dt_cls
                    exp_ts = dt_cls.fromisoformat(str(exp_val)).timestamp()
                except Exception:
                    exp_ts = 0.0
            if exp_ts > 0 and time.time() >= exp_ts:
                await self.results.update_status(request_id, "expired")
                raise InvalidStateError("Cannot complete verification: request is expired")

        # 3. Transition to processing state
        await self.results.update_status(request_id, "processing")

        # 4. Browser binding check
        expected_binding = session_data.get("browser_binding")
        if expected_binding and browser_binding != expected_binding:
            raise InvalidStateError("Browser session binding mismatch")

        # 5. Perform code exchange if client key is configured
        private_key = await self._get_private_key()
        if private_key:
            # Sign client assertion
            alg = self.config.allowed_algorithms[0] if self.config.allowed_algorithms else "RS256"
            # Official Fayda spec uses header: {"alg": "RS256", "typ": "JWT"} (no kid)
            client_assertion = create_client_assertion(
                config=self.config,
                private_key=private_key,
                algorithm=alg,
                key_id=None,
            )

            # Exchange code with original PKCE verifier
            code_verifier = session_data["code_verifier"]
            token_response = await self._http.exchange_code(
                code=code,
                code_verifier=code_verifier,
                client_assertion=client_assertion,
            )

            # Validate ID token
            id_token_str = token_response.get("id_token")
            if not id_token_str:
                raise AuthenticationError("Token response missing id_token")

            signing_key = await self.jwks.get_signing_key_for_token(
                id_token_str, client=self._http.client
            )
            id_claims = validate_id_token(
                token_str=id_token_str,
                config=self.config,
                signing_key=signing_key,
                expected_nonce=session_data["nonce"],
            )
            sub = id_claims["sub"]

            # Fetch and validate UserInfo
            userinfo_claims: Dict[str, Any] = {}
            access_token = token_response.get("access_token")
            if access_token:
                raw_userinfo = await self._http.fetch_userinfo(access_token)
                userinfo_signing_key = None
                if isinstance(raw_userinfo, str):
                    # UserInfo response is a signed JWT; resolve signing key separately by its own kid/alg
                    userinfo_signing_key = await self.jwks.get_signing_key_for_token(
                        raw_userinfo, client=self._http.client
                    )
                userinfo_claims = validate_userinfo_response(
                    userinfo=raw_userinfo,
                    config=self.config,
                    expected_sub=sub,
                    signing_key=userinfo_signing_key,
                )

            # Merge and normalize claims
            raw_all_claims = {**id_claims, **userinfo_claims}
            source_cal = getattr(self.config, "dob_source_calendar", "gregorian")
            locales = getattr(self.config, "claims_locales", ["en", "am", "om", "so", "ti", "sid", "wal"])
            normalized = normalize_claims(
                raw_all_claims,
                source_calendar=source_cal,
                preferred_locales=locales,
            )
            from fayda_mcp.predicates import DEFAULT_PREDICATE_REGISTRY, PredicateContext

            eval_tz = getattr(self.policy, "evaluation_timezone", "Africa/Addis_Ababa")
            feb29_rule = getattr(self.policy, "february_29_anniversary", "march_1")
            active_registry = (
                self.policy.get_registry()
                if hasattr(self.policy, "get_registry")
                else DEFAULT_PREDICATE_REGISTRY
            )
            pred_ctx = PredicateContext(
                as_of=None,
                timezone_name=eval_tz,
                february_29_anniversary=feb29_rule,
            )
            evaluated_outcomes, evaluated_reasons = active_registry.evaluate_all_with_reasons(
                normalized,
                checks,
                pred_ctx,
            )

            # Details matching in callback: compare permitted claims before discarding raw claims (Task 07)
            details_match_result: Optional[DetailsMatchResult] = None
            is_details_flow = (
                session_data.get("verification_type") == "details_matching"
                or record.get("verification_type") == "details_matching"
                or bool(session_data.get("expected_details_ref"))
                or bool(record.get("expected_details_ref"))
            )
            if is_details_flow and self.matching_service:
                details_ref = session_data.get("expected_details_ref") or record.get("expected_details_ref")
                user_ref = session_data.get("application_user_ref") or record.get("application_user_ref")
                req_purpose = session_data.get("purpose") or record.get("purpose")
                details_match_result = await self.matching_service.evaluate_details_for_request(
                    request_id=request_id,
                    claims=raw_all_claims,
                    provider_dob_calendar=source_cal,
                    expected_details_ref=details_ref,
                    application_user_ref=user_ref,
                    purpose=req_purpose,
                    expires_at=record.get("expires_at"),
                    identity_authenticated=True,
                )

            # Strictly discard raw citizen claims from memory immediately
            raw_all_claims.clear()
            id_claims.clear()
            userinfo_claims.clear()
            normalized.clear()
        else:
            raise ConfigurationError(
                "A Fayda signing key is required for verification."
            )

        # Distinguish required and optional checks (P4)
        optional_set = set(session_data.get("optional_checks") or [])
        policy_req = getattr(self.policy, "required_checks", None)
        if "required_checks" in session_data:
            required_set = set(session_data["required_checks"])
        elif policy_req is not None:
            required_set = set(policy_req)
        else:
            required_set = {c for c in checks if c not in optional_set}

        # Build checks dict (booleans and null) and safe reasons map
        result_checks: Dict[str, Any] = {}
        result_reasons: Dict[str, str] = {}

        has_rejection = False
        missing_required = False

        for c in checks:
            val = evaluated_outcomes.get(c)
            if val is True:
                result_checks[c] = True
            elif val is False:
                result_checks[c] = False
                has_rejection = True
            else:
                result_checks[c] = None
                reason_code = evaluated_reasons.get(c, "provider_claim_unavailable")
                result_reasons[c] = reason_code
                if c in required_set:
                    missing_required = True

        # Apply details matching outcome to verification checks
        if is_details_flow and details_match_result:
            result_reasons.update(details_match_result.reasons)
            if details_match_result.matching_status == "matched":
                result_checks["identity_verified"] = True
                result_checks["details_matched"] = True
            elif details_match_result.matching_status == "mismatched":
                result_checks["identity_verified"] = True
                result_checks["details_matched"] = False
                has_rejection = True
            else:
                result_checks["identity_verified"] = True
                result_checks["details_matched"] = None
                missing_required = True

        # Determine outcome status
        if has_rejection:
            outcome_status = "rejected"
        elif missing_required:
            outcome_status = "incomplete"
        elif all(result_checks.get(c) is True for c in required_set):
            outcome_status = "verified"
        else:
            outcome_status = "incomplete"

        now = datetime.datetime.now(datetime.timezone.utc)
        now_str = now.isoformat()
        expires_at = (
            record.get("expires_at")
            or (now + datetime.timedelta(seconds=self.config.result_ttl_seconds)).isoformat()
        )
        result = VerificationResult(
            request_id=request_id,
            status=outcome_status,
            checks=result_checks,
            reasons=result_reasons,
            verified_at=now_str,
            expires_at=expires_at,
            evidence_ref=f"ev_{request_id}",
            policy_version=self.policy.version,
        )

        if is_details_flow and details_match_result:
            audit_payload = {
                "event_type": "verification_completed",
                "metadata": {
                    "status": outcome_status,
                    "verification_type": "details_matching",
                    "matching_status": details_match_result.matching_status,
                    "comparison_policy_version": details_match_result.comparison_policy_version,
                    "evidence_ref": f"ev_{request_id}",
                    "checked_at": details_match_result.checked_at,
                },
            }
        else:
            audit_payload = {
                "event_type": "verification_completed",
                "metadata": {
                    "status": outcome_status,
                    "verification_type": "standard",
                },
            }

        # Atomically finalize to ensure concurrent callbacks cannot finalize twice
        finalized = await self.results.finalize_result(
            request_id=request_id,
            result=result,
            ttl_seconds=self.config.result_ttl_seconds,
            audit_event=audit_payload,
        )
        if not finalized:
            raise InvalidStateError("Verification request has already been finalized or cancelled")

        if is_details_flow and details_match_result:
            # Persist minimal match outcomes on the request record
            details_record_data = {
                "verification_type": "details_matching",
                "matching_status": details_match_result.matching_status,
                "matches": details_match_result.matches,
                "comparison_policy_version": details_match_result.comparison_policy_version,
                "required_fields": details_match_result.required_fields,
                "checked_at": details_match_result.checked_at,
                "identity_authenticated": details_match_result.identity_authenticated,
                "evidence_ref": f"ev_{request_id}",
                "reasons": {**result_reasons, **details_match_result.reasons},
            }
            try:
                await self.results.save_request(
                    request_id,
                    {**record, **details_record_data, "status": outcome_status},
                    ttl_seconds=self.config.result_ttl_seconds,
                )
            except Exception:
                pass

            # Task 08: Purge expected details afterward (discard temporary retained demographics)
            if self.matching_service:
                details_ref = session_data.get("expected_details_ref") or record.get("expected_details_ref")
                if details_ref:
                    try:
                        await self.matching_service.purge_expected_details(details_ref)
                    except Exception:
                        pass
                try:
                    await self.matching_service.purge_bound_expected_details_for_request(request_id)
                except Exception:
                    pass

        if self.audit:
            await self.audit.record_event(
                "verification_completed",
                {
                    "request_id": request_id,
                    "tenant_id": record.get("tenant_id", "default"),
                    "principal_id": record.get("principal_id", "default"),
                    "status": outcome_status,
                },
            )

        return result

    async def submit_qr_verification(
        self,
        qr_text: Union[str, Any],
        context: Optional[CallerContext] = None,
        purpose: Optional[str] = None,
        application_user_ref: Optional[str] = None,
        checks: Optional[Sequence[str]] = None,
        idempotency_key: Optional[str] = None,
        dob_calendar: Optional[str] = None,
        include_demographics: bool = False,
        success_hook: Optional[Any] = None,
    ) -> Any:
        """Submit a Fayda QR code for offline verification, binding caller, purpose, and application user."""
        return await self.qr_service.submit_qr_verification(
            qr_text=qr_text,
            context=context,
            purpose=purpose,
            application_user_ref=application_user_ref,
            checks=checks,
            idempotency_key=idempotency_key,
            dob_calendar=dob_calendar,
            include_demographics=include_demographics,
            success_hook=success_hook,
        )

    async def get_qr_verification_result(
        self,
        request_id: str,
        context: Optional[CallerContext] = None,
        filter_output: bool = False,
    ) -> Any:
        """Retrieve a stored QR verification result by request ID, enforcing caller ownership."""
        return await self.qr_service.get_qr_verification_result(
            request_id=request_id,
            context=context,
            filter_output=filter_output,
        )

    async def submit_expected_details(
        self,
        application_user_ref: str,
        purpose: str,
        expected_details: Union[Any, Dict[str, Any]],
        context: Optional[CallerContext] = None,
        ttl_seconds: int = 900,
    ) -> Any:
        """Submit expected identity details from an authenticated host backend and obtain an opaque reference.

        Args:
            application_user_ref: Host application user identifier to bind.
            purpose: Approved business purpose for verification (e.g. 'onboarding', 'kyc').
            expected_details: Expected citizen details (full_name and/or date_of_birth).
            context: Authenticated CallerContext identifying caller principal and tenant.
            ttl_seconds: Time-to-live for the expected details record (default: 900s).

        Returns:
            ExpectedDetailsSubmissionResponse containing opaque expected_details_ref and expiry.
        """
        return await self.matching_service.submit_expected_details(
            application_user_ref=application_user_ref,
            purpose=purpose,
            expected_details=expected_details,
            context=context,
            ttl_seconds=ttl_seconds,
        )

    async def get_expected_details_record(
        self,
        ref: str,
        context: Optional[CallerContext] = None,
        validate_caller: bool = True,
    ) -> Any:
        """Retrieve an expected details record by reference, verifying caller ownership."""
        return await self.matching_service.get_expected_details_record(
            ref=ref,
            context=context,
            validate_caller=validate_caller,
        )

    async def bind_expected_details(
        self,
        ref: str,
        request_id: str,
        application_user_ref: str,
        purpose: str,
        context: Optional[CallerContext] = None,
    ) -> Any:
        """Bind an expected details reference to a verification request, user, and purpose."""
        return await self.matching_service.bind_expected_details(
            ref=ref,
            request_id=request_id,
            application_user_ref=application_user_ref,
            purpose=purpose,
            context=context,
        )

    async def get_bound_expected_details_for_request(
        self,
        request_id: str,
        context: Optional[CallerContext] = None,
        validate_caller: bool = True,
    ) -> Any:
        """Retrieve the bound expected details record for an active verification request."""
        return await self.matching_service.get_bound_expected_details_for_request(
            request_id=request_id,
            context=context,
            validate_caller=validate_caller,
        )

    async def evaluate_details_matching_for_request(
        self,
        request_id: str,
        claims: Dict[str, Any],
        context: Optional[CallerContext] = None,
        provider_dob_calendar: Optional[str] = None,
    ) -> DetailsMatchResult:
        """Run details matching for a request against permitted claims."""
        clean_req_id = str(request_id).strip()
        record = await self.results.get_request(clean_req_id)
        if not record:
            raise VerificationNotFoundError(f"Verification request '{clean_req_id}' not found")

        if context is not None:
            self._authorize_caller(record, context)

        source_cal = provider_dob_calendar or getattr(self.config, "dob_source_calendar", "gregorian")
        details_ref = record.get("expected_details_ref")
        user_ref = record.get("application_user_ref")
        purpose = record.get("purpose")

        return await self.matching_service.evaluate_details_for_request(
            request_id=clean_req_id,
            claims=claims,
            provider_dob_calendar=source_cal,
            expected_details_ref=details_ref,
            application_user_ref=user_ref,
            purpose=purpose,
            expires_at=record.get("expires_at"),
            identity_authenticated=True,
        )

    async def get_details_match_result(
        self,
        request_id: str,
        context: Optional[CallerContext] = None,
    ) -> Optional[DetailsMatchResult]:
        """Retrieve minimal details match outcome by request_id, enforcing caller ownership and expiry."""
        clean_req_id = str(request_id).strip()
        record = await self.results.get_request(clean_req_id)
        if not record:
            return None

        ctx = context or CallerContext()
        self._authorize_caller(record, ctx)

        # Check expiry against UTC clock
        now = time.time()
        exp_val = record.get("session_expires_at") or record.get("expires_at")
        if exp_val:
            try:
                exp_ts = float(exp_val)
            except (ValueError, TypeError):
                try:
                    exp_ts = datetime.datetime.fromisoformat(str(exp_val)).timestamp()
                except Exception:
                    exp_ts = 0.0
            if exp_ts > 0 and now >= exp_ts:
                return None

        # Check in matching_service storage
        if self.matching_service:
            res = await self.matching_service.get_match_result(clean_req_id)
            if res:
                return res

        # Reconstruct from persisted repository record if finalized
        status = record.get("status", "pending")
        if status in ("pending", "initializing", "processing"):
            return DetailsMatchResult(
                request_id=clean_req_id,
                verification_method="esignet",
                matching_status="pending",
                matches={},
                comparison_policy_version=record.get("comparison_policy_version", DEFAULT_COMPARISON_POLICY_VERSION),
                required_fields=record.get("required_fields", []),
                checked_at=None,
                expires_at=str(exp_val) if exp_val else None,
                identity_authenticated=None,
            )

        matching_status = record.get("matching_status")
        if not matching_status:
            if status == "verified":
                matching_status = "matched"
            elif status == "rejected":
                matching_status = "mismatched"
            else:
                matching_status = "unavailable"

        return DetailsMatchResult(
            request_id=clean_req_id,
            verification_method="esignet",
            matching_status=matching_status,
            matches=record.get("matches", {}),
            comparison_policy_version=record.get("comparison_policy_version", DEFAULT_COMPARISON_POLICY_VERSION),
            required_fields=record.get("required_fields", []),
            checked_at=record.get("checked_at") or record.get("verified_at"),
            expires_at=str(exp_val) if exp_val else None,
            reasons=record.get("reasons", {}) if isinstance(record.get("reasons"), dict) else {},
            identity_authenticated=record.get("identity_authenticated", True if status in ("verified", "rejected") else None),
            evidence_ref=record.get("evidence_ref") or f"ev_{clean_req_id}",
        )

