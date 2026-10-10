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
            client_assertion = create_client_assertion(
                config=self.config,
                private_key=private_key,
                algorithm=alg,
                key_id=self.config.key_id,
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

        audit_payload = {
            "event_type": "verification_completed",
            "metadata": {"status": outcome_status},
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
        )

    async def get_qr_verification_result(
        self,
        request_id: str,
        context: Optional[CallerContext] = None,
    ) -> Any:
        """Retrieve a stored QR verification result by request ID, enforcing caller ownership."""
        return await self.qr_service.get_qr_verification_result(
            request_id=request_id,
            context=context,
        )
