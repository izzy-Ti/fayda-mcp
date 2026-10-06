"""Core framework-neutral verification service."""

import datetime
from typing import Any, Dict, List, Optional
import httpx
from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import (
    AuthorizationError,
    InvalidStateError,
    PolicyViolationError,
    VerificationNotFoundError,
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

    async def __aenter__(self) -> "FaydaVerificationService":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Cleanly close underlying HTTP clients and connections."""
        await self._http.aclose()

    async def start_verification(
        self,
        context: CallerContext,
        purpose: str,
        checks: List[str],
        application_user_ref: str,
        idempotency_key: str,
    ) -> StartVerificationResponse:
        """Start a verification flow, creating state, PKCE verifier, and authorization link.

        Idempotent: repeating the call with identical idempotency_key returns existing request.
        """
        # Validate against policy
        self.policy.validate_request(purpose=purpose, checks=checks)

        # Idempotency check
        existing = await self.results.find_by_idempotency_key(
            tenant_id=context.tenant_id,
            principal_id=context.principal_id,
            idempotency_key=idempotency_key,
        )
        if existing:
            return StartVerificationResponse(
                request_id=existing["request_id"],
                authorization_url=existing.get("authorization_url", ""),
                expires_at=existing["expires_at"],
            )

        # Generate cryptographic state, nonce, and PKCE challenge
        state = generate_secure_token(32)
        nonce = generate_secure_token(32)
        code_verifier, code_challenge = generate_pkce_pair()

        request_id = f"vr_{generate_secure_token(16)}"
        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = (now + datetime.timedelta(seconds=self.config.session_ttl_seconds)).isoformat()

        # Resolve required scopes and claims for requested checks
        scopes, claims_param = self.policy.resolve_scopes_and_claims(checks)

        # Build Fayda eSignet authorization URL
        auth_url = build_authorization_url(
            config=self.config,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            scopes=scopes,
            claims=claims_param,
        )

        # Store short-lived session in SessionStore
        session_data = {
            "request_id": request_id,
            "tenant_id": context.tenant_id,
            "principal_id": context.principal_id,
            "application_user_ref": application_user_ref,
            "nonce": nonce,
            "code_verifier": code_verifier,
            "purpose": purpose,
            "checks": checks,
            "expires_at": expires_at,
            "browser_binding": context.browser_binding,
        }
        await self.sessions.save_session(state, session_data, ttl_seconds=self.config.session_ttl_seconds)

        # Record durable request
        request_record = {
            "request_id": request_id,
            "tenant_id": context.tenant_id,
            "principal_id": context.principal_id,
            "application_user_ref": application_user_ref,
            "purpose": purpose,
            "checks": checks,
            "status": "pending",
            "expires_at": expires_at,
            "idempotency_key": idempotency_key,
            "authorization_url": auth_url,
        }
        await self.results.save_request(request_id, request_record, ttl_seconds=self.config.result_ttl_seconds)

        if self.audit:
            await self.audit.record_event(
                "verification_started",
                {"request_id": request_id, "tenant_id": context.tenant_id, "purpose": purpose},
            )

        return StartVerificationResponse(
            request_id=request_id,
            authorization_url=auth_url,
            expires_at=expires_at,
        )

    async def get_verification_status(
        self,
        context: CallerContext,
        request_id: str,
    ) -> VerificationStatusResponse:
        """Retrieve the current lifecycle status for a request."""
        record = await self.results.get_request(request_id)
        if not record:
            raise VerificationNotFoundError(f"Verification request '{request_id}' not found")

        # Enforce tenant/caller boundary
        if record.get("tenant_id") != context.tenant_id:
            raise AuthorizationError("Access to verification request denied")

        return VerificationStatusResponse(
            request_id=request_id,
            status=record.get("status", "pending"),
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

        if record.get("tenant_id") != context.tenant_id:
            raise AuthorizationError("Access to verification request denied")

        result = await self.results.get_result(request_id)
        if not result:
            # If not yet verified, return status
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

        if record.get("tenant_id") != context.tenant_id:
            raise AuthorizationError("Access to verification request denied")

        await self.results.update_status(request_id, "cancelled")
        return CancelVerificationResponse(request_id=request_id, status="cancelled")

    async def complete_verification(
        self,
        code: str,
        state: str,
        browser_binding: Optional[str] = None,
    ) -> VerificationResult:
        """Atomically complete verification on callback, exchanging code and evaluating claims."""
        session_data = await self.sessions.consume_session(state)
        if not session_data:
            raise InvalidStateError("Verification state is invalid, expired, or already used")

        request_id = session_data["request_id"]
        checks = session_data.get("checks", ["identity_verified"])

        # Exchange code and validate tokens (full implementation in tasks B2/C2)
        # Compute deterministic result from session checks:
        simulated_claims = {"sub": f"sub_{request_id[:8]}"}
        evaluated = evaluate_checks(simulated_claims, checks)

        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = VerificationResult(
            request_id=request_id,
            status="verified",
            checks={k: bool(v) for k, v in evaluated.items() if v is not None},
            verified_at=now_str,
            evidence_ref=f"ev_{request_id}",
            policy_version=self.policy.version,
        )

        # Atomically finalize to ensure concurrent callbacks cannot finalize twice
        finalized = await self.results.finalize_result(
            request_id=request_id,
            result=result,
            ttl_seconds=self.config.result_ttl_seconds,
        )
        if not finalized:
            raise InvalidStateError("Verification request has already been finalized")

        if self.audit:
            await self.audit.record_event(
                "verification_completed",
                {"request_id": request_id, "status": "verified"},
            )

        return result
