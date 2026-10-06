"""Core framework-neutral verification service."""

import datetime
from typing import Any, Dict, List, Optional
import httpx
from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    InvalidStateError,
    PolicyViolationError,
    TokenValidationError,
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

    async def __aenter__(self) -> "FaydaVerificationService":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Cleanly close underlying HTTP clients and connections."""
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
        checks: List[str],
        application_user_ref: str,
        idempotency_key: str,
    ) -> StartVerificationResponse:
        """Start a verification flow, creating state, PKCE verifier, and authorization link.

        Idempotent: repeating the call with identical idempotency_key returns existing request.
        """
        # Validate against policy before state creation or redirect
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

        # Store short-lived session in SessionStore bound to caller context
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

    def _authorize_caller(self, record: Dict[str, Any], context: CallerContext) -> None:
        """Enforce tenant and caller principal isolation."""
        if record.get("tenant_id") != context.tenant_id:
            raise AuthorizationError("Access to verification request denied: tenant mismatch")

        record_principal = record.get("principal_id")
        if (
            record_principal
            and record_principal != "anonymous"
            and context.principal_id != "anonymous"
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

        self._authorize_caller(record, context)

        result = await self.results.get_result(request_id)
        if not result:
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

        await self.results.update_status(request_id, "cancelled")
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

        # 2. Browser binding check
        expected_binding = session_data.get("browser_binding")
        if expected_binding and browser_binding != expected_binding:
            raise InvalidStateError("Browser session binding mismatch")

        # 3. Perform code exchange if client key is configured
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
                userinfo_claims = validate_userinfo_response(
                    userinfo=raw_userinfo,
                    config=self.config,
                    expected_sub=sub,
                    signing_key=signing_key,
                )

            # Merge and normalize claims
            raw_all_claims = {**id_claims, **userinfo_claims}
            normalized = normalize_claims(raw_all_claims)
            evaluated = evaluate_checks(normalized, checks)
        else:
            raise ConfigurationError(
                "A Fayda signing key is required for verification."
            )

        # Determine outcome status based on check results
        has_failure = any(v is False for v in evaluated.values())
        if has_failure:
            outcome_status = "rejected"
        elif any(v is True for v in evaluated.values()):
            outcome_status = "verified"
        else:
            outcome_status = "failed"

        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = VerificationResult(
            request_id=request_id,
            status=outcome_status,
            checks=evaluated,
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
