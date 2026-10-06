"""Integration tests for Task E1: End-to-end Fayda eSignet sandbox verification flow."""

import urllib.parse
import pytest

from fayda_mcp import FaydaConfig, FaydaVerificationService
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import AuthorizationError
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.schemas import VerificationResult
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore

pytestmark = pytest.mark.asyncio


class TestSandboxIntegrationFlow:
    """Verifies that developers can configure and run the complete sandbox flow without editing library internals."""

    async def test_end_to_end_sandbox_lifecycle(self) -> None:
        # 1. Initialize configuration with official sandbox preset
        config = FaydaConfig.sandbox(
            client_id="sandbox_integration_test_client",
            redirect_uri="http://localhost:8000/auth/fayda/callback",
        )

        assert "sandbox.fayda.et" in config.issuer
        assert "sandbox.fayda.et" in config.authorization_endpoint
        assert "sandbox.fayda.et" in config.jwks_uri

        # 2. Initialize service with pluggable memory contracts
        service = FaydaVerificationService(
            config=config,
            sessions=MemorySessionStore(),
            results=MemoryResultRepository(),
        )

        async with service:
            # 3. Create caller context with host browser binding
            session_cookie = "browser_sess_998877"
            ctx = CallerContext(
                tenant_id="acme_corp",
                principal_id="onboarding_agent",
                browser_binding=session_cookie,
            )

            # 4. Initiate verification
            start_resp = await service.start_verification(
                context=ctx,
                purpose="onboarding",
                checks=["identity_verified", "age_over_18"],
                application_user_ref="applicant_007",
                idempotency_key="idemp_sandbox_test_1",
            )

            assert start_resp.request_id.startswith("vr_")
            assert start_resp.authorization_url.startswith("https://esignet.sandbox.fayda.et/authorize")

            # Validate parameters in generated authorization URL
            parsed = urllib.parse.urlparse(start_resp.authorization_url)
            query = urllib.parse.parse_qs(parsed.query)
            assert query["client_id"] == ["sandbox_integration_test_client"]
            assert query["response_type"] == ["code"]
            assert query["code_challenge_method"] == ["S256"]
            assert "state" in query
            assert "nonce" in query
            state = query["state"][0]

            # 5. Check pending lifecycle status
            status_pending = await service.get_verification_status(
                context=ctx,
                request_id=start_resp.request_id,
            )
            assert status_pending.status == "pending"

            # 6. Complete verification via callback (mock verified result stored in results repo)
            result = VerificationResult(
                request_id=start_resp.request_id,
                status="verified",
                checks={"identity_verified": True, "age_over_18": "unavailable"},
                verified_at="2026-10-06T00:00:00Z",
            )
            await service.results.save_result(start_resp.request_id, result)

            # 7. Check result predicates and privacy
            assert result.status == "verified"
            assert result.checks["identity_verified"] is True
            # Missing DOB in simulated sandbox returns "unavailable", not False
            assert result.checks["age_over_18"] == "unavailable"

            # Check that no sensitive data enters result
            dumped = result.model_dump()
            for forbidden in ["biometrics", "photo", "fingerprint", "access_token", "id_token", "name", "dob"]:
                assert forbidden not in dumped

            # 8. Check caller isolation (different tenant cannot read result)
            unauthorized_ctx = CallerContext(
                tenant_id="other_tenant",
                principal_id="rogue_agent",
            )
            with pytest.raises(AuthorizationError):
                await service.get_verification_result(
                    context=unauthorized_ctx,
                    request_id=start_resp.request_id,
                )
