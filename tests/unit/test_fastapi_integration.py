"""Unit tests for Task C2: FastAPI callback router, combined lifecycle, and session binding."""

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from starlette.testclient import TestClient

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import ConfigurationError
from fayda_mcp.integrations.fastapi import (
    create_callback_router,
    create_combined_lifespan,
    create_fastapi_app,
)
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.schemas import VerificationResult
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore

pytestmark = pytest.mark.asyncio


@pytest.fixture
def test_config() -> FaydaConfig:
    return FaydaConfig(
        client_id="test_client_id",
        redirect_uri="http://localhost:8000/auth/fayda/callback",
        issuer="https://issuer.example.com",
        authorization_endpoint="https://issuer.example.com/oauth/authorize",
        token_endpoint="https://issuer.example.com/oauth/token",
        userinfo_endpoint="https://issuer.example.com/oauth/userinfo",
        jwks_uri="https://issuer.example.com/.well-known/jwks.json",
        session_ttl_seconds=300,
        result_ttl_seconds=600,
    )


@pytest.fixture
def service(test_config: FaydaConfig) -> FaydaVerificationService:
    return FaydaVerificationService(
        config=test_config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )


class TestFastApiCallbackRouter:
    """Tests for the optional callback router and host session-binding hooks."""

    async def test_session_binding_hook_is_strictly_required(
        self, service: FaydaVerificationService
    ) -> None:
        """Requirement: Require host session-binding hooks."""
        with pytest.raises(ConfigurationError) as exc_info:
            create_callback_router(service=service, session_binding_hook=None)  # type: ignore

        assert "session-binding hook is required" in str(exc_info.value).lower()

    async def test_callback_works_with_host_registered_uri(
        self, service: FaydaVerificationService
    ) -> None:
        """Acceptance requirement: Redirect/callback works with the host registered URI."""
        # 1. Start verification with a specific browser binding token
        binding_token = "sess_cookie_998877"
        ctx = CallerContext(browser_binding=binding_token)
        start_resp = await service.start_verification(
            context=ctx,
            purpose="onboarding",
            checks=["identity_verified"],
            application_user_ref="user_123",
            idempotency_key="idemp_cb_1",
        )

        import urllib.parse
        parsed = urllib.parse.urlparse(start_resp.authorization_url)
        params = urllib.parse.parse_qs(parsed.query)
        state = params["state"][0]

        # 2. Host provides session-binding hook extracting cookie
        def host_session_hook(request: Request) -> str | None:
            return request.cookies.get("session_id")

        router = create_callback_router(
            service=service,
            session_binding_hook=host_session_hook,
        )

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        client.cookies.set("session_id", binding_token)

        # 3. Invoke callback on the registered path: /auth/fayda/callback
        from unittest.mock import patch
        mock_res = VerificationResult(
            request_id=start_resp.request_id,
            status="verified",
            checks={"identity_verified": True},
            verified_at="2026-10-06T00:00:00Z",
        )
        with patch.object(service, "complete_verification", return_value=mock_res):
            response = client.get(
                "/auth/fayda/callback",
                params={"code": "auth_code_xyz", "state": state},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "verified"
        assert data["checks"]["identity_verified"] is True

    async def test_session_binding_mismatch_fails(
        self, service: FaydaVerificationService
    ) -> None:
        """Verify that an altered or hijacked session binding token is rejected."""
        ctx = CallerContext(browser_binding="correct_session_token")
        start_resp = await service.start_verification(
            context=ctx,
            purpose="onboarding",
            checks=["identity_verified"],
            application_user_ref="user_123",
            idempotency_key="idemp_cb_2",
        )

        import urllib.parse
        parsed = urllib.parse.urlparse(start_resp.authorization_url)
        state = urllib.parse.parse_qs(parsed.query)["state"][0]

        router = create_callback_router(
            service=service,
            session_binding_hook=lambda req: req.cookies.get("session_id"),
        )
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        client.cookies.set("session_id", "wrong_attacker_cookie")

        # Attacker tries to complete with mismatched cookie
        response = client.get(
            "/auth/fayda/callback",
            params={"code": "auth_code_xyz", "state": state},
        )

        # Fails with conflict / error
        assert response.status_code in (400, 409)
        assert "InvalidStateError" in response.json().get("error", "")

    async def test_provider_oauth_error_handling(
        self, service: FaydaVerificationService
    ) -> None:
        """Verify provider errors returned in redirect query params are handled cleanly."""
        router = create_callback_router(
            service=service,
            session_binding_hook=lambda req: "test_token",
        )
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        response = client.get(
            "/auth/fayda/callback",
            params={"error": "access_denied", "error_description": "User cancelled authentication"},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "access_denied"

    async def test_custom_on_success_redirect_hook(
        self, service: FaydaVerificationService
    ) -> None:
        """Verify host on_success hook can return a RedirectResponse to the citizen."""
        ctx = CallerContext(browser_binding="binding_val")
        start_resp = await service.start_verification(
            context=ctx,
            purpose="onboarding",
            checks=["identity_verified"],
            application_user_ref="user_123",
            idempotency_key="idemp_cb_3",
        )
        import urllib.parse
        state = urllib.parse.parse_qs(urllib.parse.urlparse(start_resp.authorization_url).query)["state"][0]

        def redirect_on_success(request: Request, result: VerificationResult) -> RedirectResponse:
            return RedirectResponse(
                url=f"http://host.app/welcome?status={result.status}&req={result.request_id}",
                status_code=303,
            )

        router = create_callback_router(
            service=service,
            session_binding_hook=lambda req: "binding_val",
            on_success=redirect_on_success,
        )
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app, follow_redirects=False)

        from unittest.mock import patch
        mock_res = VerificationResult(
            request_id=start_resp.request_id,
            status="verified",
            checks={"identity_verified": True},
            verified_at="2026-10-06T00:00:00Z",
        )
        with patch.object(service, "complete_verification", return_value=mock_res):
            response = client.get(
                "/auth/fayda/callback",
                params={"code": "auth_code", "state": state},
            )
        assert response.status_code == 303
        assert "http://host.app/welcome?status=verified" in response.headers["location"]


class TestCombinedFastApiMcpLifecycle:
    """Acceptance requirement: MCP lifespans run correctly in combined FastAPI app."""

    async def test_combined_lifespan_execution(
        self, service: FaydaVerificationService
    ) -> None:
        """Verify that service, MCP server, and host lifespans are all executed cleanly."""
        lifecycle_events: list[str] = []

        # Track service lifecycle with subclass honoring Python special method lookup
        class TrackedService(FaydaVerificationService):
            async def __aenter__(self):
                lifecycle_events.append("service_enter")
                return await super().__aenter__()

            async def aclose(self):
                lifecycle_events.append("service_aclose")
                await super().aclose()

        tracked_service = TrackedService(
            config=service.config,
            sessions=service.sessions,
            results=service.results,
        )

        # Track MCP server lifespan
        mcp_server = create_mcp_server(service=tracked_service)

        @asynccontextmanager
        async def custom_mcp_lifespan() -> AsyncIterator[None]:
            lifecycle_events.append("mcp_startup")
            try:
                yield
            finally:
                lifecycle_events.append("mcp_shutdown")

        mcp_server.lifespan = custom_mcp_lifespan

        # Track host application lifespan
        @asynccontextmanager
        async def host_lifespan(app: FastAPI) -> AsyncIterator[None]:
            lifecycle_events.append("host_startup")
            try:
                yield
            finally:
                lifecycle_events.append("host_shutdown")

        lifespan = create_combined_lifespan(
            service=tracked_service,
            mcp_server=mcp_server,
            host_lifespan=host_lifespan,
        )

        app = FastAPI(lifespan=lifespan)

        # Run client lifespan
        with TestClient(app) as client:
            assert "service_enter" in lifecycle_events
            assert "mcp_startup" in lifecycle_events
            assert "host_startup" in lifecycle_events
            assert "mcp_shutdown" not in lifecycle_events

        # After shutdown
        assert "host_shutdown" in lifecycle_events
        assert "mcp_shutdown" in lifecycle_events
        assert "service_aclose" in lifecycle_events

    async def test_create_fastapi_app_factory(
        self, service: FaydaVerificationService
    ) -> None:
        """Verify the create_fastapi_app convenience factory sets up /health, /mcp, and callback."""
        mcp_server = create_mcp_server(service=service)
        app = create_fastapi_app(
            service=service,
            session_binding_hook=lambda req: "token_123",
            mcp_server=mcp_server,
        )

        with TestClient(app) as client:
            # Health check endpoint
            health_res = client.get("/health")
            assert health_res.status_code == 200
            assert health_res.json() == {"status": "ok", "service": "fayda-mcp"}

            # Callback route is available
            cb_res = client.get("/auth/fayda/callback")
            # Without state/code params, returns 409 Conflict (invalid/missing state)
            assert cb_res.status_code in (400, 409)
