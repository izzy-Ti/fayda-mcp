"""Unit tests for Task C1: MCP factory, host authorization adapter, and caller isolation."""

import contextvars
from typing import Any, Dict, List, Optional
import pytest
from fastmcp.client import Client
from fastmcp.exceptions import ToolError

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import (
    CallerAuthorizationAdapter,
    CallerContext,
    SimpleCallerAdapter,
)
from fayda_mcp.exceptions import AuthorizationError
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore

pytestmark = pytest.mark.asyncio


@pytest.fixture
def mock_config() -> FaydaConfig:
    """Fixture providing minimal test configuration."""
    return FaydaConfig(
        client_id="test_client_id",
        redirect_uri="http://localhost:8000/callback",
        issuer="https://issuer.example.com",
        authorization_endpoint="https://issuer.example.com/oauth/authorize",
        token_endpoint="https://issuer.example.com/oauth/token",
        userinfo_endpoint="https://issuer.example.com/oauth/userinfo",
        jwks_uri="https://issuer.example.com/.well-known/jwks.json",
        session_ttl_seconds=300,
        result_ttl_seconds=600,
    )


@pytest.fixture
def verification_service(mock_config: FaydaConfig) -> FaydaVerificationService:
    """Fixture providing an initialized FaydaVerificationService with memory stores."""
    return FaydaVerificationService(
        config=mock_config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )


class TestMcpFactoryAndTools:
    """Tests for explicit tool registration and real MCP client flows."""

    async def test_tool_registration_and_discovery(
        self, verification_service: FaydaVerificationService
    ) -> None:
        """Verify FastMCP server exposes all four explicit verification tools."""
        server = create_mcp_server(service=verification_service)
        async with Client(server) as client:
            tools = await client.list_tools()
            tool_names = {t.name for t in tools}
            assert {
                "start_verification",
                "get_verification_status",
                "get_verification_result",
                "cancel_verification",
            }.issubset(tool_names)

    async def test_real_mcp_client_start_status_result_flow(
        self,
        mock_config: FaydaConfig,
        verification_service: FaydaVerificationService,
    ) -> None:
        """Acceptance requirement: A real MCP client completes start/status/result flows."""
        server = create_mcp_server(service=verification_service)

        async with Client(server) as client:
            # 1. Start verification
            start_res = await client.call_tool(
                "start_verification",
                {
                    "purpose": "onboarding",
                    "checks": ["identity_verified"],
                    "application_user_ref": "applicant_99",
                    "idempotency_key": "idemp_abc_1",
                },
            )
            assert start_res.is_error is False
            req_data = start_res.data
            request_id = req_data.request_id if hasattr(req_data, "request_id") else req_data["request_id"]
            auth_url = req_data.authorization_url if hasattr(req_data, "authorization_url") else req_data["authorization_url"]
            assert request_id.startswith("vr_")
            assert "https://issuer.example.com/oauth/authorize" in auth_url

            # 2. Query status while pending
            status_res = await client.call_tool(
                "get_verification_status",
                {"request_id": request_id},
            )
            assert status_res.is_error is False
            status_val = status_res.data.status if hasattr(status_res.data, "status") else status_res.data["status"]
            assert status_val == "pending"

            # 3. Simulate completion of verification via callback
            # Extract state from authorization URL to simulate citizen return
            import urllib.parse
            parsed = urllib.parse.urlparse(auth_url)
            query_params = urllib.parse.parse_qs(parsed.query)
            state = query_params["state"][0]

            from fayda_mcp.schemas import VerificationResult
            import datetime
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            await verification_service.results.save_result(
                request_id,
                VerificationResult(
                    request_id=request_id,
                    status="verified",
                    checks={"identity_verified": True},
                    verified_at=now_iso,
                ),
            )

            # 4. Read final result via MCP client
            result_res = await client.call_tool(
                "get_verification_result",
                {"request_id": request_id},
            )
            assert result_res.is_error is False
            result_data = result_res.data
            final_status = result_data.status if hasattr(result_data, "status") else result_data["status"]
            assert final_status == "verified"
            checks = result_data.checks if hasattr(result_data, "checks") else result_data["checks"]
            assert checks["identity_verified"] is True

    async def test_real_mcp_client_cancel_flow(
        self, verification_service: FaydaVerificationService
    ) -> None:
        """Verify cancelling an in-progress verification request via real MCP client."""
        server = create_mcp_server(service=verification_service)

        async with Client(server) as client:
            start_res = await client.call_tool(
                "start_verification",
                {
                    "purpose": "onboarding",
                    "checks": ["identity_verified"],
                    "application_user_ref": "applicant_cancel",
                    "idempotency_key": "idemp_cancel_1",
                },
            )
            req_data = start_res.data
            request_id = req_data.request_id if hasattr(req_data, "request_id") else req_data["request_id"]

            # Cancel verification
            cancel_res = await client.call_tool(
                "cancel_verification",
                {"request_id": request_id},
            )
            assert cancel_res.is_error is False
            cancel_status = cancel_res.data.status if hasattr(cancel_res.data, "status") else cancel_res.data["status"]
            assert cancel_status == "cancelled"

            # Status confirms cancelled
            status_res = await client.call_tool(
                "get_verification_status",
                {"request_id": request_id},
            )
            status_val = status_res.data.status if hasattr(status_res.data, "status") else status_res.data["status"]
            assert status_val == "cancelled"


class TestCallerIsolationAndHostAdapter:
    """Acceptance requirement: Caller A cannot read caller B results."""

    async def test_tenant_isolation_caller_a_cannot_read_caller_b(
        self, verification_service: FaydaVerificationService
    ) -> None:
        """Caller from Tenant A starts verification; Caller from Tenant B cannot access it."""
        current_context: contextvars.ContextVar[CallerContext] = contextvars.ContextVar(
            "current_context",
            default=CallerContext(tenant_id="tenant_a", principal_id="caller_a"),
        )

        adapter = SimpleCallerAdapter(context_resolver=lambda: current_context.get())
        server = create_mcp_server(service=verification_service, caller_adapter=adapter)

        async with Client(server) as client:
            # Caller A starts verification
            current_context.set(CallerContext(tenant_id="tenant_a", principal_id="caller_a"))
            start_res = await client.call_tool(
                "start_verification",
                {
                    "purpose": "onboarding",
                    "checks": ["identity_verified"],
                    "application_user_ref": "usr_tenant_a",
                    "idempotency_key": "idemp_t_a",
                },
            )
            req_data = start_res.data
            request_id = req_data.request_id if hasattr(req_data, "request_id") else req_data["request_id"]

            # Caller A CAN read status and result
            status_a = await client.call_tool("get_verification_status", {"request_id": request_id})
            assert status_a.is_error is False

            # Switch context to Caller B (different tenant)
            current_context.set(CallerContext(tenant_id="tenant_b", principal_id="caller_b"))

            # Caller B attempts to read status -> must fail
            with pytest.raises(ToolError) as exc_info:
                await client.call_tool("get_verification_status", {"request_id": request_id})
            assert "denied" in str(exc_info.value).lower()

            # Caller B attempts to read result -> must fail
            with pytest.raises(ToolError) as exc_info:
                await client.call_tool("get_verification_result", {"request_id": request_id})
            assert "denied" in str(exc_info.value).lower()

            # Caller B attempts to cancel -> must fail
            with pytest.raises(ToolError) as exc_info:
                await client.call_tool("cancel_verification", {"request_id": request_id})
            assert "denied" in str(exc_info.value).lower()

    async def test_principal_isolation_within_same_tenant(
        self, verification_service: FaydaVerificationService
    ) -> None:
        """Caller A and Caller B in same tenant; Caller B cannot read Caller A's verification without admin scope."""
        current_context: contextvars.ContextVar[CallerContext] = contextvars.ContextVar(
            "current_context",
            default=CallerContext(tenant_id="org_corp", principal_id="agent_alpha"),
        )

        adapter = SimpleCallerAdapter(context_resolver=lambda: current_context.get())
        server = create_mcp_server(service=verification_service, caller_adapter=adapter)

        async with Client(server) as client:
            # Agent Alpha creates verification
            current_context.set(CallerContext(tenant_id="org_corp", principal_id="agent_alpha"))
            start_res = await client.call_tool(
                "start_verification",
                {
                    "purpose": "onboarding",
                    "checks": ["identity_verified"],
                    "application_user_ref": "usr_alpha",
                    "idempotency_key": "idemp_alpha_1",
                },
            )
            req_data = start_res.data
            request_id = req_data.request_id if hasattr(req_data, "request_id") else req_data["request_id"]

            # Agent Beta tries to read Agent Alpha's result -> must fail
            current_context.set(CallerContext(tenant_id="org_corp", principal_id="agent_beta"))
            with pytest.raises(ToolError) as exc_info:
                await client.call_tool("get_verification_result", {"request_id": request_id})
            assert "denied" in str(exc_info.value).lower()

            # Admin caller in the same tenant CAN read result
            current_context.set(
                CallerContext(
                    tenant_id="org_corp",
                    principal_id="admin_auditor",
                    scopes=["verification:admin", "verification:read"],
                )
            )
            admin_res = await client.call_tool("get_verification_result", {"request_id": request_id})
            assert admin_res.is_error is False

    async def test_custom_host_caller_authorization_adapter(
        self, verification_service: FaydaVerificationService
    ) -> None:
        """Verify host can provide custom CallerAuthorizationAdapter implementing Protocol."""

        class HostCustomAdapter(CallerAuthorizationAdapter):
            """Custom adapter that denies cancellation for non-admin callers."""

            def __init__(self, current_user: str, is_admin: bool):
                self.current_user = current_user
                self.is_admin = is_admin

            async def resolve_context(self, tool_name: str, **kwargs: Any) -> CallerContext:
                return CallerContext(
                    tenant_id="acme",
                    principal_id=self.current_user,
                    scopes=["verification:create", "verification:read"]
                    + (["verification:cancel"] if self.is_admin else []),
                )

            async def authorize(
                self,
                context: CallerContext,
                action: str,
                resource_id: Optional[str] = None,
            ) -> bool:
                if action == "verification:cancel" and not self.is_admin:
                    return False
                return True

        # Non-admin host adapter
        non_admin_adapter = HostCustomAdapter(current_user="regular_agent", is_admin=False)
        server = create_mcp_server(service=verification_service, caller_adapter=non_admin_adapter)

        async with Client(server) as client:
            start_res = await client.call_tool(
                "start_verification",
                {
                    "purpose": "onboarding",
                    "checks": ["identity_verified"],
                    "application_user_ref": "user_reg",
                    "idempotency_key": "idemp_reg_1",
                },
            )
            req_data = start_res.data
            request_id = req_data.request_id if hasattr(req_data, "request_id") else req_data["request_id"]

            # Cancel is blocked at the adapter authorization level
            with pytest.raises(ToolError) as exc_info:
                await client.call_tool("cancel_verification", {"request_id": request_id})
            assert "denied" in str(exc_info.value).lower()
