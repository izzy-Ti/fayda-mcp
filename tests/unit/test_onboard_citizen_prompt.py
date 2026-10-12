"""Unit tests for Task M1: onboard_citizen prompt registration, parameterized retrieval, and safety boundaries."""

from typing import Any, Optional
import pytest
from fastmcp.client import Client

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerAuthorizationAdapter, CallerContext
from fayda_mcp.exceptions import AuthorizationError
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore

pytestmark = pytest.mark.asyncio


@pytest.fixture
def test_config() -> FaydaConfig:
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
def verification_service(test_config: FaydaConfig) -> FaydaVerificationService:
    return FaydaVerificationService(
        config=test_config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )


def _get_text(prompt_result: Any) -> str:
    msg = prompt_result.messages[0]
    content = msg.content
    return getattr(content, "text", "")


class TestOnboardCitizenPrompt:
    """Acceptance tests for onboard_citizen prompt via real FastMCP client."""

    async def test_prompts_list_discovery(
        self, verification_service: FaydaVerificationService
    ) -> None:
        """Acceptance requirement: prompts/list works in a real MCP client and exposes onboard_citizen."""
        server = create_mcp_server(service=verification_service)
        async with Client(server) as client:
            prompts = await client.list_prompts()
            prompt_map = {p.name: p for p in prompts}

            assert "onboard_citizen" in prompt_map
            prompt = prompt_map["onboard_citizen"]
            assert prompt.description is not None
            assert "Fayda eSignet" in prompt.description

            # Verify parameters
            arg_names = {arg.name for arg in prompt.arguments} if prompt.arguments else set()
            assert {"purpose", "checks", "application_user_ref"}.issubset(arg_names)

    async def test_prompts_get_default_and_custom_arguments(
        self, verification_service: FaydaVerificationService
    ) -> None:
        """Acceptance requirement: prompts/get works in a real MCP client with defaults and custom parameters."""
        server = create_mcp_server(service=verification_service)
        async with Client(server) as client:
            # 1. Test default parameters
            default_prompt = await client.get_prompt("onboard_citizen", {})
            assert len(default_prompt.messages) >= 1
            default_text = _get_text(default_prompt)
            assert "onboarding" in default_text
            assert "identity_verified" in default_text

            # 2. Test custom parameters
            custom_prompt = await client.get_prompt(
                "onboard_citizen",
                {
                    "purpose": "kyc_tier_2",
                    "checks": "identity_verified, age_over_21, optional:phone_verified",
                    "application_user_ref": "citizen_cust_12345",
                },
            )
            assert len(custom_prompt.messages) >= 1
            custom_text = _get_text(custom_prompt)
            assert "kyc_tier_2" in custom_text
            assert "age_over_21" in custom_text
            assert "optional:phone_verified" in custom_text
            assert "citizen_cust_12345" in custom_text

    async def test_prompt_describes_required_workflow_steps(
        self, verification_service: FaydaVerificationService
    ) -> None:
        """Prompt describes purpose selection, minimal checks, start tool, auth link, polling, and results."""
        server = create_mcp_server(service=verification_service)
        async with Client(server) as client:
            res = await client.get_prompt("onboard_citizen", {})
            text = _get_text(res)

            # Workflow elements
            assert "Purpose Selection" in text
            assert "Minimal Checks" in text
            assert "start_verification" in text
            assert "idempotency_key" in text
            assert "authorization_url" in text
            assert "get_verification_status" in text
            assert "Bounded Polling" in text
            assert "Unavailable Evidence" in text
            assert "get_verification_result" in text

            # Polling bounds and terminal states
            assert "Stop polling" in text
            assert "verified" in text
            assert "rejected" in text
            assert "incomplete" in text
            assert "cancelled" in text
            assert "expired" in text

    async def test_prompt_never_asks_for_credentials_or_biometrics(
        self, verification_service: FaydaVerificationService
    ) -> None:
        """Acceptance requirement: Prompt never asks for keys, OTPs, or raw biometrics."""
        server = create_mcp_server(service=verification_service)
        async with Client(server) as client:
            res = await client.get_prompt("onboard_citizen", {})
            text = _get_text(res)

            # Explicit prohibitions against sensitive data collection
            assert "NEVER ask for, accept, or log citizen passwords" in text
            assert "NEVER ask for, handle, or process raw biometric data" in text
            assert "NEVER store, output, or prompt for raw demographic information" in text

    async def test_all_tools_still_enforce_authorization_alongside_prompts(
        self, verification_service: FaydaVerificationService
    ) -> None:
        """Acceptance requirement: Prompts provide instructions, not execution/permission; tools enforce auth."""
        class RejectAllAdapter(CallerAuthorizationAdapter):
            async def resolve_context(self, tool_name: str, **kwargs: Any) -> CallerContext:
                return CallerContext(tenant_id="tenant-1", principal_id="unauthorized-agent")

            async def authorize(
                self, context: CallerContext, action: str, resource_id: Optional[str] = None
            ) -> bool:
                return False

        server = create_mcp_server(
            service=verification_service,
            caller_adapter=RejectAllAdapter(),
        )

        async with Client(server) as client:
            # Getting prompt works freely (instructions)
            prompt = await client.get_prompt("onboard_citizen", {})
            assert "Citizen Onboarding Procedure" in _get_text(prompt)

            # But invoking tools fails authorization
            with pytest.raises(Exception) as exc_info:
                await client.call_tool(
                    "start_verification",
                    {
                        "purpose": "onboarding",
                        "checks": ["identity_verified"],
                        "application_user_ref": "citizen_1",
                        "idempotency_key": "idemp_1",
                    },
                )
            assert "denied authorization" in str(exc_info.value)

