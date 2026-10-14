"""Unit tests for Task 09: Register the get_details_match_result tool.

Verifies:
- Tool registration and schema discovery on FastMCP server.
- Ownership checks (tenant & principal isolation).
- Expiration handling.
- Pending vs completed outcome retrieval.
- Zero raw citizen names, DOBs, FANs, or provider tokens in output.
"""

from unittest.mock import AsyncMock, patch
import pytest
from fastmcp.client import Client
from fastmcp.exceptions import ToolError

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext, SimpleCallerAdapter
from fayda_mcp.exceptions import AuthorizationError, VerificationNotFoundError
from fayda_mcp.matching.schemas import (
    DEFAULT_COMPARISON_POLICY_VERSION,
    DetailsMatchResult,
    ExpectedDetails,
)
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore

pytestmark = pytest.mark.asyncio


@pytest.fixture
def mock_config() -> FaydaConfig:
    return FaydaConfig(
        client_id="test_client_id",
        redirect_uri="http://localhost:8000/callback",
        issuer="https://esignet.example.com",
        authorization_endpoint="https://esignet.example.com/oauth/authorize",
        token_endpoint="https://esignet.example.com/oauth/token",
        userinfo_endpoint="https://esignet.example.com/oauth/userinfo",
        jwks_uri="https://esignet.example.com/.well-known/jwks.json",
        session_ttl_seconds=300,
        result_ttl_seconds=600,
    )


@pytest.fixture
def verification_service(mock_config: FaydaConfig) -> FaydaVerificationService:
    return FaydaVerificationService(
        config=mock_config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
        policy=VerificationPolicy(version="v1"),
    )


@pytest.fixture
def caller_context() -> CallerContext:
    return CallerContext(
        tenant_id="bank-alpha",
        principal_id="service-worker-1",
        scopes=["verification:create", "verification:read"],
    )


@pytest.fixture
def foreign_context() -> CallerContext:
    return CallerContext(
        tenant_id="bank-beta",
        principal_id="service-worker-2",
        scopes=["verification:create", "verification:read"],
    )


async def test_tool_registration_and_schema(verification_service: FaydaVerificationService):
    """Verify get_details_match_result is registered and discoverable on FastMCP server."""
    server = create_mcp_server(service=verification_service)
    async with Client(server) as client:
        tools = await client.list_tools()
        tool_names = {t.name for t in tools}
        assert "get_details_match_result" in tool_names

        tool_def = next(t for t in tools if t.name == "get_details_match_result")
        schema = getattr(tool_def, "input_schema", None) or getattr(tool_def, "inputSchema", None)
        assert schema is not None
        props = schema.get("properties", {})
        assert "request_id" in props
        assert "request_id" in schema.get("required", [])


async def test_get_details_match_result_pending_status(
    verification_service: FaydaVerificationService, caller_context: CallerContext
):
    """Returns matching_status 'pending' while verification is still awaiting citizen callback."""
    adapter = SimpleCallerAdapter(caller_context)
    server = create_mcp_server(service=verification_service, caller_adapter=adapter)

    # 1. Register expected details and start verification
    sub_resp = await verification_service.submit_expected_details(
        application_user_ref="usr-pending-1",
        purpose="onboarding",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            date_of_birth="1995/04/12",
        ),
        context=caller_context,
    )

    start_resp = await verification_service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="onboarding",
        application_user_ref="usr-pending-1",
        idempotency_key="idemp-tool-pending-1",
    )

    # 2. Invoke tool via FastMCP client before callback
    async with Client(server) as client:
        result = await client.call_tool(
            "get_details_match_result",
            {"request_id": start_resp.request_id},
        )
        assert result is not None
        assert len(result.content) >= 1
        import json
        content_dict = json.loads(result.content[0].text)

        assert content_dict["request_id"] == start_resp.request_id
        assert content_dict["matching_status"] == "pending"
        assert content_dict["comparison_policy_version"] == "details-v1"
        assert content_dict["matches"] == {}


async def test_get_details_match_result_completed_outcome(
    verification_service: FaydaVerificationService, caller_context: CallerContext
):
    """Returns completed minimal match outcome after callback completion."""
    adapter = SimpleCallerAdapter(caller_context)
    server = create_mcp_server(service=verification_service, caller_adapter=adapter)

    sub_resp = await verification_service.submit_expected_details(
        application_user_ref="usr-completed-1",
        purpose="onboarding",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            date_of_birth="1995/04/12",
        ),
        context=caller_context,
    )

    start_resp = await verification_service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="onboarding",
        application_user_ref="usr-completed-1",
        idempotency_key="idemp-tool-comp-1",
    )

    state = start_resp.authorization_url.split("state=")[1].split("&")[0]

    mock_id_claims = {"sub": "fayda:sub:comp"}
    mock_userinfo_claims = {
        "name": "Abebe Bikila",
        "birthdate": "1995-04-12",
    }

    with patch.object(verification_service, "_get_private_key", return_value="fake_pem"), \
         patch("fayda_mcp.service.create_client_assertion", return_value="fake.assertion"), \
         patch.object(verification_service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
         patch.object(verification_service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.jwt", "access_token": "at"})), \
         patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
         patch.object(verification_service._http, "fetch_userinfo", AsyncMock(return_value={})), \
         patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

        await verification_service.complete_verification(code="auth_code_comp", state=state)

    # Invoke tool via FastMCP client
    async with Client(server) as client:
        tool_res = await client.call_tool(
            "get_details_match_result",
            {"request_id": start_resp.request_id},
        )
        assert len(tool_res.content) >= 1
        import json
        content_dict = json.loads(tool_res.content[0].text)

        assert content_dict["request_id"] == start_resp.request_id
        assert content_dict["verification_method"] == "esignet"
        assert content_dict["matching_status"] == "matched"
        assert content_dict["matches"] == {"full_name": True, "date_of_birth": True}
        assert content_dict["comparison_policy_version"] == "details-v1"
        assert content_dict["identity_authenticated"] is True
        assert content_dict["checked_at"] is not None


async def test_get_details_match_result_ownership_enforcement(
    verification_service: FaydaVerificationService,
    caller_context: CallerContext,
    foreign_context: CallerContext,
):
    """Enforces tenant and principal caller isolation; unauthorized callers are rejected."""
    # Start request under bank-alpha
    sub_resp = await verification_service.submit_expected_details(
        application_user_ref="usr-iso-tool",
        purpose="onboarding",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=caller_context,
    )

    start_resp = await verification_service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="onboarding",
        application_user_ref="usr-iso-tool",
        idempotency_key="idemp-tool-iso-1",
    )

    # Attempt to query tool as bank-beta
    foreign_adapter = SimpleCallerAdapter(foreign_context)
    foreign_server = create_mcp_server(service=verification_service, caller_adapter=foreign_adapter)

    async with Client(foreign_server) as client:
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool(
                "get_details_match_result",
                {"request_id": start_resp.request_id},
            )
        assert "Access denied" in str(exc_info.value) or "denied" in str(exc_info.value)


async def test_get_details_match_result_not_found(
    verification_service: FaydaVerificationService, caller_context: CallerContext
):
    """Non-existent request returns not found error."""
    adapter = SimpleCallerAdapter(caller_context)
    server = create_mcp_server(service=verification_service, caller_adapter=adapter)

    async with Client(server) as client:
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool(
                "get_details_match_result",
                {"request_id": "vr_nonexistent_999"},
            )
        assert "not found" in str(exc_info.value).lower()


async def test_get_details_match_result_expired(
    verification_service: FaydaVerificationService, caller_context: CallerContext
):
    """Expired verification request returns not found error."""
    adapter = SimpleCallerAdapter(caller_context)
    server = create_mcp_server(service=verification_service, caller_adapter=adapter)

    sub_resp = await verification_service.submit_expected_details(
        application_user_ref="usr-exp-tool",
        purpose="onboarding",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=caller_context,
    )

    start_resp = await verification_service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="onboarding",
        application_user_ref="usr-exp-tool",
        idempotency_key="idemp-tool-exp-1",
    )

    # Artificially expire the request record
    rec = await verification_service.results.get_request(start_resp.request_id)
    rec["expires_at"] = "2020-01-01T00:00:00+00:00"
    rec["session_expires_at"] = "2020-01-01T00:00:00+00:00"
    await verification_service.results.save_request(start_resp.request_id, rec, ttl_seconds=1)

    async with Client(server) as client:
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool(
                "get_details_match_result",
                {"request_id": start_resp.request_id},
            )
        assert "not found" in str(exc_info.value).lower() or "expired" in str(exc_info.value).lower()


async def test_tool_returns_no_raw_demographics_or_tokens(
    verification_service: FaydaVerificationService, caller_context: CallerContext
):
    """Tool output strictly excludes citizen demographics (names, DOBs), FANs, and provider tokens."""
    adapter = SimpleCallerAdapter(caller_context)
    server = create_mcp_server(service=verification_service, caller_adapter=adapter)

    secret_name = "Tirunesh Dibaba"
    secret_dob = "1985/06/01"

    sub_resp = await verification_service.submit_expected_details(
        application_user_ref="usr-priv-check",
        purpose="onboarding",
        expected_details=ExpectedDetails(
            full_name=secret_name,
            date_of_birth=secret_dob,
        ),
        context=caller_context,
    )

    start_resp = await verification_service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="onboarding",
        application_user_ref="usr-priv-check",
        idempotency_key="idemp-priv-check-1",
    )

    state = start_resp.authorization_url.split("state=")[1].split("&")[0]

    mock_id_claims = {"sub": "fayda:sub:privacy"}
    mock_userinfo_claims = {
        "name": secret_name,
        "birthdate": "1985-06-01",
    }

    with patch.object(verification_service, "_get_private_key", return_value="fake_pem"), \
         patch("fayda_mcp.service.create_client_assertion", return_value="fake.assertion"), \
         patch.object(verification_service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
         patch.object(verification_service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.jwt", "access_token": "secret_access_token"})), \
         patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
         patch.object(verification_service._http, "fetch_userinfo", AsyncMock(return_value={})), \
         patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

        await verification_service.complete_verification(code="auth_code_priv", state=state)

    async with Client(server) as client:
        tool_res = await client.call_tool(
            "get_details_match_result",
            {"request_id": start_resp.request_id},
        )
        content_str = str(tool_res)

        # Strictly assert zero PII, FANs, or token strings leak to LLM
        assert secret_name not in content_str
        assert "1985" not in content_str
        assert "secret_access_token" not in content_str
        assert "mock.jwt" not in content_str
