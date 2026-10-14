"""Unit tests for Task 04: start_details_verification tool registration and eSignet start flow reuse."""

import urllib.parse
import json
import pytest
from fastmcp.client import Client
from fastmcp.exceptions import ToolError

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext, SimpleCallerAdapter
from fayda_mcp.exceptions import (
    AuthorizationError,
    IdempotencyConflictError,
)
from fayda_mcp.matching.schemas import (
    DetailsAlreadyBoundError,
    DetailsCallerMismatchError,
    DetailsPurposeMismatchError,
    DetailsReferenceExpiredError,
    DetailsReferenceNotFoundError,
    DetailsUserMismatchError,
    ExpectedDetails,
)
from fayda_mcp.mcp.factory import create_mcp_server
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
    )


@pytest.fixture
def caller_context() -> CallerContext:
    return CallerContext(
        tenant_id="bank-1",
        principal_id="service-backend-a",
        scopes=["verification:create", "verification:read"],
    )


@pytest.fixture
def other_context() -> CallerContext:
    return CallerContext(
        tenant_id="bank-2",
        principal_id="service-backend-b",
        scopes=["verification:create", "verification:read"],
    )


# ===========================================================================
# 1. Tool Registration and FastMCP Discovery Tests
# ===========================================================================


async def test_tool_registration_and_schema(verification_service: FaydaVerificationService):
    """Verify start_details_verification is exposed in FastMCP list_tools."""
    server = create_mcp_server(service=verification_service)
    async with Client(server) as client:
        tools = await client.list_tools()
        tool_names = {t.name for t in tools}
        assert "start_details_verification" in tool_names

        # Inspect parameters of start_details_verification
        tool_def = next(t for t in tools if t.name == "start_details_verification")
        schema = (
            getattr(tool_def, "input_schema", None)
            or getattr(tool_def, "inputSchema", None)
            or getattr(tool_def, "parameters", {})
        )
        props = schema.get("properties", {})
        assert "expected_details_ref" in props
        assert "purpose" in props
        assert "application_user_ref" in props
        assert "idempotency_key" in props


# ===========================================================================
# 2. End-to-End Start Details Verification Flow
# ===========================================================================


async def test_start_details_verification_success(
    verification_service: FaydaVerificationService,
    caller_context: CallerContext,
):
    """Host backend submits expected details, then start tool returns request_id and authorization_url."""
    adapter = SimpleCallerAdapter(context_resolver=lambda: caller_context)
    server = create_mcp_server(service=verification_service, caller_adapter=adapter)

    # 1. Backend submits expected details
    sub_resp = await verification_service.submit_expected_details(
        application_user_ref="citizen_usr_123",
        purpose="kyc",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            date_of_birth="1990/05/12",
        ),
        context=caller_context,
    )
    ref = sub_resp.expected_details_ref
    assert ref.startswith("edr_")

    # 2. Call start_details_verification via MCP client
    async with Client(server) as client:
        result = await client.call_tool(
            "start_details_verification",
            arguments={
                "expected_details_ref": ref,
                "purpose": "kyc",
                "application_user_ref": "citizen_usr_123",
                "idempotency_key": "idemp_test_001",
            },
        )

    # FastMCP returns a CallToolResult
    assert len(result.content) >= 1
    raw_text = result.content[0].text
    data = json.loads(raw_text)

    assert "request_id" in data
    assert data["request_id"].startswith("vr_")
    assert "authorization_url" in data
    assert "expires_at" in data

    # 3. Verify authorization_url structure and requested claims
    parsed_url = urllib.parse.urlparse(data["authorization_url"])
    params = urllib.parse.parse_qs(parsed_url.query)

    assert "openid" in params["scope"][0]
    assert "profile" in params["scope"][0]
    assert "state" in params
    assert "code_challenge" in params

    claims = json.loads(params["claims"][0])
    assert "name" in claims["userinfo"]
    assert "birthdate" in claims["userinfo"]

    # 4. Verify reference was bound to the request
    bound = await verification_service.get_expected_details_record(ref, context=caller_context)
    assert bound.bound_request_id == data["request_id"]

    # 5. Verify reverse lookup
    rev_record = await verification_service.get_bound_expected_details_for_request(
        data["request_id"], context=caller_context
    )
    assert rev_record.ref == ref


# ===========================================================================
# 3. Idempotency & Replay Semantics
# ===========================================================================


async def test_start_details_verification_idempotent(
    verification_service: FaydaVerificationService,
    caller_context: CallerContext,
):
    """Repeated calls with identical parameters and idempotency_key return identical request_id."""
    adapter = SimpleCallerAdapter(context_resolver=lambda: caller_context)
    server = create_mcp_server(service=verification_service, caller_adapter=adapter)

    sub_resp = await verification_service.submit_expected_details(
        application_user_ref="citizen_usr_idemp",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=caller_context,
    )
    ref = sub_resp.expected_details_ref

    async with Client(server) as client:
        call1 = await client.call_tool(
            "start_details_verification",
            arguments={
                "expected_details_ref": ref,
                "purpose": "kyc",
                "application_user_ref": "citizen_usr_idemp",
                "idempotency_key": "idemp_same_key",
            },
        )
        call2 = await client.call_tool(
            "start_details_verification",
            arguments={
                "expected_details_ref": ref,
                "purpose": "kyc",
                "application_user_ref": "citizen_usr_idemp",
                "idempotency_key": "idemp_same_key",
            },
        )

    res1 = json.loads(call1.content[0].text)
    res2 = json.loads(call2.content[0].text)

    assert res1["request_id"] == res2["request_id"]
    assert res1["authorization_url"] == res2["authorization_url"]


async def test_start_details_verification_idempotency_conflict(
    verification_service: FaydaVerificationService,
    caller_context: CallerContext,
):
    """Reusing an idempotency key with different expected_details returns conflict."""
    adapter = SimpleCallerAdapter(context_resolver=lambda: caller_context)
    server = create_mcp_server(service=verification_service, caller_adapter=adapter)

    sub1 = await verification_service.submit_expected_details(
        application_user_ref="citizen_user_1",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=caller_context,
    )
    sub2 = await verification_service.submit_expected_details(
        application_user_ref="citizen_user_2",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Derartu Tulu"),
        context=caller_context,
    )

    async with Client(server) as client:
        await client.call_tool(
            "start_details_verification",
            arguments={
                "expected_details_ref": sub1.expected_details_ref,
                "purpose": "kyc",
                "application_user_ref": "citizen_user_1",
                "idempotency_key": "idemp_conflict_key",
            },
        )

        # Call with different ref and user but same idempotency key
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool(
                "start_details_verification",
                arguments={
                    "expected_details_ref": sub2.expected_details_ref,
                    "purpose": "kyc",
                    "application_user_ref": "citizen_user_2",
                    "idempotency_key": "idemp_conflict_key",
                },
            )
        assert "Idempotency key" in str(exc_info.value) or "conflict" in str(exc_info.value).lower()


# ===========================================================================
# 4. Caller Ownership and Isolation
# ===========================================================================


async def test_start_details_verification_caller_isolation(
    verification_service: FaydaVerificationService,
    caller_context: CallerContext,
    other_context: CallerContext,
):
    """A caller cannot start details verification using a reference created by a different tenant/principal."""
    # Submit under caller_context
    sub_resp = await verification_service.submit_expected_details(
        application_user_ref="citizen_usr_isolate",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=caller_context,
    )
    ref = sub_resp.expected_details_ref

    # Attempt to consume via other_context
    adapter = SimpleCallerAdapter(context_resolver=lambda: other_context)
    server = create_mcp_server(service=verification_service, caller_adapter=adapter)

    async with Client(server) as client:
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool(
                "start_details_verification",
                arguments={
                    "expected_details_ref": ref,
                    "purpose": "kyc",
                    "application_user_ref": "citizen_usr_isolate",
                    "idempotency_key": "idemp_isolate",
                },
            )
        assert "not authorized" in str(exc_info.value).lower() or "mismatch" in str(exc_info.value).lower()


# ===========================================================================
# 5. User and Purpose Mismatch Validation
# ===========================================================================


async def test_start_details_verification_user_mismatch(
    verification_service: FaydaVerificationService,
    caller_context: CallerContext,
):
    """Mismatched application_user_ref raises DetailsUserMismatchError."""
    adapter = SimpleCallerAdapter(context_resolver=lambda: caller_context)
    server = create_mcp_server(service=verification_service, caller_adapter=adapter)

    sub_resp = await verification_service.submit_expected_details(
        application_user_ref="citizen_actual_user",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=caller_context,
    )

    async with Client(server) as client:
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool(
                "start_details_verification",
                arguments={
                    "expected_details_ref": sub_resp.expected_details_ref,
                    "purpose": "kyc",
                    "application_user_ref": "citizen_different_user",
                    "idempotency_key": "idemp_diff_user",
                },
            )
        assert "Application user ref does not match" in str(exc_info.value)


async def test_start_details_verification_purpose_mismatch(
    verification_service: FaydaVerificationService,
    caller_context: CallerContext,
):
    """Mismatched purpose raises DetailsPurposeMismatchError."""
    adapter = SimpleCallerAdapter(context_resolver=lambda: caller_context)
    server = create_mcp_server(service=verification_service, caller_adapter=adapter)

    sub_resp = await verification_service.submit_expected_details(
        application_user_ref="citizen_user_p",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=caller_context,
    )

    async with Client(server) as client:
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool(
                "start_details_verification",
                arguments={
                    "expected_details_ref": sub_resp.expected_details_ref,
                    "purpose": "onboarding",
                    "application_user_ref": "citizen_user_p",
                    "idempotency_key": "idemp_diff_purpose",
                },
            )
        assert "purpose does not match" in str(exc_info.value).lower()


# ===========================================================================
# 6. Replay Safety: Single Request Binding
# ===========================================================================


async def test_start_details_verification_replay_binding_fails(
    verification_service: FaydaVerificationService,
    caller_context: CallerContext,
):
    """An expected_details_ref already bound to one request cannot be reused on a different request."""
    adapter = SimpleCallerAdapter(context_resolver=lambda: caller_context)
    server = create_mcp_server(service=verification_service, caller_adapter=adapter)

    sub_resp = await verification_service.submit_expected_details(
        application_user_ref="citizen_reuse_usr",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=caller_context,
    )
    ref = sub_resp.expected_details_ref

    async with Client(server) as client:
        # First verification start succeeds
        await client.call_tool(
            "start_details_verification",
            arguments={
                "expected_details_ref": ref,
                "purpose": "kyc",
                "application_user_ref": "citizen_reuse_usr",
                "idempotency_key": "idemp_first_req",
            },
        )

        # Second verification start with a DIFFERENT idempotency key attempts fresh request
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool(
                "start_details_verification",
                arguments={
                    "expected_details_ref": ref,
                    "purpose": "kyc",
                    "application_user_ref": "citizen_reuse_usr",
                    "idempotency_key": "idemp_second_req",
                },
            )
        assert "already bound" in str(exc_info.value).lower()
