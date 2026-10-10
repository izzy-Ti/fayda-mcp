"""Unit tests for Task 15: Expose get_qr_verification_result by opaque request ID and enforce caller ownership in MCP tools."""

import contextvars
import os
from typing import Any
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastmcp.client import Client
from fastmcp.exceptions import ToolError

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext, SimpleCallerAdapter
from fayda_mcp.exceptions import AuthorizationError, VerificationNotFoundError
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.qr.trust import QRTrustStore, TrustedKey, calculate_key_thumbprint
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore

pytestmark = pytest.mark.asyncio


@pytest.fixture
def fixtures_dir() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")


@pytest.fixture
def synthetic_qr_raw(fixtures_dir: str) -> str:
    with open(os.path.join(fixtures_dir, "synthetic_authorized_qr_v4.txt"), "r", encoding="utf-8") as f:
        return f.read().strip()


@pytest.fixture
def trusted_test_public_key(fixtures_dir: str) -> rsa.RSAPublicKey:
    with open(os.path.join(fixtures_dir, "test_qr_rsa_public.pem"), "rb") as f:
        return serialization.load_pem_public_key(f.read())  # type: ignore


@pytest.fixture
def trust_store(trusted_test_public_key: rsa.RSAPublicKey) -> QRTrustStore:
    store = QRTrustStore()
    tp = calculate_key_thumbprint(trusted_test_public_key)
    store.add_key(
        TrustedKey(
            public_key=trusted_test_public_key,
            thumbprint=tp,
            key_id="test-key-2024",
            source="test_fixtures",
        )
    )
    return store


@pytest.fixture
def verification_service(trust_store: QRTrustStore) -> FaydaVerificationService:
    config = FaydaConfig(
        client_id="test_client",
        redirect_uri="http://localhost:8000/callback",
        issuer="https://issuer.example.com",
        authorization_endpoint="https://issuer.example.com/oauth/authorize",
        token_endpoint="https://issuer.example.com/oauth/token",
        userinfo_endpoint="https://issuer.example.com/oauth/userinfo",
        jwks_uri="https://issuer.example.com/.well-known/jwks.json",
        session_ttl_seconds=300,
        result_ttl_seconds=600,
        qr_verification_enabled=True,
    )
    svc = FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )
    svc.qr_service.trust_store = trust_store
    return svc


class TestMcpQrTools:
    """Test suite for FastMCP QR verification tools."""

    async def test_qr_tools_registered_on_server(
        self, verification_service: FaydaVerificationService
    ) -> None:
        """Verify FastMCP server exposes get_qr_verification_result and submit_qr_verification."""
        server = create_mcp_server(service=verification_service)
        async with Client(server) as client:
            tools = await client.list_tools()
            tool_names = {t.name for t in tools}
            assert "get_qr_verification_result" in tool_names
            assert "submit_qr_verification" in tool_names

    async def test_owner_can_submit_and_get_qr_verification_result(
        self,
        verification_service: FaydaVerificationService,
        synthetic_qr_raw: str,
    ) -> None:
        """Owner caller can submit QR and retrieve verification result by opaque request ID."""
        current_context: contextvars.ContextVar[CallerContext] = contextvars.ContextVar(
            "current_context",
            default=CallerContext(tenant_id="bank_tenant", principal_id="cashier_agent"),
        )
        adapter = SimpleCallerAdapter(context_resolver=lambda: current_context.get())
        server = create_mcp_server(service=verification_service, caller_adapter=adapter)

        async with Client(server) as client:
            # 1. Submit QR verification
            submit_res = await client.call_tool(
                "submit_qr_verification",
                {
                    "qr_text": synthetic_qr_raw,
                    "purpose": "account_opening",
                    "application_user_ref": "applicant_42",
                    "checks": ["credential_signature_valid", "age_over_18"],
                    "idempotency_key": "idemp_mcp_qr_1",
                },
            )
            assert submit_res.is_error is False
            res_data = submit_res.data
            req_id = res_data.request_id if hasattr(res_data, "request_id") else res_data["request_id"]
            status = res_data.status if hasattr(res_data, "status") else res_data["status"]
            user_ref = (
                res_data.application_user_ref
                if hasattr(res_data, "application_user_ref")
                else res_data["application_user_ref"]
            )
            assert req_id.startswith("qr_")
            assert status == "verified"
            assert user_ref == "applicant_42"

            # 2. Owner retrieves result by request ID
            get_res = await client.call_tool(
                "get_qr_verification_result",
                {"request_id": req_id},
            )
            assert get_res.is_error is False
            retrieved = get_res.data
            r_req_id = retrieved.request_id if hasattr(retrieved, "request_id") else retrieved["request_id"]
            r_status = retrieved.status if hasattr(retrieved, "status") else retrieved["status"]
            r_user = (
                retrieved.application_user_ref
                if hasattr(retrieved, "application_user_ref")
                else retrieved["application_user_ref"]
            )
            assert r_req_id == req_id
            assert r_status == "verified"
            assert r_user == "applicant_42"

    async def test_tenant_isolation_enforced(
        self,
        verification_service: FaydaVerificationService,
        synthetic_qr_raw: str,
    ) -> None:
        """Caller from differing tenant is denied access to QR verification result."""
        current_context: contextvars.ContextVar[CallerContext] = contextvars.ContextVar(
            "current_context",
            default=CallerContext(tenant_id="bank_tenant", principal_id="cashier_agent"),
        )
        adapter = SimpleCallerAdapter(context_resolver=lambda: current_context.get())
        server = create_mcp_server(service=verification_service, caller_adapter=adapter)

        async with Client(server) as client:
            submit_res = await client.call_tool(
                "submit_qr_verification",
                {
                    "qr_text": synthetic_qr_raw,
                    "purpose": "kyc",
                    "application_user_ref": "cust_101",
                },
            )
            req_data = submit_res.data
            req_id = req_data.request_id if hasattr(req_data, "request_id") else req_data["request_id"]

            # Switch context to an intruder tenant
            current_context.set(CallerContext(tenant_id="foreign_tenant", principal_id="cashier_agent"))

            with pytest.raises(ToolError) as exc_info:
                await client.call_tool(
                    "get_qr_verification_result",
                    {"request_id": req_id},
                )
            assert "denied" in str(exc_info.value).lower()

    async def test_principal_isolation_within_same_tenant(
        self,
        verification_service: FaydaVerificationService,
        synthetic_qr_raw: str,
    ) -> None:
        """Different principal in same tenant is denied without admin scope; admin caller succeeds."""
        current_context: contextvars.ContextVar[CallerContext] = contextvars.ContextVar(
            "current_context",
            default=CallerContext(tenant_id="corp_inc", principal_id="agent_alice"),
        )
        adapter = SimpleCallerAdapter(context_resolver=lambda: current_context.get())
        server = create_mcp_server(service=verification_service, caller_adapter=adapter)

        async with Client(server) as client:
            # Alice creates QR verification
            submit_res = await client.call_tool(
                "submit_qr_verification",
                {
                    "qr_text": synthetic_qr_raw,
                    "purpose": "kyc",
                    "application_user_ref": "cust_alice",
                },
            )
            req_data = submit_res.data
            req_id = req_data.request_id if hasattr(req_data, "request_id") else req_data["request_id"]

            # Bob in same tenant tries to access Alice's result -> rejected
            current_context.set(CallerContext(tenant_id="corp_inc", principal_id="agent_bob"))
            with pytest.raises(ToolError) as exc_info:
                await client.call_tool(
                    "get_qr_verification_result",
                    {"request_id": req_id},
                )
            assert "denied" in str(exc_info.value).lower()

            # Admin in same tenant with verification:admin scope succeeds
            current_context.set(
                CallerContext(
                    tenant_id="corp_inc",
                    principal_id="supervisor",
                    scopes=["verification:admin", "verification:read"],
                )
            )
            admin_res = await client.call_tool(
                "get_qr_verification_result",
                {"request_id": req_id},
            )
            assert admin_res.is_error is False
            res = admin_res.data
            res_user = (
                res.application_user_ref
                if hasattr(res, "application_user_ref")
                else res["application_user_ref"]
            )
            assert res_user == "cust_alice"

    async def test_caller_missing_read_scope_rejected_by_authorizer(
        self,
        verification_service: FaydaVerificationService,
    ) -> None:
        """Caller missing verification:read scope is rejected immediately by adapter."""
        current_context: contextvars.ContextVar[CallerContext] = contextvars.ContextVar(
            "current_context",
            default=CallerContext(
                tenant_id="bank",
                principal_id="restricted_agent",
                scopes=["verification:create"],  # Missing verification:read
            ),
        )
        adapter = SimpleCallerAdapter(context_resolver=lambda: current_context.get())
        server = create_mcp_server(service=verification_service, caller_adapter=adapter)

        async with Client(server) as client:
            with pytest.raises(ToolError) as exc_info:
                await client.call_tool(
                    "get_qr_verification_result",
                    {"request_id": "qr_dummy_123"},
                )
            assert "denied" in str(exc_info.value).lower()

    async def test_nonexistent_request_id_raises_not_found(
        self,
        verification_service: FaydaVerificationService,
    ) -> None:
        """Querying a non-existent request ID raises VerificationNotFoundError."""
        current_context: contextvars.ContextVar[CallerContext] = contextvars.ContextVar(
            "current_context",
            default=CallerContext(tenant_id="bank", principal_id="agent"),
        )
        adapter = SimpleCallerAdapter(context_resolver=lambda: current_context.get())
        server = create_mcp_server(service=verification_service, caller_adapter=adapter)

        async with Client(server) as client:
            with pytest.raises(ToolError) as exc_info:
                await client.call_tool(
                    "get_qr_verification_result",
                    {"request_id": "qr_does_not_exist"},
                )
            assert "not found" in str(exc_info.value).lower()
