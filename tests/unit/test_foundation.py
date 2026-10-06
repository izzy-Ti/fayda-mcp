"""Unit tests for A1 Package Foundation."""

import pytest
import fayda_mcp
from fayda_mcp import (
    FaydaConfig,
    CallerContext,
    FaydaVerificationService,
    create_mcp_server,
    FaydaMCPError,
    ConfigurationError,
    AuthenticationError,
    AuthorizationError,
    InvalidStateError,
    PolicyViolationError,
    ProviderError,
    VerificationNotFoundError,
    VerificationPolicy,
)
from fayda_mcp.storage.memory import MemorySessionStore, MemoryResultRepository, MemoryAuditLogger


def test_public_exports():
    """Verify that stable public symbols are cleanly exported from the root package."""
    assert hasattr(fayda_mcp, "FaydaConfig")
    assert hasattr(fayda_mcp, "CallerContext")
    assert hasattr(fayda_mcp, "FaydaVerificationService")
    assert hasattr(fayda_mcp, "create_mcp_server")
    assert hasattr(fayda_mcp, "VerificationPolicy")
    assert issubclass(ConfigurationError, FaydaMCPError)
    assert issubclass(InvalidStateError, FaydaMCPError)
    assert issubclass(PolicyViolationError, FaydaMCPError)


def test_import_performs_no_network_or_migrations(monkeypatch):
    """Verify creating config and service performs no socket connections or network calls."""
    # Monkeypatch socket to ensure nothing touches the network during instantiation
    import socket

    def forbid_socket(*args, **kwargs):
        raise RuntimeError("Network activity detected during instantiation!")

    monkeypatch.setattr(socket, "socket", forbid_socket)

    config = FaydaConfig(
        client_id="test-client",
        redirect_uri="https://test.example/callback",
        issuer="https://esignet.example",
        authorization_endpoint="https://esignet.example/authorize",
        token_endpoint="https://esignet.example/token",
        userinfo_endpoint="https://esignet.example/userinfo",
        jwks_uri="https://esignet.example/jwks",
    )

    service = FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )
    assert service is not None


@pytest.mark.asyncio
async def test_async_service_lifecycle():
    """Verify async context manager lifecycle starts and closes cleanly."""
    config = FaydaConfig(
        client_id="test-client",
        redirect_uri="https://test.example/callback",
        issuer="https://esignet.example",
        authorization_endpoint="https://esignet.example/authorize",
        token_endpoint="https://esignet.example/token",
        userinfo_endpoint="https://esignet.example/userinfo",
        jwks_uri="https://esignet.example/jwks",
    )

    sessions = MemorySessionStore()
    results = MemoryResultRepository()

    async with FaydaVerificationService(config=config, sessions=sessions, results=results) as service:
        ctx = CallerContext(tenant_id="tenant-1", principal_id="agent-1")
        resp = await service.start_verification(
            context=ctx,
            purpose="onboarding",
            checks=["identity_verified"],
            application_user_ref="user-123",
            idempotency_key="idemp-abc",
        )
        assert resp.request_id.startswith("vr_")
        assert "esignet.example/authorize" in resp.authorization_url
        assert "client_id=test-client" in resp.authorization_url

        # Check status
        status = await service.get_verification_status(ctx, resp.request_id)
        assert status.status == "pending"


@pytest.mark.asyncio
async def test_mcp_factory_and_tools():
    """Verify FastMCP server is instantiated with the 4 explicit verification tools."""
    config = FaydaConfig(
        client_id="test-client",
        redirect_uri="https://test.example/callback",
        issuer="https://esignet.example",
        authorization_endpoint="https://esignet.example/authorize",
        token_endpoint="https://esignet.example/token",
        userinfo_endpoint="https://esignet.example/userinfo",
        jwks_uri="https://esignet.example/jwks",
    )
    service = FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )

    server = create_mcp_server(service=service)
    tools = await server.list_tools()
    tool_names = [t.name for t in tools]

    assert "start_verification" in tool_names
    assert "get_verification_status" in tool_names
    assert "get_verification_result" in tool_names
    assert "cancel_verification" in tool_names
