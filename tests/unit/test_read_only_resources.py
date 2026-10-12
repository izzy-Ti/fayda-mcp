"""Unit tests for Task M2: Read-only FastMCP resources and explicit diagnostic command."""

import json
from typing import Any
from unittest.mock import AsyncMock, patch
import httpx
import pytest
from fastmcp.client import Client

from fayda_mcp.cli import main
from fayda_mcp.config import FaydaConfig
from fayda_mcp.diagnostics import run_diagnostics
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore

pytestmark = pytest.mark.asyncio


@pytest.fixture
def test_config() -> FaydaConfig:
    return FaydaConfig(
        client_id="test_client_123",
        redirect_uri="http://localhost:8000/callback",
        issuer="https://issuer.example.com",
        authorization_endpoint="https://issuer.example.com/oauth/authorize",
        token_endpoint="https://issuer.example.com/oauth/token",
        userinfo_endpoint="https://issuer.example.com/oauth/userinfo",
        jwks_uri="https://issuer.example.com/.well-known/jwks.json",
        session_ttl_seconds=300,
        result_ttl_seconds=600,
        signing_key="dummy_test_pem_key",
    )


@pytest.fixture
def test_service(test_config: FaydaConfig) -> FaydaVerificationService:
    policy = VerificationPolicy(
        version="v2",
        allowed_purposes=["onboarding", "kyc", "account_opening"],
        purpose_age_thresholds={"onboarding": (18, 100)},
        optional_checks=["phone_verified", "email_verified"],
    )
    return FaydaVerificationService(
        config=test_config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
        policy=policy,
    )


def _get_resource_text(contents: Any) -> str:
    item = contents[0]
    return getattr(item, "text", "")


class TestReadOnlyResources:
    """Acceptance tests for read-only FastMCP resources."""

    async def test_resources_list(self, test_service: FaydaVerificationService) -> None:
        """Acceptance requirement: resources/list exposes checks, purposes, and health."""
        server = create_mcp_server(service=test_service)
        async with Client(server) as client:
            resources = await client.list_resources()
            uris = {r.uri for r in resources}
            assert "fayda://policy/checks" in uris
            assert "fayda://policy/purposes" in uris
            assert "fayda://health" in uris

    async def test_read_policy_checks_resource(
        self, test_service: FaydaVerificationService
    ) -> None:
        """Verify fayda://policy/checks returns caller-visible checks without sensitive data."""
        server = create_mcp_server(service=test_service)
        async with Client(server) as client:
            contents = await client.read_resource("fayda://policy/checks")
            text = _get_resource_text(contents)
            data = json.loads(text)

            assert data["policy_version"] == "v2"
            check_names = {c["name"] for c in data["checks"]}
            assert "identity_verified" in check_names
            assert "age_over_18" in check_names
            assert "phone_verified" in check_names

            # Check optional vs required mapping
            phone_check = next(c for c in data["checks"] if c["name"] == "phone_verified")
            assert phone_check["default_requirement"] == "optional"
            id_check = next(c for c in data["checks"] if c["name"] == "identity_verified")
            assert id_check["default_requirement"] == "required"

            # Age thresholds metadata
            assert data["custom_age_thresholds"]["minimum_allowed_age"] >= 1
            assert "age_over_<N>" in data["custom_age_thresholds"]["supported_syntaxes"]

    async def test_read_policy_purposes_resource(
        self, test_service: FaydaVerificationService
    ) -> None:
        """Verify fayda://policy/purposes returns allowed purposes and constraints."""
        server = create_mcp_server(service=test_service)
        async with Client(server) as client:
            contents = await client.read_resource("fayda://policy/purposes")
            text = _get_resource_text(contents)
            data = json.loads(text)

            assert data["policy_version"] == "v2"
            assert "onboarding" in data["allowed_purposes"]
            assert "kyc" in data["allowed_purposes"]
            assert data["purpose_rules"]["onboarding"]["age_threshold_range"]["min"] == 18

    async def test_read_health_resource_sanitized_states(
        self, test_config: FaydaConfig
    ) -> None:
        """Acceptance requirement: health reports configured/ready/degraded states safely."""
        # 1. Ready state (valid config, storage, and key)
        ready_service = FaydaVerificationService(
            config=test_config,
            sessions=MemorySessionStore(),
            results=MemoryResultRepository(),
        )
        server_ready = create_mcp_server(service=ready_service)
        async with Client(server_ready) as client:
            contents = await client.read_resource("fayda://health")
            data = json.loads(_get_resource_text(contents))
            assert data["status"] == "ready"
            assert data["readiness"]["configuration"] == "valid"
            assert data["readiness"]["signing_key"]["configured"] is True
            assert "Secret presence does not prove credentials are approved or functional." in data["disclaimer"]

        # 2. Configured state (key missing)
        no_key_config = test_config.model_copy(update={"signing_key": None, "signing_key_path": None})
        conf_service = FaydaVerificationService(
            config=no_key_config,
            sessions=MemorySessionStore(),
            results=MemoryResultRepository(),
        )
        server_conf = create_mcp_server(service=conf_service)
        async with Client(server_conf) as client:
            contents = await client.read_resource("fayda://health")
            data = json.loads(_get_resource_text(contents))
            assert data["status"] == "configured"
            assert data["readiness"]["signing_key"]["configured"] is False

    async def test_no_sensitive_secrets_or_dsns_in_any_resource(
        self, test_service: FaydaVerificationService
    ) -> None:
        """Acceptance requirement: No keys, DSNs, tenant inventory, personal data, or URLs appear."""
        server = create_mcp_server(service=test_service)
        async with Client(server) as client:
            for uri in ["fayda://policy/checks", "fayda://policy/purposes", "fayda://health"]:
                contents = await client.read_resource(uri)
                text = _get_resource_text(contents)

                # Ensure sensitive patterns never appear
                assert "dummy_test_pem_key" not in text
                assert "client_secret" not in text
                assert "password" not in text
                assert "postgresql://" not in text
                assert "redis://" not in text
                assert "rediss://" not in text
                assert "Traceback" not in text
                assert "Exception" not in text
                assert "code_verifier" not in text
                assert "authorization_url" not in text


class TestDiagnosticsCommand:
    """Acceptance tests for explicit diagnostic command checking connectivity with timeouts."""

    async def test_run_diagnostics_reachable(self, test_config: FaydaConfig) -> None:
        """Diagnostic probe succeeds when endpoint is reachable."""
        mock_response = httpx.Response(status_code=200)

        with patch("httpx.AsyncClient.get", AsyncMock(return_value=mock_response)):
            report = await run_diagnostics(config=test_config, timeout_seconds=2.0)

            assert report["status"] == "ready"
            assert report["checks"]["configuration"]["status"] == "ok"
            assert report["checks"]["provider_connectivity"]["status"] == "reachable"
            assert any("Secret presence does not prove credentials are approved" in n for n in report["notes"])

    async def test_run_diagnostics_timeout(self, test_config: FaydaConfig) -> None:
        """Diagnostic probe flags timeout when endpoint exceeds threshold."""
        with patch("httpx.AsyncClient.get", AsyncMock(side_effect=httpx.TimeoutException("Timeout"))):
            report = await run_diagnostics(config=test_config, timeout_seconds=1.0)

            assert report["status"] == "degraded"
            assert report["checks"]["provider_connectivity"]["status"] == "timeout"

    async def test_cli_diagnose_command(self, monkeypatch: pytest.MonkeyPatch, test_config: FaydaConfig) -> None:
        """CLI 'fayda-mcp diagnose' command runs and outputs sanitized report."""
        monkeypatch.setenv("FAYDA_CLIENT_ID", test_config.client_id)
        monkeypatch.setenv("FAYDA_REDIRECT_URI", test_config.redirect_uri)
        monkeypatch.setenv("FAYDA_ISSUER", test_config.issuer)
        monkeypatch.setenv("FAYDA_AUTHORIZATION_ENDPOINT", test_config.authorization_endpoint)
        monkeypatch.setenv("FAYDA_TOKEN_ENDPOINT", test_config.token_endpoint)
        monkeypatch.setenv("FAYDA_USERINFO_ENDPOINT", test_config.userinfo_endpoint)
        monkeypatch.setenv("FAYDA_JWKS_URI", test_config.jwks_uri)
        monkeypatch.setenv("FAYDA_SIGNING_KEY", "test_key")

        mock_response = httpx.Response(status_code=200)
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=mock_response)):
            code = main(["diagnose", "--timeout", "3.0"])
            assert code == 0
