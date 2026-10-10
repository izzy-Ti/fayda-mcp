"""Unit tests for Task 16: Filter agent output (Return status, method, checks, times, safe reasons; exclude demographics, photo, and signature)."""

import contextvars
import os
from typing import Any, Dict
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastmcp.client import Client

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext, SimpleCallerAdapter
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.qr.schemas import (
    QRAgentVerificationResult,
    QRVerificationRequest,
    QRVerificationResult,
    filter_agent_output,
)
from fayda_mcp.qr.service import FaydaQRVerificationService
from fayda_mcp.qr.trust import QRTrustStore, TrustedKey, calculate_key_thumbprint
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


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
    )
    svc = FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )
    svc.qr_service.trust_store = trust_store
    return svc


class TestFilterAgentOutput:
    """Test suite for Task 16 agent output filtering and privacy protection."""

    def test_filter_agent_output_preserves_required_and_excludes_forbidden(
        self,
        synthetic_qr_raw: str,
        trust_store: QRTrustStore,
    ) -> None:
        """filter_agent_output retains status, method, checks, times, safe reasons and strips PII."""
        qr_svc = FaydaQRVerificationService(trust_store=trust_store)
        # Verify with include_demographics=True so internal result HAS demographics and photo
        req = QRVerificationRequest(
            qr_text=synthetic_qr_raw,
            checks=["credential_signature_valid", "age_over_18", "phone_verified"],
            purpose="kyc",
            application_user_ref="usr_agent_test",
            include_demographics=True,
        )
        internal_res = qr_svc.verify_qr_sync(req)
        assert internal_res.demographics is not None
        assert internal_res.demographics.photo_base64url != ""

        # Filter for agent
        agent_out = filter_agent_output(internal_res, expires_at="2026-10-10T12:00:00Z")

        # 1. Required fields are present
        assert isinstance(agent_out, QRAgentVerificationResult)
        assert agent_out.status == "incomplete"
        assert agent_out.method == "qr_offline"
        assert agent_out.checks["credential_signature_valid"] is True
        assert agent_out.checks["age_over_18"] is True
        assert agent_out.checks["phone_verified"] == "unavailable"
        assert agent_out.reasons["phone_verified"] == "claim_not_present_in_qr"

        # 2. Times are present
        assert agent_out.times is not None
        assert "verified_at" in agent_out.times
        assert agent_out.times["expires_at"] == "2026-10-10T12:00:00Z"
        assert agent_out.verified_at is not None
        assert agent_out.expires_at == "2026-10-10T12:00:00Z"

        # 3. Security invariants
        assert agent_out.credential_signature_valid is True
        assert agent_out.holder_authenticated is False
        assert agent_out.identity_verified is False

        # 4. Strictly excludes demographics, photo, and signature
        dumped = agent_out.model_dump()
        forbidden_keys = [
            "demographics",
            "photo",
            "photo_base64url",
            "signature",
            "signature_bytes",
            "detached_jws",
            "name",
            "fan",
            "date_of_birth",
            "raw_text",
        ]
        for key in forbidden_keys:
            assert key not in dumped, f"Forbidden key '{key}' leaked into agent output"
            assert not hasattr(agent_out, key), f"Forbidden attribute '{key}' found on agent model"

    def test_to_agent_output_method_on_qr_verification_result(
        self,
        synthetic_qr_raw: str,
        trust_store: QRTrustStore,
    ) -> None:
        """QRVerificationResult.to_agent_output() correctly strips sensitive fields."""
        qr_svc = FaydaQRVerificationService(trust_store=trust_store)
        internal_res = qr_svc.verify_qr_sync(
            QRVerificationRequest(qr_text=synthetic_qr_raw, include_demographics=True)
        )
        agent_out = internal_res.to_agent_output()

        assert isinstance(agent_out, QRAgentVerificationResult)
        assert agent_out.method == "qr_offline"
        assert agent_out.status == "verified"
        assert "demographics" not in agent_out.model_dump()
        assert "photo" not in agent_out.model_dump()

    def test_filter_dict_record(self) -> None:
        """filter_agent_output correctly parses a raw repository dictionary record."""
        record = {
            "request_id": "qr_rec_12345",
            "status": "verified",
            "credential_signature_valid": True,
            "checks": {"credential_signature_valid": True, "age_over_21": False},
            "reasons": {},
            "verified_at": "2026-10-10T06:00:00Z",
            "created_at": "2026-10-10T05:59:00Z",
            "application_user_ref": "cust_123",
            "purpose": "kyc",
            "policy_version": "v1",
            "evidence_ref": "sha256_mock_evidence",
            # Potential raw leaked data in dict that MUST be stripped
            "photo_base64url": "data:image/webp;base64,AAA...",
            "name": "Jane Doe",
            "signature": "mock_sig_bytes",
        }

        filtered = filter_agent_output(record)
        assert isinstance(filtered, QRAgentVerificationResult)
        assert filtered.request_id == "qr_rec_12345"
        assert filtered.status == "verified"
        assert filtered.method == "qr_offline"
        assert filtered.times["verified_at"] == "2026-10-10T06:00:00Z"
        assert filtered.times["created_at"] == "2026-10-10T05:59:00Z"
        assert filtered.checks["age_over_21"] is False
        assert filtered.evidence_ref == "sha256_mock_evidence"

        dumped = filtered.model_dump()
        for forbidden in ("photo_base64url", "name", "signature", "photo", "demographics"):
            assert forbidden not in dumped

    @pytest.mark.asyncio
    async def test_mcp_get_qr_verification_result_returns_filtered_output(
        self,
        verification_service: FaydaVerificationService,
        synthetic_qr_raw: str,
    ) -> None:
        """MCP tool get_qr_verification_result returns strictly filtered output to the agent."""
        current_context: contextvars.ContextVar[CallerContext] = contextvars.ContextVar(
            "current_context",
            default=CallerContext(tenant_id="fintech_tenant", principal_id="agent_1"),
        )
        adapter = SimpleCallerAdapter(context_resolver=lambda: current_context.get())
        server = create_mcp_server(service=verification_service, caller_adapter=adapter)

        async with Client(server) as client:
            # 1. Submit QR code
            submit_res = await client.call_tool(
                "submit_qr_verification",
                {
                    "qr_text": synthetic_qr_raw,
                    "purpose": "kyc",
                    "application_user_ref": "applicant_filter_test",
                    "checks": ["credential_signature_valid", "age_over_18"],
                },
            )
            assert submit_res.is_error is False
            req_data = submit_res.data
            req_id = req_data.request_id if hasattr(req_data, "request_id") else req_data["request_id"]
            sub_method = req_data.method if hasattr(req_data, "method") else req_data["method"]
            assert sub_method == "qr_offline"

            # Verify submit response does not leak photo or demographics
            assert not hasattr(req_data, "photo")
            assert not hasattr(req_data, "demographics")
            assert not hasattr(req_data, "photo_base64url")
            assert not hasattr(req_data, "signature")

            # 2. Get verification result by opaque request ID
            get_res = await client.call_tool(
                "get_qr_verification_result",
                {"request_id": req_id},
            )
            assert get_res.is_error is False
            res_data = get_res.data

            # Verify all required fields
            status = res_data.status if hasattr(res_data, "status") else res_data["status"]
            method = res_data.method if hasattr(res_data, "method") else res_data["method"]
            checks = res_data.checks if hasattr(res_data, "checks") else res_data["checks"]
            times = res_data.times if hasattr(res_data, "times") else res_data["times"]
            reasons = res_data.reasons if hasattr(res_data, "reasons") else res_data["reasons"]

            assert status == "verified"
            assert method == "qr_offline"
            assert checks["credential_signature_valid"] is True
            assert checks["age_over_18"] is True
            assert isinstance(times, dict)
            assert "verified_at" in times
            assert isinstance(reasons, dict)

            # Verify strictly excluded fields
            assert not hasattr(res_data, "photo")
            assert not hasattr(res_data, "demographics")
            assert not hasattr(res_data, "photo_base64url")
            assert not hasattr(res_data, "signature")
            assert not hasattr(res_data, "detached_jws")
