"""Unit tests for Task 02: Authenticated backend submission of expected details."""

import asyncio
from datetime import datetime, timedelta, timezone
import pytest
from httpx import ASGITransport, AsyncClient

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import (
    AuthorizationError,
    PolicyViolationError,
)
from fayda_mcp.integrations.fastapi import create_fastapi_app
from fayda_mcp.matching.schemas import (
    DetailsAlreadyBoundError,
    DetailsCallerMismatchError,
    DetailsMatchingError,
    DetailsPurposeMismatchError,
    DetailsReferenceExpiredError,
    DetailsReferenceNotFoundError,
    DetailsUserMismatchError,
    ExpectedDetails,
    ExpectedDetailsRecord,
    ExpectedDetailsSubmission,
    ExpectedDetailsSubmissionResponse,
)
from fayda_mcp.matching.service import (
    DetailsMatchingService,
    generate_expected_details_ref,
)
from fayda_mcp.matching.storage import (
    MemoryExpectedDetailsStore,
    SessionExpectedDetailsStore,
)
from fayda_mcp.policy import VerificationPolicy
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
    )


@pytest.fixture
def verification_service(test_config: FaydaConfig) -> FaydaVerificationService:
    policy = VerificationPolicy(
        allowed_purposes=["onboarding", "kyc", "account_opening"],
    )
    return FaydaVerificationService(
        config=test_config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
        policy=policy,
    )


@pytest.fixture
def matching_service() -> DetailsMatchingService:
    policy = VerificationPolicy(
        allowed_purposes=["onboarding", "kyc", "account_opening"],
    )
    return DetailsMatchingService(
        policy=policy,
        store=MemoryExpectedDetailsStore(),
    )


class TestBackendSubmissionHelper:
    """Verifies authenticated backend submission helper and opaque reference generation."""

    async def test_successful_backend_submission(self, matching_service: DetailsMatchingService):
        """Authenticated caller submits valid expected details and gets opaque reference."""
        ctx = CallerContext(
            tenant_id="bank_tenant",
            principal_id="backend_service",
            scopes=["verification:create"],
        )
        expected = ExpectedDetails(
            full_name="Abebe Bikila",
            date_of_birth="1990/01/01",
            dob_calendar="gregorian",
        )

        res = await matching_service.submit_expected_details(
            application_user_ref="app_user_42",
            purpose="onboarding",
            expected_details=expected,
            context=ctx,
            ttl_seconds=600,
        )

        assert isinstance(res, ExpectedDetailsSubmissionResponse)
        assert res.expected_details_ref.startswith("edr_")
        assert len(res.expected_details_ref) > 10

        # Reference must NOT leak citizen PII in string
        assert "Abebe" not in res.expected_details_ref
        assert "1990" not in res.expected_details_ref
        assert "app_user_42" not in res.expected_details_ref

        # Expiry timestamp must be in future
        exp_dt = datetime.fromisoformat(res.expires_at)
        assert exp_dt > datetime.now(timezone.utc)

    async def test_dict_input_parsed_automatically(self, matching_service: DetailsMatchingService):
        """Allows submitting expected_details as a plain dictionary."""
        ctx = CallerContext(scopes=["verification:create"])
        res = await matching_service.submit_expected_details(
            application_user_ref="user_99",
            purpose="kyc",
            expected_details={"full_name": "Derartu Tulu", "date_of_birth": "1972-03-21"},
            context=ctx,
        )
        assert res.expected_details_ref.startswith("edr_")

        # Verify stored record has parsed ExpectedDetails
        record = await matching_service.get_expected_details_record(res.expected_details_ref, context=ctx)
        assert record.expected_details.full_name == "Derartu Tulu"
        assert record.expected_details.date_of_birth == "1972-03-21"

    async def test_caller_authorization_required(self, matching_service: DetailsMatchingService):
        """Rejects caller lacking verification:create or details:create scope."""
        unauthorized_ctx = CallerContext(
            tenant_id="bank_tenant",
            principal_id="guest_caller",
            scopes=["read_only"],
        )
        with pytest.raises(AuthorizationError, match="denied authorization"):
            await matching_service.submit_expected_details(
                application_user_ref="user_1",
                purpose="onboarding",
                expected_details=ExpectedDetails(full_name="Abebe"),
                context=unauthorized_ctx,
            )

    async def test_unsupported_purpose_rejected(self, matching_service: DetailsMatchingService):
        """Rejects purpose not allowed by active verification policy."""
        ctx = CallerContext(scopes=["verification:create"])
        with pytest.raises(PolicyViolationError, match="Unsupported purpose"):
            await matching_service.submit_expected_details(
                application_user_ref="user_1",
                purpose="marketing_campaign",
                expected_details=ExpectedDetails(full_name="Abebe"),
                context=ctx,
            )

    async def test_empty_application_user_ref_rejected(self, matching_service: DetailsMatchingService):
        """Rejects empty application user reference."""
        ctx = CallerContext(scopes=["verification:create"])
        with pytest.raises(DetailsMatchingError, match="application_user_ref must not be empty"):
            await matching_service.submit_expected_details(
                application_user_ref="   ",
                purpose="onboarding",
                expected_details=ExpectedDetails(full_name="Abebe"),
                context=ctx,
            )


class TestStorageAndCallerIsolation:
    """Verifies storage isolation, multi-tenancy, and expiration."""

    async def test_cross_tenant_access_blocked(self, matching_service: DetailsMatchingService):
        """Different tenant cannot access expected details reference."""
        creator_ctx = CallerContext(tenant_id="tenant_A", principal_id="agent_1", scopes=["verification:create"])
        res = await matching_service.submit_expected_details(
            application_user_ref="user_1",
            purpose="onboarding",
            expected_details=ExpectedDetails(full_name="Abebe"),
            context=creator_ctx,
        )

        intruder_ctx = CallerContext(tenant_id="tenant_B", principal_id="agent_2", scopes=["verification:create"])
        with pytest.raises(DetailsCallerMismatchError):
            await matching_service.get_expected_details_record(res.expected_details_ref, context=intruder_ctx)

    async def test_cross_principal_access_blocked(self, matching_service: DetailsMatchingService):
        """Same tenant but different principal (non-admin) cannot access expected details."""
        creator_ctx = CallerContext(tenant_id="tenant_A", principal_id="agent_1", scopes=["verification:create"])
        res = await matching_service.submit_expected_details(
            application_user_ref="user_1",
            purpose="onboarding",
            expected_details=ExpectedDetails(full_name="Abebe"),
            context=creator_ctx,
        )

        other_agent_ctx = CallerContext(tenant_id="tenant_A", principal_id="agent_2", scopes=["verification:create"])
        with pytest.raises(DetailsCallerMismatchError):
            await matching_service.get_expected_details_record(res.expected_details_ref, context=other_agent_ctx)

        # Admin caller in same tenant CAN access
        admin_ctx = CallerContext(tenant_id="tenant_A", principal_id="admin_user", scopes=["admin"])
        record = await matching_service.get_expected_details_record(res.expected_details_ref, context=admin_ctx)
        assert record.ref == res.expected_details_ref

    async def test_non_existent_reference_raises_not_found(self, matching_service: DetailsMatchingService):
        """Looking up invalid reference raises DetailsReferenceNotFoundError."""
        with pytest.raises(DetailsReferenceNotFoundError):
            await matching_service.get_expected_details_record("edr_non_existent")

    async def test_session_expected_details_store_adapter(self):
        """SessionExpectedDetailsStore wraps SessionStore cleanly."""
        session_store = MemorySessionStore()
        adapter_store = SessionExpectedDetailsStore(session_store)

        record = ExpectedDetailsRecord(
            ref="edr_session_test",
            tenant_id="t1",
            principal_id="p1",
            application_user_ref="u1",
            purpose="onboarding",
            expected_details=ExpectedDetails(full_name="Kenenisa Bekele"),
            created_at=datetime.now(timezone.utc).isoformat(),
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        )

        await adapter_store.save_expected_details("edr_session_test", record, ttl_seconds=600)
        retrieved = await adapter_store.get_expected_details("edr_session_test")
        assert retrieved is not None
        assert retrieved.expected_details.full_name == "Kenenisa Bekele"

        # Delete
        assert await adapter_store.delete_expected_details("edr_session_test") is True
        assert await adapter_store.get_expected_details("edr_session_test") is None

    async def test_expired_record_raises_expired_error(self):
        """Expired reference raises DetailsReferenceExpiredError."""
        store = MemoryExpectedDetailsStore()
        matching = DetailsMatchingService(store=store)

        past_time = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
        expired_record = ExpectedDetailsRecord(
            ref="edr_expired",
            tenant_id="default",
            principal_id="anonymous",
            application_user_ref="u1",
            purpose="onboarding",
            expected_details=ExpectedDetails(full_name="Abebe"),
            created_at=past_time,
            expires_at=past_time,
        )
        await store.save_expected_details("edr_expired", expired_record, 1)

        with pytest.raises(DetailsReferenceExpiredError):
            await matching.get_expected_details_record("edr_expired")


class TestBindingAndLifecycle:
    """Verifies binding to verification request and replay prevention."""

    async def test_bind_expected_details_success(self, matching_service: DetailsMatchingService):
        """Binds reference to request_id and preserves parameters."""
        ctx = CallerContext(scopes=["verification:create"])
        res = await matching_service.submit_expected_details(
            application_user_ref="user_123",
            purpose="onboarding",
            expected_details=ExpectedDetails(full_name="Abebe"),
            context=ctx,
        )

        bound = await matching_service.bind_expected_details(
            ref=res.expected_details_ref,
            request_id="req_001",
            application_user_ref="user_123",
            purpose="onboarding",
            context=ctx,
        )
        assert bound.bound_request_id == "req_001"

        # Re-binding with same request_id is idempotent
        bound_again = await matching_service.bind_expected_details(
            ref=res.expected_details_ref,
            request_id="req_001",
            application_user_ref="user_123",
            purpose="onboarding",
            context=ctx,
        )
        assert bound_again.bound_request_id == "req_001"

    async def test_re_binding_to_different_request_fails(self, matching_service: DetailsMatchingService):
        """Prevent binding the same expected details to multiple verification requests."""
        ctx = CallerContext(scopes=["verification:create"])
        res = await matching_service.submit_expected_details(
            application_user_ref="user_123",
            purpose="onboarding",
            expected_details=ExpectedDetails(full_name="Abebe"),
            context=ctx,
        )

        await matching_service.bind_expected_details(
            ref=res.expected_details_ref,
            request_id="req_001",
            application_user_ref="user_123",
            purpose="onboarding",
            context=ctx,
        )

        with pytest.raises(DetailsAlreadyBoundError):
            await matching_service.bind_expected_details(
                ref=res.expected_details_ref,
                request_id="req_002",
                application_user_ref="user_123",
                purpose="onboarding",
                context=ctx,
            )

    async def test_binding_with_mismatched_user_fails(self, matching_service: DetailsMatchingService):
        """Rejects binding if application_user_ref differs."""
        ctx = CallerContext(scopes=["verification:create"])
        res = await matching_service.submit_expected_details(
            application_user_ref="user_123",
            purpose="onboarding",
            expected_details=ExpectedDetails(full_name="Abebe"),
            context=ctx,
        )

        with pytest.raises(DetailsUserMismatchError):
            await matching_service.bind_expected_details(
                ref=res.expected_details_ref,
                request_id="req_001",
                application_user_ref="user_999",
                purpose="onboarding",
                context=ctx,
            )

    async def test_binding_with_mismatched_purpose_fails(self, matching_service: DetailsMatchingService):
        """Rejects binding if purpose differs."""
        ctx = CallerContext(scopes=["verification:create"])
        res = await matching_service.submit_expected_details(
            application_user_ref="user_123",
            purpose="onboarding",
            expected_details=ExpectedDetails(full_name="Abebe"),
            context=ctx,
        )

        with pytest.raises(DetailsPurposeMismatchError):
            await matching_service.bind_expected_details(
                ref=res.expected_details_ref,
                request_id="req_001",
                application_user_ref="user_123",
                purpose="kyc",
                context=ctx,
            )


class TestServiceAndFastApiIntegration:
    """Verifies integration with FaydaVerificationService and FastAPI HTTP endpoint."""

    async def test_service_submit_expected_details(self, verification_service: FaydaVerificationService):
        """FaydaVerificationService exposes submit_expected_details helper."""
        res = await verification_service.submit_expected_details(
            application_user_ref="usr_77",
            purpose="onboarding",
            expected_details={"full_name": "Abebe Bikila"},
        )
        assert res.expected_details_ref.startswith("edr_")

        record = await verification_service.get_expected_details_record(res.expected_details_ref)
        assert record.application_user_ref == "usr_77"

    async def test_fastapi_expected_details_endpoint(self, verification_service: FaydaVerificationService):
        """FastAPI app exposes POST /verification/details/expected endpoint for host backend."""
        app = create_fastapi_app(
            service=verification_service,
            session_binding_hook=lambda req: "test_session_cookie",
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            payload = {
                "application_user_ref": "user_api_1",
                "purpose": "onboarding",
                "expected_details": {
                    "full_name": "Abebe Bikila",
                    "date_of_birth": "1990/01/01",
                },
                "ttl_seconds": 600,
            }
            headers = {
                "x-tenant-id": "fintech_tenant",
                "x-principal-id": "payment_service",
                "x-caller-scopes": "verification:create",
            }
            resp = await client.post("/verification/details/expected", json=payload, headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert "expected_details_ref" in data
            assert data["expected_details_ref"].startswith("edr_")
            assert "expires_at" in data
