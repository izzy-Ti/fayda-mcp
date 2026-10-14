"""Unit tests for Task 08: Save minimal outcomes and purge expected details.

Verifies:
- Persist match flags, evidence/request reference, timestamps, reasons, and policy version with finalization.
- Purge temporary expected details record afterward so no retained demographics linger.
- Match outcomes remain retrievable while raw expected details are permanently eradicated.
"""

from unittest.mock import AsyncMock, patch
import pytest

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.matching.schemas import (
    DEFAULT_COMPARISON_POLICY_VERSION,
    DetailsReferenceNotFoundError,
    ExpectedDetails,
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
        issuer="https://esignet.example.com",
        authorization_endpoint="https://esignet.example.com/oauth/authorize",
        token_endpoint="https://esignet.example.com/oauth/token",
        userinfo_endpoint="https://esignet.example.com/oauth/userinfo",
        jwks_uri="https://esignet.example.com/.well-known/jwks.json",
        session_ttl_seconds=300,
        result_ttl_seconds=600,
    )


@pytest.fixture
def service(test_config: FaydaConfig) -> FaydaVerificationService:
    return FaydaVerificationService(
        config=test_config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
        policy=VerificationPolicy(version="v1"),
    )


@pytest.fixture
def caller_context() -> CallerContext:
    return CallerContext(
        tenant_id="fintech-corp",
        principal_id="api-worker-1",
        scopes=["verification:create", "verification:read"],
    )


async def test_persist_minimal_outcomes_with_finalization(
    service: FaydaVerificationService, caller_context: CallerContext
):
    """Finalization atomically persists match flags, evidence reference, timestamps, reasons, and policy version."""
    # 1. Host backend registers expected details
    sub_resp = await service.submit_expected_details(
        application_user_ref="user-persist-1",
        purpose="onboarding",
        expected_details=ExpectedDetails(
            full_name="Derartu Tulu",
            date_of_birth="1972/03/21",
        ),
        context=caller_context,
    )

    # 2. Start verification
    start_resp = await service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="onboarding",
        application_user_ref="user-persist-1",
        idempotency_key="idemp-persist-1",
    )

    state = start_resp.authorization_url.split("state=")[1].split("&")[0]

    # 3. Simulate callback
    mock_id_claims = {"sub": "fayda:sub:tulu"}
    mock_userinfo_claims = {
        "name": "Derartu Tulu",
        "birthdate": "1972-03-21",
    }

    with patch.object(service, "_get_private_key", return_value="fake_pem"), \
         patch("fayda_mcp.service.create_client_assertion", return_value="fake.assertion"), \
         patch.object(service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
         patch.object(service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.jwt", "access_token": "at"})), \
         patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
         patch.object(service._http, "fetch_userinfo", AsyncMock(return_value={})), \
         patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

        result = await service.complete_verification(code="auth_code_tulu", state=state)

    # 4. Verify minimal outcomes on finalized VerificationResult
    assert result.status == "verified"
    assert result.evidence_ref == f"ev_{start_resp.request_id}"
    assert result.policy_version == "v1"
    assert result.checks["identity_verified"] is True
    assert result.checks["details_matched"] is True
    assert result.verified_at is not None
    assert result.expires_at is not None

    # 5. Verify minimal outcomes on DetailsMatchResult
    match_result = await service.get_details_match_result(start_resp.request_id, context=caller_context)
    assert match_result is not None
    assert match_result.matching_status == "matched"
    assert match_result.matches == {"full_name": True, "date_of_birth": True}
    assert match_result.comparison_policy_version == DEFAULT_COMPARISON_POLICY_VERSION
    assert match_result.required_fields == ["full_name", "date_of_birth"]
    assert match_result.checked_at is not None
    assert match_result.identity_authenticated is True
    assert match_result.evidence_ref == f"ev_{start_resp.request_id}"

    # 6. Verify persisted record in results repository
    rec = await service.results.get_request(start_resp.request_id)
    assert rec is not None
    assert rec["status"] == "verified"
    assert rec["matching_status"] == "matched"
    assert rec["matches"] == {"full_name": True, "date_of_birth": True}
    assert rec["comparison_policy_version"] == "details-v1"
    assert rec["evidence_ref"] == f"ev_{start_resp.request_id}"


async def test_purge_expected_details_after_successful_matching(
    service: FaydaVerificationService, caller_context: CallerContext
):
    """Temporary expected details are purged from the store after callback matching is finalized."""
    sub_resp = await service.submit_expected_details(
        application_user_ref="user-purge-1",
        purpose="kyc",
        expected_details=ExpectedDetails(
            full_name="Kenenisa Bekele",
            date_of_birth="1982/06/13",
        ),
        context=caller_context,
    )

    # Expected details exist prior to completion
    rec_before = await service.matching_service.get_expected_details_record(
        sub_resp.expected_details_ref,
        context=caller_context,
    )
    assert rec_before is not None
    assert rec_before.expected_details is not None

    start_resp = await service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="kyc",
        application_user_ref="user-purge-1",
        idempotency_key="idemp-purge-1",
    )

    state = start_resp.authorization_url.split("state=")[1].split("&")[0]

    mock_id_claims = {"sub": "fayda:sub:bekele"}
    mock_userinfo_claims = {
        "name": "Kenenisa Bekele",
        "birthdate": "1982-06-13",
    }

    with patch.object(service, "_get_private_key", return_value="fake_pem"), \
         patch("fayda_mcp.service.create_client_assertion", return_value="fake.assertion"), \
         patch.object(service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
         patch.object(service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.jwt", "access_token": "at"})), \
         patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
         patch.object(service._http, "fetch_userinfo", AsyncMock(return_value={})), \
         patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

        await service.complete_verification(code="auth_code_bekele", state=state)

    # Expected details record is now PURGED
    with pytest.raises(DetailsReferenceNotFoundError):
        await service.matching_service.get_expected_details_record(
            sub_resp.expected_details_ref,
            context=caller_context,
        )

    # Bound request lookup also raises DetailsReferenceNotFoundError
    with pytest.raises(DetailsReferenceNotFoundError):
        await service.matching_service.get_bound_expected_details_for_request(
            start_resp.request_id,
            context=caller_context,
        )

    # But minimal match result remains accessible
    match_result = await service.get_details_match_result(start_resp.request_id, context=caller_context)
    assert match_result is not None
    assert match_result.matching_status == "matched"
    assert match_result.matches == {"full_name": True, "date_of_birth": True}


async def test_purge_expected_details_after_mismatch_outcome(
    service: FaydaVerificationService, caller_context: CallerContext
):
    """Temporary expected details are purged even when verification yields a mismatch."""
    sub_resp = await service.submit_expected_details(
        application_user_ref="user-purge-mismatch",
        purpose="kyc",
        expected_details=ExpectedDetails(
            full_name="Kenenisa Bekele",
            date_of_birth="1982/06/13",
        ),
        context=caller_context,
    )

    start_resp = await service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="kyc",
        application_user_ref="user-purge-mismatch",
        idempotency_key="idemp-purge-mismatch",
    )

    state = start_resp.authorization_url.split("state=")[1].split("&")[0]

    # Provide mismatched name
    mock_id_claims = {"sub": "fayda:sub:wrong"}
    mock_userinfo_claims = {
        "name": "Different Person",
        "birthdate": "1982-06-13",
    }

    with patch.object(service, "_get_private_key", return_value="fake_pem"), \
         patch("fayda_mcp.service.create_client_assertion", return_value="fake.assertion"), \
         patch.object(service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
         patch.object(service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.jwt", "access_token": "at"})), \
         patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
         patch.object(service._http, "fetch_userinfo", AsyncMock(return_value={})), \
         patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

        result = await service.complete_verification(code="auth_code_wrong", state=state)

    assert result.status == "rejected"
    assert result.checks["details_matched"] is False

    match_result = await service.get_details_match_result(start_resp.request_id, context=caller_context)
    assert match_result is not None
    assert match_result.matching_status == "mismatched"

    # Temporary expected details were still purged
    with pytest.raises(DetailsReferenceNotFoundError):
        await service.matching_service.get_expected_details_record(
            sub_resp.expected_details_ref,
            context=caller_context,
        )


async def test_reconstructed_result_contains_no_raw_demographics(
    service: FaydaVerificationService, caller_context: CallerContext
):
    """Saved record and match results contain strictly boolean match flags and safe reasons, zero PII."""
    secret_name = "Tirunesh Dibaba"
    secret_dob = "1985/06/01"

    sub_resp = await service.submit_expected_details(
        application_user_ref="user-nopii",
        purpose="onboarding",
        expected_details=ExpectedDetails(
            full_name=secret_name,
            date_of_birth=secret_dob,
        ),
        context=caller_context,
    )

    start_resp = await service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="onboarding",
        application_user_ref="user-nopii",
        idempotency_key="idemp-nopii",
    )

    state = start_resp.authorization_url.split("state=")[1].split("&")[0]

    mock_id_claims = {"sub": "fayda:sub:dibaba"}
    mock_userinfo_claims = {
        "name": secret_name,
        "birthdate": "1985-06-01",
    }

    with patch.object(service, "_get_private_key", return_value="fake_pem"), \
         patch("fayda_mcp.service.create_client_assertion", return_value="fake.assertion"), \
         patch.object(service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
         patch.object(service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.jwt", "access_token": "at"})), \
         patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
         patch.object(service._http, "fetch_userinfo", AsyncMock(return_value={})), \
         patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

        result = await service.complete_verification(code="auth_code_dibaba", state=state)

    res_dump = result.model_dump_json()
    assert secret_name not in res_dump
    assert "1985" not in res_dump

    match_res = await service.get_details_match_result(start_resp.request_id, context=caller_context)
    match_dump = match_res.model_dump_json()
    assert secret_name not in match_dump
    assert "1985" not in match_dump
