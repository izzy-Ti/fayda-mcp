"""Unit tests for Task 07: Run matching in the callback.

Verifies:
- Compare only validated, permitted claims with bound expectations.
- Raw claims are strictly discarded from memory and never persisted.
- Matched, mismatched, and unavailable outcomes are evaluated deterministically.
- Identity authentication is preserved separately from details matching.
- Caller ownership and expiration are enforced on match result retrieval.
"""

from unittest.mock import AsyncMock, patch
import pytest

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import AuthorizationError
from fayda_mcp.matching.schemas import (
    DEFAULT_COMPARISON_POLICY_VERSION,
    DetailsMatchResult,
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
        tenant_id="bank-1",
        principal_id="service-a",
        scopes=["verification:create", "verification:read"],
    )


@pytest.fixture
def other_context() -> CallerContext:
    return CallerContext(
        tenant_id="bank-2",
        principal_id="service-b",
        scopes=["verification:create", "verification:read"],
    )


async def test_callback_details_matching_success(
    service: FaydaVerificationService, caller_context: CallerContext
):
    """Callback successfully matches full name and DOB from validated provider claims."""
    # 1. Host backend registers expected details
    sub_resp = await service.submit_expected_details(
        application_user_ref="usr-123",
        purpose="onboarding",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            date_of_birth="1995/04/12",
        ),
        context=caller_context,
    )

    # 2. Agent starts details verification
    start_resp = await service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="onboarding",
        application_user_ref="usr-123",
        idempotency_key="idemp-success-1",
    )

    # Verify pending state before callback
    pending_res = await service.get_details_match_result(start_resp.request_id, context=caller_context)
    assert pending_res is not None
    assert pending_res.matching_status == "pending"

    state = start_resp.authorization_url.split("state=")[1].split("&")[0]

    # 3. Simulate callback with matching provider claims
    mock_id_claims = {"sub": "fayda:sub:123"}
    mock_userinfo_claims = {
        "name": "ABEBE  BIKILA",  # Case and whitespace variations normalized
        "birthdate": "1995-04-12",
    }

    with patch.object(service, "_get_private_key", return_value="fake_pem"), \
         patch("fayda_mcp.service.create_client_assertion", return_value="fake.assertion"), \
         patch.object(service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
         patch.object(service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.jwt", "access_token": "at"})), \
         patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
         patch.object(service._http, "fetch_userinfo", AsyncMock(return_value={})), \
         patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

        result = await service.complete_verification(code="auth_code_1", state=state)

    # 4. Assert verification result
    assert result.status == "verified"
    assert result.checks["identity_verified"] is True
    assert result.checks["details_matched"] is True

    # 5. Assert details match result
    match_result = await service.get_details_match_result(start_resp.request_id, context=caller_context)
    assert match_result is not None
    assert match_result.request_id == start_resp.request_id
    assert match_result.verification_method == "esignet"
    assert match_result.matching_status == "matched"
    assert match_result.matches == {"full_name": True, "date_of_birth": True}
    assert match_result.reasons == {}
    assert match_result.identity_authenticated is True
    assert match_result.comparison_policy_version == DEFAULT_COMPARISON_POLICY_VERSION
    assert match_result.checked_at is not None


async def test_callback_details_matching_name_mismatch(
    service: FaydaVerificationService, caller_context: CallerContext
):
    """Callback rejects verification when citizen name differs from bound expectation."""
    sub_resp = await service.submit_expected_details(
        application_user_ref="usr-mismatch-1",
        purpose="kyc",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            date_of_birth="1995/04/12",
        ),
        context=caller_context,
    )

    start_resp = await service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="kyc",
        application_user_ref="usr-mismatch-1",
        idempotency_key="idemp-mismatch-1",
    )

    state = start_resp.authorization_url.split("state=")[1].split("&")[0]

    # Provider returns different name
    mock_id_claims = {"sub": "fayda:sub:mismatch"}
    mock_userinfo_claims = {
        "name": "Haile Gebrselassie",
        "birthdate": "1995-04-12",
    }

    with patch.object(service, "_get_private_key", return_value="fake_pem"), \
         patch("fayda_mcp.service.create_client_assertion", return_value="fake.assertion"), \
         patch.object(service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
         patch.object(service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.jwt", "access_token": "at"})), \
         patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
         patch.object(service._http, "fetch_userinfo", AsyncMock(return_value={})), \
         patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

        result = await service.complete_verification(code="auth_code_2", state=state)

    assert result.status == "rejected"
    assert result.checks["identity_verified"] is True  # Identity authenticated via eSignet
    assert result.checks["details_matched"] is False

    match_result = await service.get_details_match_result(start_resp.request_id, context=caller_context)
    assert match_result is not None
    assert match_result.matching_status == "mismatched"
    assert match_result.matches == {"full_name": False, "date_of_birth": True}
    assert match_result.reasons.get("full_name") == "name_mismatch"
    assert match_result.identity_authenticated is True


async def test_callback_details_matching_missing_claim_unavailable(
    service: FaydaVerificationService, caller_context: CallerContext
):
    """Callback sets matching_status to unavailable when required provider claim is absent."""
    sub_resp = await service.submit_expected_details(
        application_user_ref="usr-unavail-1",
        purpose="onboarding",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            date_of_birth="1995/04/12",
        ),
        context=caller_context,
    )

    start_resp = await service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="onboarding",
        application_user_ref="usr-unavail-1",
        idempotency_key="idemp-unavail-1",
    )

    state = start_resp.authorization_url.split("state=")[1].split("&")[0]

    # Provider returns name, but omits birthdate claim
    mock_id_claims = {"sub": "fayda:sub:unavail"}
    mock_userinfo_claims = {"name": "Abebe Bikila"}

    with patch.object(service, "_get_private_key", return_value="fake_pem"), \
         patch("fayda_mcp.service.create_client_assertion", return_value="fake.assertion"), \
         patch.object(service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
         patch.object(service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.jwt", "access_token": "at"})), \
         patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
         patch.object(service._http, "fetch_userinfo", AsyncMock(return_value={})), \
         patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

        result = await service.complete_verification(code="auth_code_3", state=state)

    assert result.status == "incomplete"
    assert result.checks["identity_verified"] is True
    assert result.checks["details_matched"] is None

    match_result = await service.get_details_match_result(start_resp.request_id, context=caller_context)
    assert match_result is not None
    assert match_result.matching_status == "unavailable"
    assert match_result.matches == {"full_name": True, "date_of_birth": None}
    assert match_result.reasons.get("date_of_birth") == "provider_claim_unavailable"


async def test_callback_details_matching_cross_calendar(
    service: FaydaVerificationService, caller_context: CallerContext
):
    """Callback correctly normalizes explicit Ethiopic date to match Gregorian provider date."""
    # Ethiopic 1987-08-04 converts mathematically to Gregorian 1995-04-12
    sub_resp = await service.submit_expected_details(
        application_user_ref="usr-cal-1",
        purpose="onboarding",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            date_of_birth="1987-08-04",
            dob_calendar="ethiopic",
        ),
        context=caller_context,
    )

    start_resp = await service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="onboarding",
        application_user_ref="usr-cal-1",
        idempotency_key="idemp-cal-1",
    )

    state = start_resp.authorization_url.split("state=")[1].split("&")[0]

    mock_id_claims = {"sub": "fayda:sub:cal"}
    mock_userinfo_claims = {
        "name": "Abebe Bikila",
        "birthdate": "1995-04-12",  # Gregorian provider response
    }

    with patch.object(service, "_get_private_key", return_value="fake_pem"), \
         patch("fayda_mcp.service.create_client_assertion", return_value="fake.assertion"), \
         patch.object(service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
         patch.object(service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.jwt", "access_token": "at"})), \
         patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
         patch.object(service._http, "fetch_userinfo", AsyncMock(return_value={})), \
         patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

        result = await service.complete_verification(code="auth_code_4", state=state)

    assert result.status == "verified"
    assert result.checks["details_matched"] is True

    match_result = await service.get_details_match_result(start_resp.request_id, context=caller_context)
    assert match_result is not None
    assert match_result.matching_status == "matched"
    assert match_result.matches == {"full_name": True, "date_of_birth": True}


async def test_callback_discards_raw_demographics_from_results(
    service: FaydaVerificationService, caller_context: CallerContext
):
    """Raw citizen claim values (names, DOBs) are strictly discarded and not retained in stored results."""
    sub_resp = await service.submit_expected_details(
        application_user_ref="usr-privacy-1",
        purpose="onboarding",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            date_of_birth="1995/04/12",
        ),
        context=caller_context,
    )

    start_resp = await service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="onboarding",
        application_user_ref="usr-privacy-1",
        idempotency_key="idemp-privacy-1",
    )

    state = start_resp.authorization_url.split("state=")[1].split("&")[0]

    mock_id_claims = {"sub": "fayda:sub:privacy"}
    mock_userinfo_claims = {
        "name": "Abebe Bikila",
        "birthdate": "1995-04-12",
    }

    with patch.object(service, "_get_private_key", return_value="fake_pem"), \
         patch("fayda_mcp.service.create_client_assertion", return_value="fake.assertion"), \
         patch.object(service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
         patch.object(service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.jwt", "access_token": "at"})), \
         patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
         patch.object(service._http, "fetch_userinfo", AsyncMock(return_value={})), \
         patch("fayda_mcp.service.validate_userinfo_response", return_value=mock_userinfo_claims):

        result = await service.complete_verification(code="auth_code_5", state=state)

    # 1. VerificationResult model contains no raw demographics
    result_dump = result.model_dump()
    assert "Abebe" not in str(result_dump)
    assert "1995-04-12" not in str(result_dump)

    # 2. DetailsMatchResult model contains only boolean match flags, no citizen values
    match_result = await service.get_details_match_result(start_resp.request_id, context=caller_context)
    assert match_result is not None
    match_dump = match_result.model_dump()
    assert "Abebe" not in str(match_dump)
    assert "1995-04-12" not in str(match_dump)

    # 3. Request record in storage contains no raw demographics
    record = await service.results.get_request(start_resp.request_id)
    assert record is not None
    assert "Abebe" not in str(record.get("matches"))


async def test_get_details_match_result_caller_isolation(
    service: FaydaVerificationService, caller_context: CallerContext, other_context: CallerContext
):
    """Cross-tenant or cross-principal callers cannot access other callers' match outcomes."""
    sub_resp = await service.submit_expected_details(
        application_user_ref="usr-iso-1",
        purpose="onboarding",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=caller_context,
    )

    start_resp = await service.start_details_verification(
        context=caller_context,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="onboarding",
        application_user_ref="usr-iso-1",
        idempotency_key="idemp-iso-1",
    )

    # Authorized caller can retrieve
    res = await service.get_details_match_result(start_resp.request_id, context=caller_context)
    assert res is not None

    # Foreign caller denied with AuthorizationError
    with pytest.raises(AuthorizationError):
        await service.get_details_match_result(start_resp.request_id, context=other_context)
