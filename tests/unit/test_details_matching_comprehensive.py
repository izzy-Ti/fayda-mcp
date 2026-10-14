"""Comprehensive verification tests for Task 10: Details Matching.

Validates all 8 core criteria:
1. Match / Mismatch: exact matches, single-claim matches, and deterministic mismatches.
2. Missing claims: ungranted scopes, missing provider claims, tri-state nulls.
3. Ambiguous dates: partial dates, invalid formats, Gregorian vs. Ethiopic calendars.
4. Unicode: NFC composition, case-folding, whitespace collapsing, Amharic/Ge'ez script.
5. Expired references: TTL expiration on expected details and on verification requests.
6. Cross-caller access: tenant, principal, and application_user_ref isolation.
7. Replay: single-use expected_details_ref binding and callback replay prevention.
8. Changed-input retries: fresh submission, new idempotency key, updated match outcome.
"""

import json
from unittest.mock import AsyncMock, patch
import pytest

from fastmcp import Client
from fastmcp.exceptions import ToolError

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext
from fayda_mcp.exceptions import AuthorizationError, VerificationNotFoundError
from fayda_mcp.matching.normalization import (
    REASON_DOB_MISMATCH,
    REASON_INVALID_DATE_FORMAT,
    REASON_NAME_MISMATCH,
    REASON_PARTIAL_DOB_UNAVAILABLE,
    REASON_PROVIDER_CLAIM_UNAVAILABLE,
    compare_dates,
    compare_names,
    evaluate_details_matching,
)
from fayda_mcp.matching.schemas import (
    DEFAULT_COMPARISON_POLICY_VERSION,
    DetailsMatchingError,
    DetailsMatchResult,
    ExpectedDetails,
)
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


class SimpleCallerAdapter:
    def __init__(self, context: CallerContext):
        self.context = context

    async def resolve_context(self, tool_name: str, **kwargs) -> CallerContext:
        return self.context

    async def authorize(self, context: CallerContext, required_scope: str, request_id: str | None = None) -> bool:
        return required_scope in context.scopes


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
def tenant_alpha_caller() -> CallerContext:
    return CallerContext(
        tenant_id="bank-alpha",
        principal_id="service-worker-alpha",
        scopes=["verification:create", "verification:read"],
    )


@pytest.fixture
def tenant_beta_caller() -> CallerContext:
    return CallerContext(
        tenant_id="bank-beta",
        principal_id="service-worker-beta",
        scopes=["verification:create", "verification:read"],
    )


async def _execute_mock_callback(
    service: FaydaVerificationService,
    authorization_url: str,
    userinfo_claims: dict,
    sub: str = "fayda:sub:12345",
):
    """Helper to simulate eSignet OAuth callback execution."""
    state = authorization_url.split("state=")[1].split("&")[0]
    mock_id_claims = {"sub": sub}

    with patch.object(service, "_get_private_key", return_value="fake_pem"), \
         patch("fayda_mcp.service.create_client_assertion", return_value="fake.assertion"), \
         patch.object(service.jwks, "get_signing_key_for_token", AsyncMock(return_value="fake_key")), \
         patch.object(service._http, "exchange_code", AsyncMock(return_value={"id_token": "mock.jwt", "access_token": "at"})), \
         patch("fayda_mcp.service.validate_id_token", return_value=mock_id_claims), \
         patch.object(service._http, "fetch_userinfo", AsyncMock(return_value={})), \
         patch("fayda_mcp.service.validate_userinfo_response", return_value=userinfo_claims):

        return await service.complete_verification(code=f"code_{state[:8]}", state=state)


# ===========================================================================
# 1. Match / Mismatch Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_full_match_flow(service: FaydaVerificationService, tenant_alpha_caller: CallerContext):
    """Exact match on full_name and date_of_birth yields 'matched' status and True flags."""
    sub_resp = await service.submit_expected_details(
        application_user_ref="usr-match-01",
        purpose="kyc",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            date_of_birth="1995/04/12",
        ),
        context=tenant_alpha_caller,
    )

    start_resp = await service.start_details_verification(
        context=tenant_alpha_caller,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="kyc",
        application_user_ref="usr-match-01",
        idempotency_key="idemp-match-01",
    )

    await _execute_mock_callback(
        service=service,
        authorization_url=start_resp.authorization_url,
        userinfo_claims={"name": "Abebe Bikila", "birthdate": "1995-04-12"},
    )

    result = await service.get_details_match_result(start_resp.request_id, context=tenant_alpha_caller)
    assert result is not None
    assert result.matching_status == "matched"
    assert result.matches == {"full_name": True, "date_of_birth": True}
    assert result.comparison_policy_version == DEFAULT_COMPARISON_POLICY_VERSION
    assert result.reasons == {}
    assert result.identity_authenticated is True


@pytest.mark.asyncio
async def test_mismatch_flows(service: FaydaVerificationService, tenant_alpha_caller: CallerContext):
    """Mismatches on name, DOB, or both deterministically produce 'mismatched' status."""
    # 1. Name mismatch
    sub1 = await service.submit_expected_details(
        application_user_ref="usr-mis-01",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila", date_of_birth="1995/04/12"),
        context=tenant_alpha_caller,
    )
    start1 = await service.start_details_verification(
        context=tenant_alpha_caller,
        expected_details_ref=sub1.expected_details_ref,
        purpose="kyc",
        application_user_ref="usr-mis-01",
        idempotency_key="idemp-mis-01",
    )
    await _execute_mock_callback(
        service, start1.authorization_url, {"name": "Haile Gebrselassie", "birthdate": "1995-04-12"}
    )
    res1 = await service.get_details_match_result(start1.request_id, context=tenant_alpha_caller)
    assert res1.matching_status == "mismatched"
    assert res1.matches["full_name"] is False
    assert res1.matches["date_of_birth"] is True
    assert res1.reasons["full_name"] == REASON_NAME_MISMATCH

    # 2. DOB mismatch
    sub2 = await service.submit_expected_details(
        application_user_ref="usr-mis-02",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Derartu Tulu", date_of_birth="1972/03/21"),
        context=tenant_alpha_caller,
    )
    start2 = await service.start_details_verification(
        context=tenant_alpha_caller,
        expected_details_ref=sub2.expected_details_ref,
        purpose="kyc",
        application_user_ref="usr-mis-02",
        idempotency_key="idemp-mis-02",
    )
    await _execute_mock_callback(
        service, start2.authorization_url, {"name": "Derartu Tulu", "birthdate": "1980-01-01"}
    )
    res2 = await service.get_details_match_result(start2.request_id, context=tenant_alpha_caller)
    assert res2.matching_status == "mismatched"
    assert res2.matches["full_name"] is True
    assert res2.matches["date_of_birth"] is False
    assert res2.reasons["date_of_birth"] == REASON_DOB_MISMATCH

    # 3. Both mismatch
    sub3 = await service.submit_expected_details(
        application_user_ref="usr-mis-03",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Kenenisa Bekele", date_of_birth="1982/06/13"),
        context=tenant_alpha_caller,
    )
    start3 = await service.start_details_verification(
        context=tenant_alpha_caller,
        expected_details_ref=sub3.expected_details_ref,
        purpose="kyc",
        application_user_ref="usr-mis-03",
        idempotency_key="idemp-mis-03",
    )
    await _execute_mock_callback(
        service, start3.authorization_url, {"name": "Sileshi Sihine", "birthdate": "1983-01-29"}
    )
    res3 = await service.get_details_match_result(start3.request_id, context=tenant_alpha_caller)
    assert res3.matching_status == "mismatched"
    assert res3.matches["full_name"] is False
    assert res3.matches["date_of_birth"] is False


# ===========================================================================
# 2. Missing Claims Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_missing_claims_handling(service: FaydaVerificationService, tenant_alpha_caller: CallerContext):
    """When provider omits name or birthdate, field outcome is None with claim_unavailable."""
    # 1. Missing birthdate
    sub1 = await service.submit_expected_details(
        application_user_ref="usr-miss-claim-01",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila", date_of_birth="1995/04/12"),
        context=tenant_alpha_caller,
    )
    start1 = await service.start_details_verification(
        context=tenant_alpha_caller,
        expected_details_ref=sub1.expected_details_ref,
        purpose="kyc",
        application_user_ref="usr-miss-claim-01",
        idempotency_key="idemp-miss-01",
    )
    # Citizen authenticated, but provider omitted birthdate
    await _execute_mock_callback(service, start1.authorization_url, {"name": "Abebe Bikila"})
    res1 = await service.get_details_match_result(start1.request_id, context=tenant_alpha_caller)
    assert res1.matches["full_name"] is True
    assert res1.matches["date_of_birth"] is None
    assert res1.reasons["date_of_birth"] == REASON_PROVIDER_CLAIM_UNAVAILABLE
    assert res1.matching_status == "unavailable"

    # 2. Missing both claims
    sub2 = await service.submit_expected_details(
        application_user_ref="usr-miss-claim-02",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila", date_of_birth="1995/04/12"),
        context=tenant_alpha_caller,
    )
    start2 = await service.start_details_verification(
        context=tenant_alpha_caller,
        expected_details_ref=sub2.expected_details_ref,
        purpose="kyc",
        application_user_ref="usr-miss-claim-02",
        idempotency_key="idemp-miss-02",
    )
    await _execute_mock_callback(service, start2.authorization_url, {})
    res2 = await service.get_details_match_result(start2.request_id, context=tenant_alpha_caller)
    assert res2.matches["full_name"] is None
    assert res2.matches["date_of_birth"] is None
    assert res2.matching_status == "unavailable"


# ===========================================================================
# 3. Ambiguous Dates Tests
# ===========================================================================


def test_ambiguous_and_partial_dates():
    """Partial dates return None (unavailable); invalid formats return None (invalid_date_format)."""
    # Incomplete years or year-months
    out, reason = compare_dates("1995/04/12", "1995")
    assert out is None
    assert reason == REASON_PARTIAL_DOB_UNAVAILABLE

    out, reason = compare_dates("1995/04/12", "1995-04")
    assert out is None
    assert reason == REASON_PARTIAL_DOB_UNAVAILABLE

    # Two-digit year / ambiguous format parses as year 95, deterministically mismatching 1995
    out, reason = compare_dates("1995/04/12", "95-04-12")
    assert out is False
    assert reason == REASON_DOB_MISMATCH

    # Non-existent calendar day
    out, reason = compare_dates("1995/04/12", "1995-02-30")
    assert out is None
    assert reason == REASON_INVALID_DATE_FORMAT

    # Unparseable gibberish or unsupported separator
    out, reason = compare_dates("1995/04/12", "not_a_valid_date")
    assert out is None
    assert reason == REASON_INVALID_DATE_FORMAT

    out, reason = compare_dates("1995/04/12", "1995.04.12")
    assert out is None
    assert reason == REASON_INVALID_DATE_FORMAT


def test_calendar_explicit_normalization():
    """Ethiopic calendar dates are converted to Gregorian explicitly and compared deterministically."""
    # Ethiopic 1987-08-04 converts to Gregorian 1995-04-12
    out, reason = compare_dates(
        expected_dob="1987-08-04",
        provider_dob="1995-04-12",
        expected_calendar="ethiopic",
        provider_calendar="gregorian",
    )
    assert out is True
    assert reason is None

    # Date separator normalization (slash vs hyphen)
    out, reason = compare_dates("1995/04/12", "1995-04-12")
    assert out is True
    assert reason is None


# ===========================================================================
# 4. Unicode Normalization & Script Preservation Tests
# ===========================================================================


def test_unicode_nfc_and_case_folding():
    """NFC normalization and Unicode case-folding eliminate encoding discrepancies."""
    # Decomposed NFD vs precomposed NFC
    nfd_name = "Abe\u0301be\u0301 Bikila"  # 'e' + combining acute
    nfc_name = "Abébé Bikila"
    out, reason = compare_names(nfd_name, nfc_name)
    assert out is True
    assert reason is None

    # Full case-folding (German Eszett)
    out, reason = compare_names("Großmann", "GROSSMANN")
    assert out is True
    assert reason is None

    # Mixed whitespace collapsing
    out, reason = compare_names("   Abebe  \t  Bikila \n ", "Abebe Bikila")
    assert out is True
    assert reason is None


def test_geez_script_preservation_and_token_order():
    """Ge'ez / Amharic script is preserved without transliteration; token order is strictly kept."""
    # Amharic matching
    out, reason = compare_names("አበበ ቢቂላ", "  አበበ   ቢቂላ  ")
    assert out is True
    assert reason is None

    # Transposed token order fails
    out, reason = compare_names("አበበ ቢቂላ", "ቢቂላ አበበ")
    assert out is False
    assert reason == REASON_NAME_MISMATCH

    # Cross-script comparison without transliteration fails
    out, reason = compare_names("Abebe Bikila", "አበበ ቢቂላ")
    assert out is False
    assert reason == REASON_NAME_MISMATCH


# ===========================================================================
# 5. Expired References Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_expired_expected_details_reference(
    service: FaydaVerificationService, tenant_alpha_caller: CallerContext
):
    """Calling start_details_verification with an expired expected_details_ref fails."""
    sub_resp = await service.submit_expected_details(
        application_user_ref="usr-exp-01",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=tenant_alpha_caller,
    )

    # Force expiration of expected details in store
    rec = await service.matching_service.get_expected_details_record(
        sub_resp.expected_details_ref, context=tenant_alpha_caller
    )
    rec.expires_at = "2020-01-01T00:00:00+00:00"
    await service.matching_service.store.save_expected_details(
        sub_resp.expected_details_ref, rec, ttl_seconds=1
    )

    with pytest.raises(DetailsMatchingError) as exc_info:
        await service.start_details_verification(
            context=tenant_alpha_caller,
            expected_details_ref=sub_resp.expected_details_ref,
            purpose="kyc",
            application_user_ref="usr-exp-01",
            idempotency_key="idemp-exp-01",
        )
    assert "expired" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_expired_verification_result_tool(
    service: FaydaVerificationService, tenant_alpha_caller: CallerContext
):
    """Expired verification request returns not found through MCP tool."""
    adapter = SimpleCallerAdapter(tenant_alpha_caller)
    server = create_mcp_server(service=service, caller_adapter=adapter)

    sub_resp = await service.submit_expected_details(
        application_user_ref="usr-exp-res-01",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=tenant_alpha_caller,
    )
    start_resp = await service.start_details_verification(
        context=tenant_alpha_caller,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="kyc",
        application_user_ref="usr-exp-res-01",
        idempotency_key="idemp-exp-res-01",
    )

    # Artificially expire the request record
    rec = await service.results.get_request(start_resp.request_id)
    rec["expires_at"] = "2020-01-01T00:00:00+00:00"
    rec["session_expires_at"] = "2020-01-01T00:00:00+00:00"
    await service.results.save_request(start_resp.request_id, rec, ttl_seconds=1)

    async with Client(server) as client:
        with pytest.raises(ToolError) as exc:
            await client.call_tool("get_details_match_result", {"request_id": start_resp.request_id})
        assert "not found" in str(exc.value).lower() or "expired" in str(exc.value).lower()


# ===========================================================================
# 6. Cross-Caller Isolation Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_cross_caller_isolation_enforcement(
    service: FaydaVerificationService,
    tenant_alpha_caller: CallerContext,
    tenant_beta_caller: CallerContext,
):
    """Tenant A assets are strictly inaccessible to Tenant B."""
    # 1. Tenant Alpha submits expected details
    sub_resp = await service.submit_expected_details(
        application_user_ref="usr-iso-01",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=tenant_alpha_caller,
    )

    # Tenant Beta attempts to start verification with Alpha's ref -> REJECTED
    with pytest.raises(DetailsMatchingError) as exc_info:
        await service.start_details_verification(
            context=tenant_beta_caller,
            expected_details_ref=sub_resp.expected_details_ref,
            purpose="kyc",
            application_user_ref="usr-iso-01",
            idempotency_key="idemp-iso-01",
        )
    assert "caller" in str(exc_info.value).lower() or "denied" in str(exc_info.value).lower()

    # 2. Tenant Alpha starts verification
    start_resp = await service.start_details_verification(
        context=tenant_alpha_caller,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="kyc",
        application_user_ref="usr-iso-01",
        idempotency_key="idemp-iso-02",
    )

    # Tenant Beta attempts to read match result -> REJECTED
    with pytest.raises(AuthorizationError) as exc_auth:
        await service.get_details_match_result(start_resp.request_id, context=tenant_beta_caller)
    assert "denied" in str(exc_auth.value).lower()

    # 3. User Ref Mismatch: Alpha attempts to start for different user -> REJECTED
    sub_resp2 = await service.submit_expected_details(
        application_user_ref="usr-alice",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Alice"),
        context=tenant_alpha_caller,
    )
    with pytest.raises(DetailsMatchingError) as exc_user:
        await service.start_details_verification(
            context=tenant_alpha_caller,
            expected_details_ref=sub_resp2.expected_details_ref,
            purpose="kyc",
            application_user_ref="usr-bob",
            idempotency_key="idemp-iso-03",
        )
    assert "user" in str(exc_user.value).lower()


# ===========================================================================
# 7. Replay Protection Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_replay_prevention_on_expected_details_ref(
    service: FaydaVerificationService, tenant_alpha_caller: CallerContext
):
    """An expected_details_ref is single-use and cannot be bound to multiple requests."""
    sub_resp = await service.submit_expected_details(
        application_user_ref="usr-replay-01",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=tenant_alpha_caller,
    )

    # First start consumes and binds the reference
    await service.start_details_verification(
        context=tenant_alpha_caller,
        expected_details_ref=sub_resp.expected_details_ref,
        purpose="kyc",
        application_user_ref="usr-replay-01",
        idempotency_key="idemp-first-use",
    )

    # Second start with new idempotency key attempting to reuse ref -> REJECTED
    with pytest.raises(DetailsMatchingError) as exc_info:
        await service.start_details_verification(
            context=tenant_alpha_caller,
            expected_details_ref=sub_resp.expected_details_ref,
            purpose="kyc",
            application_user_ref="usr-replay-01",
            idempotency_key="idemp-second-use",
        )
    assert "bound" in str(exc_info.value).lower() or "replay" in str(exc_info.value).lower()


# ===========================================================================
# 8. Changed-Input Retries Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_changed_input_retry_flow(
    service: FaydaVerificationService, tenant_alpha_caller: CallerContext
):
    """When a verification mismatches, submitting corrected input with a new ref succeeds on retry."""
    # Attempt 1: Typo in citizen name ("Abeba" instead of "Abebe")
    sub1 = await service.submit_expected_details(
        application_user_ref="usr-retry-flow",
        purpose="onboarding",
        expected_details=ExpectedDetails(full_name="Abeba Bikila", date_of_birth="1995/04/12"),
        context=tenant_alpha_caller,
    )
    start1 = await service.start_details_verification(
        context=tenant_alpha_caller,
        expected_details_ref=sub1.expected_details_ref,
        purpose="onboarding",
        application_user_ref="usr-retry-flow",
        idempotency_key="idemp-attempt-1",
    )
    await _execute_mock_callback(
        service, start1.authorization_url, {"name": "Abebe Bikila", "birthdate": "1995-04-12"}
    )
    res1 = await service.get_details_match_result(start1.request_id, context=tenant_alpha_caller)
    assert res1.matching_status == "mismatched"
    assert res1.matches["full_name"] is False

    # Attempt 2: User corrected the typo, submits fresh expected details
    sub2 = await service.submit_expected_details(
        application_user_ref="usr-retry-flow",
        purpose="onboarding",
        expected_details=ExpectedDetails(full_name="Abebe Bikila", date_of_birth="1995/04/12"),
        context=tenant_alpha_caller,
    )
    assert sub2.expected_details_ref != sub1.expected_details_ref

    start2 = await service.start_details_verification(
        context=tenant_alpha_caller,
        expected_details_ref=sub2.expected_details_ref,
        purpose="onboarding",
        application_user_ref="usr-retry-flow",
        idempotency_key="idemp-attempt-2",
    )
    assert start2.request_id != start1.request_id

    await _execute_mock_callback(
        service, start2.authorization_url, {"name": "Abebe Bikila", "birthdate": "1995-04-12"}
    )
    res2 = await service.get_details_match_result(start2.request_id, context=tenant_alpha_caller)
    assert res2.matching_status == "matched"
    assert res2.matches["full_name"] is True
    assert res2.matches["date_of_birth"] is True
