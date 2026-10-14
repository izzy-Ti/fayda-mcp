"""Unit tests for Task 05: Request approved claims, map name/DOB requirements, and enforce unavailable claim rules."""

import urllib.parse
import json
import pytest
from fastmcp.client import Client

from fayda_mcp.config import FaydaConfig
from fayda_mcp.context import CallerContext, SimpleCallerAdapter
from fayda_mcp.matching.claims import (
    CLAIM_BIRTHDATE,
    CLAIM_NAME,
    CLAIM_SUB,
    REASON_PROVIDER_CLAIM_UNAVAILABLE,
    REASON_UNSUPPORTED_FIELD,
    SCOPE_OPENID,
    SCOPE_PROFILE,
    evaluate_initial_availability,
    extract_approved_matching_claims,
    resolve_details_matching_scopes_and_claims,
)
from fayda_mcp.matching.schemas import (
    MATCH_FIELD_DATE_OF_BIRTH,
    MATCH_FIELD_FULL_NAME,
    ExpectedDetails,
    compute_overall_matching_status,
)
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.policy import VerificationPolicy
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


# ===========================================================================
# 1. Scopes & Claims Mapping Tests
# ===========================================================================


def test_resolve_scopes_and_claims_name_only():
    """Mapping name-only expected details produces openid, profile scopes and essential sub, name claims."""
    details = ExpectedDetails(full_name="Abebe Bikila")
    scopes, claims_param = resolve_details_matching_scopes_and_claims(details)

    assert set(scopes) == {SCOPE_OPENID, SCOPE_PROFILE}
    userinfo = claims_param["userinfo"]
    assert userinfo[CLAIM_SUB] == {"essential": True}
    assert userinfo[CLAIM_NAME] == {"essential": True}
    assert CLAIM_BIRTHDATE not in userinfo


def test_resolve_scopes_and_claims_dob_only():
    """Mapping DOB-only expected details produces openid, profile scopes and essential sub, birthdate claims."""
    details = ExpectedDetails(date_of_birth="1995/04/12")
    scopes, claims_param = resolve_details_matching_scopes_and_claims(details)

    assert set(scopes) == {SCOPE_OPENID, SCOPE_PROFILE}
    userinfo = claims_param["userinfo"]
    assert userinfo[CLAIM_SUB] == {"essential": True}
    assert userinfo[CLAIM_BIRTHDATE] == {"essential": True}
    assert CLAIM_NAME not in userinfo


def test_resolve_scopes_and_claims_both_name_and_dob():
    """Mapping both name and DOB produces openid, profile scopes and essential sub, name, birthdate claims."""
    details = ExpectedDetails(
        full_name="Derartu Tulu",
        date_of_birth="1972/03/21",
    )
    scopes, claims_param = resolve_details_matching_scopes_and_claims(details)

    assert set(scopes) == {SCOPE_OPENID, SCOPE_PROFILE}
    userinfo = claims_param["userinfo"]
    assert userinfo[CLAIM_SUB] == {"essential": True}
    assert userinfo[CLAIM_NAME] == {"essential": True}
    assert userinfo[CLAIM_BIRTHDATE] == {"essential": True}


def test_policy_delegation_matches_standalone():
    """VerificationPolicy.resolve_details_scopes_and_claims produces identical mappings."""
    policy = VerificationPolicy()
    details = ExpectedDetails(full_name="Haile Gebrselassie", date_of_birth="1973/04/18")

    scopes1, claims1 = resolve_details_matching_scopes_and_claims(details)
    scopes2, claims2 = policy.resolve_details_scopes_and_claims(details)

    assert scopes1 == scopes2
    assert claims1 == claims2


# ===========================================================================
# 2. Approved Claims Extraction & Availability Rules
# ===========================================================================


def test_extract_approved_matching_claims_success():
    """Provider claims containing name and birthdate are extracted directly."""
    provider_claims = {
        "sub": "citizen_999",
        "name": "Kenenisa Bekele",
        "birthdate": "1982-06-13",
    }
    extracted, reasons = extract_approved_matching_claims(provider_claims)

    assert extracted[MATCH_FIELD_FULL_NAME] == "Kenenisa Bekele"
    assert extracted[MATCH_FIELD_DATE_OF_BIRTH] == "1982-06-13"
    assert reasons == {}


def test_extract_approved_matching_claims_split_name_fallback():
    """Provider returning given_name + family_name is combined safely."""
    provider_claims = {
        "sub": "citizen_888",
        "given_name": "Tirunesh",
        "family_name": "Dibaba",
        "dob": "1985-06-01",
    }
    extracted, reasons = extract_approved_matching_claims(provider_claims)

    assert extracted[MATCH_FIELD_FULL_NAME] == "Tirunesh Dibaba"
    assert extracted[MATCH_FIELD_DATE_OF_BIRTH] == "1985-06-01"
    assert reasons == {}


def test_extract_approved_matching_claims_missing_name():
    """Missing name claim strictly evaluates to None with provider_claim_unavailable reason."""
    provider_claims = {
        "sub": "citizen_777",
        "birthdate": "1990-01-01",
    }
    extracted, reasons = extract_approved_matching_claims(provider_claims)

    assert extracted[MATCH_FIELD_FULL_NAME] is None
    assert reasons[MATCH_FIELD_FULL_NAME] == REASON_PROVIDER_CLAIM_UNAVAILABLE
    assert extracted[MATCH_FIELD_DATE_OF_BIRTH] == "1990-01-01"


def test_extract_approved_matching_claims_missing_dob():
    """Missing birthdate claim strictly evaluates to None with provider_claim_unavailable reason."""
    provider_claims = {
        "sub": "citizen_666",
        "name": "Sileshi Sihine",
    }
    extracted, reasons = extract_approved_matching_claims(provider_claims)

    assert extracted[MATCH_FIELD_DATE_OF_BIRTH] is None
    assert reasons[MATCH_FIELD_DATE_OF_BIRTH] == REASON_PROVIDER_CLAIM_UNAVAILABLE
    assert extracted[MATCH_FIELD_FULL_NAME] == "Sileshi Sihine"


def test_extract_approved_matching_claims_all_missing():
    """When provider returns only sub, all comparison fields evaluate to None (unavailable)."""
    provider_claims = {"sub": "citizen_555"}
    extracted, reasons = extract_approved_matching_claims(provider_claims)

    assert extracted[MATCH_FIELD_FULL_NAME] is None
    assert reasons[MATCH_FIELD_FULL_NAME] == REASON_PROVIDER_CLAIM_UNAVAILABLE
    assert extracted[MATCH_FIELD_DATE_OF_BIRTH] is None
    assert reasons[MATCH_FIELD_DATE_OF_BIRTH] == REASON_PROVIDER_CLAIM_UNAVAILABLE


def test_unavailable_claim_tri_state_outcome():
    """Missing claim produces tri-state null outcome and prevents matched overall status."""
    provider_claims = {"sub": "citizen_444", "name": "Abebe Bikila"}
    extracted, reasons = extract_approved_matching_claims(provider_claims)

    # Initial availability
    outcomes = evaluate_initial_availability(
        requested_fields=[MATCH_FIELD_FULL_NAME, MATCH_FIELD_DATE_OF_BIRTH],
        extracted_claims=extracted,
        unavailable_reasons=reasons,
    )
    # Full name is available for comparison, DOB is unavailable (None)
    assert outcomes.get(MATCH_FIELD_DATE_OF_BIRTH) is None

    # Overall outcome computation: if required_fields includes date_of_birth, overall status is 'unavailable'
    overall = compute_overall_matching_status(
        matches={MATCH_FIELD_FULL_NAME: True, MATCH_FIELD_DATE_OF_BIRTH: None},
        required_fields=[MATCH_FIELD_FULL_NAME, MATCH_FIELD_DATE_OF_BIRTH],
    )
    assert overall == "unavailable"


# ===========================================================================
# 3. Integration with start_details_verification
# ===========================================================================


@pytest.mark.asyncio
async def test_start_details_verification_requests_only_needed_claims():
    """start_details_verification dynamically builds authorization URL with only the required claims."""
    config = FaydaConfig(
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
    service = FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )
    caller = CallerContext(
        tenant_id="bank-1",
        principal_id="service-a",
        scopes=["verification:create", "verification:read"],
    )
    adapter = SimpleCallerAdapter(context_resolver=lambda: caller)
    server = create_mcp_server(service=service, caller_adapter=adapter)

    # Case 1: Name only
    sub_name = await service.submit_expected_details(
        application_user_ref="usr_name_only",
        purpose="kyc",
        expected_details=ExpectedDetails(full_name="Abebe Bikila"),
        context=caller,
    )
    async with Client(server) as client:
        res1 = await client.call_tool(
            "start_details_verification",
            arguments={
                "expected_details_ref": sub_name.expected_details_ref,
                "purpose": "kyc",
                "application_user_ref": "usr_name_only",
                "idempotency_key": "idemp_name_only",
            },
        )
    data1 = json.loads(res1.content[0].text)
    params1 = urllib.parse.parse_qs(urllib.parse.urlparse(data1["authorization_url"]).query)
    claims1 = json.loads(params1["claims"][0])["userinfo"]
    assert "name" in claims1
    assert "birthdate" not in claims1

    # Case 2: DOB only
    sub_dob = await service.submit_expected_details(
        application_user_ref="usr_dob_only",
        purpose="kyc",
        expected_details=ExpectedDetails(date_of_birth="1992/08/25"),
        context=caller,
    )
    async with Client(server) as client:
        res2 = await client.call_tool(
            "start_details_verification",
            arguments={
                "expected_details_ref": sub_dob.expected_details_ref,
                "purpose": "kyc",
                "application_user_ref": "usr_dob_only",
                "idempotency_key": "idemp_dob_only",
            },
        )
    data2 = json.loads(res2.content[0].text)
    params2 = urllib.parse.parse_qs(urllib.parse.urlparse(data2["authorization_url"]).query)
    claims2 = json.loads(params2["claims"][0])["userinfo"]
    assert "birthdate" in claims2
    assert "name" not in claims2
