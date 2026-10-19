"""Unit tests for Ethiopian name structure preservation (guide5 Task 07).

Verifies:
- Compare ordered name components (given, father, grandfather).
- Do not treat Ethiopian patronymics as Western surnames.
- Do not silently reorder or drop tokens.
- Never approve from a single shared token.
- Transposed patronymics are strictly rejected as mismatches.
- Missing components require review or mismatch, never silent approval.
"""

import pytest

from fayda_mcp.context import CallerContext
from fayda_mcp.matching.normalization import compare_names
from fayda_mcp.matching.profiles import (
    NAME_MATCH_APPROVED_EQUIVALENT,
    NAME_MATCH_EXACT,
    NAME_MATCH_MISMATCH,
    NAME_MATCH_REVIEW_REQUIRED,
    PROFILE_ETHIOPIAN_NAME_V1,
    PROFILE_STRICT,
)
from fayda_mcp.matching.schemas import (
    MATCH_FIELD_FULL_NAME,
    ExpectedDetails,
)
from fayda_mcp.matching.service import DetailsMatchingService
from fayda_mcp.matching.storage import MemoryExpectedDetailsStore
from fayda_mcp.matching.structure import (
    REASON_CONFLICTING_COMPONENTS,
    REASON_CONFLICTING_FATHER_NAME,
    REASON_CONFLICTING_GIVEN_NAME,
    REASON_CONFLICTING_GRANDFATHER_NAME,
    REASON_MISSING_COMPONENT,
    REASON_SINGLE_TOKEN_SHARED_ONLY,
    REASON_TOKEN_COUNT_MISMATCH,
    REASON_TRANSPOSED_COMPONENTS,
    STRUCTURE_SPEC_VERSION,
    compare_ethiopian_name_structures,
    parse_ethiopian_name_structure,
)


def test_structure_spec_version():
    """Verify structure spec version constant."""
    assert STRUCTURE_SPEC_VERSION == "structure-v1"


# ---------------------------------------------------------------------------
# 1. Parsing Ordered Components
# ---------------------------------------------------------------------------


def test_parse_two_token_name():
    """Two-token name parses into given and father patronymic."""
    struct = parse_ethiopian_name_structure("Abebe Bikila")
    assert struct is not None
    assert struct.given_name == "abebe"
    assert struct.father_name == "bikila"
    assert struct.grandfather_name is None
    assert struct.token_count == 2
    assert struct.raw_tokens == ["abebe", "bikila"]


def test_parse_three_token_name():
    """Three-token name parses into given, father, and grandfather."""
    struct = parse_ethiopian_name_structure("Abebe Bikila Welde")
    assert struct is not None
    assert struct.given_name == "abebe"
    assert struct.father_name == "bikila"
    assert struct.grandfather_name == "welde"
    assert struct.token_count == 3
    assert struct.additional_tokens == []


def test_parse_four_token_name():
    """Four-token name preserves additional tokens beyond grandfather."""
    struct = parse_ethiopian_name_structure("Abebe Bikila Welde Selassie")
    assert struct is not None
    assert struct.given_name == "abebe"
    assert struct.father_name == "bikila"
    assert struct.grandfather_name == "welde"
    assert struct.additional_tokens == ["selassie"]
    assert struct.token_count == 4


def test_parse_empty_or_none():
    """Empty or None name returns None."""
    assert parse_ethiopian_name_structure(None) is None
    assert parse_ethiopian_name_structure("") is None
    assert parse_ethiopian_name_structure("   ") is None


# ---------------------------------------------------------------------------
# 2. Strict Transposition Prevention (No Permutations)
# ---------------------------------------------------------------------------


def test_transposed_components_strictly_rejected():
    """Transposed components (e.g. given <-> father) must return mismatch."""
    res = compare_ethiopian_name_structures("Abebe Bikila", "Bikila Abebe")
    assert res.is_compatible is False
    assert res.is_transposed is True
    assert res.status == NAME_MATCH_MISMATCH
    assert res.reason == REASON_TRANSPOSED_COMPONENTS


def test_transposed_with_variation_still_rejected():
    """Transposed tokens even with approved spelling variations are rejected."""
    # Abbebe Biqila vs Biqila Abbebe
    res = compare_ethiopian_name_structures("Abebe Bikila", "Biqila Abbebe")
    assert res.is_compatible is False
    assert res.is_transposed is True
    assert res.status == NAME_MATCH_MISMATCH
    assert res.reason == REASON_TRANSPOSED_COMPONENTS


# ---------------------------------------------------------------------------
# 3. No Western Surname Treatment & No Single-Token Approval
# ---------------------------------------------------------------------------


def test_shared_father_name_alone_never_proves_identity():
    """Sharing father's name (patronymic) but different given name is a mismatch."""
    # Western systems might match on surname 'Bikila', but in Ethiopia they are different citizens
    res = compare_ethiopian_name_structures("Abebe Bikila", "Kenenisa Bikila")
    assert res.is_compatible is False
    assert res.is_single_token_shared_only is True
    assert res.status == NAME_MATCH_MISMATCH
    assert res.reason == REASON_CONFLICTING_GIVEN_NAME


def test_shared_given_name_alone_never_proves_identity():
    """Sharing given name but different father's name is a mismatch."""
    res = compare_ethiopian_name_structures("Abebe Bikila", "Abebe Desta")
    assert res.is_compatible is False
    assert res.is_single_token_shared_only is True
    assert res.status == NAME_MATCH_MISMATCH
    assert res.reason == REASON_CONFLICTING_FATHER_NAME


def test_three_tokens_with_conflicting_grandfather():
    """Given and father match, but grandfather conflicts."""
    res = compare_ethiopian_name_structures("Abebe Bikila Welde", "Abebe Bikila Desta")
    assert res.is_compatible is False
    assert res.status == NAME_MATCH_MISMATCH
    assert res.reason == REASON_CONFLICTING_GRANDFATHER_NAME


# ---------------------------------------------------------------------------
# 4. No Silent Dropping / Missing Components
# ---------------------------------------------------------------------------


def test_missing_component_requires_review_not_silent_approval():
    """When one name has 2 tokens and the other has 3 matching tokens, it requires review."""
    res = compare_ethiopian_name_structures("Abebe Bikila Welde", "Abebe Bikila")
    assert res.is_compatible is False
    assert res.has_missing_component is True
    assert res.status == NAME_MATCH_REVIEW_REQUIRED
    assert res.reason == REASON_MISSING_COMPONENT


def test_missing_component_reversed_requires_review():
    """Expected 2 tokens and provider 3 tokens with matching prefix requires review."""
    res = compare_ethiopian_name_structures("Abebe Bikila", "Abebe Bikila Welde")
    assert res.is_compatible is False
    assert res.has_missing_component is True
    assert res.status == NAME_MATCH_REVIEW_REQUIRED
    assert res.reason == REASON_MISSING_COMPONENT


def test_token_count_mismatch_without_matching_prefix():
    """Token counts differ and prefix does NOT match produces mismatch."""
    res = compare_ethiopian_name_structures("Abebe Bikila Welde", "Kenenisa Desta")
    assert res.is_compatible is False
    assert res.status == NAME_MATCH_MISMATCH
    assert res.reason == REASON_TOKEN_COUNT_MISMATCH


# ---------------------------------------------------------------------------
# 5. Ordered Matching Success Cases
# ---------------------------------------------------------------------------


def test_ordered_exact_match():
    """Exact ordered match succeeds with exact status."""
    res = compare_ethiopian_name_structures("Abebe Bikila Welde", "abebe bikila welde")
    assert res.is_compatible is True
    assert res.status == NAME_MATCH_EXACT
    assert res.reason is None
    assert len(res.component_comparisons) == 3


def test_ordered_approved_variation_match():
    """Ordered approved variation match succeeds with approved_equivalent status."""
    res = compare_ethiopian_name_structures("Abebe Bikila Welde", "Abbebe Biqila Wolde")
    assert res.is_compatible is True
    assert res.status == NAME_MATCH_APPROVED_EQUIVALENT
    assert res.reason is None
    assert len(res.component_comparisons) == 3
    assert all(c.is_match for c in res.component_comparisons)


# ---------------------------------------------------------------------------
# 6. compare_names and DetailsMatchingService Integration Tests
# ---------------------------------------------------------------------------


def test_compare_names_transposition_mismatch():
    """compare_names returns mismatch for transposed patronymics."""
    outcome, reason = compare_names(
        "Abebe Bikila",
        "Bikila Abebe",
        matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
    )
    assert outcome is False
    assert reason == REASON_TRANSPOSED_COMPONENTS


def test_compare_names_missing_component_review():
    """compare_names returns outcome=None and missing_name_component for 2 vs 3 tokens."""
    outcome, reason = compare_names(
        "Abebe Bikila Welde",
        "Abebe Bikila",
        matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
    )
    assert outcome is None
    assert reason == REASON_MISSING_COMPONENT


def test_compare_names_single_token_shared_mismatch():
    """compare_names returns mismatch when sharing father's name alone."""
    outcome, reason = compare_names(
        "Abebe Bikila",
        "Kenenisa Bikila",
        matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
    )
    assert outcome is False
    assert reason == REASON_CONFLICTING_GIVEN_NAME


@pytest.mark.asyncio
async def test_service_transposed_tokens_produce_mismatch():
    """DetailsMatchingService sets mismatch outcome for transposed citizen names."""
    store = MemoryExpectedDetailsStore()
    service = DetailsMatchingService(
        store=store,
        default_profile=PROFILE_STRICT,
        allowed_profiles=[PROFILE_STRICT, PROFILE_ETHIOPIAN_NAME_V1],
    )
    ctx = CallerContext(tenant_id="t1", principal_id="backend_service", scopes=["verification:create"])

    sub_res = await service.submit_expected_details(
        application_user_ref="usr_struct_1",
        purpose="kyc",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
        ),
        context=ctx,
    )

    claims = {"name": "Bikila Abebe"}

    result = await service.evaluate_details_for_request(
        request_id="req_struct_1",
        claims=claims,
        expected_details_ref=sub_res.expected_details_ref,
        application_user_ref="usr_struct_1",
        purpose="kyc",
    )

    assert result.matches[MATCH_FIELD_FULL_NAME] is False
    assert result.name_match_status == NAME_MATCH_MISMATCH
    assert result.name_match_reason == REASON_TRANSPOSED_COMPONENTS


@pytest.mark.asyncio
async def test_service_missing_component_produces_review_required():
    """DetailsMatchingService sets review_required and matches.full_name=None for missing component."""
    store = MemoryExpectedDetailsStore()
    service = DetailsMatchingService(
        store=store,
        default_profile=PROFILE_STRICT,
        allowed_profiles=[PROFILE_STRICT, PROFILE_ETHIOPIAN_NAME_V1],
    )
    ctx = CallerContext(tenant_id="t1", principal_id="backend_service", scopes=["verification:create"])

    sub_res = await service.submit_expected_details(
        application_user_ref="usr_struct_2",
        purpose="kyc",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila Welde",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
        ),
        context=ctx,
    )

    # Provider supplies only 2 tokens
    claims = {"name": "Abebe Bikila"}

    result = await service.evaluate_details_for_request(
        request_id="req_struct_2",
        claims=claims,
        expected_details_ref=sub_res.expected_details_ref,
        application_user_ref="usr_struct_2",
        purpose="kyc",
    )

    assert result.matches[MATCH_FIELD_FULL_NAME] is None
    assert result.name_match_status == NAME_MATCH_REVIEW_REQUIRED
    assert result.name_match_reason == REASON_MISSING_COMPONENT
    assert result.matching_status == "unavailable"
