"""Unit tests for context-specific spelling rules and approved variations (guide5 Task 05).

Verifies:
- Curated reviewed equivalent examples match (Abebe/Abbebe, Wolde/Welde, Bikila/Biqila, etc.).
- Context-specific rules match recognized phonetic variations without global merging.
- False positives are strictly prevented: global vowel merges (e.g., Abebe vs Ababa) and
  arbitrary doubled consonants DO NOT match.
- Name structure and token order are strictly preserved (transposition or dropping fails).
- Cross-script transliteration + variation works deterministically.
- compare_names and DetailsMatchingService produce approved_equivalent outcomes under
  ethiopian_name_v1 while strict profile remains exact-only.
"""

import pytest

from fayda_mcp.context import CallerContext
from fayda_mcp.matching.normalization import compare_names, evaluate_details_matching
from fayda_mcp.matching.profiles import (
    METHOD_APPROVED_VARIATION,
    METHOD_EXACT_NORMALIZED,
    METHOD_TRANSLITERATION,
    NAME_MATCH_APPROVED_EQUIVALENT,
    NAME_MATCH_EXACT,
    NAME_MATCH_MISMATCH,
    PROFILE_ETHIOPIAN_NAME_V1,
    PROFILE_STRICT,
)
from fayda_mcp.matching.schemas import (
    MATCH_FIELD_FULL_NAME,
    ExpectedDetails,
    ExpectedDetailsSubmission,
)
from fayda_mcp.matching.service import DetailsMatchingService
from fayda_mcp.matching.storage import MemoryExpectedDetailsStore
from fayda_mcp.matching.variations import (
    ACTIVE_CONTEXT_RULES,
    REVIEWED_EQUIVALENT_CLUSTERS,
    VARIATIONS_SPEC_VERSION,
    RuleFinalEOrYe,
    RuleHaileHaylePrefix,
    RuleInitialEpenthetic,
    RuleKQAlternation,
    RuleMedialGemination,
    RuleWoldeWeldePrefix,
    get_approved_variants_for_token,
    is_approved_name_variation,
    is_approved_token_variation,
)


def test_variations_spec_version_and_clusters():
    """Verify specification version and cluster non-emptiness."""
    assert VARIATIONS_SPEC_VERSION == "variations-v1"
    assert len(REVIEWED_EQUIVALENT_CLUSTERS) >= 20
    assert len(ACTIVE_CONTEXT_RULES) == 6


# ---------------------------------------------------------------------------
# Reviewed Examples Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token_a, token_b",
    [
        ("abebe", "abbebe"),
        ("bikila", "biqila"),
        ("bekele", "beqele"),
        ("welde", "wolde"),
        ("worku", "werku"),
        ("haile", "hayle"),
        ("hailu", "haylu"),
        ("selassie", "selase"),
        ("kassa", "kasa"),
        ("kebede", "qebede"),
        ("almaz", "almaze"),
        ("birhanu", "berhanu"),
        ("girma", "germa"),
        ("tesfaye", "tesfay"),
        ("mekonnen", "mekonen"),
        ("assefa", "asefa"),
        ("mulugeta", "mullugeta"),
        ("debebe", "debbebe"),
    ],
)
def test_reviewed_equivalent_token_pairs(token_a: str, token_b: str):
    """Reviewed equivalent pairs must match in both directions."""
    is_eq_ab, reason_ab = is_approved_token_variation(token_a, token_b)
    assert is_eq_ab is True
    assert reason_ab is not None

    is_eq_ba, reason_ba = is_approved_token_variation(token_b, token_a)
    assert is_eq_ba is True
    assert reason_ba is not None


# ---------------------------------------------------------------------------
# Context-Specific Rules Tests
# ---------------------------------------------------------------------------


def test_rule_wolde_welde_prefix():
    rule = RuleWoldeWeldePrefix()
    assert rule.matches("wolde", "welde") is True
    assert rule.matches("worku", "werku") is True
    assert rule.matches("wossen", "wessen") is True
    # Should not match non-prefix or too-short tokens
    assert rule.matches("wo", "we") is False
    assert rule.matches("alemu", "elemu") is False


def test_rule_haile_hayle_prefix():
    rule = RuleHaileHaylePrefix()
    assert rule.matches("haile", "hayle") is True
    assert rule.matches("hailu", "haylu") is True
    assert rule.matches("hailemariam", "haylemariam") is True
    assert rule.matches("haile", "haile") is False


def test_rule_kq_alternation():
    rule = RuleKQAlternation()
    assert rule.matches("bikila", "biqila") is True
    assert rule.matches("bekele", "beqele") is True
    assert rule.matches("kassa", "qassa") is True
    # Non-kq changes must fail
    assert rule.matches("bikila", "bipila") is False
    assert rule.matches("bikila", "bikila") is False


def test_rule_medial_gemination():
    rule = RuleMedialGemination()
    # Medial doubled b, d, l, s, n, m, t, r
    assert rule.matches("abebe", "abbebe") is True
    assert rule.matches("tadese", "taddese") is True
    assert rule.matches("alemu", "allemu") is True
    assert rule.matches("kasa", "kassa") is True
    assert rule.matches("debebe", "debbebe") is True
    assert rule.matches("assefa", "asefa") is True
    # Non-medial or multiple character differences
    assert rule.matches("abebe", "abdebe") is False
    assert rule.matches("abebe", "abbbebe") is False


def test_rule_final_e_or_ye():
    rule = RuleFinalEOrYe()
    assert rule.matches("almaz", "almaze") is True
    assert rule.matches("kidan", "kidane") is True
    assert rule.matches("tesfay", "tesfaye") is True
    assert rule.matches("ab", "abe") is False  # too short


def test_rule_initial_epenthetic():
    rule = RuleInitialEpenthetic()
    assert rule.matches("birhanu", "berhanu") is True
    assert rule.matches("girma", "germa") is True
    assert rule.matches("dasta", "desta") is False  # not followed by liquid r/l


# ---------------------------------------------------------------------------
# Strict Prevention of Global Merging (Negative Tests)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token_a, token_b",
    [
        ("abebe", "ababa"),      # Distinct vowels (e vs a)
        ("mamo", "meme"),        # Non-equivalent vowels
        ("dawit", "dawet"),      # i vs e in non-epenthetic position
        ("bikila", "bakila"),    # First syllable vowel change
        ("kassa", "kossa"),      # First syllable vowel change
        ("abebe", "abeebe"),     # Doubled vowel
        ("alemu", "olemu"),      # Arbitrary vowel replacement
        ("abebe", "adebe"),      # Non-equivalent consonant
        ("girma", "tarma"),      # Different root
    ],
)
def test_no_global_vowel_or_consonant_merging(token_a: str, token_b: str):
    """Names differing by arbitrary vowels or consonants MUST NOT match."""
    is_eq, reason = is_approved_token_variation(token_a, token_b)
    assert is_eq is False
    assert reason is None


# ---------------------------------------------------------------------------
# Multi-Token Name Variations
# ---------------------------------------------------------------------------


def test_approved_name_variation_multi_token():
    """Multi-token citizen names match when tokens are exact or approved variations."""
    is_eq, method, rules = is_approved_name_variation("Abebe Bikila", "Abbebe Biqila")
    assert is_eq is True
    assert method == "approved_variation"
    assert len(rules) >= 1

    is_eq2, method2, rules2 = is_approved_name_variation("Wolde Selassie Hailu", "Welde Silassie Haylu")
    assert is_eq2 is True
    assert method2 == "approved_variation"
    assert len(rules2) >= 2


def test_exact_name_variation():
    """Identical names return exact without applied variation rules."""
    is_eq, method, rules = is_approved_name_variation("Abebe Bikila", "abebe bikila")
    assert is_eq is True
    assert method == "exact"
    assert rules == []


def test_name_order_preservation():
    """Transposed patronymic tokens MUST NOT match (preserves given, father, grandfather)."""
    is_eq, method, _ = is_approved_name_variation("Abebe Bikila", "Bikila Abebe")
    assert is_eq is False
    assert method is None


def test_name_token_count_strictness():
    """Missing or added tokens MUST NOT match (no silent dropping or truncating)."""
    is_eq_short, _, _ = is_approved_name_variation("Abebe Bikila", "Abebe")
    assert is_eq_short is False

    is_eq_long, _, _ = is_approved_name_variation("Abebe Bikila", "Abebe Bikila Welde")
    assert is_eq_long is False


# ---------------------------------------------------------------------------
# Cross-Script Transliteration + Variation Tests
# ---------------------------------------------------------------------------


def test_cross_script_exact_transliteration():
    """Ethiopic script to Latin transliteration produces approved match."""
    is_eq, method, rules = is_approved_name_variation("አበበ ቢቂላ", "Abebe Bikila")
    assert is_eq is True
    assert method == "transliteration"


def test_cross_script_transliteration_plus_variation():
    """Ethiopic script with geminated/alternative Latin spelling produces approved_variation."""
    is_eq, method, rules = is_approved_name_variation("አበበ ቢቂላ", "Abbebe Biqila")
    assert is_eq is True
    assert method in ("approved_variation", "transliteration")


# ---------------------------------------------------------------------------
# compare_names Integration Tests
# ---------------------------------------------------------------------------


def test_compare_names_profile_behavior():
    """compare_names respects PROFILE_STRICT vs PROFILE_ETHIOPIAN_NAME_V1."""
    # Strict profile requires exact normalized match
    outcome_strict, reason_strict = compare_names(
        "Abebe Bikila",
        "Abbebe Biqila",
        matching_profile=PROFILE_STRICT,
    )
    assert outcome_strict is False
    assert reason_strict == "name_mismatch"

    # ethiopian_name_v1 approves reviewed variation
    outcome_eth, reason_eth = compare_names(
        "Abebe Bikila",
        "Abbebe Biqila",
        matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
    )
    assert outcome_eth is True
    assert reason_eth is None

    # ethiopian_name_v1 rejects arbitrary differences
    outcome_diff, reason_diff = compare_names(
        "Abebe Bikila",
        "Ababa Bikila",
        matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
    )
    assert outcome_diff is False
    assert reason_diff in ("name_mismatch", "conflicting_given_name")


# ---------------------------------------------------------------------------
# DetailsMatchingService End-to-End Evaluation Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_service_evaluate_ethiopian_name_v1_approved_equivalent():
    """DetailsMatchingService sets approved_equivalent status and approved_variation method."""
    store = MemoryExpectedDetailsStore()
    service = DetailsMatchingService(
        store=store,
        default_profile=PROFILE_STRICT,
        allowed_profiles=[PROFILE_STRICT, PROFILE_ETHIOPIAN_NAME_V1],
    )
    ctx = CallerContext(tenant_id="t1", principal_id="backend_service", scopes=["verification:create"])

    sub_res = await service.submit_expected_details(
        application_user_ref="usr_var_1",
        purpose="kyc",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
            language="am",
        ),
        context=ctx,
    )
    # Provider returns variation spelling
    claims = {"name": "Abbebe Biqila"}

    result = await service.evaluate_details_for_request(
        request_id="req_var_1",
        claims=claims,
        expected_details_ref=sub_res.expected_details_ref,
        application_user_ref="usr_var_1",
        purpose="kyc",
    )

    assert result.matching_status == "matched"
    assert result.matches[MATCH_FIELD_FULL_NAME] is True
    assert result.name_match_status == NAME_MATCH_APPROVED_EQUIVALENT
    assert result.name_match_method == METHOD_APPROVED_VARIATION
    assert result.matching_profile == PROFILE_ETHIOPIAN_NAME_V1


@pytest.mark.asyncio
async def test_service_evaluate_ethiopian_name_v1_exact():
    """Exact match under ethiopian_name_v1 retains exact status and exact_normalized method."""
    store = MemoryExpectedDetailsStore()
    service = DetailsMatchingService(
        store=store,
        default_profile=PROFILE_STRICT,
        allowed_profiles=[PROFILE_STRICT, PROFILE_ETHIOPIAN_NAME_V1],
    )
    ctx = CallerContext(tenant_id="t1", principal_id="backend_service", scopes=["verification:create"])

    sub_res = await service.submit_expected_details(
        application_user_ref="usr_exact_1",
        purpose="kyc",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
        ),
        context=ctx,
    )

    claims = {"name": "abebe   bikila"}

    result = await service.evaluate_details_for_request(
        request_id="req_exact_1",
        claims=claims,
        expected_details_ref=sub_res.expected_details_ref,
        application_user_ref="usr_exact_1",
        purpose="kyc",
    )

    assert result.matching_status == "matched"
    assert result.matches[MATCH_FIELD_FULL_NAME] is True
    assert result.name_match_status == NAME_MATCH_EXACT
    assert result.name_match_method == METHOD_EXACT_NORMALIZED


@pytest.mark.asyncio
async def test_service_evaluate_strict_rejects_variations():
    """Default strict profile rejects variation spellings with mismatch."""
    store = MemoryExpectedDetailsStore()
    service = DetailsMatchingService(
        store=store,
        default_profile=PROFILE_STRICT,
        allowed_profiles=[PROFILE_STRICT, PROFILE_ETHIOPIAN_NAME_V1],
    )
    ctx = CallerContext(tenant_id="t1", principal_id="backend_service", scopes=["verification:create"])

    sub_res = await service.submit_expected_details(
        application_user_ref="usr_strict_1",
        purpose="kyc",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            matching_profile=PROFILE_STRICT,
        ),
        context=ctx,
    )

    claims = {"name": "Abbebe Biqila"}

    result = await service.evaluate_details_for_request(
        request_id="req_strict_1",
        claims=claims,
        expected_details_ref=sub_res.expected_details_ref,
        application_user_ref="usr_strict_1",
        purpose="kyc",
    )

    assert result.matching_status == "mismatched"
    assert result.matches[MATCH_FIELD_FULL_NAME] is False
    assert result.name_match_status == NAME_MATCH_MISMATCH
    assert result.matching_profile == PROFILE_STRICT


def test_get_approved_variants_for_token():
    """get_approved_variants_for_token retrieves all reviewed variants."""
    variants = get_approved_variants_for_token("abebe")
    assert "abebe" in variants
    assert "abbebe" in variants

    empty = get_approved_variants_for_token("")
    assert empty == set()
