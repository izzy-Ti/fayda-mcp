"""Unit tests for uncertainty handling in Ethiopian name matching (guide5 Task 06).

Verifies:
- Return 'unavailable' or 'review_required' for unknown language, unsupported characters,
  or ambiguous transliteration.
- Distinct outcomes: exact, approved_equivalent, review_required, mismatch, unavailable.
- For review_required or unavailable outcomes, matches.full_name is set to None (null).
"""

import pytest

from fayda_mcp.context import CallerContext
from fayda_mcp.matching.detection import detect_input_script
from fayda_mcp.matching.normalization import compare_names, evaluate_details_matching
from fayda_mcp.matching.profiles import (
    NAME_MATCH_APPROVED_EQUIVALENT,
    NAME_MATCH_EXACT,
    NAME_MATCH_MISMATCH,
    NAME_MATCH_REVIEW_REQUIRED,
    NAME_MATCH_UNAVAILABLE,
    PROFILE_ETHIOPIAN_NAME_V1,
    PROFILE_STRICT,
)
from fayda_mcp.matching.schemas import (
    MATCH_FIELD_FULL_NAME,
    ExpectedDetails,
)
from fayda_mcp.matching.service import DetailsMatchingService
from fayda_mcp.matching.storage import MemoryExpectedDetailsStore
from fayda_mcp.matching.uncertainty import (
    REASON_AMBIGUOUS_TRANSLITERATION,
    REASON_DIGITS_IN_NAME,
    REASON_INVISIBLE_OR_CONTROL_CHARACTERS,
    REASON_MIXED_SCRIPT,
    REASON_UNKNOWN_LANGUAGE,
    REASON_UNKNOWN_SCRIPT,
    REASON_UNSUPPORTED_CHARACTERS,
    UNCERTAINTY_SPEC_VERSION,
    check_character_uncertainty,
    check_language_uncertainty,
    check_transliteration_uncertainty,
    evaluate_name_uncertainty,
)


def test_uncertainty_spec_version():
    """Verify uncertainty spec version constant."""
    assert UNCERTAINTY_SPEC_VERSION == "uncertainty-v1"


# ---------------------------------------------------------------------------
# 1. Unknown / Unsupported Language Tests
# ---------------------------------------------------------------------------


def test_language_uncertainty_supported():
    """Supported languages ('am', 'en') produce no uncertainty."""
    assert check_language_uncertainty("am") is None
    assert check_language_uncertainty("en") is None
    assert check_language_uncertainty("AM") is None
    assert check_language_uncertainty("EN") is None
    assert check_language_uncertainty(None) is None


def test_language_uncertainty_unsupported():
    """Unsupported or unknown language returns unavailable with reason unknown_language."""
    res = check_language_uncertainty("ti")
    assert res is not None
    status, reason = res
    assert status == NAME_MATCH_UNAVAILABLE
    assert reason == REASON_UNKNOWN_LANGUAGE

    res_om = check_language_uncertainty("om")
    assert res_om == (NAME_MATCH_UNAVAILABLE, REASON_UNKNOWN_LANGUAGE)

    res_unknown = check_language_uncertainty("klingon")
    assert res_unknown == (NAME_MATCH_UNAVAILABLE, REASON_UNKNOWN_LANGUAGE)


# ---------------------------------------------------------------------------
# 2. Unsupported Characters Tests
# ---------------------------------------------------------------------------


def test_character_uncertainty_control_and_invisible():
    """Invisible or control characters produce review_required."""
    detection = detect_input_script("Abebe\u200b Bikila")  # Zero-width space
    res = check_character_uncertainty(detection)
    assert res is not None
    status, reason = res
    assert status == NAME_MATCH_REVIEW_REQUIRED
    assert reason == REASON_INVISIBLE_OR_CONTROL_CHARACTERS


def test_character_uncertainty_digits_in_name():
    """Digits embedded in citizen name produce review_required."""
    detection = detect_input_script("Abebe 2nd")
    res = check_character_uncertainty(detection)
    assert res is not None
    status, reason = res
    assert status == NAME_MATCH_REVIEW_REQUIRED
    assert reason == REASON_DIGITS_IN_NAME


def test_character_uncertainty_unsupported_characters():
    """Emojis or symbols in name produce review_required with unsupported_characters."""
    detection = detect_input_script("Abebe 😊 Bikila")
    res = check_character_uncertainty(detection)
    assert res is not None
    status, reason = res
    assert status == NAME_MATCH_REVIEW_REQUIRED
    assert reason == REASON_UNSUPPORTED_CHARACTERS


def test_character_uncertainty_mixed_script():
    """Mixed Ethiopic and Latin within text produces review_required with mixed_script."""
    detection = detect_input_script("Abበበ Bikila")
    res = check_character_uncertainty(detection)
    assert res is not None
    status, reason = res
    assert status == NAME_MATCH_REVIEW_REQUIRED
    assert reason == REASON_MIXED_SCRIPT


def test_character_uncertainty_unknown_script():
    """Text in an unknown script (e.g. Cyrillic) returns unavailable."""
    detection = detect_input_script("Александр")
    res = check_character_uncertainty(detection)
    assert res is not None
    status, reason = res
    assert status == NAME_MATCH_UNAVAILABLE
    assert reason == REASON_UNKNOWN_SCRIPT


# ---------------------------------------------------------------------------
# 3. Ambiguous Transliteration Tests
# ---------------------------------------------------------------------------


def test_transliteration_uncertainty_valid():
    """Standard Ethiopic to Latin transliteration has no uncertainty."""
    det_a = detect_input_script("አበበ ቢቂላ")
    det_b = detect_input_script("Abebe Bikila")
    res = check_transliteration_uncertainty("አበበ ቢቂላ", det_a, "Abebe Bikila", det_b)
    assert res is None


def test_transliteration_uncertainty_unmapped():
    """Ethiopic text containing unmapped characters produces ambiguous_transliteration review."""
    # Ethiopic numeral ፻ (100) or special Ge'ez punctuation within name
    det_a = detect_input_script("አበበ ፻ ቢቂላ")
    det_b = detect_input_script("Abebe Bikila")
    res = check_transliteration_uncertainty("አበበ ፻ ቢቂላ", det_a, "Abebe Bikila", det_b)
    assert res is not None
    status, reason = res
    assert status == NAME_MATCH_REVIEW_REQUIRED
    assert reason == REASON_AMBIGUOUS_TRANSLITERATION


# ---------------------------------------------------------------------------
# 4. Master evaluate_name_uncertainty Tests
# ---------------------------------------------------------------------------


def test_evaluate_name_uncertainty_clean_pair():
    """Clean name pair produces has_uncertainty=False."""
    eval_res = evaluate_name_uncertainty("Abebe Bikila", "Abbebe Biqila", language="am")
    assert eval_res.has_uncertainty is False
    assert eval_res.status is None
    assert eval_res.reason is None


def test_evaluate_name_uncertainty_unsupported_language():
    """Unsupported language returns unavailable."""
    eval_res = evaluate_name_uncertainty("Abebe Bikila", "Abebe Bikila", language="fr")
    assert eval_res.has_uncertainty is True
    assert eval_res.status == NAME_MATCH_UNAVAILABLE
    assert eval_res.reason == REASON_UNKNOWN_LANGUAGE


def test_evaluate_name_uncertainty_invisible_chars():
    """Invisible characters trigger review_required."""
    eval_res = evaluate_name_uncertainty("Abebe\u200b Bikila", "Abebe Bikila", language="en")
    assert eval_res.has_uncertainty is True
    assert eval_res.status == NAME_MATCH_REVIEW_REQUIRED
    assert eval_res.reason == REASON_INVISIBLE_OR_CONTROL_CHARACTERS


# ---------------------------------------------------------------------------
# 5. compare_names Integration Tests with Uncertainty
# ---------------------------------------------------------------------------


def test_compare_names_returns_none_for_uncertainty():
    """compare_names returns outcome=None and reason code when uncertainty is detected in ethiopian_name_v1."""
    # Invisible character in expected name
    outcome, reason = compare_names(
        "Abebe\u200b Bikila",
        "Abebe Bikila",
        matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
    )
    assert outcome is None
    assert reason == REASON_INVISIBLE_OR_CONTROL_CHARACTERS

    # Unsupported character (emoji)
    outcome_emoji, reason_emoji = compare_names(
        "Abebe Bikila",
        "Abebe 🌟 Bikila",
        matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
    )
    assert outcome_emoji is None
    assert reason_emoji == REASON_UNSUPPORTED_CHARACTERS

    # Mixed script within token
    outcome_mixed, reason_mixed = compare_names(
        "Abበበ Bikila",
        "Abebe Bikila",
        matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
    )
    assert outcome_mixed is None
    assert reason_mixed == REASON_MIXED_SCRIPT

    # Unsupported language
    outcome_lang, reason_lang = compare_names(
        "Abebe Bikila",
        "Abebe Bikila",
        matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
        language="unsupported_lang",
    )
    assert outcome_lang is None
    assert reason_lang == REASON_UNKNOWN_LANGUAGE


# ---------------------------------------------------------------------------
# 6. DetailsMatchingService End-to-End Uncertainty Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_service_returns_review_required_for_invisible_characters():
    """Service returns review_required with matches.full_name=None when control/invisible chars present."""
    store = MemoryExpectedDetailsStore()
    service = DetailsMatchingService(
        store=store,
        default_profile=PROFILE_STRICT,
        allowed_profiles=[PROFILE_STRICT, PROFILE_ETHIOPIAN_NAME_V1],
    )
    ctx = CallerContext(tenant_id="t1", principal_id="backend_service", scopes=["verification:create"])

    sub_res = await service.submit_expected_details(
        application_user_ref="usr_unc_1",
        purpose="kyc",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
            language="am",
        ),
        context=ctx,
    )

    # Provider returns name with zero-width space
    claims = {"name": "Abebe\u200b Bikila"}

    result = await service.evaluate_details_for_request(
        request_id="req_unc_1",
        claims=claims,
        expected_details_ref=sub_res.expected_details_ref,
        application_user_ref="usr_unc_1",
        purpose="kyc",
    )

    # Per guide5 Task 06 and 12:
    # matches.full_name MUST be None (null), name_match_status MUST be review_required
    assert result.matches[MATCH_FIELD_FULL_NAME] is None
    assert result.name_match_status == NAME_MATCH_REVIEW_REQUIRED
    assert result.name_match_reason == REASON_INVISIBLE_OR_CONTROL_CHARACTERS
    assert result.matching_status == "unavailable"


@pytest.mark.asyncio
async def test_service_returns_review_required_for_unsupported_characters():
    """Service returns review_required with matches.full_name=None when unsupported characters present."""
    store = MemoryExpectedDetailsStore()
    service = DetailsMatchingService(
        store=store,
        default_profile=PROFILE_STRICT,
        allowed_profiles=[PROFILE_STRICT, PROFILE_ETHIOPIAN_NAME_V1],
    )
    ctx = CallerContext(tenant_id="t1", principal_id="backend_service", scopes=["verification:create"])

    sub_res = await service.submit_expected_details(
        application_user_ref="usr_unc_2",
        purpose="kyc",
        expected_details=ExpectedDetails(
            full_name="Abebe Bikila",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
        ),
        context=ctx,
    )

    # Provider returns name with emojis/unsupported characters
    claims = {"name": "Abebe # Bikila"}

    result = await service.evaluate_details_for_request(
        request_id="req_unc_2",
        claims=claims,
        expected_details_ref=sub_res.expected_details_ref,
        application_user_ref="usr_unc_2",
        purpose="kyc",
    )

    assert result.matches[MATCH_FIELD_FULL_NAME] is None
    assert result.name_match_status == NAME_MATCH_REVIEW_REQUIRED
    assert result.name_match_reason == REASON_UNSUPPORTED_CHARACTERS


@pytest.mark.asyncio
async def test_service_returns_review_required_for_ambiguous_transliteration():
    """Service returns review_required with matches.full_name=None when transliteration has unmapped characters."""
    store = MemoryExpectedDetailsStore()
    service = DetailsMatchingService(
        store=store,
        default_profile=PROFILE_STRICT,
        allowed_profiles=[PROFILE_STRICT, PROFILE_ETHIOPIAN_NAME_V1],
    )
    ctx = CallerContext(tenant_id="t1", principal_id="backend_service", scopes=["verification:create"])

    sub_res = await service.submit_expected_details(
        application_user_ref="usr_unc_3",
        purpose="kyc",
        expected_details=ExpectedDetails(
            full_name="አበበ ፻ ቢቂላ",  # contains numeral ፻ that cannot be transliterated to Latin name
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
            language="am",
        ),
        context=ctx,
    )

    claims = {"name": "Abebe Bikila"}

    result = await service.evaluate_details_for_request(
        request_id="req_unc_3",
        claims=claims,
        expected_details_ref=sub_res.expected_details_ref,
        application_user_ref="usr_unc_3",
        purpose="kyc",
    )

    assert result.matches[MATCH_FIELD_FULL_NAME] is None
    assert result.name_match_status == NAME_MATCH_REVIEW_REQUIRED
    assert result.name_match_reason in (REASON_AMBIGUOUS_TRANSLITERATION, REASON_UNSUPPORTED_CHARACTERS)
