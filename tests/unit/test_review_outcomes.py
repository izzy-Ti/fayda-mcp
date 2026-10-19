"""Unit tests for review and mismatch outcomes (guide5 Task 09).

Verifies:
- Phonetic-only agreement requires review (matches.full_name=None, name_match_status="review_required", method="phonetic").
- Missing components (e.g. 2 tokens vs 3 tokens) require review.
- Initials in name require review when consistent, mismatch when conflicting.
- Conflicting components and transpositions require mismatch.
- Never approve from a single shared token.
"""

import pytest

from fayda_mcp.matching.normalization import compare_names
from fayda_mcp.matching.profiles import (
    METHOD_APPROVED_VARIATION,
    METHOD_EXACT_NORMALIZED,
    METHOD_PHONETIC,
    METHOD_TRANSLITERATION,
    NAME_MATCH_APPROVED_EQUIVALENT,
    NAME_MATCH_EXACT,
    NAME_MATCH_MISMATCH,
    NAME_MATCH_REVIEW_REQUIRED,
    NAME_MATCH_UNAVAILABLE,
    PROFILE_ETHIOPIAN_NAME_V1,
    PROFILE_STRICT,
)
from fayda_mcp.matching.review import (
    REASON_INITIALS_IN_NAME,
    REASON_PHONETIC_ONLY_AGREEMENT,
    REVIEW_SPEC_VERSION,
    evaluate_review_outcomes,
    is_initial_token,
    matches_initial,
)
from fayda_mcp.matching.schemas import ExpectedDetails, ExpectedDetailsSubmission
from fayda_mcp.matching.service import DetailsMatchingService
from fayda_mcp.matching.storage import MemoryExpectedDetailsStore
from fayda_mcp.matching.structure import (
    REASON_CONFLICTING_COMPONENTS,
    REASON_CONFLICTING_FATHER_NAME,
    REASON_CONFLICTING_GIVEN_NAME,
    REASON_MISSING_COMPONENT,
    REASON_SINGLE_TOKEN_SHARED_ONLY,
    REASON_TOKEN_COUNT_MISMATCH,
    REASON_TRANSPOSED_COMPONENTS,
)


class TestInitialsHelper:
    """Tests for initial token detection and matching."""

    def test_is_initial_token(self):
        assert is_initial_token("A") is True
        assert is_initial_token("A.") is True
        assert is_initial_token("b") is True
        assert is_initial_token("B.") is True
        assert is_initial_token("Abebe") is False
        assert is_initial_token("") is False
        assert is_initial_token("1") is False

    def test_matches_initial(self):
        assert matches_initial("A.", "Abebe") is True
        assert matches_initial("a", "abebe") is True
        assert matches_initial("B.", "Bikila") is True
        assert matches_initial("K.", "Abebe") is False
        assert matches_initial("A.", "Bikila") is False


class TestReviewOutcomesEvaluation:
    """Direct unit tests for evaluate_review_outcomes."""

    def test_exact_agreement(self):
        res = evaluate_review_outcomes("Abebe Bikila", "Abebe Bikila")
        assert res.status == NAME_MATCH_EXACT
        assert res.method == METHOD_EXACT_NORMALIZED
        assert res.matches_full_name is True

    def test_approved_variation_agreement(self):
        res = evaluate_review_outcomes("Haile Bikila", "Hayle Bikila")
        assert res.status == NAME_MATCH_APPROVED_EQUIVALENT
        assert res.method == METHOD_APPROVED_VARIATION
        assert res.matches_full_name is True

    def test_cross_script_transliteration_agreement(self):
        res = evaluate_review_outcomes("አበበ ቢቂላ", "Abebe Bikila")
        assert res.status == NAME_MATCH_APPROVED_EQUIVALENT
        assert res.method == METHOD_TRANSLITERATION
        assert res.matches_full_name is True

    def test_phonetic_only_agreement_requires_review(self):
        # 'Abebe Bekile' vs 'Abebe Bekele': given name matches approved,
        # but father's name Bekile/Bekele has phonetic agreement without approved variation.
        res = evaluate_review_outcomes("Abebe Bekile", "Abebe Bekele")
        assert res.status == NAME_MATCH_REVIEW_REQUIRED
        assert res.method == METHOD_PHONETIC
        assert res.reason == REASON_PHONETIC_ONLY_AGREEMENT
        assert res.is_phonetic_only is True
        assert res.matches_full_name is None

    def test_missing_component_requires_review(self):
        # 2 tokens vs 3 tokens with matching prefix
        res = evaluate_review_outcomes("Abebe Bikila", "Abebe Bikila Desta")
        assert res.status == NAME_MATCH_REVIEW_REQUIRED
        assert res.reason == REASON_MISSING_COMPONENT
        assert res.has_missing_component is True
        assert res.matches_full_name is None

    def test_missing_component_with_different_prefix_is_mismatch(self):
        res = evaluate_review_outcomes("Abebe Bikila", "Kenenisa Desta Haile")
        assert res.status == NAME_MATCH_MISMATCH
        assert res.reason == REASON_TOKEN_COUNT_MISMATCH
        assert res.matches_full_name is False

    def test_consistent_initials_require_review(self):
        # 'A. Bikila' vs 'Abebe Bikila'
        res = evaluate_review_outcomes("A. Bikila", "Abebe Bikila")
        assert res.status == NAME_MATCH_REVIEW_REQUIRED
        assert res.reason == REASON_INITIALS_IN_NAME
        assert res.has_initials is True
        assert res.matches_full_name is None

        # 'Abebe B.' vs 'Abebe Bikila'
        res2 = evaluate_review_outcomes("Abebe B.", "Abebe Bikila")
        assert res2.status == NAME_MATCH_REVIEW_REQUIRED
        assert res2.reason == REASON_INITIALS_IN_NAME
        assert res2.matches_full_name is None

    def test_conflicting_initials_is_mismatch(self):
        # 'K. Bikila' vs 'Abebe Bikila'
        res = evaluate_review_outcomes("K. Bikila", "Abebe Bikila")
        assert res.status == NAME_MATCH_MISMATCH
        assert res.matches_full_name is False

        # 'A. Bikila' vs 'Abebe Desta'
        res2 = evaluate_review_outcomes("A. Bikila", "Abebe Desta")
        assert res2.status == NAME_MATCH_MISMATCH
        assert res2.matches_full_name is False

    def test_transposed_components_is_mismatch(self):
        # 'Abebe Bikila' vs 'Bikila Abebe'
        res = evaluate_review_outcomes("Abebe Bikila", "Bikila Abebe")
        assert res.status == NAME_MATCH_MISMATCH
        assert res.reason == REASON_TRANSPOSED_COMPONENTS
        assert res.is_transposed is True
        assert res.matches_full_name is False

    def test_never_approve_from_single_shared_token(self):
        # Sharing father's name only (different given names)
        res_shared_father = evaluate_review_outcomes("Abebe Bikila", "Kenenisa Bikila")
        assert res_shared_father.status == NAME_MATCH_MISMATCH
        assert res_shared_father.reason == REASON_CONFLICTING_GIVEN_NAME
        assert res_shared_father.matches_full_name is False

        # Sharing given name only (different father names)
        res_shared_given = evaluate_review_outcomes("Abebe Bikila", "Abebe Desta")
        assert res_shared_given.status == NAME_MATCH_MISMATCH
        assert res_shared_given.reason == REASON_CONFLICTING_FATHER_NAME
        assert res_shared_given.matches_full_name is False

    def test_missing_input_is_unavailable(self):
        res = evaluate_review_outcomes(None, "Abebe Bikila")
        assert res.status == NAME_MATCH_UNAVAILABLE
        assert res.matches_full_name is None


class TestCompareNamesIntegration:
    """Integration tests with compare_names under PROFILE_ETHIOPIAN_NAME_V1."""

    def test_phonetic_only_returns_none_and_reason(self):
        outcome, reason = compare_names(
            "Abebe Bekile",
            "Abebe Bekele",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
        )
        assert outcome is None
        assert reason == REASON_PHONETIC_ONLY_AGREEMENT

    def test_initials_returns_none_and_reason(self):
        outcome, reason = compare_names(
            "A. Bikila",
            "Abebe Bikila",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
        )
        assert outcome is None
        assert reason == REASON_INITIALS_IN_NAME

    def test_missing_component_returns_none_and_reason(self):
        outcome, reason = compare_names(
            "Abebe Bikila",
            "Abebe Bikila Desta",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
        )
        assert outcome is None
        assert reason == REASON_MISSING_COMPONENT

    def test_single_shared_token_returns_false_and_reason(self):
        outcome, reason = compare_names(
            "Abebe Bikila",
            "Kenenisa Bikila",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
        )
        assert outcome is False
        assert reason == REASON_CONFLICTING_GIVEN_NAME

    def test_transposition_returns_false_and_reason(self):
        outcome, reason = compare_names(
            "Abebe Bikila",
            "Bikila Abebe",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
        )
        assert outcome is False
        assert reason == REASON_TRANSPOSED_COMPONENTS

    def test_strict_profile_still_requires_exact_normalized(self):
        outcome, reason = compare_names(
            "Abeba Bikila",
            "Abebe Bikila",
            matching_profile=PROFILE_STRICT,
        )
        assert outcome is False
        assert reason == "name_mismatch"


@pytest.mark.asyncio
class TestDetailsMatchingServiceReviewOutcomes:
    """Tests for DetailsMatchingService handling of review outcomes."""

    async def test_phonetic_agreement_sets_review_required_and_method_phonetic(self):
        store = MemoryExpectedDetailsStore()
        service = DetailsMatchingService(store=store)

        resp = await service.submit_expected_details(
            application_user_ref="usr_phonetic_01",
            purpose="kyc",
            expected_details=ExpectedDetails(
                full_name="Abebe Bekile",
                matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
                language="am",
            ),
        )

        await service.bind_expected_details(
            ref=resp.expected_details_ref,
            request_id="req_phonetic_01",
            application_user_ref="usr_phonetic_01",
            purpose="kyc",
        )

        res = await service.evaluate_details_for_request(
            request_id="req_phonetic_01",
            claims={"name": "Abebe Bekele"},
        )

        # Phonetic-only review keeps matches.full_name=null (None)
        assert res.matches["full_name"] is None
        assert res.name_match_status == NAME_MATCH_REVIEW_REQUIRED
        assert res.name_match_method == METHOD_PHONETIC
        assert res.name_match_reason == REASON_PHONETIC_ONLY_AGREEMENT
        assert res.matching_status == "unavailable"

    async def test_initials_sets_review_required(self):
        store = MemoryExpectedDetailsStore()
        service = DetailsMatchingService(store=store)

        resp = await service.submit_expected_details(
            application_user_ref="usr_initials_01",
            purpose="kyc",
            expected_details=ExpectedDetails(
                full_name="A. Bikila",
                matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
                language="am",
            ),
        )

        await service.bind_expected_details(
            ref=resp.expected_details_ref,
            request_id="req_initials_01",
            application_user_ref="usr_initials_01",
            purpose="kyc",
        )

        res = await service.evaluate_details_for_request(
            request_id="req_initials_01",
            claims={"name": "Abebe Bikila"},
        )

        assert res.matches["full_name"] is None
        assert res.name_match_status == NAME_MATCH_REVIEW_REQUIRED
        assert res.name_match_reason == REASON_INITIALS_IN_NAME
        assert res.matching_status == "unavailable"

    async def test_single_shared_token_sets_mismatch(self):
        store = MemoryExpectedDetailsStore()
        service = DetailsMatchingService(store=store)

        resp = await service.submit_expected_details(
            application_user_ref="usr_shared_token_01",
            purpose="kyc",
            expected_details=ExpectedDetails(
                full_name="Abebe Bikila",
                matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
                language="am",
            ),
        )

        await service.bind_expected_details(
            ref=resp.expected_details_ref,
            request_id="req_shared_token_01",
            application_user_ref="usr_shared_token_01",
            purpose="kyc",
        )

        res = await service.evaluate_details_for_request(
            request_id="req_shared_token_01",
            claims={"name": "Kenenisa Bikila"},
        )

        assert res.matches["full_name"] is False
        assert res.name_match_status == NAME_MATCH_MISMATCH
        assert res.name_match_reason == REASON_CONFLICTING_GIVEN_NAME
        assert res.matching_status == "mismatched"
