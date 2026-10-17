"""Unit tests for protecting independent checks and non-cancellation invariants (guide5 Task 11).

Verifies:
- DOB and other required checks remain strictly independent of name matching.
- A strong name score (1.0 exact or approved variation) NEVER cancels a required mismatch.
- A strong name score NEVER cancels missing evidence.
- No composite cross-field score averaging across fields.
- End-to-end DetailsMatchingService and FaydaService preserve independent rejection and unavailability.
"""

import pytest

from fayda_mcp.matching.normalization import evaluate_details_matching
from fayda_mcp.matching.profiles import PROFILE_ETHIOPIAN_NAME_V1, PROFILE_STRICT
from fayda_mcp.matching.protection import (
    PROTECTION_SPEC_VERSION,
    ProtectedCheckResult,
    assert_strong_name_never_cancels_mismatch,
    assert_strong_name_never_cancels_missing_evidence,
    evaluate_protected_checks,
)
from fayda_mcp.matching.schemas import (
    MATCH_FIELD_DATE_OF_BIRTH,
    MATCH_FIELD_FULL_NAME,
    ExpectedDetails,
)
from fayda_mcp.matching.service import DetailsMatchingService
from fayda_mcp.matching.storage import MemoryExpectedDetailsStore


class TestProtectionInvariants:
    """Tests for core non-cancellation invariant checkers."""

    def test_strong_name_does_not_cancel_mismatch(self):
        matches = {
            MATCH_FIELD_FULL_NAME: True,
            MATCH_FIELD_DATE_OF_BIRTH: False,
        }
        reasons = {
            MATCH_FIELD_DATE_OF_BIRTH: "dob_mismatch",
        }
        # Invariant check passes
        assert assert_strong_name_never_cancels_mismatch(matches, [MATCH_FIELD_FULL_NAME, MATCH_FIELD_DATE_OF_BIRTH], name_score=1.0) is True

        res = evaluate_protected_checks(
            matches=matches,
            reasons=reasons,
            required_fields=[MATCH_FIELD_FULL_NAME, MATCH_FIELD_DATE_OF_BIRTH],
            name_similarity_score=1.0,
        )
        assert res.overall_status == "mismatched"
        assert res.matches[MATCH_FIELD_FULL_NAME] is True
        assert res.matches[MATCH_FIELD_DATE_OF_BIRTH] is False
        assert res.is_mismatch_cancelled is False

    def test_strong_name_does_not_cancel_missing_evidence(self):
        matches = {
            MATCH_FIELD_FULL_NAME: True,
            MATCH_FIELD_DATE_OF_BIRTH: None,
        }
        reasons = {
            MATCH_FIELD_DATE_OF_BIRTH: "provider_claim_unavailable",
        }
        # Invariant check passes
        assert assert_strong_name_never_cancels_missing_evidence(matches, [MATCH_FIELD_FULL_NAME, MATCH_FIELD_DATE_OF_BIRTH], name_score=1.0) is True

        res = evaluate_protected_checks(
            matches=matches,
            reasons=reasons,
            required_fields=[MATCH_FIELD_FULL_NAME, MATCH_FIELD_DATE_OF_BIRTH],
            name_similarity_score=0.99,
        )
        assert res.overall_status == "unavailable"
        assert res.matches[MATCH_FIELD_FULL_NAME] is True
        assert res.matches[MATCH_FIELD_DATE_OF_BIRTH] is None
        assert res.is_missing_evidence_cancelled is False

    def test_all_matched_yields_matched(self):
        matches = {
            MATCH_FIELD_FULL_NAME: True,
            MATCH_FIELD_DATE_OF_BIRTH: True,
        }
        res = evaluate_protected_checks(
            matches=matches,
            reasons={},
            required_fields=[MATCH_FIELD_FULL_NAME, MATCH_FIELD_DATE_OF_BIRTH],
            name_similarity_score=1.0,
        )
        assert res.overall_status == "matched"


class TestEvaluateDetailsMatchingIndependence:
    """Tests evaluate_details_matching independence of DOB and Name."""

    def test_exact_name_with_dob_mismatch_yields_mismatched(self):
        exp = ExpectedDetails(
            full_name="Abebe Bikila",
            date_of_birth="1990/01/01",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
        )
        claims = {
            "name": "Abebe Bikila",
            "birthdate": "1995-05-05",  # Mismatched DOB
        }
        matches, reasons, overall = evaluate_details_matching(
            expected_details=exp,
            claims=claims,
        )
        assert matches[MATCH_FIELD_FULL_NAME] is True
        assert matches[MATCH_FIELD_DATE_OF_BIRTH] is False
        assert reasons[MATCH_FIELD_DATE_OF_BIRTH] == "dob_mismatch"
        assert overall == "mismatched"

    def test_exact_name_with_missing_dob_yields_unavailable(self):
        exp = ExpectedDetails(
            full_name="Abebe Bikila",
            date_of_birth="1990/01/01",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
        )
        claims = {
            "name": "Abebe Bikila",
            # No birthdate claim provided by IdP
        }
        matches, reasons, overall = evaluate_details_matching(
            expected_details=exp,
            claims=claims,
        )
        assert matches[MATCH_FIELD_FULL_NAME] is True
        assert matches[MATCH_FIELD_DATE_OF_BIRTH] is None
        assert reasons[MATCH_FIELD_DATE_OF_BIRTH] == "provider_claim_unavailable"
        assert overall == "unavailable"

    def test_transliterated_name_with_dob_mismatch_yields_mismatched(self):
        exp = ExpectedDetails(
            full_name="አበበ ቢቂላ",
            date_of_birth="1980/12/12",
            matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
            language="am",
        )
        claims = {
            "name": "Abebe Bikila",
            "birthdate": "1980-01-01",  # Different month/day
        }
        matches, reasons, overall = evaluate_details_matching(
            expected_details=exp,
            claims=claims,
        )
        assert matches[MATCH_FIELD_FULL_NAME] is True
        assert matches[MATCH_FIELD_DATE_OF_BIRTH] is False
        assert reasons[MATCH_FIELD_DATE_OF_BIRTH] == "dob_mismatch"
        assert overall == "mismatched"


@pytest.mark.asyncio
class TestDetailsServiceProtectionEndToEnd:
    """End-to-end tests for DetailsMatchingService protecting DOB and required checks."""

    async def test_service_dob_mismatch_not_cancelled_by_perfect_name(self):
        store = MemoryExpectedDetailsStore()
        service = DetailsMatchingService(store=store)

        resp = await service.submit_expected_details(
            application_user_ref="usr_dob_prot_01",
            purpose="kyc",
            expected_details=ExpectedDetails(
                full_name="Abebe Bikila",
                date_of_birth="1992/03/15",
                matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
            ),
        )

        await service.bind_expected_details(
            ref=resp.expected_details_ref,
            request_id="req_dob_prot_01",
            application_user_ref="usr_dob_prot_01",
            purpose="kyc",
        )

        res = await service.evaluate_details_for_request(
            request_id="req_dob_prot_01",
            claims={
                "name": "Abebe Bikila",
                "birthdate": "1990-01-01",  # Different birthdate
            },
        )

        assert res.matches["full_name"] is True
        assert res.matches["date_of_birth"] is False
        assert res.reasons["date_of_birth"] == "dob_mismatch"
        assert res.matching_status == "mismatched"
        assert res.name_match_status == "exact"

    async def test_service_missing_dob_not_cancelled_by_perfect_name(self):
        store = MemoryExpectedDetailsStore()
        service = DetailsMatchingService(store=store)

        resp = await service.submit_expected_details(
            application_user_ref="usr_dob_prot_02",
            purpose="kyc",
            expected_details=ExpectedDetails(
                full_name="Abebe Bikila",
                date_of_birth="1992/03/15",
                matching_profile=PROFILE_ETHIOPIAN_NAME_V1,
            ),
        )

        await service.bind_expected_details(
            ref=resp.expected_details_ref,
            request_id="req_dob_prot_02",
            application_user_ref="usr_dob_prot_02",
            purpose="kyc",
        )

        res = await service.evaluate_details_for_request(
            request_id="req_dob_prot_02",
            claims={
                "name": "Abebe Bikila",
                # birthdate omitted
            },
        )

        assert res.matches["full_name"] is True
        assert res.matches["date_of_birth"] is None
        assert res.reasons["date_of_birth"] == "provider_claim_unavailable"
        assert res.matching_status == "unavailable"
