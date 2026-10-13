"""Unit tests for Task 01: Comparison schemas, expected details, tri-state outcomes, and policy versions."""

import json
import pytest
from pydantic import ValidationError

from fayda_mcp.matching.schemas import (
    DEFAULT_COMPARISON_POLICY_VERSION,
    DEFAULT_EXPECTED_DETAILS_TTL_SECONDS,
    MATCH_FIELD_DATE_OF_BIRTH,
    MATCH_FIELD_FULL_NAME,
    SUPPORTED_MATCH_FIELDS,
    DetailsAlreadyBoundError,
    DetailsCallerMismatchError,
    DetailsMatchResult,
    DetailsMatchingError,
    DetailsMatchingErrorCode,
    DetailsPurposeMismatchError,
    DetailsReferenceExpiredError,
    DetailsReferenceNotFoundError,
    DetailsUserMismatchError,
    ExpectedDetails,
    ExpectedDetailsRecord,
    ExpectedDetailsSubmission,
    ExpectedDetailsSubmissionResponse,
    StartDetailsVerificationRequest,
    StartDetailsVerificationResponse,
    compute_overall_matching_status,
)


class TestExpectedDetailsSchema:
    """Verifies expected identity details validation, calendar conventions, and DOB constraints."""

    def test_valid_expected_details_both_fields(self):
        """Allows providing both full_name and date_of_birth."""
        details = ExpectedDetails(
            full_name="Abebe Bikila",
            date_of_birth="1995/04/12",
            dob_calendar="gregorian",
        )
        assert details.full_name == "Abebe Bikila"
        assert details.date_of_birth == "1995/04/12"
        assert details.dob_calendar == "gregorian"
        assert details.required_fields == ["full_name", "date_of_birth"]

    def test_valid_expected_details_name_only(self):
        """Allows providing name only; defaults required_fields to ['full_name']."""
        details = ExpectedDetails(full_name="Almaz Ayana")
        assert details.full_name == "Almaz Ayana"
        assert details.date_of_birth is None
        assert details.required_fields == ["full_name"]

    def test_valid_expected_details_dob_only(self):
        """Allows providing DOB only; defaults required_fields to ['date_of_birth']."""
        details = ExpectedDetails(date_of_birth="2000-01-01")
        assert details.full_name is None
        assert details.date_of_birth == "2000-01-01"
        assert details.required_fields == ["date_of_birth"]

    def test_explicit_required_fields_subset(self):
        """Allows explicitly specifying required_fields subset."""
        details = ExpectedDetails(
            full_name="Haile Gebrselassie",
            date_of_birth="1973/04/18",
            required_fields=["full_name"],
        )
        assert details.required_fields == ["full_name"]

    def test_ethiopian_calendar_accepted(self):
        """Accepts Ethiopian/Ethiopic calendar names normalized to 'ethiopian'."""
        details1 = ExpectedDetails(full_name="Tirunesh Dibaba", dob_calendar="ethiopian")
        assert details1.dob_calendar == "ethiopian"

        details2 = ExpectedDetails(full_name="Tirunesh Dibaba", dob_calendar="Ethiopic")
        assert details2.dob_calendar == "ethiopian"

    def test_reject_unsupported_calendar(self):
        """Rejects unapproved calendar schemes (e.g., hijri, julian)."""
        with pytest.raises(ValidationError, match="Unsupported DOB calendar"):
            ExpectedDetails(full_name="Kenilworth", dob_calendar="hijri")

    def test_reject_empty_expected_details(self):
        """Rejects model when neither name nor DOB is provided."""
        with pytest.raises(ValidationError, match="At least one expected detail"):
            ExpectedDetails()

        with pytest.raises(ValidationError, match="At least one expected detail"):
            ExpectedDetails(full_name="", date_of_birth="")

    def test_reject_partial_date_of_birth(self):
        """Rule: Partial DOB is unavailable/disallowed in first release."""
        # Year only
        with pytest.raises(ValidationError, match="Partial or invalid date of birth rejected"):
            ExpectedDetails(full_name="Abebe", date_of_birth="1995")

        # Year and month only
        with pytest.raises(ValidationError, match="Partial or invalid date of birth rejected"):
            ExpectedDetails(full_name="Abebe", date_of_birth="1995/04")

        # Non-numeric
        with pytest.raises(ValidationError, match="Partial or invalid date of birth rejected"):
            ExpectedDetails(full_name="Abebe", date_of_birth="1995/Apr/12")

    def test_reject_unsupported_required_fields(self):
        """Rejects field names not in SUPPORTED_MATCH_FIELDS."""
        with pytest.raises(ValidationError, match="Unsupported field 'phone_number'"):
            ExpectedDetails(
                full_name="Abebe",
                required_fields=["full_name", "phone_number"],
            )

    def test_reject_required_field_without_value(self):
        """Cannot mark a field as required if no expected value was provided."""
        with pytest.raises(ValidationError, match="cannot be required without an expected value"):
            ExpectedDetails(
                full_name="Abebe",
                date_of_birth=None,
                required_fields=["date_of_birth"],
            )

    def test_reject_extra_fields(self):
        """Strictly forbids unexpected attributes (e.g. FAN or biometrics)."""
        with pytest.raises(ValidationError):
            ExpectedDetails(
                full_name="Abebe",
                fan="1234 5678 9012 3456",  # type: ignore
            )


class TestTriStateMatchingOutcomes:
    """Verifies tri-state field match logic and overall outcome computation."""

    def test_tri_state_matched_when_all_required_match(self):
        """Every required field is True -> 'matched'."""
        matches = {"full_name": True, "date_of_birth": True}
        assert compute_overall_matching_status(matches, ["full_name", "date_of_birth"]) == "matched"

        matches_single = {"full_name": True}
        assert compute_overall_matching_status(matches_single, ["full_name"]) == "matched"

    def test_tri_state_mismatched_when_any_required_fails(self):
        """If any required field evaluates to False -> 'mismatched'."""
        matches = {"full_name": True, "date_of_birth": False}
        assert compute_overall_matching_status(matches, ["full_name", "date_of_birth"]) == "mismatched"

        matches_both_false = {"full_name": False, "date_of_birth": False}
        assert compute_overall_matching_status(matches_both_false, ["full_name", "date_of_birth"]) == "mismatched"

    def test_tri_state_unavailable_when_evidence_missing(self):
        """If a required field is None (unavailable evidence) and none are False -> 'unavailable'."""
        matches = {"full_name": True, "date_of_birth": None}
        assert compute_overall_matching_status(matches, ["full_name", "date_of_birth"]) == "unavailable"

        matches_missing_key = {"full_name": True}
        assert compute_overall_matching_status(matches_missing_key, ["full_name", "date_of_birth"]) == "unavailable"

    def test_mismatched_takes_precedence_over_unavailable(self):
        """If one required field is False and another is None -> 'mismatched' takes precedence."""
        matches = {"full_name": False, "date_of_birth": None}
        assert compute_overall_matching_status(matches, ["full_name", "date_of_birth"]) == "mismatched"

    def test_optional_unmatched_field_does_not_break_matched(self):
        """If a non-required field is False/None, but all required fields are True -> 'matched'."""
        matches = {"full_name": True, "date_of_birth": False}
        assert compute_overall_matching_status(matches, required_fields=["full_name"]) == "matched"


class TestDetailsMatchResultSchema:
    """Verifies DetailsMatchResult serialization and comparison policy versioning."""

    def test_example_completed_response_serialization(self):
        """Matches the exact guide4 JSON contract."""
        result = DetailsMatchResult(
            request_id="opaque-id-123",
            verification_method="esignet",
            matching_status="matched",
            matches={"full_name": True, "date_of_birth": True},
            comparison_policy_version="details-v1",
            required_fields=["full_name", "date_of_birth"],
            checked_at="2026-10-13T07:15:00Z",
            expires_at="2026-10-13T07:30:00Z",
            identity_authenticated=True,
            evidence_ref="evi_abc987",
        )

        dumped = json.loads(result.model_dump_json())
        assert dumped["request_id"] == "opaque-id-123"
        assert dumped["verification_method"] == "esignet"
        assert dumped["matching_status"] == "matched"
        assert dumped["matches"] == {"full_name": True, "date_of_birth": True}
        assert dumped["comparison_policy_version"] == "details-v1"
        assert dumped["identity_authenticated"] is True

    def test_tri_state_null_serialization(self):
        """Null in JSON corresponds to unavailable evidence."""
        result = DetailsMatchResult(
            request_id="opaque-id-456",
            matching_status="unavailable",
            matches={"full_name": True, "date_of_birth": None},
            required_fields=["full_name", "date_of_birth"],
            reasons={"date_of_birth": "provider_claim_missing"},
        )

        dumped = json.loads(result.model_dump_json())
        assert dumped["matches"]["date_of_birth"] is None
        assert dumped["reasons"]["date_of_birth"] == "provider_claim_missing"

    def test_default_comparison_policy_version(self):
        """Default comparison policy version is 'details-v1'."""
        result = DetailsMatchResult(
            request_id="req_test",
            matching_status="pending",
        )
        assert result.comparison_policy_version == DEFAULT_COMPARISON_POLICY_VERSION
        assert result.comparison_policy_version == "details-v1"

    def test_forbid_raw_demographics_injection(self):
        """Strictly forbids adding arbitrary citizen demographic data to match result."""
        with pytest.raises(ValidationError):
            DetailsMatchResult(
                request_id="req_test",
                matching_status="matched",
                citizen_name="Abebe Bikila",  # type: ignore
            )


class TestSubmissionAndStartSchemas:
    """Verifies backend submission and MCP start schemas."""

    def test_expected_details_submission_model(self):
        """Verifies ExpectedDetailsSubmission model validation."""
        submission = ExpectedDetailsSubmission(
            application_user_ref="user_12345",
            purpose="onboarding",
            expected_details=ExpectedDetails(full_name="Abebe Bikila"),
            ttl_seconds=600,
        )
        assert submission.application_user_ref == "user_12345"
        assert submission.ttl_seconds == 600

    def test_expected_details_submission_response(self):
        """Verifies ExpectedDetailsSubmissionResponse."""
        resp = ExpectedDetailsSubmissionResponse(
            expected_details_ref="edr_01j9abc",
            expires_at="2026-10-13T07:30:00Z",
        )
        assert resp.expected_details_ref == "edr_01j9abc"

    def test_expected_details_record_binding(self):
        """Verifies ExpectedDetailsRecord model."""
        record = ExpectedDetailsRecord(
            ref="edr_test_01",
            tenant_id="tenant_bank",
            principal_id="agent_teller",
            application_user_ref="app_user_1",
            purpose="kyc",
            expected_details=ExpectedDetails(full_name="Derartu Tulu"),
            created_at="2026-10-13T07:00:00Z",
            expires_at="2026-10-13T07:15:00Z",
            bound_request_id=None,
        )
        assert record.bound_request_id is None
        assert record.expected_details.full_name == "Derartu Tulu"

    def test_start_details_verification_schemas(self):
        """Verifies StartDetailsVerificationRequest & Response models."""
        req = StartDetailsVerificationRequest(
            expected_details_ref="edr_test_01",
            purpose="onboarding",
            application_user_ref="app_user_1",
            idempotency_key="idemp_123",
        )
        assert req.expected_details_ref == "edr_test_01"

        res = StartDetailsVerificationResponse(
            request_id="vr_det_999",
            authorization_url="https://esignet.ida.fayda.et/authorize?client_id=...",
            expires_at="2026-10-13T07:20:00Z",
        )
        assert res.request_id == "vr_det_999"


class TestMatchingExceptionsHierarchy:
    """Verifies that all matching error types inherit from FaydaMCPError and expose safe error codes."""

    def test_exception_codes_and_hierarchy(self):
        err = DetailsReferenceNotFoundError("edr_missing")
        assert isinstance(err, DetailsMatchingError)
        assert err.code == DetailsMatchingErrorCode.REFERENCE_NOT_FOUND.value
        assert "edr_missing" in err.message

        safe_dict = err.to_dict()
        assert safe_dict["error"] == "matching_reference_not_found"

        expired_err = DetailsReferenceExpiredError("edr_old")
        assert expired_err.code == DetailsMatchingErrorCode.REFERENCE_EXPIRED.value

        caller_err = DetailsCallerMismatchError("edr_cross")
        assert caller_err.code == DetailsMatchingErrorCode.CALLER_MISMATCH.value

        user_err = DetailsUserMismatchError("edr_user")
        assert user_err.code == DetailsMatchingErrorCode.USER_MISMATCH.value

        purpose_err = DetailsPurposeMismatchError("edr_purp")
        assert purpose_err.code == DetailsMatchingErrorCode.PURPOSE_MISMATCH.value

        bound_err = DetailsAlreadyBoundError("edr_bound")
        assert bound_err.code == DetailsMatchingErrorCode.ALREADY_BOUND.value
