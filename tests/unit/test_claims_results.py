"""Unit tests for Task B3: Claims normalization, checks evaluation, and result privacy."""

from datetime import date
from typing import Any, Dict
import pytest
from pydantic import ValidationError

from fayda_mcp.claims import calculate_age, evaluate_checks
from fayda_mcp.oidc.mapping import (
    DISALLOWED_PROVIDER_FIELDS,
    extract_localized_string,
    normalize_birthdate,
    normalize_claims,
)
from fayda_mcp.schemas import VerificationResult


class TestClaimsNormalization:
    """Tests for normalizing provider fields and stripping sensitive/biometric data."""

    def test_normalize_birthdate_formats(self) -> None:
        """Verify varied date-of-birth formats normalize to standard ISO YYYY-MM-DD."""
        assert normalize_birthdate("1995-05-12") == "1995-05-12"
        assert normalize_birthdate("1995/05/12") == "1995-05-12"
        assert normalize_birthdate("12-05-1995") == "1995-05-12"
        assert normalize_birthdate("12/05/1995") == "1995-05-12"

    def test_normalize_birthdate_localized_dict(self) -> None:
        """Verify dict-wrapped localized dates are properly parsed."""
        assert normalize_birthdate({"@value": "1990-01-15", "@language": "en"}) == "1990-01-15"
        assert normalize_birthdate({"default": "1990/01/15"}) == "1990-01-15"

    def test_normalize_birthdate_invalid_calendar_or_syntax(self) -> None:
        """Verify invalid dates return None."""
        assert normalize_birthdate("not-a-date") is None
        assert normalize_birthdate("") is None
        assert normalize_birthdate(None) is None
        assert normalize_birthdate("2000-02-31") is None  # Invalid calendar day
        assert normalize_birthdate("1850-01-01") is None  # Out of range year

    def test_extract_localized_string(self) -> None:
        """Verify extraction of plain strings from multilingual dictionaries."""
        assert extract_localized_string("Plain Name") == "Plain Name"
        assert extract_localized_string({"@value": "Abebe Bikila", "@language": "amh"}) == "Abebe Bikila"
        assert extract_localized_string({"en": "Abebe", "am": "አበበ"}) == "Abebe"
        assert extract_localized_string({"am": "አበበ"}) == "አበበ"
        assert extract_localized_string(12345) is None

    def test_normalize_claims_purges_disallowed_and_biometrics(self) -> None:
        """Verify all tokens, secrets, national ID, and raw biometric data are purged."""
        raw_provider_claims: Dict[str, Any] = {
            "sub": "urn:fayda:user:12345",
            "birthdate": "1998-04-20",
            "name": {"@value": "Almaz Ayana", "@language": "en"},
            # Disallowed biometrics and credentials:
            "biometrics": "RAW_FINGERPRINT_TEMPLATE_BASE64",
            "biometric_data": {"finger": "MINUTIAE_DATA"},
            "fingerprint": "BASE64_DATA",
            "iris": "BASE64_IRIS_IMAGE",
            "photo": "BASE64_FACE_JPEG",
            "access_token": "secret_oauth_access_token",
            "id_token": "secret_jwt_id_token",
            "refresh_token": "secret_refresh_token",
            "client_secret": "client_secret_xyz",
            "private_key": "private_key_pem",
            "fayda_number": "FIN-987654321",
            "national_id": "ETH-12345678",
        }

        normalized = normalize_claims(raw_provider_claims)

        # Permitted normalized fields exist
        assert normalized["sub"] == "urn:fayda:user:12345"
        assert normalized["birthdate"] == "1998-04-20"
        assert normalized["name"] == "Almaz Ayana"

        # Disallowed fields must be completely stripped
        for field in DISALLOWED_PROVIDER_FIELDS:
            assert field not in normalized


class TestChecksEvaluation:
    """Tests for evaluating permitted checks while strictly distinguishing unavailable from false."""

    def test_calculate_age(self) -> None:
        """Verify accurate age calculation relative to specific reference dates."""
        ref_date = date(2026, 10, 6)

        # Exactly 18 years old today
        assert calculate_age("2008-10-06", as_of=ref_date) == 18
        # Day before 18th birthday -> age 17
        assert calculate_age("2008-10-07", as_of=ref_date) == 17
        # Day after 18th birthday -> age 18
        assert calculate_age("2008-10-05", as_of=ref_date) == 18

        # Future birth date returns None
        assert calculate_age("2030-01-01", as_of=ref_date) is None

        # Missing or invalid birthdate returns None
        assert calculate_age("", as_of=ref_date) is None
        assert calculate_age("invalid-date", as_of=ref_date) is None

    def test_missing_dob_returns_unavailable_not_false(self) -> None:
        """Acceptance requirement: Missing DOB returns 'unavailable', never False or True."""
        claims_without_dob = {"sub": "user_123"}
        outcomes = evaluate_checks(
            claims=claims_without_dob,
            requested_checks=["age_over_18", "age_over_21", "identity_verified"],
        )

        assert outcomes["age_over_18"] == "unavailable"
        assert outcomes["age_over_21"] == "unavailable"
        assert outcomes["identity_verified"] is True

        # Crucial distinction: outcomes["age_over_18"] must NOT be False
        assert outcomes["age_over_18"] is not False
        assert outcomes["age_over_18"] is not True

    def test_malformed_dob_returns_unavailable(self) -> None:
        """Malformed DOB returns 'unavailable'."""
        claims_bad_dob = {"sub": "user_123", "birthdate": "invalid-format"}
        outcomes = evaluate_checks(
            claims=claims_bad_dob,
            requested_checks=["age_over_18"],
        )
        assert outcomes["age_over_18"] == "unavailable"

    def test_underage_citizen_returns_false_not_unavailable(self) -> None:
        """Citizen under 18 with valid DOB returns boolean False (distinguished from unavailable)."""
        ref_date = date(2026, 10, 6)
        claims_underage = {"sub": "user_minor", "birthdate": "2012-05-10"}  # 14 years old
        outcomes = evaluate_checks(
            claims=claims_underage,
            requested_checks=["age_over_18", "identity_verified"],
            as_of=ref_date,
        )

        assert outcomes["age_over_18"] is False
        assert outcomes["age_over_18"] != "unavailable"
        assert outcomes["identity_verified"] is True

    def test_adult_citizen_returns_true(self) -> None:
        """Citizen over 18 with valid DOB returns boolean True."""
        ref_date = date(2026, 10, 6)
        claims_adult = {"sub": "user_adult", "birthdate": "1990-01-01"}  # 36 years old
        outcomes = evaluate_checks(
            claims=claims_adult,
            requested_checks=["age_over_18", "age_over_21", "identity_verified"],
            as_of=ref_date,
        )

        assert outcomes["age_over_18"] is True
        assert outcomes["age_over_21"] is True
        assert outcomes["identity_verified"] is True

    def test_identity_verified_missing_sub_returns_unavailable(self) -> None:
        """Missing or empty sub returns 'unavailable' for identity_verified."""
        outcomes = evaluate_checks(claims={}, requested_checks=["identity_verified"])
        assert outcomes["identity_verified"] == "unavailable"

        outcomes_empty = evaluate_checks(claims={"sub": "  "}, requested_checks=["identity_verified"])
        assert outcomes_empty["identity_verified"] == "unavailable"

    def test_unknown_check_returns_unavailable(self) -> None:
        """Any unmapped check returns 'unavailable'."""
        outcomes = evaluate_checks(
            claims={"sub": "user_123", "birthdate": "1990-01-01"},
            requested_checks=["residency_status", "custom_check"],
        )
        assert outcomes["residency_status"] == "unavailable"
        assert outcomes["custom_check"] == "unavailable"


class TestMcpResultPrivacy:
    """Acceptance requirement: No tokens, raw biometric data, or unnecessary demographics enter MCP results."""

    def test_verification_result_forbids_demographics_and_tokens(self) -> None:
        """VerificationResult schema must strictly forbid demographic payloads or tokens."""
        # Valid minimal result
        valid_res = VerificationResult(
            request_id="req_123",
            status="verified",
            checks={"identity_verified": True, "age_over_18": "unavailable"},
        )
        assert valid_res.request_id == "req_123"
        assert valid_res.checks["age_over_18"] == "unavailable"

        # Attempting to add unnecessary demographic fields must fail at schema level
        with pytest.raises(ValidationError):
            VerificationResult(
                request_id="req_123",
                status="verified",
                name="Abebe Bikila",  # Disallowed demographic
            )  # type: ignore

        with pytest.raises(ValidationError):
            VerificationResult(
                request_id="req_123",
                status="verified",
                birthdate="1990-01-01",  # Disallowed raw DOB
            )  # type: ignore

        # Attempting to add tokens or biometrics must fail at schema level
        with pytest.raises(ValidationError):
            VerificationResult(
                request_id="req_123",
                status="verified",
                access_token="secret_token",  # Disallowed token
            )  # type: ignore

        with pytest.raises(ValidationError):
            VerificationResult(
                request_id="req_123",
                status="verified",
                biometrics="raw_face_image",  # Disallowed biometric data
            )  # type: ignore

    def test_serialized_result_contains_only_minimal_predicates(self) -> None:
        """Serialized MCP result contains only boolean predicates and verification metadata."""
        result = VerificationResult(
            request_id="req_abc456",
            status="verified",
            checks={
                "identity_verified": True,
                "age_over_18": False,
                "age_over_21": "unavailable",
            },
            verified_at="2026-10-06T12:00:00Z",
            policy_version="1.0.0",
        )
        dumped = result.model_dump()

        # Check expected allowed keys
        assert set(dumped.keys()) == {
            "request_id",
            "status",
            "checks",
            "reasons",
            "verified_at",
            "expires_at",
            "evidence_ref",
            "policy_version",
        }

        # Check values
        assert dumped["checks"]["identity_verified"] is True
        assert dumped["checks"]["age_over_18"] is False
        assert dumped["checks"]["age_over_21"] == "unavailable"

        # Explicitly verify no demographic or token keys exist
        for forbidden in [
            "name",
            "birthdate",
            "dob",
            "gender",
            "biometrics",
            "fingerprint",
            "national_id",
            "access_token",
            "id_token",
        ]:
            assert forbidden not in dumped
