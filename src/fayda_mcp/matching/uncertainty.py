"""Uncertainty handling for Ethiopian name matching (guide5 Task 06).

Per guide5 specification:
- Return 'unavailable' or 'review_required' for:
  1. Unknown or unsupported language.
  2. Unsupported characters, digits, invisible/control characters, or mixed script.
  3. Ambiguous transliteration.
- Preserve distinct outcomes: exact, approved_equivalent, review_required, mismatch, unavailable.
- For review_required or unavailable outcomes, matches.full_name is set to None (null).
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.matching.detection import (
    DETECTED_SCRIPT_ETHIOPIC,
    DETECTED_SCRIPT_LATIN,
    DETECTED_SCRIPT_MIXED,
    DETECTED_SCRIPT_UNKNOWN,
    REVIEW_REASON_DIGITS_IN_NAME,
    REVIEW_REASON_INVISIBLE_OR_CONTROL_CHARACTERS,
    REVIEW_REASON_MIXED_SCRIPT,
    REVIEW_REASON_UNKNOWN_SCRIPT,
    REVIEW_REASON_UNSUPPORTED_CHARACTERS,
    InputDetectionResult,
)
from fayda_mcp.matching.normalization import NormalizedName, normalize_name_safely
from fayda_mcp.matching.profiles import (
    NAME_MATCH_REVIEW_REQUIRED,
    NAME_MATCH_UNAVAILABLE,
    PROFILE_ETHIOPIAN_NAME_V1,
    PROFILE_STRICT,
    SUPPORTED_NAME_MATCHING_LANGUAGES,
)
from fayda_mcp.matching.transliteration import transliterate_amharic_to_latin

# ---------------------------------------------------------------------------
# Constants & Reasons
# ---------------------------------------------------------------------------

UNCERTAINTY_SPEC_VERSION: str = "uncertainty-v1"

REASON_UNKNOWN_LANGUAGE: str = "unknown_language"
REASON_UNSUPPORTED_LANGUAGE: str = "unsupported_language"
REASON_UNSUPPORTED_CHARACTERS: str = REVIEW_REASON_UNSUPPORTED_CHARACTERS
REASON_INVISIBLE_OR_CONTROL_CHARACTERS: str = REVIEW_REASON_INVISIBLE_OR_CONTROL_CHARACTERS
REASON_AMBIGUOUS_TRANSLITERATION: str = "ambiguous_transliteration"
REASON_MIXED_SCRIPT: str = REVIEW_REASON_MIXED_SCRIPT
REASON_UNKNOWN_SCRIPT: str = REVIEW_REASON_UNKNOWN_SCRIPT
REASON_DIGITS_IN_NAME: str = REVIEW_REASON_DIGITS_IN_NAME

SUPPORTED_LANGUAGES_LOWER: Set[str] = {lang.lower() for lang in SUPPORTED_NAME_MATCHING_LANGUAGES}


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


class UncertaintyEvaluation(BaseModel):
    """Result of uncertainty evaluation on expected and provider names."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    has_uncertainty: bool = Field(..., description="True if uncertainty was detected")
    status: Optional[str] = Field(
        default=None,
        description="Outcome status if uncertain: 'review_required' or 'unavailable'",
    )
    reason: Optional[str] = Field(
        default=None,
        description="Safe machine-readable reason code for uncertainty",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Safe diagnostic details (no raw PII)",
    )


# ---------------------------------------------------------------------------
# Individual Uncertainty Checkers
# ---------------------------------------------------------------------------


def check_language_uncertainty(language: Optional[str]) -> Optional[Tuple[str, str]]:
    """Check if the provided language is unknown or unsupported.

    Returns:
        Tuple of (status, reason) if uncertain, else None.
    """
    if language is None:
        return None

    clean_lang = str(language).strip().lower()
    if not clean_lang:
        return None

    if clean_lang not in SUPPORTED_LANGUAGES_LOWER:
        # Unknown/unsupported language is unavailable for ethiopian_name_v1 rules
        return NAME_MATCH_UNAVAILABLE, REASON_UNKNOWN_LANGUAGE

    return None


def check_character_uncertainty(detection: Optional[InputDetectionResult]) -> Optional[Tuple[str, str]]:
    """Check if input text has unsupported, invisible, mixed, or control characters.

    Returns:
        Tuple of (status, reason) if uncertain, else None.
    """
    if detection is None:
        return None

    if detection.has_control_or_invisible_chars:
        return NAME_MATCH_REVIEW_REQUIRED, REASON_INVISIBLE_OR_CONTROL_CHARACTERS

    if detection.script == DETECTED_SCRIPT_UNKNOWN:
        return NAME_MATCH_UNAVAILABLE, REASON_UNKNOWN_SCRIPT

    if detection.script == DETECTED_SCRIPT_MIXED:
        return NAME_MATCH_REVIEW_REQUIRED, REASON_MIXED_SCRIPT

    if REVIEW_REASON_DIGITS_IN_NAME in detection.review_reasons:
        return NAME_MATCH_REVIEW_REQUIRED, REASON_DIGITS_IN_NAME

    if detection.has_unsupported_chars:
        return NAME_MATCH_REVIEW_REQUIRED, REASON_UNSUPPORTED_CHARACTERS

    return None


def check_transliteration_uncertainty(
    name_a: str,
    detection_a: InputDetectionResult,
    name_b: str,
    detection_b: InputDetectionResult,
) -> Optional[Tuple[str, str]]:
    """Check for ambiguous transliteration between Ethiopic and Latin names.

    Triggers review_required if:
    - Ethiopic name contains unmapped characters or symbols that cannot be transliterated.
    - Transliteration produces incomplete token mappings.

    Returns:
        Tuple of (status, reason) if uncertain, else None.
    """
    # Only applicable when one is Ethiopic and one is Latin
    script_a = detection_a.script
    script_b = detection_b.script

    is_cross_script = (
        (script_a == DETECTED_SCRIPT_ETHIOPIC and script_b == DETECTED_SCRIPT_LATIN)
        or (script_a == DETECTED_SCRIPT_LATIN and script_b == DETECTED_SCRIPT_ETHIOPIC)
    )

    if not is_cross_script:
        return None

    ethiopic_name = name_a if script_a == DETECTED_SCRIPT_ETHIOPIC else name_b
    trans_res = transliterate_amharic_to_latin(ethiopic_name)

    if trans_res is None:
        return NAME_MATCH_REVIEW_REQUIRED, REASON_AMBIGUOUS_TRANSLITERATION

    if not trans_res.is_fully_transliterated or len(trans_res.unmapped_characters) > 0:
        return NAME_MATCH_REVIEW_REQUIRED, REASON_AMBIGUOUS_TRANSLITERATION

    return None


# ---------------------------------------------------------------------------
# Master Uncertainty Evaluator
# ---------------------------------------------------------------------------


def evaluate_name_uncertainty(
    expected_name: Optional[str],
    provider_name: Optional[str],
    language: Optional[str] = None,
    matching_profile: str = PROFILE_ETHIOPIAN_NAME_V1,
) -> UncertaintyEvaluation:
    """Evaluate whether name matching involves uncertainty requiring review or unavailable status.

    Evaluates:
    1. Language check: unknown or unsupported language returns 'unavailable'.
    2. Character check: control/invisible, unsupported characters, digits, or mixed script
       return 'review_required' (or 'unavailable' for unknown script).
    3. Ambiguous transliteration: unmapped characters or ambiguous cross-script mappings
       return 'review_required'.

    Args:
        expected_name: Expected citizen name string.
        provider_name: Provider citizen name string.
        language: Language code if specified ('am', 'en').
        matching_profile: Active matching profile ('strict' or 'ethiopian_name_v1').

    Returns:
        UncertaintyEvaluation instance.
    """
    # 1. Language uncertainty check
    lang_issue = check_language_uncertainty(language)
    if lang_issue is not None:
        status, reason = lang_issue
        return UncertaintyEvaluation(
            has_uncertainty=True,
            status=status,
            reason=reason,
            details={"language": language},
        )

    if expected_name is None or provider_name is None:
        return UncertaintyEvaluation(has_uncertainty=False)

    norm_exp = normalize_name_safely(expected_name)
    norm_prov = normalize_name_safely(provider_name)

    if norm_exp is None or norm_prov is None:
        return UncertaintyEvaluation(has_uncertainty=False)

    # 2. Input character detection checks on expected name
    exp_char_issue = check_character_uncertainty(norm_exp.detection)
    if exp_char_issue is not None:
        status, reason = exp_char_issue
        return UncertaintyEvaluation(
            has_uncertainty=True,
            status=status,
            reason=reason,
            details={"field": "expected_name", "detection": norm_exp.detection.model_dump()},
        )

    # Input character detection checks on provider name
    prov_char_issue = check_character_uncertainty(norm_prov.detection)
    if prov_char_issue is not None:
        status, reason = prov_char_issue
        return UncertaintyEvaluation(
            has_uncertainty=True,
            status=status,
            reason=reason,
            details={"field": "provider_name", "detection": norm_prov.detection.model_dump()},
        )

    # 3. Ambiguous transliteration check for cross-script comparison
    trans_issue = check_transliteration_uncertainty(
        norm_exp.normalized,
        norm_exp.detection,
        norm_prov.normalized,
        norm_prov.detection,
    )
    if trans_issue is not None:
        status, reason = trans_issue
        return UncertaintyEvaluation(
            has_uncertainty=True,
            status=status,
            reason=reason,
            details={"type": "cross_script_transliteration"},
        )

    return UncertaintyEvaluation(has_uncertainty=False)
