"""Matching profiles, specifications, supported languages, and host opt-in controls.

Per guide5 specification:
- Strict matching is the default profile (exact normalization, no transliteration/phonetic fuzziness).
- Host must explicitly opt in to 'ethiopian_name_v1', never the agent.
- Supported languages start with Amharic ('am') plus Latin spelling variants ('en').
- Distinct outcomes: exact, approved_equivalent, review_required, mismatch, unavailable.
"""

from typing import Dict, List, Literal, Optional, Sequence
from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Profile Names & Constants
# ---------------------------------------------------------------------------

PROFILE_STRICT: Literal["strict"] = "strict"
PROFILE_ETHIOPIAN_NAME_V1: Literal["ethiopian_name_v1"] = "ethiopian_name_v1"

DEFAULT_MATCHING_PROFILE: str = PROFILE_STRICT
SUPPORTED_MATCHING_PROFILES: tuple[str, ...] = (
    PROFILE_STRICT,
    PROFILE_ETHIOPIAN_NAME_V1,
)

MatchingProfile = Literal["strict", "ethiopian_name_v1"]

# ---------------------------------------------------------------------------
# Supported Languages
# ---------------------------------------------------------------------------

LANGUAGE_AMHARIC: Literal["am"] = "am"
LANGUAGE_ENGLISH: Literal["en"] = "en"

DEFAULT_NAME_MATCHING_LANGUAGE: str = LANGUAGE_AMHARIC
SUPPORTED_NAME_MATCHING_LANGUAGES: tuple[str, ...] = (
    LANGUAGE_AMHARIC,
    LANGUAGE_ENGLISH,
)

NameMatchingLanguage = Literal["am", "en"]

# ---------------------------------------------------------------------------
# Outcome Types & Statuses
# ---------------------------------------------------------------------------

NAME_MATCH_EXACT: Literal["exact"] = "exact"
NAME_MATCH_APPROVED_EQUIVALENT: Literal["approved_equivalent"] = "approved_equivalent"
NAME_MATCH_REVIEW_REQUIRED: Literal["review_required"] = "review_required"
NAME_MATCH_MISMATCH: Literal["mismatch"] = "mismatch"
NAME_MATCH_UNAVAILABLE: Literal["unavailable"] = "unavailable"

SUPPORTED_NAME_MATCH_STATUSES: tuple[str, ...] = (
    NAME_MATCH_EXACT,
    NAME_MATCH_APPROVED_EQUIVALENT,
    NAME_MATCH_REVIEW_REQUIRED,
    NAME_MATCH_MISMATCH,
    NAME_MATCH_UNAVAILABLE,
)

NameMatchStatus = Literal[
    "exact",
    "approved_equivalent",
    "review_required",
    "mismatch",
    "unavailable",
]

# ---------------------------------------------------------------------------
# Comparison Methods
# ---------------------------------------------------------------------------

METHOD_EXACT_NORMALIZED: Literal["exact_normalized"] = "exact_normalized"
METHOD_TRANSLITERATION: Literal["transliteration"] = "transliteration"
METHOD_PHONETIC: Literal["phonetic"] = "phonetic"
METHOD_APPROVED_VARIATION: Literal["approved_variation"] = "approved_variation"

NameMatchMethod = Literal[
    "exact_normalized",
    "transliteration",
    "phonetic",
    "approved_variation",
]

# ---------------------------------------------------------------------------
# Profile Specification Model
# ---------------------------------------------------------------------------


class MatchingProfileSpec(BaseModel):
    """Specification defining capabilities, constraints, and requirements of a matching profile."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., description="Unique profile identifier ('strict', 'ethiopian_name_v1')")
    version: str = Field(..., description="Profile algorithm specification version")
    description: str = Field(..., description="Human-readable description of profile semantics")
    default_language: str = Field(
        default=DEFAULT_NAME_MATCHING_LANGUAGE,
        description="Default language code for script evaluation",
    )
    supported_languages: List[str] = Field(
        default_factory=lambda: list(SUPPORTED_NAME_MATCHING_LANGUAGES),
        description="Languages supported by this profile",
    )
    allows_transliteration: bool = Field(
        default=False,
        description="Whether cross-script Ethiopic-to-Latin transliteration is enabled",
    )
    allows_phonetics: bool = Field(
        default=False,
        description="Whether phonetic comparison is enabled",
    )
    allows_spelling_variants: bool = Field(
        default=False,
        description="Whether approved spelling variation rules are applied",
    )
    requires_explicit_host_opt_in: bool = Field(
        default=False,
        description="Whether this profile requires explicit host backend opt-in (never agent selected)",
    )


# ---------------------------------------------------------------------------
# Profile Registry
# ---------------------------------------------------------------------------

PROFILES: Dict[str, MatchingProfileSpec] = {
    PROFILE_STRICT: MatchingProfileSpec(
        name=PROFILE_STRICT,
        version="details-v1",
        description=(
            "Default exact normalization matching (Unicode NFC, Latin case-folding, whitespace collapse). "
            "No cross-script transliteration, approved variations, or phonetic fuzziness."
        ),
        default_language=LANGUAGE_AMHARIC,
        supported_languages=list(SUPPORTED_NAME_MATCHING_LANGUAGES),
        allows_transliteration=False,
        allows_phonetics=False,
        allows_spelling_variants=False,
        requires_explicit_host_opt_in=False,
    ),
    PROFILE_ETHIOPIAN_NAME_V1: MatchingProfileSpec(
        name=PROFILE_ETHIOPIAN_NAME_V1,
        version="ethiopian_name_v1",
        description=(
            "Ethiopian name matching extension with Amharic-Latin transliteration, approved variations, "
            "and phonetic comparison. Requires explicit host opt-in; never selectable by agents."
        ),
        default_language=LANGUAGE_AMHARIC,
        supported_languages=list(SUPPORTED_NAME_MATCHING_LANGUAGES),
        allows_transliteration=True,
        allows_phonetics=True,
        allows_spelling_variants=True,
        requires_explicit_host_opt_in=True,
    ),
}


def get_profile_spec(profile_name: str) -> MatchingProfileSpec:
    """Retrieve the MatchingProfileSpec for a profile name.

    Raises:
        ValueError: If profile_name is not registered.
    """
    clean_name = str(profile_name).strip().lower() if profile_name else ""
    spec = PROFILES.get(clean_name)
    if spec is None:
        raise ValueError(
            f"Unsupported matching profile '{profile_name}'. Supported profiles: {list(PROFILES.keys())}"
        )
    return spec


def validate_matching_profile(
    profile: Optional[str],
    allowed_profiles: Optional[Sequence[str]] = None,
) -> str:
    """Validate a requested matching profile against supported and host-allowed profiles.

    Args:
        profile: Requested profile name (e.g. 'strict', 'ethiopian_name_v1').
        allowed_profiles: Optional host-configured subset of permitted profiles.

    Returns:
        Canonical validated profile name string.

    Raises:
        ValueError: If profile is invalid or not permitted.
    """
    if profile is None or not str(profile).strip():
        return DEFAULT_MATCHING_PROFILE

    clean_profile = str(profile).strip().lower()
    if clean_profile not in SUPPORTED_MATCHING_PROFILES:
        raise ValueError(
            f"Unsupported matching profile '{profile}'. Supported: {list(SUPPORTED_MATCHING_PROFILES)}"
        )

    if allowed_profiles is not None:
        clean_allowed = {str(p).strip().lower() for p in allowed_profiles}
        if clean_profile not in clean_allowed:
            raise ValueError(
                f"Matching profile '{profile}' is not permitted by host configuration. "
                f"Permitted profiles: {list(allowed_profiles)}"
            )

    return clean_profile


def validate_matching_language(
    language: Optional[str],
    allowed_languages: Optional[Sequence[str]] = None,
) -> Optional[str]:
    """Validate a requested language code against supported and host-allowed languages.

    Args:
        language: Language code (e.g. 'am', 'en').
        allowed_languages: Optional host-configured subset of permitted languages.

    Returns:
        Canonical language code or None.

    Raises:
        ValueError: If language is invalid or not permitted.
    """
    if language is None or not str(language).strip():
        return None

    clean_lang = str(language).strip().lower()
    if clean_lang not in SUPPORTED_NAME_MATCHING_LANGUAGES:
        raise ValueError(
            f"Unsupported name matching language '{language}'. Supported: {list(SUPPORTED_NAME_MATCHING_LANGUAGES)}"
        )

    if allowed_languages is not None:
        clean_allowed = {str(l).strip().lower() for l in allowed_languages}
        if clean_lang not in clean_allowed:
            raise ValueError(
                f"Name matching language '{language}' is not permitted by host configuration. "
                f"Permitted languages: {list(allowed_languages)}"
            )

    return clean_lang
