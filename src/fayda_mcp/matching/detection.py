"""Input script detection, character validation, and control/invisible character review flagging.

Per guide5 Task 03:
- Identify Ethiopic, Latin, and mixed text.
- Flag unsupported characters (e.g. digits, emojis, non-supported scripts like Cyrillic/Arabic).
- Flag invisible and control characters (zero-width spaces, joiners, BOMs, C0/C1 control codes).
- Provide machine-readable review reasons for downstream matching policy (Task 06 / 09).
"""

from enum import Enum
import re
from typing import Any, Dict, List, Literal, Optional, Sequence, Set
import unicodedata
from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Script Types & Constants
# ---------------------------------------------------------------------------

DETECTED_SCRIPT_ETHIOPIC: Literal["ethiopic"] = "ethiopic"
DETECTED_SCRIPT_LATIN: Literal["latin"] = "latin"
DETECTED_SCRIPT_MIXED: Literal["mixed"] = "mixed"
DETECTED_SCRIPT_UNKNOWN: Literal["unknown"] = "unknown"

DetectedScript = Literal["ethiopic", "latin", "mixed", "unknown"]

SUPPORTED_DETECTED_SCRIPTS: tuple[str, ...] = (
    DETECTED_SCRIPT_ETHIOPIC,
    DETECTED_SCRIPT_LATIN,
    DETECTED_SCRIPT_MIXED,
    DETECTED_SCRIPT_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Review Reason Codes
# ---------------------------------------------------------------------------

REVIEW_REASON_UNSUPPORTED_CHARACTERS: str = "unsupported_characters"
REVIEW_REASON_INVISIBLE_OR_CONTROL_CHARACTERS: str = "invisible_control_characters"
REVIEW_REASON_MIXED_SCRIPT: str = "mixed_script"
REVIEW_REASON_UNKNOWN_SCRIPT: str = "unknown_script"
REVIEW_REASON_DIGITS_IN_NAME: str = "digits_in_name"
REVIEW_REASON_EMPTY_INPUT: str = "empty_input"

# ---------------------------------------------------------------------------
# Permitted Punctuation & Separator Characters
# ---------------------------------------------------------------------------

# Common transliteration glottals/ejectives: ASCII apostrophe, right/left single quotes, modifier apostrophes
PERMITTED_APOSTROPHES: Set[str] = {
    "'",  # U+0027 APOSTROPHE
    "’",  # U+2019 RIGHT SINGLE QUOTATION MARK
    "‘",  # U+2018 LEFT SINGLE QUOTATION MARK
    "ʻ",  # U+02BB MODIFIER LETTER TURNED COMMA
    "ʼ",  # U+02BC MODIFIER LETTER APOSTROPHE
    "`",  # U+0060 GRAVE ACCENT
}

# Permitted hyphens / dashes:
PERMITTED_HYPHENS: Set[str] = {
    "-",  # U+002D HYPHEN-MINUS
    "‐",  # U+2010 HYPHEN
    "‑",  # U+2011 NON-BREAKING HYPHEN
    "–",  # U+2013 EN DASH
}

# Permitted dots (e.g. for initials)
PERMITTED_DOTS: Set[str] = {
    ".",  # U+002E FULL STOP
}

# Ethiopic word separators & punctuation:
PERMITTED_ETHIOPIC_PUNCTUATION: Set[str] = {
    "፡",  # U+1361 ETHIOPIC WORDSPACE
    "።",  # U+1362 ETHIOPIC FULL STOP
    "፣",  # U+1363 ETHIOPIC COMMA
    "፤",  # U+1364 ETHIOPIC SEMICOLON
    "፥",  # U+1365 ETHIOPIC COLON
    "፦",  # U+1366 ETHIOPIC PREFACE COLON
}

# Known invisible / format characters that must be flagged for review
SUSPICIOUS_INVISIBLE_CODEPOINTS: Set[int] = {
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0x200D,  # ZERO WIDTH JOINER
    0x2060,  # WORD JOINER
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE (BOM)
    0x00AD,  # SOFT HYPHEN
    0x200E,  # LEFT-TO-RIGHT MARK
    0x200F,  # RIGHT-TO-LEFT MARK
    0x202A,  # LEFT-TO-RIGHT EMBEDDING
    0x202B,  # RIGHT-TO-LEFT EMBEDDING
    0x202C,  # POP DIRECTIONAL FORMATTING
    0x202D,  # LEFT-TO-RIGHT OVERRIDE
    0x202E,  # RIGHT-TO-LEFT OVERRIDE
    0x2066,  # LEFT-TO-RIGHT ISOLATE
    0x2067,  # RIGHT-TO-LEFT ISOLATE
    0x2068,  # FIRST STRONG ISOLATE
    0x2069,  # POP DIRECTIONAL ISOLATE
}


# ---------------------------------------------------------------------------
# Character Classifier Helpers
# ---------------------------------------------------------------------------


def is_ethiopic_char(ch: str) -> bool:
    """Return True if character belongs to Ethiopic Unicode script."""
    if not ch:
        return False
    cp = ord(ch)
    # Ethiopic syllable and punctuation blocks:
    # U+1200 - U+137F : Ethiopic
    # U+1380 - U+139F : Ethiopic Supplement
    # U+2D80 - U+2DDF : Ethiopic Extended
    # U+AB00 - U+AB2F : Ethiopic Extended-A
    if (
        (0x1200 <= cp <= 0x137F)
        or (0x1380 <= cp <= 0x139F)
        or (0x2D80 <= cp <= 0x2DDF)
        or (0xAB00 <= cp <= 0xAB2F)
    ):
        return True
    try:
        name = unicodedata.name(ch, "")
        return name.startswith("ETHIOPIC ")
    except Exception:
        return False


def is_latin_char(ch: str) -> bool:
    """Return True if character belongs to Latin script."""
    if not ch:
        return False
    cp = ord(ch)
    # Basic Latin ASCII letters:
    if (0x0041 <= cp <= 0x005A) or (0x0061 <= cp <= 0x007A):
        return True
    # Latin-1 Supplement letters:
    if (0x00C0 <= cp <= 0x00D6) or (0x00D8 <= cp <= 0x00F6) or (0x00F8 <= cp <= 0x00FF):
        return True
    # Latin Extended-A, Extended-B, and Extended Additional:
    if (0x0100 <= cp <= 0x024F) or (0x1E00 <= cp <= 0x1EFF):
        return True
    try:
        name = unicodedata.name(ch, "")
        return name.startswith("LATIN ")
    except Exception:
        return False


def is_control_or_invisible(ch: str) -> bool:
    """Return True if character is a control code or invisible/formatting character."""
    if not ch:
        return False
    cp = ord(ch)
    if cp in SUSPICIOUS_INVISIBLE_CODEPOINTS:
        return True

    # Standard ASCII control characters (C0: 0x00-0x1F, except normal space, and DEL 0x7F)
    # and C1 control characters (0x80-0x9F)
    if (0x00 <= cp <= 0x1F and ch not in (" ", "\t", "\n", "\r")) or (0x7F <= cp <= 0x9F):
        return True

    # Unicode Category: 'Cc' (Control), 'Cf' (Format), 'Cs' (Surrogate), 'Co' (Private Use), 'Cn' (Unassigned)
    cat = unicodedata.category(ch)
    if cat in ("Cc", "Cf", "Cs", "Co", "Cn"):
        # Allow standard space characters
        if cp in (0x0020, 0x00A0):
            return False
        return True

    return False


def is_permitted_punctuation(ch: str) -> bool:
    """Return True if character is a permitted punctuation mark in citizen names."""
    return (
        ch in PERMITTED_APOSTROPHES
        or ch in PERMITTED_HYPHENS
        or ch in PERMITTED_DOTS
        or ch in PERMITTED_ETHIOPIC_PUNCTUATION
    )


def is_whitespace_char(ch: str) -> bool:
    """Return True if character is a standard whitespace character."""
    return ch in (" ", "\t", "\n", "\r", "\u00a0")


# ---------------------------------------------------------------------------
# Detection Result Schema
# ---------------------------------------------------------------------------


class InputDetectionResult(BaseModel):
    """Result of script detection, character validation, and invisible/control flagging."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    script: DetectedScript = Field(
        ...,
        description="Detected script type: 'ethiopic', 'latin', 'mixed', or 'unknown'",
    )
    is_supported: bool = Field(
        ...,
        description="True if input contains only supported Ethiopic or Latin characters without control/invisible chars",
    )
    requires_review: bool = Field(
        ...,
        description="True if unsupported characters, mixed scripts, or control/invisible characters were detected",
    )
    review_reasons: List[str] = Field(
        default_factory=list,
        description="Safe machine-readable review reason codes",
    )
    has_ethiopic: bool = Field(
        default=False,
        description="Whether input contains at least one Ethiopic character",
    )
    has_latin: bool = Field(
        default=False,
        description="Whether input contains at least one Latin character",
    )
    has_unsupported_chars: bool = Field(
        default=False,
        description="Whether input contains characters outside permitted Latin, Ethiopic, and approved punctuation",
    )
    has_control_or_invisible_chars: bool = Field(
        default=False,
        description="Whether input contains suspicious invisible or control characters",
    )
    unsupported_chars: List[str] = Field(
        default_factory=list,
        description="List of distinct unsupported characters found in input",
    )
    control_or_invisible_chars: List[str] = Field(
        default_factory=list,
        description="List of distinct control/invisible characters found in input (formatted as Unicode hex)",
    )


# ---------------------------------------------------------------------------
# Detector Core Function
# ---------------------------------------------------------------------------


def detect_input_script(text: Optional[str]) -> InputDetectionResult:
    """Detect script and validate characters in a name string.

    Per guide5 Task 03:
    - Identifies Ethiopic, Latin, and mixed script text.
    - Flags unsupported characters (digits, emojis, foreign scripts).
    - Flags invisible and control characters.
    - Sets requires_review=True whenever anomalies or mixed scripts are detected.

    Args:
        text: Raw or normalized citizen name string.

    Returns:
        InputDetectionResult with detected script, review flags, and reasons.
    """
    if text is None:
        return InputDetectionResult(
            script=DETECTED_SCRIPT_UNKNOWN,
            is_supported=False,
            requires_review=True,
            review_reasons=[REVIEW_REASON_EMPTY_INPUT],
        )

    s = str(text)
    if not s.strip():
        return InputDetectionResult(
            script=DETECTED_SCRIPT_UNKNOWN,
            is_supported=False,
            requires_review=True,
            review_reasons=[REVIEW_REASON_EMPTY_INPUT],
        )

    has_ethiopic = False
    has_latin = False
    has_digits = False
    unsupported_chars_set: Set[str] = set()
    control_chars_set: Set[str] = set()

    for ch in s:
        # 1. Check for invisible or control characters
        if is_control_or_invisible(ch):
            control_chars_set.add(f"U+{ord(ch):04X}")
            continue

        # 2. Check for whitespace or permitted punctuation
        if is_whitespace_char(ch) or is_permitted_punctuation(ch):
            continue

        # 3. Check for digits
        if ch.isdigit():
            has_digits = True
            unsupported_chars_set.add(ch)
            continue

        # 4. Check for Ethiopic
        if is_ethiopic_char(ch):
            has_ethiopic = True
            continue

        # 5. Check for Latin
        if is_latin_char(ch):
            has_latin = True
            continue

        # 6. Any other character is unsupported (emojis, foreign alphabets, math symbols)
        unsupported_chars_set.add(ch)

    # Determine script
    if has_ethiopic and has_latin:
        script: DetectedScript = DETECTED_SCRIPT_MIXED
    elif has_ethiopic:
        script = DETECTED_SCRIPT_ETHIOPIC
    elif has_latin:
        script = DETECTED_SCRIPT_LATIN
    else:
        script = DETECTED_SCRIPT_UNKNOWN

    has_unsupported = bool(unsupported_chars_set) or has_digits
    has_control_invisible = bool(control_chars_set)

    # Build review reasons
    review_reasons: List[str] = []
    if has_control_invisible:
        review_reasons.append(REVIEW_REASON_INVISIBLE_OR_CONTROL_CHARACTERS)
    if has_digits:
        review_reasons.append(REVIEW_REASON_DIGITS_IN_NAME)
    if unsupported_chars_set and not (has_digits and len(unsupported_chars_set) == sum(1 for c in unsupported_chars_set if c.isdigit())):
        review_reasons.append(REVIEW_REASON_UNSUPPORTED_CHARACTERS)
    elif unsupported_chars_set and REVIEW_REASON_UNSUPPORTED_CHARACTERS not in review_reasons:
        review_reasons.append(REVIEW_REASON_UNSUPPORTED_CHARACTERS)
    if script == DETECTED_SCRIPT_MIXED:
        review_reasons.append(REVIEW_REASON_MIXED_SCRIPT)
    if script == DETECTED_SCRIPT_UNKNOWN and not has_unsupported:
        review_reasons.append(REVIEW_REASON_UNKNOWN_SCRIPT)

    requires_review = (
        has_control_invisible
        or has_unsupported
        or (script == DETECTED_SCRIPT_MIXED)
        or (script == DETECTED_SCRIPT_UNKNOWN)
    )

    is_supported = (
        not has_control_invisible
        and not has_unsupported
        and script in (DETECTED_SCRIPT_ETHIOPIC, DETECTED_SCRIPT_LATIN)
    )

    return InputDetectionResult(
        script=script,
        is_supported=is_supported,
        requires_review=requires_review,
        review_reasons=review_reasons,
        has_ethiopic=has_ethiopic,
        has_latin=has_latin,
        has_unsupported_chars=has_unsupported,
        has_control_or_invisible_chars=has_control_invisible,
        unsupported_chars=sorted(list(unsupported_chars_set)),
        control_or_invisible_chars=sorted(list(control_chars_set)),
    )
