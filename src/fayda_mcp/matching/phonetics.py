"""Phonetic encoding algorithms for Ethiopian name matching (guide5 Task 08).

Per guide5 specification:
- Pure-Python Double Metaphone implementation as a baseline to evaluate.
- Ethiopian-specific phonetic adaptation addressing Fidel orthography and Latin transliteration.
- Double Metaphone is a baseline to evaluate, NOT Ethiopian-ready proof.
- Phonetic codes are kept backend-only by default.
"""

import re
from typing import Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PHONETICS_SPEC_VERSION: str = "phonetics-v1"


class PhoneticCodes(BaseModel):
    """Phonetic codes produced for a name token."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    token: str = Field(..., description="Normalized input token")
    double_metaphone_primary: str = Field(..., description="Double Metaphone primary code")
    double_metaphone_secondary: str = Field(..., description="Double Metaphone secondary code")
    ethiopian_phonetic_code: str = Field(..., description="Ethiopian-adapted phonetic code")


# ---------------------------------------------------------------------------
# Ethiopian Phonetic Encoding
# Designed specifically for Amharic orthography and Ethiopian-Latin transliteration
# (referencing arxiv:cs/0408052: Application of Double Metaphone to Amharic Orthography).
# ---------------------------------------------------------------------------


def compute_ethiopian_phonetic_code(token: str) -> str:
    """Compute an Ethiopian-adapted phonetic representation of a name token.

    Rules:
    1. Lowercase and collapse consecutive identical consonants (gemination neutralization).
    2. Normalize common Ethiopian transliteration digraphs:
       - 'sh' -> 'X' (ሸ)
       - 'ch' / 'tch' -> 'C' (ጨ / ቸ)
       - 'zh' -> 'Z' (ዠ)
       - 'ts' / 'tz' -> 'S' (ጸ / ፀ)
       - 'gn' / 'ny' -> 'N' (ኘ)
       - 'kh' / 'q' -> 'K' (ቀ / ኀ)
       - 'ph' -> 'F' (ፈ / ጰ)
    3. Normalize initial/medial Ethiopian vowel prefixes:
       - 'wol' / 'wel' -> 'WL'
       - 'wor' / 'wer' -> 'WR'
       - 'wos' / 'wes' -> 'WS'
       - 'hai' / 'hay' -> 'HY'
    4. Collapse medial epenthetic vowels (i/e) while retaining root consonants.
    5. Retain initial vowel character, but drop weak trailing vowels.
    """
    clean = token.strip().lower()
    if not clean:
        return ""

    # Remove non-alphabetical characters
    clean = re.sub(r"[^a-z]", "", clean)
    if not clean:
        return ""

    # Collapse repeated adjacent characters (neutralize Latin gemination)
    collapsed = re.sub(r"(.)\1+", r"\1", clean)

    # Prefix normalization for common Ethiopian name prefixes
    if collapsed.startswith("wol") or collapsed.startswith("wel"):
        collapsed = "wl" + collapsed[3:]
    elif collapsed.startswith("wor") or collapsed.startswith("wer"):
        collapsed = "wr" + collapsed[3:]
    elif collapsed.startswith("wos") or collapsed.startswith("wes"):
        collapsed = "ws" + collapsed[3:]
    elif collapsed.startswith("hai") or collapsed.startswith("hay"):
        collapsed = "hy" + collapsed[3:]

    # Multi-character phonetic substitutions
    s = collapsed
    s = s.replace("tch", "C")
    s = s.replace("ch", "C")
    s = s.replace("sh", "X")
    s = s.replace("zh", "Z")
    s = s.replace("ts", "S")
    s = s.replace("tz", "S")
    s = s.replace("gn", "N")
    s = s.replace("ny", "N")
    s = s.replace("ph", "F")
    s = s.replace("kh", "K")
    s = s.replace("q", "K")

    # Preserve initial character
    first_char = s[0].upper()
    rest = s[1:]

    # In rest, collapse vowel glides and weak vowels
    # Epenthetic vowel alternation: i <-> e, u <-> o
    rest = rest.replace("ou", "u").replace("ee", "i").replace("oo", "u").replace("ie", "i")
    # Drop unstressed vowels in rest while preserving consonants
    rest_consonants = re.sub(r"[aeiouy]", "", rest)

    res = first_char + rest_consonants.upper()
    # Deduplicate again after substitutions
    res = re.sub(r"(.)\1+", r"\1", res)

    return res[:8] if res else first_char


# ---------------------------------------------------------------------------
# Double Metaphone Implementation (Lawrence Philips)
# Self-contained, robust pure-Python implementation.
# ---------------------------------------------------------------------------


def compute_double_metaphone(token: str) -> Tuple[str, str]:
    """Compute primary and secondary Double Metaphone phonetic codes for a token.

    Baseline phonetic algorithm specified by guide5 Task 08.
    """
    clean = token.strip().upper()
    if not clean:
        return "", ""

    # Pad with spaces
    length = len(clean)
    last = length - 1
    pos = 0

    primary = []
    secondary = []

    # Skip initial silent letters
    if clean.startswith(("GN", "KN", "PN", "WR", "PS")):
        pos += 1

    # Initial 'X' sounds like 'S'
    if clean.startswith("X"):
        primary.append("S")
        secondary.append("S")
        pos += 1

    while pos < length:
        ch = clean[pos]

        # Vowels at start get 'A'
        if ch in ("A", "E", "I", "O", "U", "Y"):
            if pos == 0:
                primary.append("A")
                secondary.append("A")
            pos += 1
            continue

        if ch == "B":
            primary.append("P")
            secondary.append("P")
            if pos + 1 < length and clean[pos + 1] == "B":
                pos += 2
            else:
                pos += 1
            continue

        if ch == "C":
            # Various 'C' rules
            if pos + 1 < length and clean[pos + 1] == "H":
                primary.append("X")
                secondary.append("K")
                pos += 2
            elif pos + 1 < length and clean[pos + 1] in ("I", "E", "Y"):
                primary.append("S")
                secondary.append("S")
                pos += 2
            else:
                primary.append("K")
                secondary.append("K")
                if pos + 1 < length and clean[pos + 1] in ("K", "Q"):
                    pos += 2
                else:
                    pos += 1
            continue

        if ch == "D":
            if pos + 1 < length and clean[pos + 1] in ("G", "J"):
                primary.append("J")
                secondary.append("J")
                pos += 2
            else:
                primary.append("T")
                secondary.append("T")
                if pos + 1 < length and clean[pos + 1] == "D":
                    pos += 2
                else:
                    pos += 1
            continue

        if ch == "F":
            primary.append("F")
            secondary.append("F")
            if pos + 1 < length and clean[pos + 1] == "F":
                pos += 2
            else:
                pos += 1
            continue

        if ch == "G":
            if pos + 1 < length and clean[pos + 1] == "H":
                pos += 2
            elif pos + 1 < length and clean[pos + 1] in ("I", "E", "Y"):
                primary.append("J")
                secondary.append("K")
                pos += 2
            else:
                primary.append("K")
                secondary.append("K")
                if pos + 1 < length and clean[pos + 1] == "G":
                    pos += 2
                else:
                    pos += 1
            continue

        if ch == "H":
            # Keep 'H' if followed by vowel and not preceded by vowel
            if (pos == 0 or clean[pos - 1] not in ("A", "E", "I", "O", "U", "Y")) and (
                pos + 1 < length and clean[pos + 1] in ("A", "E", "I", "O", "U", "Y")
            ):
                primary.append("H")
                secondary.append("H")
                pos += 2
            else:
                pos += 1
            continue

        if ch in ("J", "K"):
            primary.append("K" if ch == "K" else "J")
            secondary.append("K" if ch == "K" else "J")
            if pos + 1 < length and clean[pos + 1] == ch:
                pos += 2
            else:
                pos += 1
            continue

        if ch == "L":
            primary.append("L")
            secondary.append("L")
            if pos + 1 < length and clean[pos + 1] == "L":
                pos += 2
            else:
                pos += 1
            continue

        if ch == "M":
            primary.append("M")
            secondary.append("M")
            if pos + 1 < length and clean[pos + 1] == "M":
                pos += 2
            else:
                pos += 1
            continue

        if ch == "N":
            primary.append("N")
            secondary.append("N")
            if pos + 1 < length and clean[pos + 1] == "N":
                pos += 2
            else:
                pos += 1
            continue

        if ch == "P":
            if pos + 1 < length and clean[pos + 1] == "H":
                primary.append("F")
                secondary.append("F")
                pos += 2
            else:
                primary.append("P")
                secondary.append("P")
                if pos + 1 < length and clean[pos + 1] == "P":
                    pos += 2
                else:
                    pos += 1
            continue

        if ch == "Q":
            primary.append("K")
            secondary.append("K")
            if pos + 1 < length and clean[pos + 1] == "Q":
                pos += 2
            else:
                pos += 1
            continue

        if ch == "R":
            primary.append("R")
            secondary.append("R")
            if pos + 1 < length and clean[pos + 1] == "R":
                pos += 2
            else:
                pos += 1
            continue

        if ch == "S":
            if pos + 1 < length and clean[pos + 1] == "H":
                primary.append("X")
                secondary.append("X")
                pos += 2
            else:
                primary.append("S")
                secondary.append("S")
                if pos + 1 < length and clean[pos + 1] == "S":
                    pos += 2
                else:
                    pos += 1
            continue

        if ch == "T":
            if pos + 1 < length and clean[pos + 1] == "H":
                primary.append("0")  # theta
                secondary.append("T")
                pos += 2
            else:
                primary.append("T")
                secondary.append("T")
                if pos + 1 < length and clean[pos + 1] == "T":
                    pos += 2
                else:
                    pos += 1
            continue

        if ch == "V":
            primary.append("F")
            secondary.append("F")
            if pos + 1 < length and clean[pos + 1] == "V":
                pos += 2
            else:
                pos += 1
            continue

        if ch == "W":
            if pos + 1 < length and clean[pos + 1] in ("A", "E", "I", "O", "U"):
                primary.append("A")
                secondary.append("F")
            pos += 1
            continue

        if ch == "X":
            primary.append("KS")
            secondary.append("KS")
            pos += 1
            continue

        if ch == "Z":
            primary.append("S")
            secondary.append("S")
            if pos + 1 < length and clean[pos + 1] == "Z":
                pos += 2
            else:
                pos += 1
            continue

        pos += 1

    prim_str = "".join(primary)[:4]
    sec_str = "".join(secondary)[:4]
    return prim_str, sec_str


# ---------------------------------------------------------------------------
# High-Level Token Phonetics
# ---------------------------------------------------------------------------


def get_token_phonetic_codes(token: str) -> PhoneticCodes:
    """Generate all phonetic representations for a given name token.

    Args:
        token: Normalized name token.

    Returns:
        PhoneticCodes dataclass containing Double Metaphone and Ethiopian codes.
    """
    clean = token.strip().lower()
    dm_prim, dm_sec = compute_double_metaphone(clean)
    eth_code = compute_ethiopian_phonetic_code(clean)

    return PhoneticCodes(
        token=clean,
        double_metaphone_primary=dm_prim,
        double_metaphone_secondary=dm_sec,
        ethiopian_phonetic_code=eth_code,
    )


def are_phonetically_similar(token_a: str, token_b: str) -> Tuple[bool, bool, str]:
    """Check whether two tokens match phonetically under Double Metaphone and Ethiopian rules.

    Returns:
        Tuple of (dm_match: bool, eth_match: bool, matched_code: str).
    """
    codes_a = get_token_phonetic_codes(token_a)
    codes_b = get_token_phonetic_codes(token_b)

    # Double Metaphone match check
    dm_match = bool(
        (codes_a.double_metaphone_primary and codes_a.double_metaphone_primary == codes_b.double_metaphone_primary)
        or (codes_a.double_metaphone_primary and codes_a.double_metaphone_primary == codes_b.double_metaphone_secondary)
        or (codes_a.double_metaphone_secondary and codes_a.double_metaphone_secondary == codes_b.double_metaphone_primary)
    )

    # Ethiopian phonetic code match check
    eth_match = bool(
        codes_a.ethiopian_phonetic_code
        and codes_a.ethiopian_phonetic_code == codes_b.ethiopian_phonetic_code
    )

    matched_code = codes_a.ethiopian_phonetic_code if eth_match else codes_a.double_metaphone_primary

    return dm_match, eth_match, matched_code
