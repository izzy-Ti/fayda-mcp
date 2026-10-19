"""Context-specific spelling variations and reviewed Ethiopian name equivalents.

Per guide5 Task 05:
- Maintain context-specific spelling rules and reviewed examples.
- Do not globally merge vowels or doubled consonants.
- Preserve distinct outcomes: exact, approved_equivalent, review_required, mismatch.
- Support token-level and full-name approved equivalence.
"""

from typing import Dict, List, Optional, Sequence, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.matching.detection import DETECTED_SCRIPT_ETHIOPIC, DETECTED_SCRIPT_LATIN
from fayda_mcp.matching.normalization import normalize_name_safely
from fayda_mcp.matching.transliteration import transliterate_token

# ---------------------------------------------------------------------------
# Versions & Constants
# ---------------------------------------------------------------------------

VARIATIONS_SPEC_VERSION: str = "variations-v1"

# ---------------------------------------------------------------------------
# Reviewed Name Equivalent Clusters
# Curated and reviewed according to Ethiopian naming conventions, passport records,
# and civil registry transliterations.
# ---------------------------------------------------------------------------

REVIEWED_EQUIVALENT_CLUSTERS: List[Tuple[str, ...]] = [
    ("abebe", "abbebe"),
    ("bikila", "biqila"),
    ("bekele", "beqele"),
    ("welde", "wolde"),
    ("worku", "werku"),
    ("workneh", "werkneh"),
    ("wossen", "wessen"),
    ("haile", "hayle"),
    ("hailu", "haylu"),
    ("selassie", "selase", "silassie", "silase"),
    ("alemu", "allemu"),
    ("tadese", "taddese", "tadesse"),
    ("kassa", "kasa"),
    ("kebede", "qebede"),
    ("almaz", "almaze"),
    ("birhanu", "berhanu"),
    ("girma", "germa"),
    ("desta", "dasta"),
    ("tesfaye", "tesfay"),
    ("mekonnen", "mekonen"),
    ("assefa", "asefa"),
    ("ayele", "ayel"),
    ("berhe", "barhe"),
    ("fisseha", "fiseha"),
    ("mulugeta", "mullugeta"),
    ("debebe", "debbebe"),
    ("mengistu", "menghistu"),
    ("getachew", "getachow"),
    ("yohannes", "johannes"),
    ("kidane", "kidan"),
]

# Fast token to cluster lookup
_TOKEN_TO_CLUSTER: Dict[str, Set[str]] = {}
for cluster in REVIEWED_EQUIVALENT_CLUSTERS:
    cluster_set = set(cluster)
    for tok in cluster:
        _TOKEN_TO_CLUSTER[tok] = cluster_set


# ---------------------------------------------------------------------------
# Context-Specific Spelling Rules
# Strict, targeted rules addressing known phonetic/transliteration variations
# without destructive global merging of vowels or consonants.
# ---------------------------------------------------------------------------


class ContextSpellingRule(BaseModel):
    """Specification for a context-specific spelling variation rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(..., description="Unique rule identifier")
    description: str = Field(..., description="Explanation of linguistic context")

    def matches(self, token_a: str, token_b: str) -> bool:
        """Check if token_a and token_b are approved equivalents under this specific rule."""
        raise NotImplementedError


class RuleWoldeWeldePrefix(ContextSpellingRule):
    """Context Rule 1: 'wol' <-> 'wel', 'wor' <-> 'wer', 'wos' <-> 'wes' prefix variation in 'ወ' series."""

    rule_id: str = "rule_wol_wel_prefix"
    description: str = "Prefix variation between wol/wel, wor/wer, and wos/wes for 1st order 'ወ'"

    def matches(self, a: str, b: str) -> bool:
        if a == b:
            return False
        # Must be at least 4 characters long (e.g. wolde/welde, worku/werku)
        if len(a) < 4 or len(b) < 4:
            return False
        for pref_o, pref_e in (("wol", "wel"), ("wor", "wer"), ("wos", "wes")):
            if a.startswith(pref_o) and b.startswith(pref_e):
                return a[len(pref_o):] == b[len(pref_e):]
            if a.startswith(pref_e) and b.startswith(pref_o):
                return a[len(pref_e):] == b[len(pref_o):]
        return False


class RuleHaileHaylePrefix(ContextSpellingRule):
    """Context Rule 2: 'haile' <-> 'hayle', 'hailu' <-> 'haylu' prefix in compound names."""

    rule_id: str = "rule_haile_hayle_prefix"
    description: str = "Diphthong variation between haile/hayle and hailu/haylu compound names"

    def matches(self, a: str, b: str) -> bool:
        if a == b:
            return False
        for p1, p2 in (("haile", "hayle"), ("hailu", "haylu")):
            if a.startswith(p1) and b.startswith(p2):
                return a[len(p1):] == b[len(p2):]
            if a.startswith(p2) and b.startswith(p1):
                return a[len(p2):] == b[len(p1):]
        return False


class RuleKQAlternation(ContextSpellingRule):
    """Context Rule 3: 'k' <-> 'q' alternation representing Ethiopic 'ቀ' in syllables."""

    rule_id: str = "rule_kq_alternation"
    description: str = "Consonant alternation between k and q representing Ethiopic 'ቀ'"

    def matches(self, a: str, b: str) -> bool:
        if a == b:
            return False
        if len(a) != len(b):
            return False
        diff_count = 0
        for ca, cb in zip(a, b):
            if ca != cb:
                if (ca == "k" and cb == "q") or (ca == "q" and cb == "k"):
                    diff_count += 1
                else:
                    return False
        # Matched if exactly 1 or 2 k/q differences and all other characters identical
        return diff_count in (1, 2)


class RuleMedialGemination(ContextSpellingRule):
    """Context Rule 4: Context-specific medial gemination (doubled consonant) in Ethiopian root syllables."""

    rule_id: str = "rule_medial_gemination"
    description: str = "Medial consonant gemination in recognized Ethiopian name patterns"

    # Permitted geminated consonants in medial position: b, d, l, s, n, m, t
    GEMINATED_CONSONANTS: Set[str] = {"b", "d", "l", "s", "n", "m", "t", "r"}

    def matches(self, a: str, b: str) -> bool:
        if a == b:
            return False
        short_s, long_s = (a, b) if len(a) < len(b) else (b, a)
        # Must differ by exactly one character (the doubled consonant)
        if len(long_s) != len(short_s) + 1:
            return False

        # Find the insertion index
        i = 0
        while i < len(short_s) and short_s[i] == long_s[i]:
            i += 1

        # Check if the extra character in long_s is a repeat of short_s[i-1] or short_s[i]
        # and belongs to the permitted geminated consonants
        if i > 0 and long_s[i] == long_s[i - 1] and long_s[i] in self.GEMINATED_CONSONANTS:
            # Suffix must match rest of short_s
            return long_s[i + 1:] == short_s[i:]

        return False


class RuleFinalEOrYe(ContextSpellingRule):
    """Context Rule 5: Final silent '-e' or '-ye' in Amharic transliteration."""

    rule_id: str = "rule_final_e_or_ye"
    description: str = "Terminal vowel/semi-vowel variation (-e or -ye) on masculine/feminine names"

    def matches(self, a: str, b: str) -> bool:
        if a == b:
            return False
        short_s, long_s = (a, b) if len(a) < len(b) else (b, a)
        # Terminal 'e': e.g. almaz / almaze, kidan / kidane
        if len(long_s) == len(short_s) + 1 and long_s.endswith("e") and long_s[:-1] == short_s:
            return len(short_s) >= 4

        # Terminal 'ye' <-> 'y': e.g. tesfay / tesfaye
        if short_s.endswith("y") and long_s.endswith("ye") and short_s + "e" == long_s:
            return True

        return False


class RuleInitialEpenthetic(ContextSpellingRule):
    """Context Rule 6: Name-initial epenthetic 6th order vowel variation ('bir-' <-> 'ber-', 'gir-' <-> 'ger-')."""

    rule_id: str = "rule_initial_epenthetic"
    description: str = "Initial epenthetic vowel variation between i and e before liquids (r, l)"

    def matches(self, a: str, b: str) -> bool:
        if a == b:
            return False
        if len(a) != len(b) or len(a) < 4:
            return False
        # Must differ only at index 1 with 'i' vs 'e' followed by 'r' or 'l'
        if (
            (a[0] == b[0])
            and (a[2] in ("r", "l"))
            and (b[2] in ("r", "l"))
            and ((a[1] == "i" and b[1] == "e") or (a[1] == "e" and b[1] == "i"))
            and a[2:] == b[2:]
        ):
            return True
        return False


# Active context-specific rules list
ACTIVE_CONTEXT_RULES: List[ContextSpellingRule] = [
    RuleWoldeWeldePrefix(),
    RuleHaileHaylePrefix(),
    RuleKQAlternation(),
    RuleMedialGemination(),
    RuleFinalEOrYe(),
    RuleInitialEpenthetic(),
]


# ---------------------------------------------------------------------------
# Equivalence Evaluator Functions
# ---------------------------------------------------------------------------


def _has_ethiopic_chars(s: str) -> bool:
    """Check if string contains any Ethiopic characters."""
    return any(
        ("\u1200" <= ch <= "\u137f")
        or ("\u2d80" <= ch <= "\u2ddf")
        or ("\uab00" <= ch <= "\uab2f")
        for ch in s
    )


def is_approved_token_variation(token_a: str, token_b: str) -> Tuple[bool, Optional[str]]:
    """Determine whether two name tokens are approved equivalent variations.

    Rules applied:
    1. Cross-script transliteration check if one token is Ethiopic and one is Latin.
    2. Curated reviewed equivalent clusters.
    3. Active context-specific spelling rules.
    Does NOT globally merge vowels or consonants.

    Args:
        token_a: First normalized name token.
        token_b: Second normalized name token.

    Returns:
        Tuple of (is_approved: bool, reason_or_rule_id: Optional[str]).
    """
    clean_a = token_a.strip().lower()
    clean_b = token_b.strip().lower()

    if not clean_a or not clean_b:
        return False, None

    if clean_a == clean_b:
        return True, "exact"

    # Cross-script comparison: one Ethiopic, one Latin
    eth_a = _has_ethiopic_chars(clean_a)
    eth_b = _has_ethiopic_chars(clean_b)

    if eth_a and not eth_b:
        trans_res = transliterate_token(clean_a)
        # Check exact transliteration variant first
        for var in trans_res.variants:
            if var.lower() == clean_b:
                return True, "transliteration"
        # Check if any transliteration variant is an approved variation of clean_b
        for var in trans_res.variants:
            is_eq, rule_id = is_approved_token_variation(var, clean_b)
            if is_eq and rule_id:
                return True, f"transliteration+{rule_id}"
        return False, None
    elif eth_b and not eth_a:
        return is_approved_token_variation(clean_b, clean_a)

    # 1. Check curated reviewed cluster
    cluster_a = _TOKEN_TO_CLUSTER.get(clean_a)
    if cluster_a is not None and clean_b in cluster_a:
        return True, "reviewed_example"

    # 2. Check context-specific rules
    for rule in ACTIVE_CONTEXT_RULES:
        if rule.matches(clean_a, clean_b):
            return True, rule.rule_id

    return False, None


def is_approved_name_variation(
    name_a: Optional[str],
    name_b: Optional[str],
) -> Tuple[bool, Optional[str], List[str]]:
    """Determine whether two multi-token citizen names are approved equivalents.

    Enforces:
    - Ordered name components must match token-for-token (given, father, grandfather).
    - Every token must match either exactly, via transliteration, or via an approved variation.
    - At least one token must differ via approved variation or transliteration (if all exact, returns exact).
    - Preserves name structure; does not permute or drop tokens.

    Args:
        name_a: First citizen name string.
        name_b: Second citizen name string.

    Returns:
        Tuple of (is_approved: bool, overall_method: Optional[str], applied_rules: List[str]).
    """
    if name_a is None or name_b is None:
        return False, None, []

    norm_a = normalize_name_safely(name_a)
    norm_b = normalize_name_safely(name_b)

    if norm_a is None or norm_b is None:
        return False, None, []

    if norm_a.normalized == norm_b.normalized:
        return True, "exact", []

    tokens_a = norm_a.tokens
    tokens_b = norm_b.tokens

    # Token counts must match strictly in ethiopian_name_v1 (no silent dropping)
    if len(tokens_a) != len(tokens_b) or len(tokens_a) == 0:
        return False, None, []

    applied_rules: List[str] = []
    has_variation = False
    has_transliteration = False

    for tok_a, tok_b in zip(tokens_a, tokens_b):
        if tok_a == tok_b:
            continue
        is_equiv, rule_id = is_approved_token_variation(tok_a, tok_b)
        if not is_equiv or not rule_id:
            return False, None, []
        if rule_id == "transliteration":
            has_transliteration = True
        else:
            has_variation = True
        applied_rules.append(rule_id)

    if has_variation:
        return True, "approved_variation", applied_rules
    if has_transliteration:
        return True, "transliteration", applied_rules

    return True, "exact", []


def get_approved_variants_for_token(token: str) -> Set[str]:
    """Return all known approved equivalent variants for a given name token.

    Args:
        token: Normalized name token (e.g. 'abebe', 'wolde', 'bikila').

    Returns:
        Set of approved variant spellings including the input token.
    """
    clean_tok = token.strip().lower()
    if not clean_tok:
        return set()

    variants: Set[str] = {clean_tok}

    # Add from reviewed clusters
    cluster = _TOKEN_TO_CLUSTER.get(clean_tok)
    if cluster:
        variants.update(cluster)

    return variants
