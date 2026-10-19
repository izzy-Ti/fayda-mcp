# Ethiopian Name Matching Architecture & Release Guide (`ethiopian_name_v1`)

**Specification Version:** 1.0.0  
**Status:** Canonical Release Specification (guide5 Tasks 01–16)  
**Reference:** Fayda MCP Ethiopian Name Matching Extension

---

## 1. Executive Summary & Design Principles

The **Ethiopian Name Matching Extension** (`ethiopian_name_v1`) enables relying parties (banks, telecom providers, public portals) to verify citizen identities where Amharic-script and Latin-script spellings differ, without false mismatch rejections on standard transliteration and phonetic variations.

```
+-------------------------------------------------------------------------------------------------+
|                                 NAME MATCHING PIPELINE FLOW                                     |
+-------------------------------------------------------------------------------------------------+
|                                                                                                 |
| 1. Authenticated Host Submission:                                                               |
|    • Host Backend registers expected details with matching_profile="ethiopian_name_v1"           |
|    • Reuses caller/user binding, 60s-3600s TTL, and rate limiting (sliding window)              |
|    • Retained expectations encrypted at rest (AES-256-GCM)                                      |
|                                                                                                 |
| 2. Input Script Detection & Safe Normalization:                                                 |
|    • Detects Ethiopic, Latin, and mixed script; flags control/invisible characters              |
|    • Unicode NFC normalization, Latin case-folding, whitespace collapsed                        |
|                                                                                                 |
| 3. Structural Decomposition:                                                                    |
|    • Preserves Ethiopian naming structure: [Given Name] [Father's Name] [Grandfather's Name]    |
|    • Rejects component transposition (father vs son) and single-token shared approvals          |
|                                                                                                 |
| 4. Multi-Evidence Comparison:                                                                   |
|    • Versioned Amharic Ethiopic-to-Latin transliteration mapping (bounded variants)             |
|    • Approved variations (Wolde/Welde, gemination, compound theophoric whitespace)              |
|    • Phonetic similarity (Double Metaphone + Ethiopian phonetic code generator)                 |
|    • Token-level string distance (Levenshtein & Jaro-Winkler)                                   |
|                                                                                                 |
| 5. Policy, Protection & Tri-State Outcomes:                                                     |
|    • Threshold calibration against host-approved False Match Rate limit (FMR <= limit)          |
|    • Non-cancellation protection: Strong name score NEVER cancels DOB mismatch or missing claim |
|    • Tri-state result: matches['full_name'] is True, False, or None (review required)           |
|                                                                                                 |
| 6. Privacy & Minimal Agent Tool Response:                                                       |
|    • Rich comparison trace (variants, codes, scores) stored backend-only                        |
|    • ZERO raw names, variants, phonetic codes, or numerical scores exposed to MCP agent         |
|                                                                                                 |
+-------------------------------------------------------------------------------------------------+
```

### Core Security Invariants
1. **No Population Search / Identity Inference**: Compares strictly one submitted name against one verified identity.
2. **Deterministic & Bounded**: No LLM makes name matching decisions. Outcomes are deterministic.
3. **Similarity Score is NOT a Probability of Identity**: High phonetic similarity alone never approves identity.
4. **Non-Cancellation**: DOB and other required checks remain strictly independent.
5. **Backend Privacy**: Raw names, candidate transliteration variants, phonetic codes, and numerical scores are kept backend-only by default.

---

## 2. Architecture & Modules

The implementation is modularized under `src/fayda_mcp/matching/`:

| Module | Responsibility | Version / Standard |
| :--- | :--- | :--- |
| [`profiles.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/profiles.py) | Matching profile registry (`strict`, `ethiopian_name_v1`), language constraints, explicit host opt-in. | `profile-v1` |
| [`normalization.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/normalization.py) | Unicode NFC normalization, Latin case-folding, whitespace collapsing, token preservation. | `details-v1` |
| [`detection.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/detection.py) | Script detection (Ethiopic, Latin, Mixed), control character and punctuation filtering. | `detection-v1` |
| [`transliteration.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/transliteration.py) | Versioned Amharic Ethiopic-to-Latin transliteration mapping reviewed by native speakers. | `translit-am-v1` |
| [`variations.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/variations.py) | Approved context-specific spelling rules (Wolde/Welde, gemination, compound names). | `variations-v1` |
| [`uncertainty.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/uncertainty.py) | Uncertainty handling: flags ambiguous transliterations, unsupported languages, or control chars. | `uncertainty-v1` |
| [`structure.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/structure.py) | Ethiopian patronymic component parsing and order preservation (no Western surname logic). | `structure-v1` |
| [`phonetics.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/phonetics.py) | Double Metaphone baseline and specialized Ethiopian phonetic code generation. | `phonetics-v1` |
| [`scoring.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/scoring.py) | Multi-evidence scoring combining spelling distance, approved transliteration, and phonetics. | `scoring-v1` |
| [`review.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/review.py) | Review outcome evaluator: triages initials, phonetic-only agreement, missing components. | `review-v1` |
| [`calibration.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/calibration.py) | Empirical threshold calibration on labeled pairs against host false-match limit (FMR). | `calibration-v1` |
| [`protection.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/protection.py) | Invariant protection ensuring strong name scores never cancel DOB mismatches or missing claims. | `protection-v1` |
| [`privacy.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/privacy.py) | Backend-only comparison details (`BackendComparisonDetails`), caller/user binding, TTL, rate limiter. | `privacy-v1` |
| [`fixtures.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/fixtures.py) | De-identified, native-speaker reviewed fixtures with leakage-free person splitting. | `fixtures-v1` |
| [`evaluation.py`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/matching/evaluation.py) | Held-out evaluation, FMR/FNMR/review reporting, strict baseline comparison, release gate. | `evaluation-v1` |

---

## 3. Strict Fallback and Rollback Procedures

### Strict Matching as Default
`strict` matching is the default profile across all endpoints and services. The `ethiopian_name_v1` profile requires explicit host opt-in:

```python
# Host explicitly chooses ethiopian_name_v1:
expected = ExpectedDetails(
    full_name="Abebe Bikila",
    matching_profile="ethiopian_name_v1",
)
```

If `matching_profile` is omitted, the service falls back deterministically to `strict`:
- Exact Unicode NFC normalization
- Full Latin case-folding
- Whitespace collapsing
- Zero transliteration or fuzzy approvals

### Operational Fallback
In any of the following operational scenarios, the system safely falls back to strict evaluation:
1. **Unrecognized language or unsupported script**: Returns `unavailable` or falls back to strict normalization.
2. **Ambiguous transliteration or unmapped character sets**: Generates safe reason code (`ambiguous_transliteration`, `unsupported_characters`) and routes to `review_required` or strict fallback.
3. **Host profile restriction**: If a host configures `allowed_profiles=["strict"]`, any request attempting to use `ethiopian_name_v1` is rejected with `DetailsMatchingError(INVALID_EXPECTATIONS)`.

### Operational Rollback Procedure
If unexpected production issues or regulatory changes require rolling back `ethiopian_name_v1`:

1. **Zero-Downtime Environment Switch**:
   Set the default matching profile environment variable:
   ```bash
   FAYDA_MATCHING_DEFAULT_PROFILE=strict
   ```
   Or restrict allowed profiles:
   ```bash
   FAYDA_MATCHING_ALLOWED_PROFILES=strict
   ```

2. **No Database Migrations Required**:
   Because matching outcomes and expected details records are stored in ephemeral session storage (short TTL) and audit result repositories with versioned metadata (`profile_version="strict"`, `comparison_policy_version="details-v1"`), rolling back requires no schema alterations or data migrations.

3. **Audit Trail Integrity**:
   All historical results preserve `matching_profile`, `profile_version`, and safe reason codes, allowing unambiguous retrospective audits regardless of which profile evaluated the request.

---

## 4. Packaging & Clean Wheel Verification

The package builds via `hatchling` into standard wheel (`.whl`) and source distribution (`.tar.gz`) archives.

### Building Artifacts:
```bash
python -m build
```

### Clean Wheel Install Test:
To verify that the wheel installs and operates cleanly without optional dependencies:
```bash
# In a fresh virtual environment:
pip install dist/fayda_mcp-*.whl

# Verify core imports work without extras:
python -c "import fayda_mcp; from fayda_mcp.matching import DetailsMatchingService; print('Core OK')"
```

### Optional Extras:
- `fayda-mcp[fastapi]`: Installs FastAPI and Uvicorn for HTTP endpoints.
- `fayda-mcp[redis]`: Installs Redis client for distributed session storage.
- `fayda-mcp[postgres]`: Installs SQLAlchemy, asyncpg, and psycopg for persistent audit storage.
- `fayda-mcp[all]`: Installs all optional adapters.

### Security Audit Guarantee:
No environment files (`.env`), private keys (`.pem`, `.key`), certificates, or embedded secrets are included in the distributed wheel or sdist packages.
