# Separate Holder Authentication & Trust Boundaries

**Document Version:** 1.0.0  
**Status:** Canonical Security Architecture  
**Reference:** Fayda MCP QR Verification Addendum (Section 13, Task 13)

---

## 1. Executive Security Principle

Offline Fayda National ID QR verification establishes **credential origin and cryptographic integrity** under configured trusted issuer keys. It **does NOT authenticate the human presenter** (the holder).

A scanned QR code:
- **Proves:** The data payload was issued and digitally signed by the National ID Program (NIDP) / Fayda Authority and has not been tampered with (`credential_signature_valid = True`).
- **Does NOT Prove:** The individual holding or presenting the card is the actual owner of that credential (`holder_authenticated = False`).
- **Does NOT Establish:** Live identity assertion or real-time revocation status (`identity_verified = False`).

```
+-----------------------------------------------------------------------------+
|                          FAYDA TRUST BOUNDARIES                              |
+-----------------------------------------------------------------------------+
|                                                                             |
|  [ Offline QR Credential Scan ]         [ Online eSignet OIDC Journey ]     |
|  -------------------------------         -------------------------------    |
|  • detached RS256 verification           • Live holder redirected to eSignet|
|  • Public key in local trust store       • Biometric / OTP / PIN auth       |
|  • Fast edge / zero network roundtrip    • OIDC ID Token & UserInfo claims  |
|                                                                             |
|  Result Invariants:                      Result Invariants:                 |
|  • credential_signature_valid = True     • credential_signature_valid = True|
|  • holder_authenticated = FALSE          • holder_authenticated = TRUE      |
|  • identity_verified    = FALSE          • identity_verified    = TRUE      |
|                                                                             |
+-----------------------------------------------------------------------------+
```

---

## 2. Threat Model: Copied & Replayed Credentials

A physical photo, printout, or stolen Fayda National ID card carries the exact same valid digital signature as the legitimate card. 

1. **Bearer Presentation Risk:**
   Without biometric matching (e.g., face comparison with the embedded WebP photo) or live proof-of-presence, an automated scanner cannot determine if the presenter is the person named in the card.
2. **Offline Registry Limitations:**
   Offline QR checks cannot consult real-time Fayda registries for credential revocation, lost-card reports, or status updates.

Therefore, the system enforces **fail-safe separation**:
- `holder_authenticated` is **strictly typed as `Literal[False]`** in `QREvidence` and `QRVerificationResult`.
- `identity_verified` is **strictly typed as `Literal[False]`** for all QR evidence records.
- Any caller requesting `holder_authenticated` or `identity_verified` checks against a QR code receives `False` with explicit explanation reasons:
  - `holder_authenticated: False` -> `"qr_scan_does_not_authenticate_holder"`
  - `identity_verified: False` -> `"offline_qr_alone_cannot_assert_identity"`

---

## 3. When to Use Which Verification Route

| Requirement | Recommended Route | Primary Output |
| :--- | :--- | :--- |
| **Offline Age Gating** (e.g. retail, venue access) | **QR Route** (`FaydaQRVerificationService`) | `credential_signature_valid`, `age_over_18` |
| **Tamper-Evident ID Inspection** (field audits) | **QR Route** (`FaydaQRVerificationService`) | `credential_signature_valid`, `evidence` |
| **Remote Account Creation** (KYC onboarding) | **eSignet Route** (`FaydaVerificationService`) | `identity_verified = True`, `holder_authenticated = True` |
| **High-Assurance Transactions** (banking transfers) | **eSignet Route** (`FaydaVerificationService`) | Real-time authentication + assurance level |

---

## 4. Code & Architecture Invariants

1. **Type-Level Enforcement:**
   [`QREvidence`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/qr/schemas.py) and [`QRVerificationResult`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/qr/schemas.py) declare:
   ```python
   holder_authenticated: Literal[False] = Field(default=False)
   identity_verified: Literal[False] = Field(default=False)
   ```
   Any runtime attempt to instantiate these models with `True` raises a Pydantic `ValidationError`.

2. **Policy Evaluation Interception:**
   [`FaydaQRVerificationService._evaluate_qr_checks`](file:///c:/Users/y/Documents/Fayda%20MCP/src/fayda_mcp/qr/service.py) intercepts `holder_authenticated` and `identity_verified` before claims engine execution, guaranteeing they never resolve to `True`.
