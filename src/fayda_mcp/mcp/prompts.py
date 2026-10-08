"""Parameterized FastMCP prompts for citizen verification and onboarding workflows."""

import json
from typing import Any, List, Optional
from fayda_mcp.service import FaydaVerificationService


def register_prompts(
    server: Any,
    service: Optional[FaydaVerificationService] = None,
) -> None:
    """Register FastMCP citizen onboarding prompts onto the server.

    Args:
        server: FastMCP server instance.
        service: Optional initialized FaydaVerificationService instance.
    """

    @server.prompt(
        name="onboard_citizen",
        description=(
            "Guiding instructions for onboarding a citizen using Fayda eSignet: "
            "purpose selection, minimal checks, authorization delivery, bounded polling, "
            "handling unavailable evidence, and strict privacy boundaries."
        ),
    )
    def onboard_citizen(
        purpose: str = "onboarding",
        checks: str = "identity_verified",
        application_user_ref: str = "",
    ) -> str:
        """Guiding instructions for onboarding a citizen using Fayda eSignet.

        Args:
            purpose: Approved business purpose for verification (e.g. 'onboarding', 'kyc', 'account_opening').
            checks: Comma-separated list of minimal requested checks (e.g. 'identity_verified,optional:phone_verified').
            application_user_ref: Opaque caller identifier for the user.
        """
        # Parse check list
        parsed_checks: List[str] = [
            c.strip() for c in checks.split(",") if c.strip()
        ]
        if not parsed_checks:
            parsed_checks = ["identity_verified"]

        user_ref_display = application_user_ref.strip() or "<unique_application_user_ref>"
        checks_json_str = json.dumps(parsed_checks)

        return f"""# Citizen Onboarding Procedure (Fayda eSignet)

Follow this privacy-preserving procedure to verify and onboard a citizen:

## 1. Purpose Selection
- **Requested Purpose**: `{purpose}`
- Ensure this matches an approved business purpose registered in the verification policy (e.g., `onboarding`, `kyc`, `account_opening`).
- Never proceed with an unapproved or arbitrary purpose.

## 2. Minimal Checks & Predicate Selection
- **Requested Checks**: `{', '.join(parsed_checks)}`
- Enforce strict data minimization: request only the minimal predicates strictly necessary for this purpose (e.g., `identity_verified`, `age_over_18` or `age_at_least`, `phone_verified`, `email_verified`).
- Distinguish required vs. optional checks: prefix non-critical checks with `optional:` (e.g., `optional:phone_verified`) so unverified contact claims do not block onboarding.

## 3. Initiate Verification Tool
- Invoke the `start_verification` tool with:
  - `purpose`: `"{purpose}"`
  - `checks`: {checks_json_str}
  - `application_user_ref`: `"{user_ref_display}"`
  - `idempotency_key`: `"<unique_uuid_or_idempotency_key>"`
- Provide a distinct, deterministic `idempotency_key` per citizen session to prevent duplicate starts and allow safe retries.

## 4. Authorization Link Delivery
- Securely present the returned `authorization_url` to the citizen.
- Instruct the citizen to open the link in their secure browser or mobile device to authenticate directly via the official Fayda eSignet portal.
- Do NOT attempt to log in or handle credentials on behalf of the citizen.

## 5. Bounded Polling for Status
- Check verification progress using `get_verification_status(request_id=...)`.
- Use **bounded polling intervals** (e.g., poll every 3 to 5 seconds with exponential backoff or jitter, up to a maximum attempt limit or until `expires_at`).
- **CRITICAL**: Stop polling immediately when reaching any terminal state:
  - `verified`: Verification completed successfully.
  - `rejected`: Policy failed (e.g., age threshold not met or invalid contact).
  - `incomplete`: Required evidence missing from provider.
  - `cancelled`: Verification was cancelled.
  - `failed`: Provider or system error.
  - `expired`: Session or request TTL expired.

## 6. Unavailable Evidence Handling
- Provider claims may be absent or unverified (e.g., `phone_verified: null` with reason `provider_claim_unavailable`).
- If required evidence is missing, the status resolves to `incomplete`.
- Do not assume missing evidence indicates citizen dishonesty, and never invent or hallucinate citizen claims.

## 7. Result Retrieval
- Once status reaches completion, call `get_verification_result(request_id=...)`.
- Inspect the evaluated boolean predicates in `checks` and safe reason codes in `reasons`.
- Use these predicates to guide application onboarding decisions.

## 8. Privacy & Security Rules (Mandatory Guardrails)
- **NO CREDENTIALS / OTPs**: NEVER ask for, accept, or log citizen passwords, SMS/OTP codes, PINs, or private keys.
- **NO RAW BIOMETRICS**: NEVER ask for, handle, or process raw biometric data (fingerprint minutiae, iris templates, facial photos).
- **NO RAW DEMOGRAPHICS**: NEVER store, output, or prompt for raw demographic information (dates of birth, phone numbers, email addresses, and national IDs).
- **AUTHORIZATION ENFORCEMENT**: Prompts provide instructions, not automatic execution or permission. All tool invocations strictly enforce host caller authorization and policy rules.
- **CLIENT MENU SYNTAX**: Menu or slash command syntax (e.g., `/onboard_citizen`) depends entirely on the MCP client UI and is not guaranteed across all clients.
"""
