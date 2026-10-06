"""End-to-end walkthrough of the Fayda eSignet sandbox verification flow.

Demonstrates how a developer configures their own Fayda relying party client
and runs the complete verification lifecycle without touching library internals:
1. Initialize service and configuration with sandbox preset
2. Start verification via service or MCP tool
3. Retrieve generated eSignet authorization URL
4. Simulate citizen authorization callback with browser session binding
5. Query status and retrieve minimal privacy-preserving verification results
6. Cleanly shut down connections and storage

Usage:
    python examples/sandbox_flow.py
"""

import asyncio
import os
import urllib.parse
from fayda_mcp import FaydaConfig, FaydaVerificationService
from fayda_mcp.context import CallerContext
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


async def run_sandbox_flow() -> None:
    print("=" * 70)
    print("Fayda MCP Sandbox Verification Flow Walkthrough")
    print("=" * 70)

    # -------------------------------------------------------------------------
    # Step 1: Developer Configuration
    # -------------------------------------------------------------------------
    client_id = os.environ.get("FAYDA_CLIENT_ID", "sandbox_demo_client_id")
    redirect_uri = os.environ.get("FAYDA_REDIRECT_URI", "http://localhost:8000/auth/fayda/callback")

    print(f"\n[1] Initializing configuration...")
    if os.environ.get("FAYDA_ISSUER_URL") or os.environ.get("FAYDA_ISSUER"):
        config = FaydaConfig.from_env()
        print("    Loaded configuration from environment variables.")
    else:
        config = FaydaConfig.sandbox(
            client_id=client_id,
            redirect_uri=redirect_uri,
        )
        print("    Using official Ethiopian Fayda eSignet sandbox preset:")
        print(f"    - Issuer: {config.issuer}")
        print(f"    - Authorization Endpoint: {config.authorization_endpoint}")
        print(f"    - Redirect URI: {config.redirect_uri}")

    # -------------------------------------------------------------------------
    # Step 2: Initialize Service with Pluggable Storage
    # -------------------------------------------------------------------------
    print("\n[2] Starting FaydaVerificationService...")
    service = FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )

    # Use async context manager for automated cleanup
    async with service:
        # ---------------------------------------------------------------------
        # Step 3: Initiate Verification Request
        # ---------------------------------------------------------------------
        caller_ctx = CallerContext(
            tenant_id="acme_tenant",
            principal_id="onboarding_agent",
            browser_binding="sess_cookie_abc123",  # Binds user's browser session
        )

        print("\n[3] Calling start_verification...")
        start_response = await service.start_verification(
            context=caller_ctx,
            purpose="onboarding",
            checks=["identity_verified", "age_over_18"],
            application_user_ref="applicant_eth_001",
            idempotency_key="idemp_applicant_001",
        )

        print(f"    -> Request ID: {start_response.request_id}")
        print(f"    -> Expires At: {start_response.expires_at}")
        print(f"    -> Authorization URL:\n       {start_response.authorization_url}")

        # ---------------------------------------------------------------------
        # Step 4: Check Pending Status
        # ---------------------------------------------------------------------
        print("\n[4] Checking status before user authorization...")
        status_resp = await service.get_verification_status(
            context=caller_ctx,
            request_id=start_response.request_id,
        )
        print(f"    -> Current Status: {status_resp.status}")

        # ---------------------------------------------------------------------
        # Step 5: Simulate Citizen Authorization Callback
        # ---------------------------------------------------------------------
        # Extract the cryptographic state parameter from the authorization URL
        parsed_url = urllib.parse.urlparse(start_response.authorization_url)
        state_param = urllib.parse.parse_qs(parsed_url.query)["state"][0]

        print("\n[5] Simulating citizen callback with state and auth code...")
        print(f"    - State token: {state_param[:16]}...")
        print("    - Validating host browser session binding...")

        # In production, Fayda redirects back with ?code=auth_code&state=...
        result = await service.complete_verification(
            code="mock_auth_code_sandbox",
            state=state_param,
            browser_binding="sess_cookie_abc123",  # Must match start_verification
        )

        # ---------------------------------------------------------------------
        # Step 6: Verify Minimal, Privacy-Preserving Output
        # ---------------------------------------------------------------------
        print("\n[6] Completed Verification Result:")
        print(f"    -> Request ID:     {result.request_id}")
        print(f"    -> Status:         {result.status}")
        print(f"    -> Checks:         {result.checks}")
        print(f"    -> Evidence Ref:   {result.evidence_ref}")
        print(f"    -> Policy Version: {result.policy_version}")
        print(f"    -> Verified At:    {result.verified_at}")

        # Demonstrate privacy guarantee: No tokens, passwords, or biometrics leaked
        result_dict = result.model_dump()
        disallowed = ["biometrics", "photo", "fingerprint", "access_token", "id_token", "name"]
        leaked = [k for k in disallowed if k in result_dict]
        print(f"\n    Privacy Verification: Leaked sensitive fields: {leaked} (Should be empty)")

        # ---------------------------------------------------------------------
        # Step 7: Multi-tenant / Caller Isolation Demonstration
        # ---------------------------------------------------------------------
        print("\n[7] Testing Caller Isolation...")
        other_caller = CallerContext(
            tenant_id="competing_tenant",
            principal_id="unauthorized_agent",
        )
        try:
            await service.get_verification_result(
                context=other_caller,
                request_id=start_response.request_id,
            )
            print("    [!] Warning: Access was not denied!")
        except Exception as err:
            print(f"    [OK] Unauthorized caller was blocked: {err}")

    print("\n[8] Service closed and storage cleaned up cleanly.")
    print("=" * 70)
    print("Sandbox flow completed successfully!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_sandbox_flow())
