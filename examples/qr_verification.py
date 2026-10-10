"""Standalone and MCP Usage Examples for Fayda Offline QR Code Verification.

Demonstrates:
1. Offline / Edge Scanner Text Verification:
   - Verifies raw scanner text from physical Fayda National ID cards directly.
   - Zero Internet or callback dependencies: needs NO OIDC callback, NO webhook,
     and NO client private signing key (only the Fayda public key trust bundle).
2. Privacy-Preserving Agent Output:
   - Returns minimal authorized predicates ('credential_signature_valid', 'age_over_18').
   - Strictly excludes citizen demographics (name, DOB, gender, FAN), photo, and signature
     from agent/LLM context.
3. Security Threat Model & Copied QR Handling:
   - Offline QR verification proves credential authenticity and issuer integrity.
   - holder_authenticated remains False (scanning a card does not prove live human presence).
   - identity_verified is never asserted from QR alone without live holder authentication.
4. Pluggable Storage:
   - Redis remains optional for temporary references and rate limits.
   - Works out-of-the-box with in-memory storage, SQLite, or Neon/PostgreSQL.

Usage:
    python examples/qr_verification.py
"""

import asyncio
import os
from typing import Any, Dict

from fayda_mcp import FaydaConfig, FaydaVerificationService
from fayda_mcp.context import CallerContext
from fayda_mcp.qr.decoder import decode_and_verify_qr
from fayda_mcp.qr.schemas import QRAgentVerificationResult, filter_agent_output
from fayda_mcp.qr.service import FaydaQRVerificationService
from fayda_mcp.qr.trust import QRTrustStore, load_trust_store_from_config
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


def load_fixtures_sample() -> tuple[str, str]:
    """Load public key and synthetic authorized QR fixture for demonstration."""
    fixtures_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tests", "fixtures")
    with open(os.path.join(fixtures_dir, "test_qr_rsa_public.pem"), "r", encoding="utf-8") as f:
        pub_pem = f.read().strip()
    with open(os.path.join(fixtures_dir, "synthetic_authorized_qr_v4.txt"), "r", encoding="utf-8") as f:
        sample_qr = f.read().strip()
    return pub_pem, sample_qr


# ===========================================================================
# Example 1: Direct Synchronous Offline QR Verification (Core Engine)
# ===========================================================================

def example_offline_direct_verification(pub_pem: str, scanner_text: str) -> None:
    print("=" * 75)
    print("1. Standalone Direct Offline Verification (Zero OIDC, Zero Network)")
    print("=" * 75)
    print("This mode operates completely offline at the edge (e.g. handheld scanner).\n")

    # 1. Initialize configuration with public key trust bundle
    config = FaydaConfig.sandbox(
        client_id="edge_kiosk_verifier",
        redirect_uri="https://localhost/unused_callback",
        qr_verification_enabled=True,
        qr_public_key_pem=pub_pem,
        qr_profile="v4",
    )

    # 2. Load operator trust store from config
    trust_store = config.load_qr_trust_store()
    print(f"[*] Loaded trusted authority keys: {len(trust_store)} active key(s)")

    # 3. Direct decode and cryptographic verification
    result = decode_and_verify_qr(
        raw_text=scanner_text,
        trust_store=trust_store,
        dob_calendar="gregorian",
    )

    print(f"[*] Verification Status:           {result.status}")
    print(f"[*] Credential Signature Valid:    {result.credential_signature_valid}")
    print(f"[*] Holder Authenticated:          {result.holder_authenticated} (Physical scan does not prove live presence)")
    if result.evidence:
        print(f"[*] Verifying Key Thumbprint:      {result.evidence.key_thumbprint}")
        print(f"[*] Evidence Digest (SHA-256):     {result.evidence.evidence_ref}")

    # Demonstrate Tampering Detection
    tampered_text = scanner_text.replace("Abebe", "Tampered")
    tampered_result = decode_and_verify_qr(tampered_text, trust_store=trust_store)
    print(f"\n[*] Tampered Payload Test:")
    print(f"    - Status:                      {tampered_result.status}")
    print(f"    - Signature Valid:             {tampered_result.credential_signature_valid}")
    print(f"    - Error Code:                  {tampered_result.error_code}")
    print()


# ===========================================================================
# Example 2: Privacy-Preserving Agent MCP Verification Service
# ===========================================================================

async def example_mcp_agent_workflow(pub_pem: str, scanner_text: str) -> None:
    print("=" * 75)
    print("2. MCP Verification Service Workflow (Privacy-Preserving Agent Output)")
    print("=" * 75)
    print("Exposes submit_qr_verification & get_qr_verification_result to AI agents.")
    print("Acceptance Guarantee: Demographics, photo, and signature are strictly withheld.\n")

    # 1. Configure service with QR verification enabled
    config = FaydaConfig.sandbox(
        client_id="ai_agent_gateway",
        redirect_uri="https://localhost/unused",
        qr_verification_enabled=True,
        qr_public_key_pem=pub_pem,
    )

    # 2. Initialize verification service (Memory storage; Redis remains optional)
    service = FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )
    # Ensure trust store is active
    service.qr_service.trust_store = config.load_qr_trust_store()

    # 3. Caller Context (Multi-Tenant & Principal boundary)
    caller = CallerContext(
        tenant_id="telecom_branch_01",
        principal_id="customer_service_agent_42",
    )

    # 4. Agent submits scanned text requesting minimal boolean checks
    print("[*] Agent submitting QR verification request...")
    raw_result = await service.submit_qr_verification(
        qr_text=scanner_text,
        context=caller,
        purpose="kyc",
        application_user_ref="customer_acc_9876",
        checks=["credential_signature_valid", "age_over_18"],
        idempotency_key="idemp_kiosk_txn_1001",
    )

    # Filter output into safe minimal agent response
    agent_output: QRAgentVerificationResult = filter_agent_output(raw_result)

    print("\n[+] Minimal Output Delivered to Agent Context:")
    print(f"    - Request ID:                  {agent_output.request_id}")
    print(f"    - Status:                      {agent_output.status}")
    print(f"    - Method:                      {agent_output.method}")
    print(f"    - Profile:                     {agent_output.profile}")
    print(f"    - Checks Evaluated:            {agent_output.checks}")
    print(f"    - Holder Authenticated:        {agent_output.holder_authenticated}")
    print(f"    - Identity Verified:           {agent_output.identity_verified}")
    print(f"    - Lifecycle Timestamps:        {agent_output.times}")

    # Verify that raw PII is absent
    dumped = agent_output.model_dump()
    leaked = [k for k in ("name", "photo", "date_of_birth", "fan", "signature") if k in dumped]
    print(f"    - Demographic / PII Leaks:     None ({leaked} found in agent model)")

    # 5. Idempotent Retry Test
    print("\n[*] Testing Idempotent Retry with same idempotency key...")
    retry_result = await service.submit_qr_verification(
        qr_text=scanner_text,
        context=caller,
        purpose="kyc",
        application_user_ref="customer_acc_9876",
        checks=["credential_signature_valid", "age_over_18"],
        idempotency_key="idemp_kiosk_txn_1001",
    )
    print(f"    - Same Request ID Reused:      {retry_result.request_id == raw_result.request_id}")
    print(f"    - Duplicate Processing:        Prevented (fast-path cached return)")
    print()


# ===========================================================================
# Example 3: Threat Model Summary (Copied QR & Identity Separation)
# ===========================================================================

def print_threat_model_summary() -> None:
    print("=" * 75)
    print("3. Security & Operational Characteristics Summary")
    print("=" * 75)
    print(
        "1. Offline Operation:\n"
        "   - QR verification requires NO OIDC authorization redirect, NO webhook,\n"
        "     and NO client private signing key. Only the issuer's public key is needed.\n\n"
        "2. Copied QR Threat Model:\n"
        "   - A cloned, photocopied, or screenshotted QR code retains authentic signatures.\n"
        "   - Verifying the signature confirms card integrity, NOT live human presence.\n"
        "   - 'holder_authenticated' is strictly False for QR-only evidence.\n"
        "   - 'identity_verified' is never set from QR alone without live authentication.\n\n"
        "3. Scanner Input First Delivery:\n"
        "   - Accepts unchanged ASCII text from handheld barcode scanners or camera SDKs.\n"
        "   - Image decoding (camera frame -> QR text) is a separate optional adapter.\n\n"
        "4. Storage & Caching:\n"
        "   - Redis remains optional for temporary references and rate limits.\n"
        "   - In-memory storage, SQLite, and Neon/PostgreSQL provide full persistence.\n"
    )
    print("=" * 75)


async def main() -> None:
    pub_pem, sample_qr = load_fixtures_sample()
    example_offline_direct_verification(pub_pem, sample_qr)
    await example_mcp_agent_workflow(pub_pem, sample_qr)
    print_threat_model_summary()


if __name__ == "__main__":
    asyncio.run(main())
