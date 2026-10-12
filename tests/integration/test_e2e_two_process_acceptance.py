"""End-to-end two-process acceptance scenario sharing Redis and Neon.

Scenario specification:
1. Launch two test processes (Process A and Process B) sharing Redis and Neon.
2. Start a verification request in Process A.
3. Complete the registered browser callback in Process B with valid session binding.
4. Retrieve the result in Process A.
5. Restart Process A and retrieve an unexpired completed result again.
6. Retry the same start with the same idempotency key and verify no new flow.
7. Replay the callback in Process B and verify rejection.
"""

import asyncio
import http.server
import json
import multiprocessing
import os
import sys
import threading
import time
import urllib.parse
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import dotenv
import jwt
import pytest

from fayda_mcp import (
    CallerContext,
    FaydaConfig,
    FaydaVerificationService,
    InvalidStateError,
)
from fayda_mcp.storage.postgres import PostgresAuditLogger, PostgresResultRepository
from fayda_mcp.storage.redis import RedisSessionStore, parse_redis_url


# Global state holder for the Mock OIDC HTTP Server
_OIDC_SERVER_STATE: Dict[str, Any] = {
    "current_nonce": "",
    "userinfo_sub": "citizen_sub_e2e_42",
}


class MockOidcHttpHandler(http.server.BaseHTTPRequestHandler):
    """Local OIDC provider handling /jwks, /token, and /userinfo."""

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Quiet logging

    def do_GET(self) -> None:
        if self.path == "/jwks":
            jwk = self.server.provider_jwk  # type: ignore
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"keys": [jwk]}).encode("utf-8"))
        elif self.path == "/userinfo":
            sub = _OIDC_SERVER_STATE.get("userinfo_sub", "citizen_sub_e2e_42")
            userinfo_payload = {
                "sub": sub,
                "name": "Abebe Bikila",
                "birthdate": "1990-01-01",
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(userinfo_payload).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        if self.path == "/token":
            content_len = int(self.headers.get("Content-Length", 0))
            self.rfile.read(content_len)

            now = int(time.time())
            nonce = _OIDC_SERVER_STATE.get("current_nonce", "")
            port = self.server.server_port  # type: ignore
            prov_priv = self.server.provider_private_key  # type: ignore
            kid = self.server.provider_jwk["kid"]  # type: ignore

            id_payload = {
                "iss": f"http://127.0.0.1:{port}",
                "aud": "e2e_client_app",
                "sub": _OIDC_SERVER_STATE.get("userinfo_sub", "citizen_sub_e2e_42"),
                "nonce": nonce,
                "iat": now,
                "exp": now + 600,
            }
            id_token = jwt.encode(
                id_payload,
                prov_priv,
                algorithm="RS256",
                headers={"kid": kid},
            )
            resp_data = {
                "access_token": "mock_e2e_access_token_xyz",
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": 600,
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp_data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def _run_mock_oidc_server(prov_priv: Any, prov_jwk: Dict[str, Any]) -> tuple[http.server.ThreadingHTTPServer, int]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockOidcHttpHandler)
    server.provider_private_key = prov_priv  # type: ignore
    server.provider_jwk = prov_jwk  # type: ignore
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port


# ---------------------------------------------------------------------------
# Worker process functions (run in dedicated spawned child processes)
# ---------------------------------------------------------------------------

def _worker_process_a_entrypoint(
    pipe: Any,
    db_url: str,
    redis_url: str,
    config_dict: Dict[str, Any],
) -> None:
    """Process A entrypoint: starts requests, retrieves results, and re-queries on demand."""
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    async def _runner() -> None:
        cfg = FaydaConfig(**config_dict)
        sessions = RedisSessionStore.from_url(redis_url)
        results = PostgresResultRepository.from_url(db_url)
        audit = PostgresAuditLogger(session_factory=results.session_factory)
        service = FaydaVerificationService(
            config=cfg,
            sessions=sessions,
            results=results,
            audit=audit,
        )

        try:
            while True:
                msg = await asyncio.to_thread(pipe.recv)
                action = msg.get("action")

                if action == "start":
                    tenant_id = msg.get("tenant_id", "e2e-tenant")
                    principal_id = msg.get("principal_id", "e2e-agent-a")
                    browser_binding = msg.get("browser_binding")
                    ctx = CallerContext(
                        tenant_id=tenant_id,
                        principal_id=principal_id,
                        browser_binding=browser_binding,
                    )
                    try:
                        resp = await service.start_verification(
                            context=ctx,
                            purpose=msg.get("purpose", "onboarding"),
                            checks=msg.get("checks", ["identity_verified"]),
                            application_user_ref=msg.get("application_user_ref", "user-e2e-1"),
                            idempotency_key=msg.get("idempotency_key"),
                        )
                        pipe.send({
                            "ok": True,
                            "request_id": resp.request_id,
                            "authorization_url": resp.authorization_url,
                            "expires_at": resp.expires_at,
                        })
                    except Exception as exc:
                        pipe.send({
                            "ok": False,
                            "error_type": type(exc).__name__,
                            "error": str(exc),
                        })

                elif action == "get_result":
                    tenant_id = msg.get("tenant_id", "e2e-tenant")
                    principal_id = msg.get("principal_id", "e2e-agent-a")
                    ctx = CallerContext(tenant_id=tenant_id, principal_id=principal_id)
                    try:
                        res = await service.get_verification_result(ctx, msg["request_id"])
                        pipe.send({
                            "ok": True,
                            "request_id": res.request_id,
                            "status": res.status,
                            "checks": res.checks,
                            "verified_at": res.verified_at,
                        })
                    except Exception as exc:
                        pipe.send({
                            "ok": False,
                            "error_type": type(exc).__name__,
                            "error": str(exc),
                        })

                elif action == "stop":
                    await service.aclose()
                    await sessions.close()
                    await results.close()
                    await audit.close()
                    pipe.send({"ok": True, "stopped": True})
                    break
        finally:
            await service.aclose()
            await sessions.close()
            await results.close()
            await audit.close()

    asyncio.run(_runner())


def _worker_process_b_entrypoint(
    pipe: Any,
    db_url: str,
    redis_url: str,
    config_dict: Dict[str, Any],
) -> None:
    """Process B entrypoint: completes browser callbacks with session binding."""
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    async def _runner() -> None:
        cfg = FaydaConfig(**config_dict)
        sessions = RedisSessionStore.from_url(redis_url)
        results = PostgresResultRepository.from_url(db_url)
        audit = PostgresAuditLogger(session_factory=results.session_factory)
        service = FaydaVerificationService(
            config=cfg,
            sessions=sessions,
            results=results,
            audit=audit,
        )

        try:
            while True:
                msg = await asyncio.to_thread(pipe.recv)
                action = msg.get("action")

                if action == "complete":
                    code = msg.get("code")
                    state = msg.get("state")
                    browser_binding = msg.get("browser_binding")
                    try:
                        res = await service.complete_verification(
                            code=code,
                            state=state,
                            browser_binding=browser_binding,
                        )
                        pipe.send({
                            "ok": True,
                            "request_id": res.request_id,
                            "status": res.status,
                            "checks": res.checks,
                            "verified_at": res.verified_at,
                        })
                    except Exception as exc:
                        pipe.send({
                            "ok": False,
                            "error_type": type(exc).__name__,
                            "error": str(exc),
                        })

                elif action == "stop":
                    await service.aclose()
                    await sessions.close()
                    await results.close()
                    await audit.close()
                    pipe.send({"ok": True, "stopped": True})
                    break
        finally:
            await service.aclose()
            await sessions.close()
            await results.close()
            await audit.close()

    asyncio.run(_runner())


# ---------------------------------------------------------------------------
# Acceptance Test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_end_to_end_two_process_acceptance() -> None:
    """Full End-to-End Acceptance Scenario:

    - Launch two test processes sharing Redis and Neon.
    - Start a request in Process A.
    - Complete the registered browser callback in Process B with valid session binding.
    - Retrieve the result in Process A.
    - Restart Process A and retrieve an unexpired completed result again.
    - Retry the same start with the same idempotency key and verify no new flow.
    - Replay the callback and verify rejection.
    """
    env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env")
    env_vals = dotenv.dotenv_values(env_file) if os.path.exists(env_file) else {}

    db_url = os.environ.get("DATABASE_URL") or env_vals.get("DATABASE_URL")
    redis_url = os.environ.get("REDIS_URL") or env_vals.get("REDIS_URL")

    if not db_url or not redis_url:
        pytest.skip("Shared Redis and Neon (DATABASE_URL and REDIS_URL) required for multi-process E2E acceptance test")

    # 1. Setup Mock OIDC Provider Keys
    prov_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    prov_pub = prov_priv.public_key()
    prov_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(prov_pub))
    prov_jwk["kid"] = "prov-kid-e2e-acceptance"

    # Setup RP Client Private Key for client assertion
    rp_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rp_pem = rp_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    server, port = _run_mock_oidc_server(prov_priv, prov_jwk)
    issuer_url = f"http://127.0.0.1:{port}"

    config_dict = {
        "client_id": "e2e_client_app",
        "redirect_uri": "http://127.0.0.1:3000/callback",
        "issuer": issuer_url,
        "authorization_endpoint": f"{issuer_url}/authorize",
        "token_endpoint": f"{issuer_url}/token",
        "userinfo_endpoint": f"{issuer_url}/userinfo",
        "jwks_uri": f"{issuer_url}/jwks",
        "signing_key": rp_pem,
        "allowed_algorithms": ["RS256"],
        "session_ttl_seconds": 300,
        "result_ttl_seconds": 600,
    }

    mp_ctx = multiprocessing.get_context("spawn")

    # 2. Launch Process A and Process B
    pipe_parent_a, pipe_child_a = mp_ctx.Pipe()
    proc_a = mp_ctx.Process(
        target=_worker_process_a_entrypoint,
        args=(pipe_child_a, db_url, redis_url, config_dict),
    )
    proc_a.start()

    pipe_parent_b, pipe_child_b = mp_ctx.Pipe()
    proc_b = mp_ctx.Process(
        target=_worker_process_b_entrypoint,
        args=(pipe_child_b, db_url, redis_url, config_dict),
    )
    proc_b.start()

    unique_suffix = f"{int(time.time())}_{os.getpid()}"
    idempotency_key = f"idemp_e2e_{unique_suffix}"
    session_binding = f"browser_sess_bound_{unique_suffix}"
    app_user_ref = f"user_app_{unique_suffix}"

    try:
        # STEP 1: Start request in Process A
        pipe_parent_a.send({
            "action": "start",
            "tenant_id": "e2e-tenant",
            "principal_id": "e2e-agent-a",
            "browser_binding": session_binding,
            "purpose": "onboarding",
            "checks": ["identity_verified"],
            "application_user_ref": app_user_ref,
            "idempotency_key": idempotency_key,
        })
        start_resp = pipe_parent_a.recv()
        assert start_resp["ok"] is True, f"Process A start failed: {start_resp}"
        request_id = start_resp["request_id"]
        auth_url = start_resp["authorization_url"]
        assert request_id.startswith("vr_")
        assert "state=" in auth_url

        # Parse state and nonce from the authorization URL
        parsed_url = urllib.parse.urlparse(auth_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        state = query_params["state"][0]
        nonce = query_params["nonce"][0]

        # Register nonce with mock OIDC server
        _OIDC_SERVER_STATE["current_nonce"] = nonce

        # STEP 2: Complete the registered browser callback in Process B with valid session binding
        pipe_parent_b.send({
            "action": "complete",
            "code": "auth_code_e2e_valid",
            "state": state,
            "browser_binding": session_binding,
        })
        comp_resp = pipe_parent_b.recv()
        assert comp_resp["ok"] is True, f"Process B callback failed: {comp_resp}"
        assert comp_resp["status"] == "verified"
        assert comp_resp["checks"]["identity_verified"] is True
        assert comp_resp["request_id"] == request_id

        # STEP 3: Retrieve the result in Process A
        pipe_parent_a.send({
            "action": "get_result",
            "tenant_id": "e2e-tenant",
            "principal_id": "e2e-agent-a",
            "request_id": request_id,
        })
        get_resp = pipe_parent_a.recv()
        assert get_resp["ok"] is True, f"Process A get_result failed: {get_resp}"
        assert get_resp["status"] == "verified"
        assert get_resp["checks"]["identity_verified"] is True
        assert get_resp["request_id"] == request_id

        # STEP 4: Restart Process A and retrieve an unexpired completed result again
        pipe_parent_a.send({"action": "stop"})
        stop_resp_a = pipe_parent_a.recv()
        assert stop_resp_a["ok"] is True
        proc_a.join(timeout=5)
        assert not proc_a.is_alive()

        # Spawn restarted Process A (Process A')
        pipe_parent_a2, pipe_child_a2 = mp_ctx.Pipe()
        proc_a2 = mp_ctx.Process(
            target=_worker_process_a_entrypoint,
            args=(pipe_child_a2, db_url, redis_url, config_dict),
        )
        proc_a2.start()

        # Retrieve unexpired completed result in the restarted Process A'
        pipe_parent_a2.send({
            "action": "get_result",
            "tenant_id": "e2e-tenant",
            "principal_id": "e2e-agent-a",
            "request_id": request_id,
        })
        get_resp2 = pipe_parent_a2.recv()
        assert get_resp2["ok"] is True, f"Restarted Process A' get_result failed: {get_resp2}"
        assert get_resp2["status"] == "verified"
        assert get_resp2["checks"]["identity_verified"] is True
        assert get_resp2["request_id"] == request_id

        # STEP 5: Retry the same start with the same idempotency key and verify no new flow
        pipe_parent_a2.send({
            "action": "start",
            "tenant_id": "e2e-tenant",
            "principal_id": "e2e-agent-a",
            "browser_binding": session_binding,
            "purpose": "onboarding",
            "checks": ["identity_verified"],
            "application_user_ref": app_user_ref,
            "idempotency_key": idempotency_key,
        })
        retry_start_resp = pipe_parent_a2.recv()
        assert retry_start_resp["ok"] is True
        assert retry_start_resp["request_id"] == request_id, (
            f"Expected same request_id '{request_id}' on retry, got '{retry_start_resp['request_id']}'"
        )

        # STEP 6: Replay the callback in Process B and verify rejection
        pipe_parent_b.send({
            "action": "complete",
            "code": "auth_code_e2e_valid",
            "state": state,
            "browser_binding": session_binding,
        })
        replay_resp = pipe_parent_b.recv()
        assert replay_resp["ok"] is False, "Expected callback replay to be rejected, but it succeeded!"
        assert replay_resp["error_type"] == "InvalidStateError", (
            f"Expected InvalidStateError on callback replay, got {replay_resp['error_type']}"
        )

        # Clean shutdown of restarted Process A'
        pipe_parent_a2.send({"action": "stop"})
        pipe_parent_a2.recv()
        proc_a2.join(timeout=5)

    finally:
        # Ensure child processes are terminated
        try:
            pipe_parent_b.send({"action": "stop"})
            pipe_parent_b.recv()
        except Exception:
            pass

        if proc_a.is_alive():
            proc_a.terminate()
            proc_a.join(timeout=2)
        if proc_b.is_alive():
            proc_b.terminate()
            proc_b.join(timeout=2)

        server.shutdown()
        server.server_close()
