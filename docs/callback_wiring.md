# Callback Wiring & Session Binding

In the Fayda eSignet OpenID Connect flow, citizens authorize in their web browser and are redirected back to the host application's registered `redirect_uri`.

## Why Host Session Binding is Required

Without session binding, an attacker could initiate an identity verification flow and trick a victim into completing it, or hijack another user's verification state (CSRF / session injection).

`fayda-mcp` requires a **host session-binding hook** to ensure:
1. When verification is started, the caller context records a secure browser binding identifier (e.g. `session_id`, cookie HMAC, or authenticated user reference).
2. When the user returns from Fayda eSignet to `/callback`, the callback router invokes the host hook to extract the browser identifier from the HTTP request.
3. If the returned session does not match the bound identifier, the callback is rejected with `InvalidStateError`.

---

## FastAPI Integration

Use `create_callback_router` to mount the callback handler on your FastAPI app:

```python
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fayda_mcp.integrations.fastapi import create_callback_router

app = FastAPI()

# 1. Define host session-binding hook
def resolve_browser_session(request: Request) -> str | None:
    # Extracts the host session cookie from incoming citizen request
    return request.cookies.get("app_session_id")

# 2. Define on_success redirect hook
async def on_verification_complete(request: Request, result) -> RedirectResponse:
    # Redirect citizen to host onboarding completion screen
    return RedirectResponse(
        url=f"/onboarding/complete?request_id={result.request_id}&status={result.status}",
        status_code=303,
    )

# 3. Mount callback router
router = create_callback_router(
    service=service,
    session_binding_hook=resolve_browser_session,
    on_success=on_verification_complete,
)

app.include_router(router)
```

---

## Registered Redirect URI Alignment

By default, `create_callback_router` inspects `service.config.redirect_uri` to determine the exact path to mount:
- If `redirect_uri="https://my-app.example/auth/fayda/callback"`, the router mounts on `/auth/fayda/callback`.
- If `redirect_uri="http://localhost:8000/callback"`, the router mounts on `/callback`.

You can also pass explicit `prefix` and `callback_path` arguments if you mount behind reverse proxies or API gateways.

---

## Error Handling

When Fayda returns an error (such as a citizen canceling consent), Fayda redirects with query parameters `?error=access_denied&error_description=...`.
The router automatically parses provider errors and passes them to `on_error` if configured, or returns an HTTP 400 Bad Request JSON response.
