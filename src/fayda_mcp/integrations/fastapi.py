"""Optional FastAPI callback router and combined FastMCP lifecycle integration.

Requires 'fastapi' extra installed: pip install 'fayda-mcp[fastapi]'
"""

from contextlib import AsyncExitStack, asynccontextmanager
import inspect
from typing import Any, AsyncIterator, Awaitable, Callable, Optional, Union
import urllib.parse

try:
    from fastapi import APIRouter, FastAPI, Request, status
    from fastapi.responses import JSONResponse, RedirectResponse
except ImportError:
    APIRouter = None  # type: ignore
    FastAPI = None  # type: ignore
    Request = None  # type: ignore
    JSONResponse = None  # type: ignore
    RedirectResponse = None  # type: ignore

from fayda_mcp.exceptions import (
    AuthenticationError,
    ConfigurationError,
    InvalidStateError,
    ProviderError,
    StateConsumedError,
    TokenValidationError,
)
from fayda_mcp.schemas import VerificationResult
from fayda_mcp.service import FaydaVerificationService


def create_callback_router(
    service: FaydaVerificationService,
    session_binding_hook: Callable[[Any], Union[Optional[str], Awaitable[Optional[str]]]],
    prefix: Optional[str] = None,
    callback_path: Optional[str] = None,
    on_success: Optional[Callable[[Any, VerificationResult], Any]] = None,
    on_error: Optional[Callable[[Any, Exception], Any]] = None,
) -> Any:
    """Build a FastAPI APIRouter handling the registered Fayda eSignet callback.

    Requires host session-binding hook to securely link browser requests to verification state.
    Does NOT ship or render any UI templates.

    Args:
        service: Initialized FaydaVerificationService.
        session_binding_hook: Required host hook resolving browser session token/cookie.
        prefix: Optional route prefix. If None, inferred from service.config.redirect_uri.
        callback_path: Optional callback endpoint path. If None, inferred from service.config.redirect_uri.
        on_success: Optional hook executed on successful verification.
        on_error: Optional hook executed on verification failure.
    """
    if APIRouter is None:
        raise ImportError(
            "FastAPI extra is not installed. Install with: pip install 'fayda-mcp[fastapi]'"
        )

    if session_binding_hook is None or not callable(session_binding_hook):
        raise ConfigurationError(
            "Host session-binding hook is required to bind browser sessions securely."
        )

    # Incur registered URI path from config if not explicitly provided
    if prefix is None and callback_path is None:
        parsed_uri = urllib.parse.urlparse(service.config.redirect_uri)
        registered_path = parsed_uri.path or "/callback"
        route_prefix = ""
        route_path = registered_path
    else:
        route_prefix = prefix or ""
        route_path = callback_path or "/callback"

    router = APIRouter(prefix=route_prefix, tags=["fayda-verification"])

    @router.get(route_path)
    async def fayda_callback(
        request: Request,
        code: str = "",
        state: str = "",
        error: Optional[str] = None,
        error_description: Optional[str] = None,
    ):
        # 1. Handle error response from provider redirect
        if error:
            exc = ProviderError(f"OAuth error from provider: {error} - {error_description or ''}")
            if on_error:
                res = on_error(request, exc)
                return await res if inspect.isawaitable(res) else res
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": error, "description": error_description},
            )

        # 2. Extract host browser binding via required hook
        try:
            hook_res = session_binding_hook(request)
            browser_binding = await hook_res if inspect.isawaitable(hook_res) else hook_res
        except Exception as hook_err:
            if on_error:
                res = on_error(request, hook_err)
                return await res if inspect.isawaitable(res) else res
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "session_binding_failed", "message": str(hook_err)},
            )

        # 3. Complete verification atomically in service
        try:
            result = await service.complete_verification(
                code=code,
                state=state,
                browser_binding=browser_binding,
            )
            if on_success:
                res = on_success(request, result)
                return await res if inspect.isawaitable(res) else res
            return result
        except Exception as exc:
            if on_error:
                res = on_error(request, exc)
                return await res if inspect.isawaitable(res) else res

            status_code = status.HTTP_400_BAD_REQUEST
            if isinstance(exc, (InvalidStateError, StateConsumedError)):
                status_code = status.HTTP_409_CONFLICT
            elif isinstance(exc, (AuthenticationError, TokenValidationError)):
                status_code = status.HTTP_401_UNAUTHORIZED

            return JSONResponse(
                status_code=status_code,
                content={"error": type(exc).__name__, "message": str(exc)},
            )

    return router


def create_combined_lifespan(
    service: Optional[FaydaVerificationService] = None,
    mcp_server: Optional[Any] = None,
    host_lifespan: Optional[Callable[[Any], Any]] = None,
) -> Callable[[Any], AsyncIterator[None]]:
    """Build an async combined lifespan context manager for FastAPI and FastMCP.

    Ensures service resources, MCP server lifespans, and host lifespans run cleanly.
    """

    @asynccontextmanager
    async def combined_lifespan(app: Any) -> AsyncIterator[None]:
        async with AsyncExitStack() as stack:
            # 1. Manage service lifecycle if provided
            if service is not None:
                await stack.enter_async_context(service)

            # 2. Manage FastMCP lifespan
            if mcp_server is not None and hasattr(mcp_server, "lifespan"):
                await stack.enter_async_context(mcp_server.lifespan())

            # 3. Manage host-provided application lifespan
            if host_lifespan is not None:
                await stack.enter_async_context(host_lifespan(app))

            yield

    return combined_lifespan


def create_fastapi_app(
    service: FaydaVerificationService,
    session_binding_hook: Callable[[Any], Union[Optional[str], Awaitable[Optional[str]]]],
    mcp_server: Optional[Any] = None,
    host_lifespan: Optional[Callable[[Any], Any]] = None,
    mcp_path: str = "/mcp",
    on_success: Optional[Callable[[Any, VerificationResult], Any]] = None,
    on_error: Optional[Callable[[Any, Exception], Any]] = None,
    **fastapi_kwargs: Any,
) -> Any:
    """Convenience factory creating a ready-to-use FastAPI application.

    Combines service/MCP lifespans, mounts the FastMCP server, and registers the callback router.
    Shipped without any UI templates.
    """
    if FastAPI is None:
        raise ImportError(
            "FastAPI extra is not installed. Install with: pip install 'fayda-mcp[fastapi]'"
        )

    lifespan = create_combined_lifespan(
        service=service,
        mcp_server=mcp_server,
        host_lifespan=host_lifespan,
    )

    fastapi_kwargs.setdefault("title", "Fayda Verification Server")
    fastapi_kwargs["lifespan"] = lifespan

    app = FastAPI(**fastapi_kwargs)

    # Health check route
    @app.get("/health", tags=["system"])
    async def health_check():
        return {"status": "ok", "service": "fayda-mcp"}

    # Mount FastMCP server if provided
    if mcp_server is not None and hasattr(mcp_server, "http_app"):
        app.mount(mcp_path, mcp_server.http_app())

    # Include callback router matching registered redirect URI
    router = create_callback_router(
        service=service,
        session_binding_hook=session_binding_hook,
        on_success=on_success,
        on_error=on_error,
    )
    app.include_router(router)

    return app
