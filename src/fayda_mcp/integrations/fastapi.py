"""Optional FastAPI callback router integration."""

from typing import Any, Callable, Optional

try:
    from fastapi import APIRouter, Request, status
    from fastapi.responses import JSONResponse
except ImportError:
    APIRouter = None  # type: ignore
    Request = None  # type: ignore
    JSONResponse = None  # type: ignore

from fayda_mcp.service import FaydaVerificationService


def create_callback_router(
    service: FaydaVerificationService,
    prefix: str = "/auth/fayda",
    on_success: Optional[Callable[[Any], Any]] = None,
    on_error: Optional[Callable[[Exception], Any]] = None,
) -> Any:
    """Build a FastAPI APIRouter handling registered Fayda eSignet callback.

    Requires 'fastapi' extra installed: pip install 'fayda-mcp[fastapi]'
    """
    if APIRouter is None:
        raise ImportError(
            "FastAPI extra is not installed. Install with: pip install 'fayda-mcp[fastapi]'"
        )

    router = APIRouter(prefix=prefix, tags=["fayda-callback"])

    @router.get("/callback")
    async def fayda_callback(request: Request, code: str = "", state: str = ""):
        browser_binding = request.cookies.get("fayda_session")
        try:
            result = await service.complete_verification(
                code=code,
                state=state,
                browser_binding=browser_binding,
            )
            if on_success:
                return await on_success(result) if callable(on_success) else on_success
            return result
        except Exception as exc:
            if on_error:
                return await on_error(exc) if callable(on_error) else on_error
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "callback_failed", "message": str(exc)},
            )

    return router
