"""eSignet provider callback endpoint."""

from fastapi import APIRouter

router = APIRouter(prefix="/auth/fayda", tags=["fayda-callback"])


@router.get("/callback")
async def fayda_callback(code: str = "", state: str = ""):
    """Registered provider callback endpoint."""
    return {"message": "Fayda callback placeholder", "state_received": bool(state)}
