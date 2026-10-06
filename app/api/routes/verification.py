"""Human verification consent and redirect endpoints."""

from fastapi import APIRouter

router = APIRouter(prefix="/verify", tags=["verification"])


@router.get("/{opaque_link}")
async def get_consent_page(opaque_link: str):
    """Render purpose and consent confirmation page."""
    return {"message": "Verification consent page placeholder", "link": opaque_link}


@router.post("/{opaque_link}/start")
async def start_oidc_flow(opaque_link: str):
    """CSRF-protected action redirecting to eSignet authorization endpoint."""
    return {"message": "OIDC redirect placeholder", "link": opaque_link}
