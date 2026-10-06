"""Admin onboarding endpoints for Fayda client credentials and connections."""

from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/admin/fayda-connections", tags=["admin-onboarding"])


@router.post("")
async def create_connection():
    """Register Fayda relying-party connection configuration."""
    return {"message": "Onboarding endpoint placeholder"}


@router.get("/{id}")
async def get_connection(id: str):
    """Retrieve connection metadata without secret keys."""
    return {"id": id, "status": "active"}


@router.post("/{id}/rotate-key")
async def rotate_key(id: str):
    """Rotate signing key version for tenant connection."""
    return {"id": id, "status": "rotated"}
