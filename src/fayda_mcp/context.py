"""Caller and host application context bindings."""

from typing import List, Optional
from pydantic import BaseModel, Field


class CallerContext(BaseModel):
    """Context identifying the authenticated agent or tenant making verification requests."""

    tenant_id: str = Field(default="default", description="Tenant or organization identifier")
    principal_id: str = Field(default="anonymous", description="Authenticated caller/agent identifier")
    scopes: List[str] = Field(default_factory=lambda: ["verification:create", "verification:read"])
    application_user_ref: Optional[str] = Field(None, description="Host application user identifier")
    browser_binding: Optional[str] = Field(None, description="Optional cookie or session token binding")
