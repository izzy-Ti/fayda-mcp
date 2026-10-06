"""Schemas for business onboarding and Fayda connection management."""

from typing import List, Optional
from pydantic import BaseModel, Field


class FaydaConnectionCreate(BaseModel):
    """Payload to register a tenant's Fayda relying-party connection."""

    tenant_id: str
    environment: str = "sandbox"
    client_id: str
    secret_ref: str
    key_version: str = "1"
    allowed_scopes: List[str] = Field(default_factory=lambda: ["openid"])
    allowed_claims: List[str] = Field(default_factory=lambda: ["name", "birthdate"])


class FaydaConnectionResponse(BaseModel):
    """Safe connection metadata response excluding private keys."""

    id: str
    tenant_id: str
    environment: str
    client_id: str
    key_version: str
    status: str
