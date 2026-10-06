"""Caller and host application context bindings."""

import inspect
from typing import Any, Awaitable, Callable, List, Optional, Protocol, Union, runtime_checkable
from pydantic import BaseModel, Field


class CallerContext(BaseModel):
    """Context identifying the authenticated agent or tenant making verification requests."""

    tenant_id: str = Field(default="default", description="Tenant or organization identifier")
    principal_id: str = Field(default="anonymous", description="Authenticated caller/agent identifier")
    scopes: List[str] = Field(
        default_factory=lambda: ["verification:create", "verification:read", "verification:cancel"]
    )
    application_user_ref: Optional[str] = Field(default=None, description="Host application user identifier")
    browser_binding: Optional[str] = Field(default=None, description="Optional cookie or session token binding")


@runtime_checkable
class CallerAuthorizationAdapter(Protocol):
    """Host-provided adapter interface for caller identity resolution and action authorization."""

    async def resolve_context(self, tool_name: str, **kwargs: Any) -> CallerContext:
        """Resolve the CallerContext for the current invocation."""
        ...

    async def authorize(
        self,
        context: CallerContext,
        action: str,
        resource_id: Optional[str] = None,
    ) -> bool:
        """Check whether the resolved caller context is permitted to perform the action."""
        ...


class SimpleCallerAdapter:
    """Standard host caller adapter supporting static context, dynamic resolvers, and scope checks."""

    def __init__(
        self,
        context_resolver: Optional[Any] = None,
        authorizer: Optional[Any] = None,
        enforce_scopes: bool = True,
    ) -> None:
        self._resolver = context_resolver
        self._authorizer = authorizer
        self._enforce_scopes = enforce_scopes

    async def resolve_context(self, tool_name: str, **kwargs: Any) -> CallerContext:
        if self._resolver is None:
            return CallerContext()
        if isinstance(self._resolver, CallerContext):
            return self._resolver
        if callable(self._resolver):
            sig = inspect.signature(self._resolver)
            num_params = len(sig.parameters)
            if num_params == 0:
                res = self._resolver()
            elif num_params == 1:
                res = self._resolver(tool_name)
            else:
                res = self._resolver(tool_name, **kwargs)
            if inspect.isawaitable(res):
                return await res
            return res  # type: ignore
        return CallerContext()

    async def authorize(
        self,
        context: CallerContext,
        action: str,
        resource_id: Optional[str] = None,
    ) -> bool:
        # 1. Custom host authorizer check
        if self._authorizer is not None:
            res = self._authorizer(context, action, resource_id)
            if inspect.isawaitable(res):
                res = await res
            if not res:
                return False

        # 2. Scope enforcement
        if self._enforce_scopes:
            permitted = (
                action in context.scopes
                or "verification:*" in context.scopes
                or "admin" in context.scopes
                or "*" in context.scopes
            )
            if not permitted:
                return False

        return True
