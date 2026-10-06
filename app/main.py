"""FastAPI application factory and MCP mount."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from app.core.config import get_settings
from app.lifespan import application_lifespan, create_mcp_app
from app.api.router import api_router
# Import tools to ensure tool registration on the FastMCP instance
import app.mcp.tools  # noqa: F401


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    settings = get_settings()

    # Create the standalone FastMCP streamable HTTP sub-application
    mcp_app = create_mcp_app()

    app = FastAPI(
        title=settings.APP_NAME,
        description="Fayda MCP Bridge for privacy-preserving citizen verification via eSignet.",
        version="0.1.0",
        lifespan=application_lifespan,
    )

    # Attach mcp_app to app.state so the combined lifespan can manage it
    app.state.mcp_app = mcp_app

    # Middleware: Trusted hosts
    if settings.ALLOWED_HOSTS:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.ALLOWED_HOSTS,
        )

    # Middleware: CORS
    if settings.CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.CORS_ORIGINS,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Central REST & Health API routes
    app.include_router(api_router)

    # Mount FastMCP HTTP app (exposing /mcp streamable endpoint)
    app.mount("", mcp_app)

    return app


app = create_app()
