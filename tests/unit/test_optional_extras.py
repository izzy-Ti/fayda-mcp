"""Unit tests for optional extra dependency behavior and isolation."""

import sys
from unittest.mock import patch
import pytest

from fayda_mcp import FaydaConfig, FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


class TestOptionalExtrasIsolation:
    """Verifies that optional extras fail with helpful instructions when their dependencies are absent."""

    def test_fastapi_extra_missing_raises_import_error(self) -> None:
        """When fastapi is uninstalled, fastapi integration functions raise an actionable ImportError."""
        from fayda_mcp.integrations import fastapi as fastapi_mod

        config = FaydaConfig.sandbox("client", "http://localhost/cb")
        service = FaydaVerificationService(config, MemorySessionStore(), MemoryResultRepository())

        # Simulate missing fastapi module
        with patch.object(fastapi_mod, "APIRouter", None), patch.object(fastapi_mod, "JSONResponse", None):
            with pytest.raises(ImportError) as exc_info:
                fastapi_mod.create_callback_router(
                    service=service,
                    session_binding_hook=lambda req: "token",
                )
            assert "pip install 'fayda-mcp[fastapi]'" in str(exc_info.value)

    def test_redis_extra_missing_raises_import_error(self) -> None:
        """When redis is uninstalled, RedisSessionStore raises an actionable ImportError."""
        from fayda_mcp.storage import redis as redis_mod

        with patch.object(redis_mod, "aioredis", None):
            with pytest.raises(ImportError) as exc_info:
                redis_mod.RedisSessionStore(redis_client=None)
            assert "pip install 'fayda-mcp[redis]'" in str(exc_info.value)

    def test_postgres_extra_missing_raises_import_error(self) -> None:
        """When sqlalchemy is uninstalled, PostgresResultRepository raises an actionable ImportError."""
        from fayda_mcp.storage import postgres as postgres_mod

        with patch.object(postgres_mod, "AsyncSession", None):
            with pytest.raises(ImportError) as exc_info:
                postgres_mod.PostgresResultRepository(session_factory=None)  # type: ignore
            assert "pip install 'fayda-mcp[postgres]'" in str(exc_info.value)
