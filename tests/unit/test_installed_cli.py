"""Unit tests for Task M3: Installed CLI, subcommands, validation, and combined HTTP mode."""

import os
from unittest.mock import MagicMock, patch
import pytest

from fayda_mcp.cli import (
    init_caller_adapter,
    init_storage,
    main,
    validate_callback_uri,
    validate_port,
)
from fayda_mcp.config import FaydaConfig


@pytest.fixture
def valid_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set minimal valid environment for FaydaConfig."""
    monkeypatch.setenv("FAYDA_CLIENT_ID", "test_client_cli")
    monkeypatch.setenv("FAYDA_REDIRECT_URI", "https://app.example.com/callback")
    monkeypatch.setenv("FAYDA_ISSUER", "https://issuer.example.com")
    monkeypatch.setenv("FAYDA_AUTHORIZATION_ENDPOINT", "https://issuer.example.com/oauth/authorize")
    monkeypatch.setenv("FAYDA_TOKEN_ENDPOINT", "https://issuer.example.com/oauth/token")
    monkeypatch.setenv("FAYDA_USERINFO_ENDPOINT", "https://issuer.example.com/oauth/userinfo")
    monkeypatch.setenv("FAYDA_JWKS_URI", "https://issuer.example.com/.well-known/jwks.json")
    monkeypatch.setenv("FAYDA_SIGNING_KEY", "super_secret_signing_key_pem")


class TestInstalledCli:
    """Acceptance tests for installed CLI entry point and subcommands."""

    def test_help_exposes_all_subcommands(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Acceptance requirement: fayda-mcp --help displays help and subcommands."""
        code = main(["--help"])
        assert code == 0
        captured = capsys.readouterr()
        assert "run" in captured.out
        assert "check-config" in captured.out
        assert "migrate" in captured.out
        assert "diagnose" in captured.out
        assert "cleanup" in captured.out

    def test_no_subcommand_prints_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Invoking fayda-mcp without arguments prints help and returns 0."""
        code = main([])
        assert code == 0
        captured = capsys.readouterr()
        assert "Fayda MCP" in captured.out

    def test_check_config_prints_only_redacted_settings(
        self, valid_env: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Acceptance requirement: check-config prints only redacted settings without secrets."""
        code = main(["check-config"])
        assert code == 0
        captured = capsys.readouterr()

        assert "Configuration validated successfully" in captured.out
        assert "test_client_cli" in captured.out
        assert "https://app.example.com/callback" in captured.out
        assert "Configured (redacted)" in captured.out

        # Secrets must NEVER be printed
        assert "super_secret_signing_key_pem" not in captured.out
        assert "client_secret" not in captured.out

    def test_check_config_invalid_returns_nonzero(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Acceptance requirement: Invalid configuration returns nonzero."""
        monkeypatch.delenv("FAYDA_CLIENT_ID", raising=False)
        monkeypatch.delenv("CLIENT_ID", raising=False)

        # Pointing to an invalid or missing required field causes failure
        code = main(["check-config", "--callback-uri", "not-a-valid-url"])
        assert code != 0
        captured = capsys.readouterr()
        assert "Configuration error" in captured.err

    def test_validate_port_bounds(self) -> None:
        """Acceptance requirement: Validate port numbers within 1..65535."""
        assert validate_port(80) == 80
        assert validate_port(3000) == 3000
        assert validate_port(65535) == 65535

        with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
            validate_port(0)

        with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
            validate_port(70000)

        with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
            validate_port(-80)

    def test_validate_callback_uri(self) -> None:
        """Acceptance requirement: Validate callback URI format."""
        assert validate_callback_uri("https://app.example.com/cb") == "https://app.example.com/cb"
        assert validate_callback_uri("http://localhost:8000/callback") == "http://localhost:8000/callback"

        with pytest.raises(ValueError, match="Must be an absolute http or https URL"):
            validate_callback_uri("ftp://invalid.com")

        with pytest.raises(ValueError, match="Must be an absolute http or https URL"):
            validate_callback_uri("/relative/path")

        with pytest.raises(ValueError, match="Must be an absolute http or https URL"):
            validate_callback_uri("not-a-url")

    def test_validate_storage_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Acceptance requirement: Validate storage mode selection."""
        # Memory storage works without external services
        sessions, results = init_storage("memory")
        assert sessions.__class__.__name__ == "MemorySessionStore"
        assert results.__class__.__name__ == "MemoryResultRepository"

        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)

        # Redis storage without URL fails cleanly
        with pytest.raises(ValueError, match="Redis storage mode requires"):
            init_storage("redis", redis_url=None)

        # Postgres storage without URL fails cleanly
        with pytest.raises(ValueError, match="PostgreSQL storage mode requires"):
            init_storage("postgres", database_url=None)

        # Unsupported storage mode fails
        with pytest.raises(ValueError, match="Unsupported storage mode"):
            init_storage("cassandra")

    def test_validate_caller_adapter(self) -> None:
        """Acceptance requirement: Validate host authorization adapter."""
        # Default and strict
        adapter_default = init_caller_adapter("default")
        assert adapter_default.__class__.__name__ == "SimpleCallerAdapter"

        adapter_strict = init_caller_adapter("strict")
        assert adapter_strict.__class__.__name__ == "SimpleCallerAdapter"

        # Invalid adapter string
        with pytest.raises(ValueError, match="Invalid caller adapter"):
            init_caller_adapter("unsupported_mode")

    def test_run_stdio_mode(
        self, valid_env: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Acceptance requirement: stdout contains only protocol messages under stdio."""
        mock_server = MagicMock()
        mock_server.run = MagicMock(return_value=None)

        with patch("fayda_mcp.mcp.factory.create_mcp_server", return_value=mock_server):
            code = main(["run", "--transport", "stdio"])
            assert code == 0
            mock_server.run.assert_called_once_with(transport="stdio")

            # Check that nothing was printed to stdout before server.run
            captured = capsys.readouterr()
            assert captured.out == ""

    def test_run_combined_http_mode(self, valid_env: None) -> None:
        """Acceptance requirement: Local combined HTTP mode hosts MCP endpoint and registered callback."""
        mock_uvicorn = MagicMock()
        mock_uvicorn.run = MagicMock(return_value=None)

        with patch("uvicorn.run", mock_uvicorn.run):
            code = main(["run", "--transport", "http", "--host", "127.0.0.1", "--port", "3000"])
            assert code == 0
            mock_uvicorn.run.assert_called_once()
            args, kwargs = mock_uvicorn.run.call_args
            assert kwargs.get("host") == "127.0.0.1"
            assert kwargs.get("port") == 3000

    def test_run_invalid_port_returns_nonzero(
        self, valid_env: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Invalid port configuration returns nonzero."""
        code = main(["run", "--port", "99999"])
        assert code != 0
        captured = capsys.readouterr()
        assert "Invalid port" in captured.err

    def test_run_invalid_callback_uri_returns_nonzero(
        self, valid_env: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Invalid callback URI returns nonzero."""
        code = main(["run", "--callback-uri", "invalid-uri"])
        assert code != 0
        captured = capsys.readouterr()
        assert "Invalid callback URI" in captured.err

    def test_migrate_command_without_db_returns_nonzero(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """migrate without database URL returns nonzero."""
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.delenv("DATABASE_MIGRATION_URL", raising=False)

        code = main(["migrate"])
        assert code != 0
        captured = capsys.readouterr()
        assert "Database URL must be provided" in captured.err
