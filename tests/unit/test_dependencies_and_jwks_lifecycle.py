"""Unit tests for Task H1: Explicit dotenv loading, dependency bounds, and wheel assets."""

import glob
import os
import tempfile
import tomllib
import zipfile
import pytest

from fayda_mcp.config import FaydaConfig


class TestExplicitDotenvAndDependencies:
    """Acceptance tests for Task H1: Explicit dotenv, dependency bounds, and packaging."""

    def test_dotenv_declared_in_dependencies(self) -> None:
        """Acceptance requirement: Declare python-dotenv>=1.0.0 in dependencies."""
        pyproject_path = os.path.join(os.path.dirname(__file__), "..", "..", "pyproject.toml")
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)

        deps = data["project"]["dependencies"]
        dotenv_dep = next((d for d in deps if "python-dotenv" in d), None)
        assert dotenv_dep is not None, "python-dotenv must be declared in dependencies"
        assert ">=1.0.0" in dotenv_dep

    def test_fastmcp_pinned_to_supported_major_version(self) -> None:
        """Acceptance requirement: Pin supported major versions for FastMCP and test bounds."""
        pyproject_path = os.path.join(os.path.dirname(__file__), "..", "..", "pyproject.toml")
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)

        deps = data["project"]["dependencies"]
        fastmcp_dep = next((d for d in deps if "fastmcp" in d), None)
        assert fastmcp_dep is not None, "fastmcp must be declared in dependencies"
        assert "<5.0.0" in fastmcp_dep, "FastMCP must be pinned below major version 5.0.0"
        assert ">=4.0.0" in fastmcp_dep or ">=2.0.0" in fastmcp_dep

    def test_import_and_construction_do_not_silently_read_cwd_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Acceptance requirement: Import and config construction do not silently read cwd files."""
        # Clear any environment variables
        monkeypatch.delenv("FAYDA_CLIENT_ID", raising=False)
        monkeypatch.delenv("CLIENT_ID", raising=False)
        monkeypatch.delenv("FAYDA_REDIRECT_URI", raising=False)
        monkeypatch.delenv("REDIRECT_URI", raising=False)

        # Calling from_env() without explicit dotenv_path does NOT load .env from cwd
        with pytest.raises(Exception):
            FaydaConfig.from_env()

    def test_explicit_dotenv_loading_and_existing_env_wins(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Acceptance requirement: Load only explicitly requested file; existing process env wins."""
        monkeypatch.setenv("FAYDA_CLIENT_ID", "existing_proc_client_id")

        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
            f.write("FAYDA_CLIENT_ID=file_client_id\n")
            f.write("FAYDA_REDIRECT_URI=https://example.com/callback\n")
            f.write("FAYDA_ISSUER=https://example.com\n")
            f.write("FAYDA_AUTHORIZATION_ENDPOINT=https://example.com/auth\n")
            f.write("FAYDA_TOKEN_ENDPOINT=https://example.com/token\n")
            f.write("FAYDA_USERINFO_ENDPOINT=https://example.com/userinfo\n")
            f.write("FAYDA_JWKS_URI=https://example.com/jwks\n")
            temp_path = f.name

        try:
            cfg = FaydaConfig.from_env(dotenv_path=temp_path)
            # Existing process environment wins by default
            assert cfg.client_id == "existing_proc_client_id"
            # Non-colliding keys load from file
            assert cfg.redirect_uri == "https://example.com/callback"
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_configuration_output_redacts_all_secrets(self) -> None:
        """Acceptance requirement: Configuration output redacts all secrets."""
        cfg = FaydaConfig(
            client_id="cid_123",
            redirect_uri="https://app.example.com/cb",
            issuer="https://issuer.example.com",
            authorization_endpoint="https://issuer.example.com/auth",
            token_endpoint="https://issuer.example.com/token",
            userinfo_endpoint="https://issuer.example.com/userinfo",
            jwks_uri="https://issuer.example.com/jwks",
            signing_key="VERY_SENSITIVE_RSA_PRIVATE_KEY_MATERIAL",
        )

        # 1. repr() must not include the signing key
        cfg_repr = repr(cfg)
        assert "VERY_SENSITIVE_RSA_PRIVATE_KEY_MATERIAL" not in cfg_repr

        # 2. to_redacted_dict() replaces signing_key with [REDACTED]
        redacted = cfg.to_redacted_dict()
        assert redacted["signing_key"] == "[REDACTED]"
        assert "VERY_SENSITIVE_RSA_PRIVATE_KEY_MATERIAL" not in str(redacted)

    def test_portal_to_library_variable_mapping(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Acceptance requirement: Support portal-to-library variable mapping."""
        # Generic portal variables without FAYDA_ prefix
        monkeypatch.setenv("CLIENT_ID", "portal_client_xyz")
        monkeypatch.setenv("REDIRECT_URI", "https://portal.example.com/callback")
        monkeypatch.setenv("ISSUER", "https://esignet.portal.et")
        monkeypatch.setenv("AUTHORIZATION_ENDPOINT", "https://esignet.portal.et/auth")
        monkeypatch.setenv("TOKEN_ENDPOINT", "https://esignet.portal.et/token")
        monkeypatch.setenv("USERINFO_ENDPOINT", "https://esignet.portal.et/userinfo")
        monkeypatch.setenv("JWKS_URI", "https://esignet.portal.et/jwks")
        monkeypatch.setenv("SIGNING_KEY", "portal_private_key_material")

        # Clear FAYDA_ prefixed variables to ensure generic mapping works
        monkeypatch.delenv("FAYDA_CLIENT_ID", raising=False)
        monkeypatch.delenv("FAYDA_REDIRECT_URI", raising=False)
        monkeypatch.delenv("FAYDA_ISSUER", raising=False)
        monkeypatch.delenv("FAYDA_AUTHORIZATION_ENDPOINT", raising=False)
        monkeypatch.delenv("FAYDA_TOKEN_ENDPOINT", raising=False)
        monkeypatch.delenv("FAYDA_USERINFO_ENDPOINT", raising=False)
        monkeypatch.delenv("FAYDA_JWKS_URI", raising=False)
        monkeypatch.delenv("FAYDA_SIGNING_KEY", raising=False)

        cfg = FaydaConfig.from_env()
        assert cfg.client_id == "portal_client_xyz"
        assert cfg.redirect_uri == "https://portal.example.com/callback"
        assert cfg.issuer == "https://esignet.portal.et"
        assert cfg.signing_key == "portal_private_key_material"

    def test_wheel_package_data_includes_migrations(self) -> None:
        """Acceptance requirement: Verify wheel package data includes migrations."""
        dist_dir = os.path.join(os.path.dirname(__file__), "..", "..", "dist")
        wheels = glob.glob(os.path.join(dist_dir, "*.whl"))
        assert len(wheels) > 0, "No built wheel found in dist/ directory"

        with zipfile.ZipFile(wheels[0]) as z:
            names = z.namelist()
            migration_sqls = [n for n in names if n.endswith(".sql") and "migration" in n]
            assert len(migration_sqls) >= 2, f"Migrations must be packaged in wheel: found {migration_sqls}"
            assert any("0001_initial_schema.up.sql" in n for n in migration_sqls)
            assert any("0001_initial_schema.down.sql" in n for n in migration_sqls)

    def test_extras_remain_optional(self) -> None:
        """Acceptance requirement: Keep redis, Postgres/driver, and FastAPI extras optional."""
        pyproject_path = os.path.join(os.path.dirname(__file__), "..", "..", "pyproject.toml")
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)

        core_deps = [d.split(">=")[0].split("[")[0].strip().lower() for d in data["project"]["dependencies"]]
        assert "fastapi" not in core_deps
        assert "redis" not in core_deps
        assert "sqlalchemy" not in core_deps
        assert "psycopg" not in core_deps

        extras = data["project"]["optional-dependencies"]
        assert "fastapi" in extras
        assert "redis" in extras
        assert "postgres" in extras
