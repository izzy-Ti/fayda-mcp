"""Unit tests for Task E1: Release packaging, wheel/sdist audit, and supported-version checks."""

import glob
import os
import tarfile
import zipfile
import tomllib
import pytest

DIST_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "dist")


@pytest.fixture(scope="module")
def dist_artifacts() -> dict[str, str]:
    """Locates the built wheel and sdist archives."""
    wheels = glob.glob(os.path.join(DIST_DIR, "*.whl"))
    sdists = glob.glob(os.path.join(DIST_DIR, "*.tar.gz"))
    assert len(wheels) > 0, "No built wheel found in dist/ directory. Run python -m build."
    assert len(sdists) > 0, "No built sdist found in dist/ directory. Run python -m build."
    return {"wheel": wheels[0], "sdist": sdists[0]}


class TestReleasePackaging:
    """Verifies that built wheels and sdists meet security and release requirements."""

    def test_supported_python_version_configuration(self) -> None:
        """Verify supported Python version constraint is properly configured in pyproject.toml."""
        pyproject_path = os.path.join(os.path.dirname(__file__), "..", "..", "pyproject.toml")
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)

        project = data["project"]
        assert "requires-python" in project
        assert ">=3.12" in project["requires-python"]

    def test_optional_extras_definitions(self) -> None:
        """Verify optional dependency extras are cleanly defined without polluting core."""
        pyproject_path = os.path.join(os.path.dirname(__file__), "..", "..", "pyproject.toml")
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)

        core_deps = [d.split(">=")[0].split("[")[0].strip().lower() for d in data["project"]["dependencies"]]
        # Core MUST NOT depend on database or web frameworks
        assert "fastapi" not in core_deps
        assert "redis" not in core_deps
        assert "sqlalchemy" not in core_deps
        assert "psycopg" not in core_deps

        extras = data["project"]["optional-dependencies"]
        assert "fastapi" in extras
        assert "redis" in extras
        assert "postgres" in extras
        assert "all" in extras

    def test_no_credentials_or_secrets_in_wheel(self, dist_artifacts: dict[str, str]) -> None:
        """Acceptance requirement: No credentials ship in wheels."""
        wheel_path = dist_artifacts["wheel"]
        forbidden_extensions = {".env", ".pem", ".key", ".crt", ".p12", ".pfx", ".secret"}

        with zipfile.ZipFile(wheel_path) as z:
            names = z.namelist()
            for name in names:
                lower = name.lower()
                base = os.path.basename(lower)
                # Check forbidden extensions
                ext = os.path.splitext(lower)[1]
                assert ext not in forbidden_extensions, f"Forbidden file in wheel: {name}"
                assert not base.startswith(".env"), f"Environment file in wheel: {name}"

                # Content audit for embedded private key headers
                if not name.endswith("/"):
                    content = z.read(name)
                    marker = b"-----" + b"BEGIN "
                    assert (marker + b"RSA PRIVATE KEY-----") not in content
                    assert (marker + b"PRIVATE KEY-----") not in content
                    assert (marker + b"OPENSSH PRIVATE KEY-----") not in content

    def test_no_credentials_or_secrets_in_sdist(self, dist_artifacts: dict[str, str]) -> None:
        """Acceptance requirement: No credentials ship in source distributions (sdist)."""
        sdist_path = dist_artifacts["sdist"]
        forbidden_extensions = {".pem", ".key", ".crt", ".p12", ".pfx", ".secret"}

        with tarfile.open(sdist_path) as t:
            for member in t.getmembers():
                name = member.name.lower()
                base = os.path.basename(name)
                ext = os.path.splitext(name)[1]
                assert ext not in forbidden_extensions, f"Forbidden file in sdist: {member.name}"
                # .env or .env.local must not be packaged
                if base.startswith(".env") and not base.endswith(".example"):
                    pytest.fail(f"Environment file packaged in sdist: {member.name}")

                # Check file contents for private keys
                if member.isfile():
                    if "test_release_packaging" in base:
                        continue
                    f = t.extractfile(member)
                    if f:
                        content = f.read()
                        marker = b"-----" + b"BEGIN "
                        assert (marker + b"RSA PRIVATE KEY-----") not in content
                        assert (marker + b"PRIVATE KEY-----") not in content
                        assert (marker + b"OPENSSH PRIVATE KEY-----") not in content
