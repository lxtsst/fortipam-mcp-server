from __future__ import annotations

from pathlib import Path

import pytest

from scripts.bp007_web_fixture_material import FixtureMaterialError, project_fixture_material


PREFIX = "FORTIPAM_MCP_V4_SECRET_CREATE_LAB_AUTO_"


def _owner_file(path: Path, value: str) -> Path:
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)
    return path


def _environment(tmp_path: Path) -> dict[str, str]:
    binding = _owner_file(
        tmp_path / "bindings.yaml",
        """schema_version: credential-bindings-v1
bindings:
  - id: bp007-fixture
    provider: env-file
    variables:
      username: BP007_FIXTURE_USERNAME
      password: BP007_FIXTURE_PASSWORD
""",
    )
    secret_env = _owner_file(
        tmp_path / "secrets.env",
        "BP007_FIXTURE_USERNAME=fixture-user\nBP007_FIXTURE_PASSWORD=fixture-password\n",
    )
    return {
        f"{PREFIX}CREDENTIAL_BINDINGS_FILE": str(binding),
        f"{PREFIX}SECRET_ENV_FILE": str(secret_env),
        f"{PREFIX}CREDENTIAL_BINDING_ID": "bp007-fixture",
    }


def test_projects_only_the_prebound_owner_only_pair(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    project_fixture_material(output, _environment(tmp_path))

    assert (output / "username").read_text(encoding="utf-8") == "fixture-user"
    assert (output / "password").read_text(encoding="utf-8") == "fixture-password"
    assert (output / "username").stat().st_mode & 0o077 == 0
    assert (output / "password").stat().st_mode & 0o077 == 0


def test_rejects_a_binding_with_any_extra_credential_role(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    binding = Path(environment[f"{PREFIX}CREDENTIAL_BINDINGS_FILE"])
    binding.write_text(
        binding.read_text(encoding="utf-8").replace(
            "      password: BP007_FIXTURE_PASSWORD",
            "      password: BP007_FIXTURE_PASSWORD\n      token: BP007_FIXTURE_TOKEN",
        ),
        encoding="utf-8",
    )
    binding.chmod(0o600)
    output = tmp_path / "output"
    output.mkdir(mode=0o700)

    with pytest.raises(FixtureMaterialError):
        project_fixture_material(output, environment)
    assert not list(output.iterdir())
