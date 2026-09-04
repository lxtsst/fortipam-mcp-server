from __future__ import annotations

import os

import pytest

from fortipam_mcp.env import (
    ENV_FILE_VARIABLE,
    EnvironmentFileError,
    load_runtime_environment,
)


def test_loads_owner_only_explicit_environment_file(tmp_path, monkeypatch) -> None:
    env_file = tmp_path / "fortipam.env"
    env_file.write_text(
        "export FPA_HOME_LAB_FPA1_TEST_MARKER='safe-test-value'\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    monkeypatch.setenv(ENV_FILE_VARIABLE, str(env_file))
    monkeypatch.delenv("FPA_HOME_LAB_FPA1_TEST_MARKER", raising=False)

    report = load_runtime_environment()

    assert report.source == "operator_env_file"
    assert report.loaded is True
    assert os.environ["FPA_HOME_LAB_FPA1_TEST_MARKER"] == "safe-test-value"


def test_rejects_group_or_world_accessible_environment_file(
    tmp_path, monkeypatch
) -> None:
    env_file = tmp_path / "fortipam.env"
    env_file.write_text("FPA_HOME_LAB_FPA1_TEST_MARKER=value\n", encoding="utf-8")
    env_file.chmod(0o644)
    monkeypatch.setenv(ENV_FILE_VARIABLE, str(env_file))

    with pytest.raises(EnvironmentFileError):
        load_runtime_environment()


def test_ignores_variables_outside_the_selected_device_prefix(
    tmp_path, monkeypatch
) -> None:
    env_file = tmp_path / "fortipam.env"
    env_file.write_text(
        "FPA_HOME_LAB_FPA1_TEST_MARKER=selected-device\n"
        "UNRELATED_LAB_SECRET=must-not-enter-process\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    monkeypatch.setenv(ENV_FILE_VARIABLE, str(env_file))
    monkeypatch.delenv("FPA_HOME_LAB_FPA1_TEST_MARKER", raising=False)
    monkeypatch.delenv("UNRELATED_LAB_SECRET", raising=False)

    report = load_runtime_environment()

    assert report.loaded is True
    assert os.environ["FPA_HOME_LAB_FPA1_TEST_MARKER"] == "selected-device"
    assert "UNRELATED_LAB_SECRET" not in os.environ
