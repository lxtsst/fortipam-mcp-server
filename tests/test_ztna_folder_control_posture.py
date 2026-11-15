from __future__ import annotations

from pathlib import Path

import pytest

from fortipam_mcp.antivirus_profile_ssh_transport import (
    ENV_PREFIX as PROFILE_SSH_ENV_PREFIX,
)
from fortipam_mcp.ztna_folder_control_posture import (
    ENV_PREFIX,
    FortiPamZtnaFolderControlPosture,
    FortiPamZtnaFolderControlPostureSshTransport,
    V4_ZTNA_FOLDER_POSTURE_FEATURE_ENV,
    V4_ZTNA_FOLDER_POSTURE_SELECTOR_ENV,
    ZtnaFolderControlPostureConfig,
    ZtnaFolderControlPostureConfigurationError,
    ZtnaFolderControlPostureTransportError,
    build_v4_ztna_folder_control_posture,
    load_v4_ztna_folder_posture_feature,
    load_ztna_folder_control_posture_config,
)


class _FakeTransport:
    def __init__(self, compact: bytes, full: bytes) -> None:
        self._compact = compact
        self._full = full
        self.calls = 0

    def collect(self) -> tuple[bytes, bytes]:
        self.calls += 1
        return self._compact, self._full


class _UnavailableTransport:
    def collect(self) -> tuple[bytes, bytes]:
        raise ZtnaFolderControlPostureTransportError("not returned")


def _folder_block(*fields: bytes) -> bytes:
    body = b"".join(b"        " + field + b"\n" for field in fields)
    return b"config secret folder\n    edit 42\n" + body + b"    next\nend\n"


def _posture(
    compact: bytes,
    full: bytes,
) -> FortiPamZtnaFolderControlPosture:
    return FortiPamZtnaFolderControlPosture(
        _FakeTransport(compact, full),
        folder_id="42",
    )


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> ZtnaFolderControlPostureConfig:
    known_hosts, password = _files(tmp_path)
    return ZtnaFolderControlPostureConfig(
        host="fpa.example",
        port=22,
        username="fortipam-ztna-reader",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        folder_id="42",
        timeout_seconds=15,
    )


def test_posture_reports_explicit_tag_control_without_disclosing_values() -> None:
    compact = _folder_block()
    full = _folder_block(
        b"set inherit-folder-ztna disable",
        b'set ztna-ems-tag "private-tag-value"',
    )

    result = _posture(compact, full).collect()

    assert result == {
        "contract": "fortipam_v4_ztna_folder_control_posture_v1",
        "execution_status": "succeeded",
        "folder_ztna_control": "explicit_override",
        "folder_ztna_tag_assignment": "configured",
        "folder_ztna_match_logic": "unresolved",
        "folder_reference_returned": False,
        "tag_value_returned": False,
        "raw_cli_returned": False,
        "device_write_executed": False,
        "secret_override_assessed": False,
        "match_logic_assessed": False,
    }
    rendered = repr(result)
    for forbidden in ("42", "private-tag-value"):
        assert forbidden not in rendered


def test_posture_accepts_compact_grep_locator_and_parses_only_full_output() -> None:
    compact = b"    edit 42\n"
    full = _folder_block(
        b"set inherit-folder-ztna disable",
        b'set ztna-ems-tag "private-tag-value"',
    )

    result = _posture(compact, full).collect()

    assert result["execution_status"] == "succeeded"
    assert result["folder_ztna_control"] == "explicit_override"
    assert result["folder_ztna_tag_assignment"] == "configured"
    assert "42" not in repr(result)
    assert "private-tag-value" not in repr(result)


def test_posture_distinguishes_inherited_from_no_tag_observation() -> None:
    block = _folder_block(b"set inherit-folder-ztna enable")

    result = _posture(block, block).collect()

    assert result["execution_status"] == "succeeded"
    assert result["folder_ztna_control"] == "inherits_parent"
    assert result["folder_ztna_tag_assignment"] == "not_observed"
    assert result["folder_ztna_match_logic"] == "unresolved"


def test_posture_reports_explicit_empty_tag_as_not_configured() -> None:
    compact = _folder_block()
    full = _folder_block(
        b"set inherit-folder-ztna disable",
        b'set ztna-ems-tag ""',
    )

    result = _posture(compact, full).collect()

    assert result["execution_status"] == "succeeded"
    assert result["folder_ztna_control"] == "explicit_override"
    assert result["folder_ztna_tag_assignment"] == "not_configured"


def test_posture_fails_closed_on_duplicate_or_rejected_output() -> None:
    compact = _folder_block()
    duplicate = _folder_block(b"set inherit-folder-ztna enable") + _folder_block(
        b"set inherit-folder-ztna disable"
    )
    rejected = b"permission denied private-folder\n"

    for result in (
        _posture(compact, duplicate).collect(),
        _posture(b"    edit 420\n", _folder_block()).collect(),
        _posture(rejected, rejected).collect(),
    ):
        assert result["execution_status"] == "unavailable"
        assert result["folder_ztna_control"] == "unknown"
        assert result["raw_cli_returned"] is False
        assert "private-folder" not in repr(result)


def test_posture_transport_failure_is_categorical() -> None:
    result = FortiPamZtnaFolderControlPosture(
        _UnavailableTransport(),
        folder_id="42",
    ).collect()

    assert result["execution_status"] == "unavailable"
    assert result["folder_ztna_tag_assignment"] == "unknown"
    assert result["device_write_executed"] is False


def test_loader_requires_private_owner_only_settings(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        f"{ENV_PREFIX}ENABLED": "true",
        f"{ENV_PREFIX}SSH_HOST": "fpa.example",
        f"{ENV_PREFIX}SSH_USERNAME": "fortipam-ztna-reader",
        f"{ENV_PREFIX}SSH_PASSWORD_FILE": str(password),
        f"{ENV_PREFIX}SSH_KNOWN_HOSTS_FILE": str(known_hosts),
        f"{ENV_PREFIX}FOLDER_ID": "42",
    }

    loaded = load_ztna_folder_control_posture_config(environment)

    assert loaded.folder_id == "42"
    environment[f"{ENV_PREFIX}FOLDER_ID"] = "42\nset status enable"
    with pytest.raises(ZtnaFolderControlPostureConfigurationError, match="reference"):
        load_ztna_folder_control_posture_config(environment)
    environment[f"{ENV_PREFIX}FOLDER_ID"] = "42"
    password.chmod(0o640)
    with pytest.raises(ZtnaFolderControlPostureConfigurationError, match="owner-only"):
        load_ztna_folder_control_posture_config(environment)


def test_feature_flag_is_exactly_opt_in() -> None:
    assert load_v4_ztna_folder_posture_feature({}) is False
    assert load_v4_ztna_folder_posture_feature(
        {V4_ZTNA_FOLDER_POSTURE_FEATURE_ENV: "false"}
    ) is False
    assert load_v4_ztna_folder_posture_feature(
        {V4_ZTNA_FOLDER_POSTURE_FEATURE_ENV: "true"}
    ) is True
    with pytest.raises(ZtnaFolderControlPostureConfigurationError, match="exactly"):
        load_v4_ztna_folder_posture_feature(
            {V4_ZTNA_FOLDER_POSTURE_FEATURE_ENV: "TRUE"}
        )


def test_builder_reuses_current_profile_ssh_binding(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    posture = build_v4_ztna_folder_control_posture(
        {
            PROFILE_SSH_ENV_PREFIX + "ENABLED": "true",
            PROFILE_SSH_ENV_PREFIX + "SSH_HOST": "fpa.example",
            PROFILE_SSH_ENV_PREFIX + "SSH_USERNAME": "adminapi",
            PROFILE_SSH_ENV_PREFIX + "SSH_PASSWORD_FILE": str(password),
            PROFILE_SSH_ENV_PREFIX + "SSH_KNOWN_HOSTS_FILE": str(known_hosts),
            V4_ZTNA_FOLDER_POSTURE_SELECTOR_ENV: "42",
        }
    )

    assert isinstance(posture, FortiPamZtnaFolderControlPosture)


def test_ssh_transport_compiles_only_fixed_read_commands(tmp_path: Path) -> None:
    transport = FortiPamZtnaFolderControlPostureSshTransport(_config(tmp_path))

    assert transport._commands() == (
        "config secret folder",
        "show | grep 42",
        'show full-configuration | grep -A 80 "edit 42"',
    )
