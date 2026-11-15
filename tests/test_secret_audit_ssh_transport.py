from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.secret_audit_ssh_transport as transport_module
from fortipam_mcp.secret_audit_ssh_transport import (
    FortiPamSecretAuditSshTransport,
    SecretAuditSshTransportConfig,
    SecretAuditSshTransportConfigurationError,
    SecretAuditSshTransportError,
    _generated_report_name_observed,
    load_secret_audit_ssh_transport_config,
)


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> SecretAuditSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return SecretAuditSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-secret-audit-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_ssh_configuration(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_SECRET_AUDIT_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SECRET_AUDIT_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_SECRET_AUDIT_SSH_USERNAME": "fortipam-secret-audit-writer",
        "FPA_HOME_LAB_FPA1_V4_SECRET_AUDIT_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_SECRET_AUDIT_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_secret_audit_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    invalid = dict(environment)
    invalid["FPA_HOME_LAB_FPA1_V4_SECRET_AUDIT_SSH_HOST"] = "fpa.example\nexecute x"
    with pytest.raises(SecretAuditSshTransportConfigurationError):
        load_secret_audit_ssh_transport_config(invalid)


def test_generated_report_evidence_requires_the_documented_name_and_no_error() -> None:
    assert (
        _generated_report_name_observed(
            b"Created SecretAccessAuditReport-2026-08-27-120000.csv\r\n"
        )
        is True
    )
    assert _generated_report_name_observed(b"report created\n") is False
    with pytest.raises(SecretAuditSshTransportError):
        _generated_report_name_observed(b"permission denied\n")


def test_generator_uses_only_the_documented_fixed_cli_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretAuditSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command == "execute audit secret-access"
        return b"Created SecretAccessAuditReport-2026-08-27-120000.csv\n"

    monkeypatch.setattr(transport_module, "_send_and_read", send)

    output = asyncio.run(transport._generate(object(), b"fpa #", 100.0))

    assert _generated_report_name_observed(output) is True
    assert commands == ["execute audit secret-access"]
