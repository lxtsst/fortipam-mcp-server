from dataclasses import replace
from pathlib import Path
import asyncio

import pytest

from fortipam_mcp.approval_profile_ssh_transport import ApprovalProfileSshTransportConfig
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataProjectionInspection
import fortipam_mcp.web_secret_service_ssh_transport as module


def _transport(tmp_path: Path):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAtest\n")
    known_hosts.chmod(0o600)
    config = ApprovalProfileSshTransportConfig(
        host="fpa.example", port=22, username="test-writer", password="test-only",
        known_hosts_file=known_hosts, timeout_seconds=15,
    )
    return module.FortiPamWebSecretServiceSshTransport(
        config, enabled=True, api_unavailable_reason=module.API_UNAVAILABLE_REASON,
    )


def _prewrite():
    return SecretMetadataProjectionInspection(
        True, True, True, True, True, True, True, False, recording_matches=True,
    )


def test_fixed_web_service_command_preserves_all_other_fields(monkeypatch, tmp_path):
    transport = _transport(tmp_path)
    commands = []

    async def dynamic(process, command, root, deadline):
        commands.append(command)
        return {"config secret database": b"table #", "edit 24": b"entry #",
                "next": b"table #", "end": b"root #"}[command]

    async def send(process, command, prompt, deadline):
        commands.append(command)
        assert prompt == b"entry #"
        return b""

    async def enable(secret_id):
        await transport._apply(object(), b"root #", 10.0, secret_id)

    monkeypatch.setattr(module, "_send_and_read_dynamic_prompt", dynamic)
    monkeypatch.setattr(module, "_send_and_read", send)
    monkeypatch.setattr(transport, "_enable", enable)
    transport.enable_http_service(24, prewrite=_prewrite())
    assert commands == ["config secret database", "edit 24",
                        "set http-service-status up", "next", "end"]


@pytest.mark.parametrize("change", [
    {"secret_exists": False}, {"target_matches": False},
    {"recording_matches": False}, {"inherit_permission_matches": False},
    {"http_service_enabled": True}, {"http_service_enabled": None},
])
def test_invalid_baseline_rejected_without_connection(monkeypatch, tmp_path, change):
    transport = _transport(tmp_path)
    monkeypatch.setattr(module.asyncssh, "connect", lambda *a, **k: pytest.fail("connected"))
    with pytest.raises(module.WebSecretServiceSshTransportError):
        transport.enable_http_service(24, prewrite=replace(_prewrite(), **change))


@pytest.mark.parametrize("secret_id", [True, 0, -1, "24", 2_147_483_648])
def test_invalid_id_rejected_without_connection(monkeypatch, tmp_path, secret_id):
    transport = _transport(tmp_path)
    monkeypatch.setattr(module.asyncssh, "connect", lambda *a, **k: pytest.fail("connected"))
    with pytest.raises(module.WebSecretServiceSshTransportError):
        transport.enable_http_service(secret_id, prewrite=_prewrite())


def test_connection_failure_is_sanitized_and_not_retried(monkeypatch, tmp_path):
    transport = _transport(tmp_path)
    calls = []

    def connect(*args, **kwargs):
        calls.append(1)
        raise OSError("private connection detail")

    monkeypatch.setattr(module.asyncssh, "connect", connect)
    with pytest.raises(module.WebSecretServiceSshTransportError) as result:
        transport.enable_http_service(24, prewrite=_prewrite())
    assert "private" not in str(result.value)
    assert len(calls) == 1
