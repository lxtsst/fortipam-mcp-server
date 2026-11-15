from __future__ import annotations

import asyncio
import stat
from pathlib import Path

import pytest

import scripts.v4_launcher_mcp_oauth_acceptance as subject
from scripts.v4_launcher_mcp_oauth_acceptance import (
    LauncherMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_private_ip_lab_flag_is_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    async def fake_acceptance(*_args: object, **kwargs: object) -> dict[str, object]:
        observed.update(kwargs)
        callback = kwargs["tool_session_callback"]

        class Session:
            async def list_tools(self) -> object:
                return type("Tools", (), {"tools": []})()

        await callback(Session())
        return {
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
            "token_revoked": True,
            "credential_values_returned": False,
        }

    monkeypatch.setattr(subject.oauth, "run_address_mcp_oauth_surface_acceptance", fake_acceptance)
    with pytest.raises(subject.LauncherMcpOAuthAcceptanceError):
        asyncio.run(
            subject.run_launcher_mcp_oauth_acceptance(
                "http://192.0.2.10/fpamcp-v4-b97",
                Path("login"),
                Path("state"),
                allow_insecure_private_ip_lab=True,
            )
        )
    assert observed["allow_insecure_private_ip_lab"] is True


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    _write_preview_state(path, "launcher-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "launcher-preview-opaque"
    with pytest.raises(LauncherMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_rejects_session_or_association_effect_claim() -> None:
    name = "mcp-v4-launcher-b52"
    projection = {
        "contract": "fortipam_v4_launcher_create_cli_fallback_workflow_v1",
        "preview_ref": "launcher-preview-opaque",
        "device_write_executed": False,
        "Current State": {"requested_launcher_name": name, "launcher_name_exists": False, "write_transport": "ssh_cli_fallback"},
        "Proposed Changes": {"operation": "create_native_rdp_launcher_via_cli_fallback", "launcher_name": name, "configuration_profile": "windows-rdp-mstsc-cmdkey-timeout-15-v2", "launcher_type": "rdp", "client_executable": "mstsc.exe", "rdp_parameter_template": "/V:$HOST:$PORT /noConsentPrompt", "initial_command": "cmdkey_setup", "cleanup_command": "cmdkey_delete", "launch_timeout_seconds": 15, "secret_or_template_association_changes": False, "session_or_target_changes": False, "rest_write_attempted": False},
        "Expected State": {"launcher_name_matches": True, "launcher_name_exists": True, "type_is_rdp": True, "mstsc_executable_present": True, "native_rdp_parameter_present": True, "cmdkey_initial_command_present": True, "cmdkey_clean_command_present": True, "launch_timeout_seconds": 15, "secret_or_template_association_changes": False, "readback_transport": "ssh_cli"},
    }
    _validate_preview(projection, name, False)
    projection["Proposed Changes"]["session_or_target_changes"] = True
    with pytest.raises(LauncherMcpOAuthAcceptanceError):
        _validate_preview(projection, name, False)


def test_execution_requires_categorical_no_association_readback() -> None:
    result = {"contract": "fortipam_v4_launcher_create_cli_fallback_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "separate_launcher_archive_action_required", "launcher_name_returned": False, "secret_or_template_association_changes": False, "raw_cli_returned": False}
    _validate_execution(result, False)
    result["secret_or_template_association_changes"] = True
    with pytest.raises(LauncherMcpOAuthAcceptanceError):
        _validate_execution(result, False)
