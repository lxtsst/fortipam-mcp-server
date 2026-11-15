from __future__ import annotations

import asyncio
import stat
from pathlib import Path

import pytest

from scripts.v4_launcher_update_mcp_oauth_acceptance import (
    LauncherUpdateMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)
from fortipam_mcp.launcher_ssh_transport import LAUNCHER_UPDATE_CONFIGURATION


def test_private_ip_lab_flag_is_forwarded(monkeypatch) -> None:
    import scripts.v4_launcher_update_mcp_oauth_acceptance as subject

    observed: dict[str, object] = {}

    async def stub(*_args, **kwargs):
        observed.update(kwargs)
        callback = kwargs["tool_session_callback"]

        class Tools:
            tools = [type("Tool", (), {"name": name})() for name in subject.TOOLS]

        class Session:
            async def list_tools(self):
                return Tools()

        await callback(Session())
        return {
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
            "token_revoked": True,
            "credential_values_returned": False,
        }

    monkeypatch.setattr(subject.oauth, "run_address_mcp_oauth_surface_acceptance", stub)
    result = asyncio.run(
        subject.run_launcher_update_mcp_oauth_acceptance(
            "http://192.0.2.10/mcp",
            Path("login"),
            Path("state"),
            allow_insecure_private_ip_lab=True,
        )
    )

    assert observed["allow_insecure_private_ip_lab"] is True
    assert result["launcher_update_tool_surface_complete"] is True


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    _write_preview_state(path, "launcher-update-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "launcher-update-preview-opaque"
    with pytest.raises(LauncherUpdateMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_and_execution_require_exact_launcher_timeout_contract() -> None:
    name = "mcp-v4-launcher-b79"
    projection = {"contract": "fortipam_v4_launcher_timeout_update_cli_workflow_v1", "preview_ref": "launcher-update-preview-opaque", "device_write_executed": False, "Current State": {"requested_launcher_name": name, "launcher_name_exists": True, "known_native_rdp_create_baseline_verified": True, "launch_timeout_seconds": 15, "write_transport": "ssh_cli_fallback"}, "Proposed Changes": {"operation": "update_native_rdp_launcher_timeout_via_cli_fallback", "launcher_name": name, "configuration_profile": LAUNCHER_UPDATE_CONFIGURATION, "launch_timeout_seconds": {"from": 15, "to": 30}, "launcher_type_or_command_changes": False, "secret_or_template_association_changes": False, "session_or_target_changes": False, "rest_write_attempted": False}, "Expected State": {"launcher_name_matches": True, "launcher_name_exists": True, "native_rdp_create_baseline_preserved": True, "launch_timeout_seconds": 30, "launcher_type_or_command_changes": False, "secret_or_template_association_changes": False, "session_or_target_changes": False, "readback_transport": "ssh_cli_fallback"}}
    _validate_preview(projection, name, False)
    result = {"contract": "fortipam_v4_launcher_timeout_update_cli_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "separate_launcher_timeout_restore_action_required", "launcher_name_returned": False, "launcher_type_or_command_changes": False, "secret_or_template_association_changes": False, "raw_cli_returned": False}
    _validate_execution(result, False)
    result["raw_cli_returned"] = True
    with pytest.raises(LauncherUpdateMcpOAuthAcceptanceError):
        _validate_execution(result, False)
