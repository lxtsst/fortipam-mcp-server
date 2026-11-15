from __future__ import annotations

import asyncio
from pathlib import Path
import stat

import pytest

from scripts.v4_active_launch_disconnect_mcp_oauth_acceptance import (
    ActiveLaunchDisconnectMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_private_ip_lab_flag_is_forwarded(monkeypatch) -> None:
    import scripts.v4_active_launch_disconnect_mcp_oauth_acceptance as subject

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
        return {"oauth_metadata_verified": True, "mcp_initialized": True, "token_revoked": True, "credential_values_returned": False}

    monkeypatch.setattr(subject.oauth, "run_address_mcp_oauth_surface_acceptance", stub)
    result = asyncio.run(subject.run_active_launch_disconnect_mcp_oauth_acceptance("http://192.0.2.10/mcp", Path("login"), Path("state"), allow_insecure_private_ip_lab=True))
    assert observed["allow_insecure_private_ip_lab"] is True
    assert result["active_launch_disconnect_tool_surface_complete"] is True


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_preview_state(path, "active-launch-disconnect-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "active-launch-disconnect-preview-opaque"
    with pytest.raises(ActiveLaunchDisconnectMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_and_execution_require_exact_single_launch_contract() -> None:
    launch_ref = "active-launch-ref-opaque"
    projection = {
        "contract": "fortipam_v4_active_launch_disconnect_cli_workflow_v1",
        "preview_ref": "active-launch-disconnect-preview-opaque",
        "device_write_executed": False,
        "Current State": {"requested_active_launch_reference": launch_ref, "selected_active_launch_present": True, "selected_launch_reference_returned": True, "raw_cli_returned": False, "wad_token_returned": False, "identity_target_secret_or_session_data_returned": False, "write_transport": "ssh_cli_fallback"},
        "Proposed Changes": {"operation": "disconnect_exactly_one_previously_observed_active_launch", "selected_active_launch_reference": launch_ref, "selected_launch_reference_returned": True, "clear_all_active_launches": False, "caller_controlled_cli": False, "raw_cli_returned": False, "wad_token_returned": False, "identity_target_secret_or_session_data_returned": False, "rest_write_attempted": False},
        "Expected State": {"selected_active_launch_reference_matches": True, "selected_active_launch_present": False, "single_active_launch_disconnect_command_used": True, "clear_all_active_launches": False, "verification_transport": "ssh_cli_fallback", "raw_cli_returned": False, "wad_token_returned": False, "identity_target_secret_or_session_data_returned": False},
    }

    _validate_preview(projection, launch_ref, False)
    result = {"contract": "fortipam_v4_active_launch_disconnect_cli_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "a_new_secret_launch_is_required_to_restore_a_disconnected_launch", "selected_active_launch_disconnected": True, "clear_all_active_launches": False, "raw_cli_returned": False, "wad_token_returned": False, "identity_target_secret_or_session_data_returned": False}
    _validate_execution(result, False)
    result["clear_all_active_launches"] = True
    with pytest.raises(ActiveLaunchDisconnectMcpOAuthAcceptanceError):
        _validate_execution(result, False)
