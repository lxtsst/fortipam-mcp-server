from __future__ import annotations

import stat
import asyncio
from pathlib import Path

import pytest

from scripts.v4_template_update_mcp_oauth_acceptance import (
    TemplateUpdateMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_private_ip_lab_flag_is_forwarded(monkeypatch) -> None:
    import scripts.v4_template_update_mcp_oauth_acceptance as subject

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
        subject.run_template_update_mcp_oauth_acceptance(
            "http://192.0.2.10/",
            Path("login"),
            Path("state"),
            allow_insecure_private_ip_lab=True,
        )
    )

    assert observed["allow_insecure_private_ip_lab"] is True
    assert result["template_update_tool_surface_complete"] is True


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_preview_state(path, "template-update-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "template-update-preview-opaque"
    with pytest.raises(TemplateUpdateMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_and_execution_require_exact_template_update_contract() -> None:
    template_name = "mcp-v4-template-b86"
    projection = {
        "contract": "fortipam_v4_template_web_vnc_port_update_cli_workflow_v1",
        "preview_ref": "template-update-preview-opaque",
        "device_write_executed": False,
        "Current State": {"requested_template_name": template_name, "template_name_exists": True, "known_web_vnc_create_baseline_verified": True, "web_vnc_launcher_port": 5900, "write_transport": "ssh_cli_fallback"},
        "Proposed Changes": {"operation": "update_web_vnc_template_launcher_port_via_cli_fallback", "template_name": template_name, "configuration_profile": "web-vnc-launcher-port-5900-to-5901-v1", "web_vnc_launcher_port": {"from": 5900, "to": 5901}, "template_field_or_access_changes": False, "secret_or_target_association_changes": False, "session_or_target_changes": False, "rest_write_attempted": False},
        "Expected State": {"template_name_matches": True, "template_name_exists": True, "web_vnc_create_baseline_preserved": True, "web_vnc_launcher_port": 5901, "template_field_or_access_changes": False, "secret_or_target_association_changes": False, "session_or_target_changes": False, "readback_transport": "ssh_cli_fallback"},
    }

    _validate_preview(projection, template_name, False)
    result = {"contract": "fortipam_v4_template_web_vnc_port_update_cli_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "separate_template_web_vnc_port_restore_action_required", "template_name_returned": False, "template_field_or_access_changes": False, "secret_or_target_association_changes": False, "session_or_target_changes": False, "device_write_executed": True}
    _validate_execution(result, False)
    projection["Current State"]["write_transport"] = "rest_api"
    projection["Proposed Changes"]["operation"] = "update_web_vnc_template_launcher_port_via_rest_api"
    with pytest.raises(TemplateUpdateMcpOAuthAcceptanceError):
        _validate_preview(projection, template_name, False)
    _validate_preview(projection, template_name, False, write_transport="rest_api")
    with pytest.raises(TemplateUpdateMcpOAuthAcceptanceError):
        _validate_execution(result, False, write_transport="rest_api")
    result["write_transport"] = "rest_api"
    _validate_execution(result, False, write_transport="rest_api")
    result["device_write_executed"] = False
    with pytest.raises(TemplateUpdateMcpOAuthAcceptanceError):
        _validate_execution(result, False)
