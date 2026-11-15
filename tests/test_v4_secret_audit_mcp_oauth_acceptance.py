from __future__ import annotations

import asyncio
import stat
from pathlib import Path

import pytest

from scripts.v4_secret_audit_mcp_oauth_acceptance import (
    SecretAuditMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_preview,
    _write_preview_state,
)


def test_private_ip_lab_flag_is_forwarded(monkeypatch) -> None:
    import scripts.v4_secret_audit_mcp_oauth_acceptance as subject

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
        subject.run_secret_audit_mcp_oauth_acceptance(
            "http://192.0.2.10/mcp",
            Path("login"),
            Path("state"),
            allow_insecure_private_ip_lab=True,
        )
    )

    assert observed["allow_insecure_private_ip_lab"] is True
    assert result["secret_audit_tool_surface_complete"] is True


def test_preview_reference_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    _write_preview_state(path, "secret-audit-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "secret-audit-preview-opaque"
    with pytest.raises(SecretAuditMcpOAuthAcceptanceError):
        _write_preview_state(path, "secret-audit-preview-other")


def test_preview_requires_fixed_redacted_report_contract() -> None:
    projection = {
        "contract": "fortipam_v4_secret_audit_generate_workflow_v1",
        "preview_ref": "secret-audit-preview-opaque",
        "device_write_executed": False,
        "Current State": {"fixed_cli_preflight_reachable": True, "report_inventory_read": False, "write_transport": "ssh_cli_fallback"},
        "Proposed Changes": {"operation": "generate_secret_access_audit_report_via_cli_fallback", "configuration_profile": "generate-secret-access-audit-report-v1", "caller_controlled_report_scope": False, "report_content_returned": False, "report_name_returned": False, "identity_target_folder_secret_data_returned": False, "rest_write_attempted": False},
        "Expected State": {"report_generation_command_completed": True, "generated_report_name_observed_internally": True, "report_content_returned": False, "report_name_returned": False, "identity_target_folder_secret_data_returned": False, "readback_transport": "ssh_cli"},
    }
    _validate_preview(projection, False)
    projection["Expected State"]["report_name_returned"] = True
    with pytest.raises(SecretAuditMcpOAuthAcceptanceError):
        _validate_preview(projection, False)
