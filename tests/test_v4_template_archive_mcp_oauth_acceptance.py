from __future__ import annotations

import asyncio
import stat
from pathlib import Path

import pytest

from scripts.v4_template_archive_mcp_oauth_acceptance import (
    TemplateArchiveMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_private_ip_lab_flag_is_forwarded(monkeypatch) -> None:
    import scripts.v4_template_archive_mcp_oauth_acceptance as subject

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
        subject.run_template_archive_mcp_oauth_acceptance(
            "http://192.0.2.10/mcp",
            Path("login"),
            Path("state"),
            allow_insecure_private_ip_lab=True,
        )
    )

    assert observed["allow_insecure_private_ip_lab"] is True
    assert result["template_archive_tool_surface_complete"] is True


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_preview_state(path, "template-archive-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "template-archive-preview-opaque"
    with pytest.raises(TemplateArchiveMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_and_execution_require_exact_irreversible_archive_contract() -> None:
    template_name = "mcp-v4-template-archive-b87"
    projection = {
        "contract": "fortipam_v4_template_archive_api_workflow_v1",
        "preview_ref": "template-archive-preview-opaque",
        "device_write_executed": False,
        "Current State": {"requested_template_name": template_name, "template_exists": True, "known_web_vnc_create_baseline_verified": True, "secret_reference_absent": True, "target_reference_absent": True, "write_transport": "rest_api"},
        "Proposed Changes": {"operation": "archive_by_deleting_unreferenced_v4_template_via_api", "template_name": template_name, "configuration_profile": "unreferenced-web-vnc-template-delete-v1", "irreversible_after_execution": True, "secret_or_target_association_changes": False, "rest_write_attempted": False},
        "Expected State": {"template_name_absent": True, "template_exists": False, "template_absence_verified_by_ssh_readback": True, "secret_reference_absent": True, "target_reference_absent": True, "other_template_configuration_modified": False, "secret_or_target_association_changes": False, "readback_transport": "ssh_cli"},
    }

    _validate_preview(projection, template_name, False)
    result = {"contract": "fortipam_v4_template_archive_api_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "manual_recreation_or_backup_restore_required", "irreversible_after_execution": True, "template_name_returned": False, "secret_or_target_association_changes": False, "raw_api_response_returned": False}
    _validate_execution(result, False)
    result["irreversible_after_execution"] = False
    with pytest.raises(TemplateArchiveMcpOAuthAcceptanceError):
        _validate_execution(result, False)
