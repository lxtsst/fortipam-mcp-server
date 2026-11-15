from __future__ import annotations

import asyncio
from pathlib import Path
import stat

import pytest

from scripts.v4_secret_metadata_mcp_oauth_acceptance import (
    SecretMetadataMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_private_ip_lab_flag_is_forwarded(monkeypatch) -> None:
    import scripts.v4_secret_metadata_mcp_oauth_acceptance as subject

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
        subject.run_secret_metadata_mcp_oauth_acceptance(
            "http://192.0.2.10/mcp",
            Path("login"),
            Path("state"),
            allow_insecure_private_ip_lab=True,
        )
    )

    assert observed["allow_insecure_private_ip_lab"] is True
    assert result["secret_metadata_tool_surface_complete"] is True


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    _write_preview_state(path, "secret-metadata-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "secret-metadata-preview-opaque"
    with pytest.raises(SecretMetadataMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_and_execution_require_exact_no_c3_contract() -> None:
    folder, secret, template = "Public/mcp-v4-folder-01", "mcp-v4-secret-metadata-01", "Unix Account (SSH Password)"
    projection = {"contract": "fortipam_v4_secret_metadata_api_workflow_v2", "preview_ref": "secret-metadata-preview-opaque", "device_write_executed": False, "Current State": {"requested_folder_path": folder, "requested_secret_name": secret, "requested_template": template, "secret_exists": False, "folder_exists": True, "template_exists": True, "write_transport": "rest_api", "credential_material_attached": False}, "Proposed Changes": {"operation": "create_secret_metadata_without_credential_material_via_api", "folder_path": folder, "secret_name": secret, "template": template, "credential_material_supplied": False, "credential_material_returned": False}, "Expected State": {"secret_exists": True, "secret_name_matches": True, "folder_matches": True, "template_matches": True, "inherit_permission_matches": True, "credential_material_attached": False}}
    _validate_preview(projection, folder, secret, template, False)
    result = {"contract": "fortipam_v4_secret_metadata_api_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "not_requested", "credential_material_supplied": False, "credential_material_returned": False, "raw_api_response_returned": False}
    _validate_execution(result, False)
    result["credential_material_returned"] = True
    with pytest.raises(SecretMetadataMcpOAuthAcceptanceError):
        _validate_execution(result, False)
