from __future__ import annotations

import stat
import asyncio
from pathlib import Path

import pytest

from scripts.v4_folder_policy_detach_mcp_oauth_acceptance import (
    FolderPolicyDetachMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_private_ip_lab_flag_is_forwarded(monkeypatch) -> None:
    import scripts.v4_folder_policy_detach_mcp_oauth_acceptance as subject

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
        subject.run_folder_policy_detach_mcp_oauth_acceptance(
            "http://192.0.2.10/",
            Path("login"),
            Path("state"),
            allow_insecure_private_ip_lab=True,
        )
    )

    assert observed["allow_insecure_private_ip_lab"] is True
    assert result["folder_policy_detach_tool_surface_complete"] is True


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_preview_state(path, "folder-policy-detach-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "folder-policy-detach-preview-opaque"
    with pytest.raises(FolderPolicyDetachMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_and_execution_require_exact_folder_policy_contract() -> None:
    folder_id = 42
    projection = {
        "contract": "fortipam_v4_public_child_folder_policy_detach_api_workflow_v1",
        "preview_ref": "folder-policy-detach-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "selected_folder_id": folder_id,
            "folder_exists": True,
            "folder_scope": "public_child",
            "policy_inheritance": "disable",
            "permission_inheritance": "disable",
            "explicit_policy_binding_present": True,
            "write_transport": "rest_api",
        },
        "Proposed Changes": {
            "operation": "detach_public_child_folder_explicit_secret_policy_via_api",
            "folder_id": folder_id,
            "current_policy_identifier_returned": False,
            "policy_inheritance_enabled": True,
            "non_policy_projection_preserved": True,
        },
        "Expected State": {
            "folder_id_matches": True,
            "folder_exists": True,
            "folder_scope": "public_child",
            "policy_inheritance": "enable",
            "explicit_policy_binding_removed": True,
            "parent_relation_preserved": True,
            "permission_and_ztna_projection_preserved": True,
        },
    }

    _validate_preview(projection, folder_id, False)
    result = {
        "contract": "fortipam_v4_public_child_folder_policy_detach_api_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "restore_explicit_policy_requires_new_assignment_confirmation",
        "folder_id_returned": False,
        "policy_identifier_returned": False,
        "raw_api_response_returned": False,
    }
    _validate_execution(result, False)
    result["raw_api_response_returned"] = True
    with pytest.raises(FolderPolicyDetachMcpOAuthAcceptanceError):
        _validate_execution(result, False)
