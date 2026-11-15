from __future__ import annotations

import asyncio
from pathlib import Path
import stat

import pytest

from scripts import v4_folder_policy_assign_mcp_oauth_acceptance as subject
from scripts.v4_folder_policy_assign_mcp_oauth_acceptance import (
    FolderPolicyAssignMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_preview_state(path, "folder-policy-assign-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "folder-policy-assign-preview-opaque"
    with pytest.raises(FolderPolicyAssignMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_and_execution_require_exact_folder_policy_contract() -> None:
    folder_id = 42
    policy_name = "mcp-v4-secret-policy-01"
    projection = {
        "contract": "fortipam_v4_public_child_folder_policy_assign_api_workflow_v1",
        "preview_ref": "folder-policy-assign-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "selected_folder_id": folder_id,
            "requested_policy_name": policy_name,
            "folder_exists": True,
            "folder_scope": "public_child",
            "policy_inheritance": "disable",
            "permission_inheritance": "disable",
            "explicit_policy_binding_present": True,
            "requested_policy_already_matches": False,
            "write_transport": "rest_api",
        },
        "Proposed Changes": {
            "operation": "assign_public_child_folder_secret_policy_via_api",
            "folder_id": folder_id,
            "current_policy_identifier_returned": False,
            "secret_policy": policy_name,
            "policy_inheritance_preserved": True,
            "non_policy_projection_preserved": True,
        },
        "Expected State": {
            "folder_id_matches": True,
            "folder_exists": True,
            "folder_scope": "public_child",
            "policy_inheritance": "disable",
            "requested_explicit_policy_matches": True,
            "parent_relation_preserved": True,
            "permission_and_ztna_projection_preserved": True,
        },
    }

    _validate_preview(projection, folder_id, policy_name, False)
    result = {
        "contract": "fortipam_v4_public_child_folder_policy_assign_api_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "assign_prior_explicit_policy_after_new_confirmation",
        "folder_id_returned": False,
        "policy_identifier_returned": False,
        "raw_api_response_returned": False,
    }
    _validate_execution(result, False)
    result["raw_api_response_returned"] = True
    with pytest.raises(FolderPolicyAssignMcpOAuthAcceptanceError):
        _validate_execution(result, False)


def test_private_ip_lab_flag_is_forwarded_to_shared_oauth_acceptance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class Session:
        async def list_tools(self):
            return type("Tools", (), {"tools": [type("Tool", (), {"name": name})() for name in subject.TOOLS]})()

    async def fake_acceptance(*_args: object, **kwargs: object) -> dict[str, object]:
        observed.update(kwargs)
        await kwargs["tool_session_callback"](Session())
        return {"oauth_metadata_verified": True, "mcp_initialized": True, "token_revoked": True, "credential_values_returned": False}

    monkeypatch.setattr(subject.oauth, "run_address_mcp_oauth_surface_acceptance", fake_acceptance)
    result = asyncio.run(
        subject.run_folder_policy_assign_mcp_oauth_acceptance(
            "http://192.0.2.10/path",
            Path("login"),
            Path("state"),
            allow_insecure_private_ip_lab=True,
        )
    )

    assert observed["allow_insecure_private_ip_lab"] is True
    assert result["folder_policy_assign_tool_surface_complete"] is True
