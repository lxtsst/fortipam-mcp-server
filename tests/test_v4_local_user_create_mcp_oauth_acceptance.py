from __future__ import annotations

import stat

import pytest

from scripts.v4_local_user_create_mcp_oauth_acceptance import (
    LocalUserCreateMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_confirmation,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_owner_only_state_and_fixed_create_contract(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    state = directory / "preview.json"
    username = "mcp-v4-user-b58"
    _write_preview_state(state, "local-user-create-preview-opaque")
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    assert _read_preview_ref(state) == "local-user-create-preview-opaque"
    preview = {"contract": "fortipam_v4_local_user_create_workflow_v1", "preview_ref": "local-user-create-preview-opaque", "device_write_executed": False, "Current State": {"requested_username": username, "user_exists": False}, "Proposed Changes": {"operation": "create_disabled_local_user", "username": username, "access_profile": "Guest", "status": "disable", "initial_password": "generated_not_returned"}, "Expected State": {"username_matches": True, "user_exists": True, "access_profile_matches": True, "status_disabled": True, "credentials_returned": False}}
    _validate_preview(preview, username, False)
    assert _validate_confirmation({"contract": "fortipam_v4_local_user_create_workflow_v1", "authorization_ref": "local-user-create-authorized-opaque", "confirmation": "recorded", "execution": "authorized_once", "device_write_executed": False}, False) == "local-user-create-authorized-opaque"
    result = {"contract": "fortipam_v4_local_user_create_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "not_requested", "credentials_returned": False, "raw_cli_returned": False}
    _validate_execution(result, False)
    result["credentials_returned"] = True
    with pytest.raises(LocalUserCreateMcpOAuthAcceptanceError):
        _validate_execution(result, False)


def test_unprotected_preview_state_is_rejected(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o755)
    with pytest.raises(LocalUserCreateMcpOAuthAcceptanceError):
        _write_preview_state(directory / "preview.json", "local-user-create-preview-opaque")
