from __future__ import annotations

import stat
import pytest
from scripts.v4_local_user_reset_mcp_oauth_acceptance import LocalUserResetMcpOAuthAcceptanceError, _read_preview_ref, _validate_execution, _validate_preview, _write_preview_state


def test_preview_state_is_owner_only_and_reset_contract_is_fixed(tmp_path) -> None:
    directory = tmp_path / "state"; directory.mkdir(mode=0o700); directory.chmod(0o700); path = directory / "preview.json"
    _write_preview_state(path, "local-user-reset-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "local-user-reset-preview-opaque"
    username = "mcp-v4-user-01"
    projection = {"contract": "fortipam_v4_local_user_reset_workflow_v1", "preview_ref": "local-user-reset-preview-opaque", "device_write_executed": False, "Current State": {"requested_username": username, "user_exists": True, "access_profile": "Guest", "status": "disable"}, "Proposed Changes": {"operation": "reset_disabled_guest_local_user_password", "username": username, "replacement_password": "generated_not_returned"}, "Expected State": {"username_matches": True, "user_exists": True, "access_profile": "Guest", "status": "disable", "replacement_password_returned": False}}
    _validate_preview(projection, username, False)
    result = {"contract": "fortipam_v4_local_user_reset_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "not_requested", "credentials_returned": False, "raw_cli_returned": False}
    _validate_execution(result, False)
    result["credentials_returned"] = True
    with pytest.raises(LocalUserResetMcpOAuthAcceptanceError): _validate_execution(result, False)
