from __future__ import annotations

import stat

import pytest

from scripts.v4_recording_policy_mcp_oauth_acceptance import (
    RecordingPolicyMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_owner_only_state_and_fixed_recording_contract(tmp_path) -> None:
    directory = tmp_path / "state"; directory.mkdir(mode=0o700); directory.chmod(0o700)
    state = directory / "preview.json"; ref = "recording-policy-preview-opaque"
    _write_preview_state(state, ref)
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    assert _read_preview_ref(state) == ref
    name = "mcp-v4-secret-policy-recording-01"
    preview = {"contract": "fortipam_v4_recording_policy_enable_api_workflow_v1", "preview_ref": ref, "device_write_executed": False, "Current State": {"secret_policy_name": name, "secret_policy_exists": True, "recording_enabled": False, "write_transport": "rest_api"}, "Proposed Changes": {"operation": "enable_session_recording_on_existing_secret_policy_via_api", "recording": "enable", "other_policy_fields_modified": False, "folder_or_secret_association_changes": False}, "Expected State": {"recording_enabled": True, "other_policy_fields_modified": False, "folder_or_secret_association_changes": False, "readback_transport": "rest_api"}}
    _validate_preview(preview, name, False)
    result = {"contract": "fortipam_v4_recording_policy_enable_api_execution_v1", "outcome": "succeeded", "verification": "verified", "idempotent_replay": False, "compensation": "separate_confirmed_secret_policy_reconciliation_required", "policy_name_returned": False, "raw_api_returned": False}
    _validate_execution(result, False)
    result["raw_api_returned"] = True
    with pytest.raises(RecordingPolicyMcpOAuthAcceptanceError): _validate_execution(result, False)
