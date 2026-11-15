from __future__ import annotations

import stat

import pytest

from scripts.v4_target_update_mcp_oauth_acceptance import (
    TargetUpdateMcpOAuthAcceptanceError,
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
    _write_preview_state(path, "target-update-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "target-update-preview-opaque"
    with pytest.raises(TargetUpdateMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_requires_the_exact_minimal_description_contract() -> None:
    name = "mcp-v4-target-b80"
    description = "bounded laboratory metadata"
    projection = {
        "contract": "fortipam_v4_target_description_update_api_workflow_v1",
        "preview_ref": "target-update-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "requested_target_name": name,
            "target_exists": True,
            "requested_description_already_matches": False,
            "write_transport": "rest_api",
        },
        "Proposed Changes": {
            "operation": "update_target_description_via_api",
            "target_name": name,
            "requested_description": description,
        },
        "Expected State": {
            "target_exists": True,
            "target_name_matches": True,
            "description_matches_requested_value": True,
        },
    }
    _validate_preview(projection, name, description, False)
    projection["Proposed Changes"]["unexpected"] = True
    with pytest.raises(TargetUpdateMcpOAuthAcceptanceError):
        _validate_preview(projection, name, description, False)


def test_execution_requires_categorical_verified_readback() -> None:
    result = {
        "contract": "fortipam_v4_target_description_update_api_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "not_requested",
        "target_name_returned": False,
        "description_returned": False,
        "raw_api_response_returned": False,
    }
    _validate_execution(result, False)
    result["description_returned"] = True
    with pytest.raises(TargetUpdateMcpOAuthAcceptanceError):
        _validate_execution(result, False)
