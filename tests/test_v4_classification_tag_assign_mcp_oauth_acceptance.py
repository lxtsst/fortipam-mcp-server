from __future__ import annotations

import asyncio
import stat
from types import SimpleNamespace

import pytest

from scripts.v4_classification_tag_assign_mcp_oauth_acceptance import (
    ClassificationTagAssignMcpOAuthAcceptanceError,
    TOOLS,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
    run_classification_tag_assign_mcp_oauth_acceptance,
)


TARGET_NAME = "mcp-v4-target-update-01"
TAG_NAME = "mcp-v4-classification-tag-01"


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    _write_preview_state(path, "classification-tag-assign-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "classification-tag-assign-preview-opaque"
    with pytest.raises(ClassificationTagAssignMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_requires_exact_class_only_contract() -> None:
    projection = {
        "contract": "fortipam_v4_classification_tag_assign_api_workflow_v1",
        "preview_ref": "classification-tag-assign-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "requested_target_name": TARGET_NAME,
            "target_exists": True,
            "current_classification_tag_is_default": True,
            "requested_classification_tag_name": TAG_NAME,
            "classification_tag_exists": True,
            "write_transport": "rest_api",
        },
        "Proposed Changes": {
            "operation": "assign_classification_tag_to_target_via_api",
            "target_name": TARGET_NAME,
            "classification_tag_name": TAG_NAME,
            "request_body": "fixed_class_only",
        },
        "Expected State": {
            "target_exists": True,
            "classification_tag_exists": True,
            "target_class_matches": True,
            "target_non_class_state_preserved": True,
            "classification_tag_state_preserved": True,
            "readback_transport": "rest_api",
        },
    }
    _validate_preview(projection, TARGET_NAME, TAG_NAME, False)
    projection["Proposed Changes"]["unexpected"] = True
    with pytest.raises(ClassificationTagAssignMcpOAuthAcceptanceError):
        _validate_preview(projection, TARGET_NAME, TAG_NAME, False)


def test_execution_requires_categorical_preservation_readback() -> None:
    result = {
        "contract": "fortipam_v4_classification_tag_assign_api_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "separate_confirmed_target_classification_change_required",
        "target_name_returned": False,
        "classification_tag_name_returned": False,
        "target_payload_returned": False,
        "classification_tag_payload_returned": False,
        "raw_api_response_returned": False,
    }
    _validate_execution(result, False)
    result["target_payload_returned"] = True
    with pytest.raises(ClassificationTagAssignMcpOAuthAcceptanceError):
        _validate_execution(result, False)


def test_rollback_preview_state_is_direction_bound(tmp_path) -> None:
    directory = tmp_path / "rollback-state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    prefix = "classification-tag-assign-rollback-preview-"
    _write_preview_state(path, prefix + "opaque", prefix=prefix)

    assert _read_preview_ref(path, prefix=prefix) == prefix + "opaque"
    with pytest.raises(ClassificationTagAssignMcpOAuthAcceptanceError):
        _read_preview_ref(path)


def test_rollback_preview_is_value_minimized_and_fixed_to_other() -> None:
    projection = {
        "contract": "fortipam_v4_classification_tag_assign_rollback_api_workflow_v1",
        "preview_ref": "classification-tag-assign-rollback-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "target_exists": True,
            "classification_tag_exists": True,
            "target_class_matches_protected_tag": True,
            "target_or_tag_reference_returned": False,
            "write_transport": "rest_api",
        },
        "Proposed Changes": {
            "operation": "restore_target_default_classification_via_api",
            "request_body": "fixed_class_only",
            "target_classification": "Other",
            "target_non_class_fields_changed": False,
            "classification_tag_changed": False,
            "secret_folder_ztna_or_session_changed": False,
        },
        "Expected State": {
            "pre_action_state_restored": True,
            "target_classification_is_default": True,
            "target_non_class_state_preserved": True,
            "classification_tag_state_preserved": True,
            "target_or_tag_reference_returned": False,
            "readback_transport": "rest_api",
        },
    }

    _validate_preview(projection, None, None, False, rollback=True)
    projection["Current State"]["target_reference"] = TARGET_NAME
    with pytest.raises(ClassificationTagAssignMcpOAuthAcceptanceError):
        _validate_preview(projection, None, None, False, rollback=True)


def test_rollback_execution_requires_restoration_and_no_values() -> None:
    result = {
        "contract": "fortipam_v4_classification_tag_assign_rollback_api_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "pre_action_state_restored": True,
        "target_classification_is_default": True,
        "target_non_class_state_preserved": True,
        "classification_tag_state_preserved": True,
        "target_name_returned": False,
        "classification_tag_name_returned": False,
        "target_payload_returned": False,
        "classification_tag_payload_returned": False,
        "raw_api_response_returned": False,
    }

    _validate_execution(result, False, rollback=True)
    result["pre_action_state_restored"] = False
    with pytest.raises(ClassificationTagAssignMcpOAuthAcceptanceError):
        _validate_execution(result, False, rollback=True)


def test_delete_preview_and_execution_are_fixed_and_value_minimized() -> None:
    projection = {
        "contract": "fortipam_v4_classification_tag_delete_api_workflow_v1",
        "preview_ref": "classification-tag-delete-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "accepted_classification_tag_exists": True,
            "complete_api_record_digest_matches": True,
            "protected_target_class_is_other": True,
            "classification_tag_reference_count": 0,
            "selectors_returned": False,
            "read_transports": ["rest_api", "ssh_cli"],
        },
        "Proposed Changes": {
            "operation": "delete_exact_unreferenced_classification_tag_via_api",
            "classification_tag_count_affected": 1,
            "irreversible_after_execution": True,
            "target_write": False,
            "secret_folder_or_session_change": False,
        },
        "Expected State": {
            "classification_tag_absent": True,
            "protected_target_exists": True,
            "protected_target_class_is_other": True,
            "protected_target_non_class_state_preserved": True,
            "classification_tag_reference_count": 0,
            "read_transports": ["rest_api", "ssh_cli"],
        },
    }
    _validate_preview(projection, None, None, False, delete=True)

    result = {
        "contract": "fortipam_v4_classification_tag_delete_api_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "separate_classification_tag_create_action_required",
        "classification_tag_name_returned": False,
        "target_name_returned": False,
        "raw_api_response_returned": False,
    }
    _validate_execution(result, False, delete=True)
    result["target_name_returned"] = True
    with pytest.raises(ClassificationTagAssignMcpOAuthAcceptanceError):
        _validate_execution(result, False, delete=True)


def test_rollback_rejects_caller_selected_target_or_tag(tmp_path) -> None:
    with pytest.raises(
        ClassificationTagAssignMcpOAuthAcceptanceError,
        match="does not accept",
    ):
        asyncio.run(
            run_classification_tag_assign_mcp_oauth_acceptance(
                "https://fpamcp.example.test/fpamcp-v4",
                tmp_path / "login.env",
                tmp_path / "client.json",
                target_name=TARGET_NAME,
                rollback=True,
            )
        )


def test_delete_rejects_selectors_and_cannot_combine_with_rollback(tmp_path) -> None:
    with pytest.raises(ClassificationTagAssignMcpOAuthAcceptanceError):
        asyncio.run(
            run_classification_tag_assign_mcp_oauth_acceptance(
                "https://fpamcp.example.test/fpamcp-v4",
                tmp_path / "login.env",
                tmp_path / "client.json",
                classification_tag_name=TAG_NAME,
                delete=True,
            )
        )
    with pytest.raises(ClassificationTagAssignMcpOAuthAcceptanceError):
        asyncio.run(
            run_classification_tag_assign_mcp_oauth_acceptance(
                "https://fpamcp.example.test/fpamcp-v4",
                tmp_path / "login.env",
                tmp_path / "client.json",
                rollback=True,
                delete=True,
            )
        )


def test_rollback_execution_selects_only_fixed_rollback_tools(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    directory = tmp_path / "rollback-execution"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    state = directory / "preview.json"
    prefix = "classification-tag-assign-rollback-preview-"
    _write_preview_state(state, f"{prefix}opaque", prefix=prefix)
    names = TOOLS | {f"other_tool_{index}" for index in range(289)}
    calls: list[tuple[str, dict[str, object]]] = []

    class FakeSession:
        async def list_tools(self):
            return SimpleNamespace(
                tools=[SimpleNamespace(name=name) for name in sorted(names)]
            )

        async def call_tool(self, name: str, arguments: dict[str, object]):
            calls.append((name, arguments))
            if name == "confirm_v4_classification_tag_assign_rollback":
                return SimpleNamespace(
                    is_error=False,
                    structured_content={
                        "contract": (
                            "fortipam_v4_classification_tag_assign_rollback_api_workflow_v1"
                        ),
                        "authorization_ref": (
                            "classification-tag-assign-rollback-authorized-opaque"
                        ),
                        "confirmation": "recorded",
                        "execution": "authorized_once",
                        "device_write_executed": False,
                    },
                )
            if name == "execute_confirmed_v4_classification_tag_assign_rollback":
                return SimpleNamespace(
                    is_error=False,
                    structured_content={
                        "contract": (
                            "fortipam_v4_classification_tag_assign_rollback_api_execution_v1"
                        ),
                        "outcome": "succeeded",
                        "verification": "verified",
                        "idempotent_replay": False,
                        "pre_action_state_restored": True,
                        "target_classification_is_default": True,
                        "target_non_class_state_preserved": True,
                        "classification_tag_state_preserved": True,
                        "target_name_returned": False,
                        "classification_tag_name_returned": False,
                        "target_payload_returned": False,
                        "classification_tag_payload_returned": False,
                        "raw_api_response_returned": False,
                    },
                )
            raise AssertionError(name)

    async def fake_common(*args, **kwargs):
        await kwargs["tool_session_callback"](FakeSession())
        return {
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
            "token_revoked": True,
            "credential_values_returned": False,
        }

    monkeypatch.setattr(
        "scripts.v4_classification_tag_assign_mcp_oauth_acceptance.oauth.run_address_mcp_oauth_surface_acceptance",
        fake_common,
    )
    result = asyncio.run(
        run_classification_tag_assign_mcp_oauth_acceptance(
            "https://fpamcp.example.test/fpamcp-v4",
            tmp_path / "login.env",
            tmp_path / "client.json",
            execute_preview_state_file=state,
            rollback=True,
        )
    )

    assert calls == [
        (
            "confirm_v4_classification_tag_assign_rollback",
            {"preview_ref": f"{prefix}opaque"},
        ),
        (
            "execute_confirmed_v4_classification_tag_assign_rollback",
            {
                "authorization_ref": (
                    "classification-tag-assign-rollback-authorized-opaque"
                )
            },
        ),
    ]
    assert result["classification_tag_assign_direction"] == "rollback"
    assert result["classification_tag_assign_execution_verified"] is True
    assert result["device_write_executed"] is True
    assert not state.exists()
