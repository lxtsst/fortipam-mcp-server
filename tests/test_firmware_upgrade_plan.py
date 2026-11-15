from __future__ import annotations

import pytest

from fortipam_mcp.firmware_upgrade_plan import (
    V4_FIRMWARE_UPGRADE_BUILD_CONTRACT,
    V4_FIRMWARE_UPGRADE_PLAN_CONTRACT,
    build_firmware_upgrade_plan,
    firmware_upgrade_plan_requirements,
)


def test_firmware_upgrade_plan_is_fixed_value_free_and_non_executable() -> None:
    result = firmware_upgrade_plan_requirements()

    assert result["contract"] == V4_FIRMWARE_UPGRADE_PLAN_CONTRACT
    assert result["action_family"] == "firmware.upgrade.plan"
    assert result["target_version"] == "1.9.1"
    assert result["documented_upgrade_origins"] == ["1.7.x", "1.8.x"]
    assert result["planning_status"] == "requirements_only"
    assert result["execution_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["local_state_written"] is False
    assert result["protected_material_accepted"] is False
    assert result["raw_source_content_returned"] is False
    assert set(result["blocked_operations"]) == {
        "device_state_read",
        "upgrade_path_inference",
        "firmware_download",
        "firmware_upload",
        "maintenance_mode_change",
        "backup_create_or_restore",
        "reboot",
        "execution_authorization",
    }


def test_firmware_upgrade_plan_returns_fresh_mutable_collections() -> None:
    first = firmware_upgrade_plan_requirements()
    second = firmware_upgrade_plan_requirements()

    first["documented_prerequisites"].clear()  # type: ignore[union-attr]
    first["documented_upgrade_origins"].clear()  # type: ignore[union-attr]

    assert second["documented_prerequisites"]
    assert second["documented_upgrade_origins"] == ["1.7.x", "1.8.x"]


def _build_plan(**overrides: bool) -> dict[str, object]:
    evidence = {
        "current_version_path_verified": True,
        "deployment_ha_procedure_ready": True,
        "backup_custody_verified": True,
        "isolated_restore_test_passed": True,
        "maintenance_window_approved": True,
        "pre_post_checks_defined": True,
        "failure_rollback_approved": True,
    }
    evidence.update(overrides)
    return build_firmware_upgrade_plan(**evidence)


def test_firmware_upgrade_builder_returns_only_categorical_readiness() -> None:
    result = _build_plan(current_version_path_verified=False)

    assert result["contract"] == V4_FIRMWARE_UPGRADE_BUILD_CONTRACT
    assert result["action_family"] == "firmware.upgrade.plan"
    assert result["planning_status"] == "incomplete_evidence"
    assert result["missing_requirements"] == ["current_version_path_verified"]
    assert result["satisfied_requirement_count"] == 6
    assert result["requirement_count"] == 7
    assert result["plan_ready"] is False
    assert result["authoritative_device_state_observed"] is False
    assert result["firmware_artifact_verified"] is False
    assert result["upgrade_execution_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["protected_material_accepted"] is False


def test_firmware_upgrade_builder_can_finish_plan_without_authorizing_upgrade() -> None:
    result = _build_plan()

    assert result["planning_status"] == "ready_for_operator_review"
    assert result["missing_requirements"] == []
    assert result["plan_ready"] is True
    assert result["firmware_artifact_verified"] is False
    assert result["upgrade_execution_ready"] is False
    assert result["execution_authorized"] is False


def test_firmware_upgrade_builder_rejects_non_boolean_evidence() -> None:
    with pytest.raises(ValueError, match="must be boolean"):
        _build_plan(current_version_path_verified=1)  # type: ignore[arg-type]
