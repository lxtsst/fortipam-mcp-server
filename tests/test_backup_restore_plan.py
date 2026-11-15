from __future__ import annotations

import pytest

from fortipam_mcp.backup_restore_plan import (
    V4_BACKUP_CREATE_BUILD_CONTRACT,
    V4_BACKUP_CREATE_PLAN_CONTRACT,
    V4_BACKUP_RESTORE_BUILD_CONTRACT,
    V4_BACKUP_RESTORE_PLAN_CONTRACT,
    backup_create_plan_requirements,
    backup_restore_plan_requirements,
    build_backup_create_plan,
    build_backup_restore_plan,
)


def test_backup_create_plan_is_fixed_value_free_and_non_executable() -> None:
    result = backup_create_plan_requirements()

    assert result["contract"] == V4_BACKUP_CREATE_PLAN_CONTRACT
    assert result["action_family"] == "backup.create"
    assert result["target_version"] == "1.9.1"
    assert result["planning_status"] == "requirements_only"
    assert result["backup_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["local_state_written"] is False
    assert result["protected_material_accepted"] is False
    assert result["raw_source_content_returned"] is False
    assert set(result["blocked_operations"]) == {
        "device_state_read",
        "backup_create_dispatch",
        "backup_download",
        "backup_artifact_input_or_output",
        "password_or_encryption_key_input_or_output",
        "maintenance_mode_change",
        "restore_dispatch",
        "reboot",
        "execution_authorization",
    }


def test_backup_create_plan_returns_fresh_mutable_collections() -> None:
    first = backup_create_plan_requirements()
    second = backup_create_plan_requirements()

    first["documented_requirements"].clear()  # type: ignore[union-attr]
    first["project_acceptance_requirements"].clear()  # type: ignore[union-attr]

    assert second["documented_requirements"]
    assert second["project_acceptance_requirements"]


def _build_backup_plan(**overrides: bool) -> dict[str, object]:
    evidence = {
        "source_appliance_version_recorded": True,
        "operator_destination_ready": True,
        "encryption_policy_approved": True,
        "protected_material_custody_ready": True,
        "artifact_integrity_record_ready": True,
        "retention_policy_verified": True,
        "isolated_restore_test_defined": True,
        "failure_recovery_approved": True,
    }
    evidence.update(overrides)
    return build_backup_create_plan(**evidence)


def test_backup_create_plan_builder_returns_only_categorical_readiness() -> None:
    result = _build_backup_plan(retention_policy_verified=False)

    assert result["contract"] == V4_BACKUP_CREATE_BUILD_CONTRACT
    assert result["action_family"] == "backup.create"
    assert result["planning_status"] == "incomplete_evidence"
    assert result["missing_requirements"] == ["retention_policy_verified"]
    assert result["satisfied_requirement_count"] == 7
    assert result["requirement_count"] == 8
    assert result["plan_ready"] is False
    assert result["authoritative_device_state_observed"] is False
    assert result["backup_execution_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["protected_material_accepted"] is False


def test_backup_create_plan_builder_can_finish_plan_without_authorizing_backup() -> None:
    result = _build_backup_plan()

    assert result["planning_status"] == "ready_for_operator_review"
    assert result["missing_requirements"] == []
    assert result["plan_ready"] is True
    assert result["backup_execution_ready"] is False
    assert result["execution_authorized"] is False


def test_backup_create_plan_builder_rejects_non_boolean_evidence() -> None:
    with pytest.raises(ValueError, match="must be boolean"):
        _build_backup_plan(retention_policy_verified=1)  # type: ignore[arg-type]


def test_backup_restore_plan_is_fixed_value_free_and_non_executable() -> None:
    result = backup_restore_plan_requirements()

    assert result["contract"] == V4_BACKUP_RESTORE_PLAN_CONTRACT
    assert result["action_family"] == "backup.restore.plan"
    assert result["target_version"] == "1.9.1"
    assert result["planning_status"] == "requirements_only"
    assert result["backup_ready"] is False
    assert result["restore_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["local_state_written"] is False
    assert result["protected_material_accepted"] is False
    assert result["raw_source_content_returned"] is False
    assert set(result["blocked_operations"]) == {
        "device_state_read",
        "backup_download",
        "backup_upload",
        "backup_artifact_input_or_output",
        "password_or_encryption_key_input_or_output",
        "maintenance_mode_change",
        "restore_dispatch",
        "session_termination",
        "reboot",
        "execution_authorization",
    }


def test_backup_restore_plan_returns_fresh_mutable_collections() -> None:
    first = backup_restore_plan_requirements()
    second = backup_restore_plan_requirements()

    first["documented_requirements"].clear()  # type: ignore[union-attr]
    first["documented_restore_effects"].clear()  # type: ignore[union-attr]

    assert second["documented_requirements"]
    assert second["documented_restore_effects"]


def _build_plan(**overrides: bool) -> dict[str, object]:
    evidence = {
        "source_destination_version_compatible": True,
        "deployment_restore_procedure_ready": True,
        "protected_material_custody_ready": True,
        "artifact_integrity_verified": True,
        "isolated_restore_test_passed": True,
        "maintenance_window_approved": True,
        "pre_post_checks_defined": True,
        "failure_recovery_approved": True,
    }
    evidence.update(overrides)
    return build_backup_restore_plan(**evidence)


def test_backup_restore_plan_builder_returns_only_categorical_readiness() -> None:
    result = _build_plan(artifact_integrity_verified=False)

    assert result["contract"] == V4_BACKUP_RESTORE_BUILD_CONTRACT
    assert result["action_family"] == "backup.restore.plan"
    assert result["planning_status"] == "incomplete_evidence"
    assert result["missing_requirements"] == ["artifact_integrity_verified"]
    assert result["satisfied_requirement_count"] == 7
    assert result["requirement_count"] == 8
    assert result["plan_ready"] is False
    assert result["authoritative_device_state_observed"] is False
    assert result["restore_execution_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["protected_material_accepted"] is False


def test_backup_restore_plan_builder_can_finish_plan_without_authorizing_restore() -> None:
    result = _build_plan()

    assert result["planning_status"] == "ready_for_operator_review"
    assert result["missing_requirements"] == []
    assert result["plan_ready"] is True
    assert result["restore_execution_ready"] is False
    assert result["execution_authorized"] is False


def test_backup_restore_plan_builder_rejects_non_boolean_evidence() -> None:
    with pytest.raises(ValueError, match="must be boolean"):
        _build_plan(artifact_integrity_verified=1)  # type: ignore[arg-type]
