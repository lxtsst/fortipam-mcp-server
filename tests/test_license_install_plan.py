from __future__ import annotations

import pytest

from fortipam_mcp.license_install_plan import (
    V4_LICENSE_INSTALL_BUILD_CONTRACT,
    V4_LICENSE_INSTALL_PLAN_CONTRACT,
    build_license_install_plan,
    license_install_plan_requirements,
)


def test_license_install_plan_is_fixed_value_free_and_non_executable() -> None:
    result = license_install_plan_requirements()

    assert result["contract"] == V4_LICENSE_INSTALL_PLAN_CONTRACT
    assert result["action_family"] == "license.install"
    assert result["target_version"] == "1.9.1"
    assert result["planning_status"] == "requirements_only"
    assert result["license_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["forticloud_contacted"] is False
    assert result["local_state_written"] is False
    assert result["protected_material_accepted"] is False
    assert result["raw_source_content_returned"] is False
    assert set(result["blocked_operations"]) == {
        "forticloud_authentication_or_registration",
        "registration_code_input_or_output",
        "license_file_input_or_output",
        "device_state_read",
        "maintenance_mode_change",
        "gui_license_upload",
        "scp_license_upload",
        "reboot",
        "execution_authorization",
    }


def test_license_install_plan_returns_fresh_mutable_collections() -> None:
    first = license_install_plan_requirements()
    second = license_install_plan_requirements()

    first["documented_requirements"].clear()  # type: ignore[union-attr]
    first["documented_evaluation_limits"].clear()  # type: ignore[union-attr]

    assert second["documented_requirements"]
    assert second["documented_evaluation_limits"]


def _build_plan(**overrides: bool) -> dict[str, object]:
    evidence = {
        "entitlement_owner_verified": True,
        "deployment_ha_mode_verified": True,
        "license_custody_ready": True,
        "backup_recovery_verified": True,
        "maintenance_reboot_approved": True,
        "break_fix_access_verified": True,
        "post_boot_checks_defined": True,
        "failure_recovery_approved": True,
    }
    evidence.update(overrides)
    return build_license_install_plan(**evidence)


def test_license_builder_is_categorical_and_non_executing() -> None:
    result = _build_plan(license_custody_ready=False)
    assert result["contract"] == V4_LICENSE_INSTALL_BUILD_CONTRACT
    assert result["missing_requirements"] == ["license_custody_ready"]
    assert result["plan_ready"] is False
    assert result["license_artifact_verified"] is False
    assert result["license_execution_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["forticloud_contacted"] is False


def test_license_builder_complete_plan_still_has_no_execution_authority() -> None:
    result = _build_plan()
    assert result["planning_status"] == "ready_for_operator_review"
    assert result["plan_ready"] is True
    assert result["license_execution_ready"] is False
    assert result["execution_authorized"] is False


def test_license_builder_rejects_non_boolean_evidence() -> None:
    with pytest.raises(ValueError, match="must be boolean"):
        _build_plan(license_custody_ready=1)  # type: ignore[arg-type]
    build_license_install_plan,
