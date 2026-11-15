from __future__ import annotations

from collections.abc import Callable

import pytest

from fortipam_mcp.secret_onboarding_plan import (
    V4_SECRET_BULK_IMPORT_BUILD_CONTRACT,
    build_secret_bulk_import_plan,
    launcher_clone_plan_requirements,
    policy_assign_plan_requirements,
    secret_bulk_import_apply_requirements,
    secret_bulk_import_plan_requirements,
)


@pytest.mark.parametrize(
    ("factory", "action_family"),
    (
        (secret_bulk_import_plan_requirements, "secret.bulk-import.plan"),
        (secret_bulk_import_apply_requirements, "secret.bulk-import.apply"),
        (launcher_clone_plan_requirements, "launcher.clone"),
        (policy_assign_plan_requirements, "policy.assign"),
    ),
)
def test_secret_onboarding_plans_are_version_bounded_and_non_executable(
    factory: Callable[[], dict[str, object]],
    action_family: str,
) -> None:
    result = factory()
    assert result["action_family"] == action_family
    assert result["source_version"] == "1.9.1"
    assert result["target_version"] == "1.9.1"
    assert result["target_version_validation_required"] is False
    assert result["planning_status"] == "requirements_only"
    for key in (
        "configuration_ready",
        "execution_authorized",
        "fortipam_contacted",
        "protected_material_loaded",
        "import_file_loaded",
        "secret_created",
        "launcher_cloned",
        "policy_assigned",
        "session_effect_applied",
        "local_state_written",
        "raw_source_content_returned",
    ):
        assert result[key] is False


def test_secret_onboarding_results_return_fresh_mutable_collections() -> None:
    first = secret_bulk_import_plan_requirements()
    second = secret_bulk_import_plan_requirements()
    first["blocked_operations"].clear()  # type: ignore[union-attr]
    assert second["blocked_operations"]


def _build_bulk_import_plan(**overrides: bool) -> dict[str, object]:
    evidence = {
        "template_schema_verified": True,
        "fixed_scope_dependencies_verified": True,
        "protected_file_custody_ready": True,
        "value_free_preview_verified": True,
        "duplicate_conflict_policy_verified": True,
        "bounded_row_limits_defined": True,
        "preview_binding_verified": True,
        "cleanup_recovery_approved": True,
    }
    evidence.update(overrides)
    return build_secret_bulk_import_plan(**evidence)


def test_bulk_import_plan_builder_returns_only_categorical_readiness() -> None:
    result = _build_bulk_import_plan(preview_binding_verified=False)

    assert result["contract"] == V4_SECRET_BULK_IMPORT_BUILD_CONTRACT
    assert result["action_family"] == "secret.bulk-import.plan"
    assert result["planning_status"] == "incomplete_evidence"
    assert result["missing_requirements"] == ["preview_binding_verified"]
    assert result["satisfied_requirement_count"] == 7
    assert result["requirement_count"] == 8
    assert result["plan_ready"] is False
    assert result["authoritative_device_state_observed"] is False
    assert result["import_file_loaded"] is False
    assert result["preview_generated"] is False
    assert result["apply_execution_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["protected_material_accepted"] is False


def test_bulk_import_plan_builder_can_finish_plan_without_authorizing_apply() -> None:
    result = _build_bulk_import_plan()

    assert result["planning_status"] == "ready_for_operator_review"
    assert result["missing_requirements"] == []
    assert result["plan_ready"] is True
    assert result["apply_execution_ready"] is False
    assert result["execution_authorized"] is False


def test_bulk_import_plan_builder_rejects_non_boolean_evidence() -> None:
    with pytest.raises(ValueError, match="must be boolean"):
        _build_bulk_import_plan(preview_binding_verified=1)  # type: ignore[arg-type]
