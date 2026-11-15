from __future__ import annotations

from collections.abc import Callable

import pytest

from fortipam_mcp.lifecycle_gap_plan import (
    approval_profile_disable_plan_requirements,
    launcher_disable_contract_gap,
    secret_disable_contract_gap,
    secret_metadata_update_plan_requirements,
    target_disable_plan_requirements,
)


@pytest.mark.parametrize(
    ("factory", "action_family", "source_version", "target_validation_required"),
    (
        (
            secret_metadata_update_plan_requirements,
            "secret.update-metadata",
            "latest-provider-guidance",
            True,
        ),
    ),
)
def test_lifecycle_gap_plans_are_bounded_and_non_executable(
    factory: Callable[[], dict[str, object]],
    action_family: str,
    source_version: str,
    target_validation_required: bool,
) -> None:
    result = factory()
    assert result["action_family"] == action_family
    assert result["source_version"] == source_version
    assert result["target_version"] == "1.9.1"
    assert result["target_version_validation_required"] is target_validation_required
    assert result["planning_status"] == "requirements_only"
    assert result["lifecycle_contract_established"] is False
    for key in (
        "configuration_ready",
        "execution_authorized",
        "fortipam_contacted",
        "protected_material_loaded",
        "target_state_changed",
        "secret_metadata_changed",
        "approval_profile_state_changed",
        "access_or_session_effect_applied",
        "local_state_written",
        "raw_source_content_returned",
    ):
        assert result[key] is False


def test_lifecycle_gap_results_return_fresh_mutable_collections() -> None:
    first = target_disable_plan_requirements()
    second = target_disable_plan_requirements()
    first["blocked_operations"].clear()  # type: ignore[union-attr]
    assert second["blocked_operations"]


@pytest.mark.parametrize(
    "factory",
    (
        target_disable_plan_requirements,
        approval_profile_disable_plan_requirements,
        secret_disable_contract_gap,
        launcher_disable_contract_gap,
    ),
)
def test_product_unavailable_disable_gaps_reject_guessed_lifecycle_controls(
    factory: Callable[[], dict[str, object]],
) -> None:
    result = factory()
    assert result["target_version"] == "1.9.1"
    assert result["planning_status"] == "product_unavailable_in_target_version"
    assert result["action_available"] is False
    assert result["resolution_requires_implementation"] is False
    assert result["resolution_scope"] == "fortipam_1_9_1_only"
    assert result["lifecycle_contract_established"] is False
    documented = result["documented_requirements"]
    blocked = result["blocked_operations"]
    assert isinstance(documented, list)
    assert isinstance(blocked, list)
    assert any("no_" in item and "disable_field_or_command" in item for item in documented)
    assert "execution_authorization" in blocked
