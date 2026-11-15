from __future__ import annotations

from collections.abc import Callable

import pytest

from fortipam_mcp.secret_experience_plan import (
    event_subscription_plan_requirements,
    instruction_profile_create_plan_requirements,
)


@pytest.mark.parametrize(
    ("factory", "action_family"),
    (
        (instruction_profile_create_plan_requirements, "instruction-profile.create"),
        (event_subscription_plan_requirements, "event-subscription.configure"),
    ),
)
def test_secret_experience_plans_are_version_bounded_and_non_executable(
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
        "instruction_content_loaded",
        "resource_uploaded",
        "subscription_changed",
        "notification_sent",
        "secret_attachment_changed",
        "local_state_written",
        "raw_source_content_returned",
    ):
        assert result[key] is False


def test_secret_experience_results_return_fresh_mutable_collections() -> None:
    first = instruction_profile_create_plan_requirements()
    second = instruction_profile_create_plan_requirements()
    first["blocked_operations"].clear()  # type: ignore[union-attr]
    assert second["blocked_operations"]
