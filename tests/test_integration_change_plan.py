from __future__ import annotations

from collections.abc import Callable

import pytest

from fortipam_mcp.integration_change_plan import (
    approval_delivery_plan_requirements,
    fabric_connector_plan_requirements,
    reverse_service_plan_requirements,
    secret_gateway_chain_plan_requirements,
    ztna_tag_create_plan_requirements,
    ztna_tag_group_create_plan_requirements,
)


@pytest.mark.parametrize(
    ("factory", "action_family"),
    (
        (approval_delivery_plan_requirements, "approval-delivery.configure"),
        (fabric_connector_plan_requirements, "fabric-connector.configure"),
        (secret_gateway_chain_plan_requirements, "secret-gateway.chain.configure"),
        (reverse_service_plan_requirements, "reverse-service.configure"),
        (ztna_tag_create_plan_requirements, "ztna-tag.create"),
        (ztna_tag_group_create_plan_requirements, "ztna-tag-group.create"),
    ),
)
def test_integration_change_plans_are_version_bounded_and_non_executable(
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
        "external_service_contacted",
        "protected_material_loaded",
        "topology_loaded",
        "notification_sent",
        "trust_changed",
        "routing_changed",
        "tag_changed",
        "policy_effect_applied",
        "local_state_written",
        "raw_source_content_returned",
    ):
        assert result[key] is False


def test_integration_change_results_return_fresh_mutable_collections() -> None:
    first = fabric_connector_plan_requirements()
    second = fabric_connector_plan_requirements()
    first["blocked_operations"].clear()  # type: ignore[union-attr]
    assert second["blocked_operations"]
