from __future__ import annotations

from collections.abc import Callable

import pytest

from fortipam_mcp.password_lifecycle_plan import (
    checkout_policy_plan_requirements,
    jit_policy_plan_requirements,
    password_changer_create_plan_requirements,
    password_verification_plan_requirements,
    service_account_update_plan_requirements,
)


@pytest.mark.parametrize(
    ("factory", "action_family"),
    (
        (password_changer_create_plan_requirements, "password-changer.create"),
        (password_verification_plan_requirements, "password-verification.configure"),
        (checkout_policy_plan_requirements, "checkout-policy.configure"),
        (jit_policy_plan_requirements, "jit-policy.configure"),
        (service_account_update_plan_requirements, "service-account.update"),
    ),
)
def test_password_lifecycle_plans_are_version_bounded_and_non_executable(
    factory: Callable[[], dict[str, object]],
    action_family: str,
) -> None:
    result = factory()
    assert result["action_family"] == action_family
    assert result["source_version"] == "1.9.0"
    assert result["target_version"] == "1.9.1"
    assert result["target_version_validation_required"] is True
    assert result["planning_status"] == "requirements_only"
    for key in (
        "configuration_ready",
        "execution_authorized",
        "fortipam_contacted",
        "target_contacted",
        "protected_material_loaded",
        "credential_changed_or_verified",
        "privilege_changed",
        "script_executed",
        "local_state_written",
        "raw_source_content_returned",
    ):
        assert result[key] is False


def test_password_lifecycle_results_return_fresh_mutable_collections() -> None:
    first = password_changer_create_plan_requirements()
    second = password_changer_create_plan_requirements()
    first["blocked_operations"].clear()  # type: ignore[union-attr]
    assert second["blocked_operations"]


def test_password_changer_plan_reports_only_fixed_non_callable_api_candidates() -> None:
    result = password_changer_create_plan_requirements()

    assert result["candidate_api_contract"] == {
        "source": "sanitized_fndn_ui_catalog_1_9_0",
        "status": "catalogued_body_unproven",
        "create": {
            "method": "POST",
            "path": "/api/v2/cmdb/secret/password-changer",
            "required_body": True,
            "body_schema_available": False,
        },
        "detail_readback": {
            "method": "GET",
            "path": "/api/v2/cmdb/secret/password-changer/{name}",
            "response_schema_available": False,
        },
        "target_version_validated": False,
        "live_call_permitted": False,
    }


def test_password_changer_api_candidate_is_fresh_per_call() -> None:
    first = password_changer_create_plan_requirements()
    second = password_changer_create_plan_requirements()

    first_candidate = first["candidate_api_contract"]
    assert isinstance(first_candidate, dict)
    create = first_candidate["create"]
    assert isinstance(create, dict)
    create["method"] = "PUT"

    second_candidate = second["candidate_api_contract"]
    assert isinstance(second_candidate, dict)
    assert second_candidate["create"] == {
        "method": "POST",
        "path": "/api/v2/cmdb/secret/password-changer",
        "required_body": True,
        "body_schema_available": False,
    }
