from __future__ import annotations

from collections.abc import Callable

import pytest

from fortipam_mcp.discovery_job_plan import (
    discovery_entry_create_plan_requirements,
    discovery_review_plan_requirements,
    discovery_run_plan_requirements,
    job_create_plan_requirements,
    job_execute_plan_requirements,
)


@pytest.mark.parametrize(
    ("factory", "action_family"),
    (
        (discovery_entry_create_plan_requirements, "discovery-entry.create"),
        (discovery_run_plan_requirements, "discovery.run"),
        (discovery_review_plan_requirements, "discovery.review"),
        (job_create_plan_requirements, "job.create"),
        (job_execute_plan_requirements, "job.execute"),
    ),
)
def test_discovery_and_job_plans_are_version_bounded_and_non_executable(
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
        "network_scan_performed",
        "script_executed",
        "protected_material_loaded",
        "discovery_results_returned",
        "local_state_written",
        "raw_source_content_returned",
    ):
        assert result[key] is False


def test_discovery_and_job_results_return_fresh_mutable_collections() -> None:
    first = job_create_plan_requirements()
    second = job_create_plan_requirements()
    blocked_operations = first["blocked_operations"]
    assert isinstance(blocked_operations, list)
    blocked_operations.clear()
    assert second["blocked_operations"]


def test_discovery_entry_plan_reports_only_fixed_non_callable_api_candidates() -> None:
    result = discovery_entry_create_plan_requirements()

    assert result["candidate_api_contract"] == {
        "source": "sanitized_fndn_ui_catalog_1_9_0",
        "status": "catalogued_body_unproven",
        "create": {
            "method": "POST",
            "path": "/api/v2/cmdb/secret/discovery",
            "required_body": True,
            "body_schema_available": False,
        },
        "detail_readback": {
            "method": "GET",
            "path": "/api/v2/cmdb/secret/discovery/{name}",
            "response_schema_available": False,
        },
        "target_version_validated": False,
        "live_call_permitted": False,
    }
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False


def test_discovery_entry_api_candidate_is_fresh_per_call() -> None:
    first = discovery_entry_create_plan_requirements()
    second = discovery_entry_create_plan_requirements()

    first_candidate = first["candidate_api_contract"]
    assert isinstance(first_candidate, dict)
    create = first_candidate["create"]
    assert isinstance(create, dict)
    create["method"] = "PUT"

    second_candidate = second["candidate_api_contract"]
    assert isinstance(second_candidate, dict)
    assert second_candidate["create"] == {
        "method": "POST",
        "path": "/api/v2/cmdb/secret/discovery",
        "required_body": True,
        "body_schema_available": False,
    }
