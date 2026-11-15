from __future__ import annotations

from fortipam_mcp.jwt_key_plan import (
    V4_JWT_KEY_CREATE_PLAN_CONTRACT,
    V4_JWT_KEY_ROTATE_PLAN_CONTRACT,
    jwt_key_create_plan_requirements,
    jwt_key_rotate_plan_requirements,
)


def _assert_common_boundary(result: dict[str, object]) -> None:
    assert result["source_version"] == "1.8.1"
    assert result["target_version"] == "1.9.1"
    assert result["target_version_validation_required"] is True
    assert result["planning_status"] == "requirements_only"
    assert result["configuration_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["identity_provider_contacted"] is False
    assert result["protected_material_loaded"] is False
    assert result["authentication_effect_applied"] is False
    assert result["local_state_written"] is False
    assert result["raw_source_content_returned"] is False


def test_jwt_key_create_plan_is_version_bounded_and_non_executable() -> None:
    result = jwt_key_create_plan_requirements()

    _assert_common_boundary(result)
    assert result["contract"] == V4_JWT_KEY_CREATE_PLAN_CONTRACT
    assert result["action_family"] == "jwt-key.create"
    assert "jwks_oidc_metadata_or_key_fetch" in result["blocked_operations"]
    assert "jwt_validation_login_or_secret_access_test" in result[
        "blocked_operations"
    ]


def test_jwt_key_rotate_plan_is_version_bounded_and_non_executable() -> None:
    result = jwt_key_rotate_plan_requirements()

    _assert_common_boundary(result)
    assert result["contract"] == V4_JWT_KEY_ROTATE_PLAN_CONTRACT
    assert result["action_family"] == "jwt-key.rotate"
    assert "jwt_key_create_update_rotate_or_delete" in result["blocked_operations"]


def test_jwt_key_plan_results_return_fresh_mutable_collections() -> None:
    first_create = jwt_key_create_plan_requirements()
    second_create = jwt_key_create_plan_requirements()
    first_rotate = jwt_key_rotate_plan_requirements()
    second_rotate = jwt_key_rotate_plan_requirements()

    first_create["documented_requirements"].clear()  # type: ignore[union-attr]
    first_rotate["project_acceptance_requirements"].clear()  # type: ignore[union-attr]

    assert second_create["documented_requirements"]
    assert second_rotate["project_acceptance_requirements"]


def test_jwt_key_plans_report_only_fixed_non_callable_api_candidates() -> None:
    create = jwt_key_create_plan_requirements()
    rotate = jwt_key_rotate_plan_requirements()

    common = {
        "source": "sanitized_fndn_ui_catalog_1_9_0",
        "status": "catalogued_body_unproven",
        "detail_readback": {
            "method": "GET",
            "path": "/api/v2/cmdb/secret/jwt-key/{name}",
            "response_schema_available": False,
        },
        "target_version_validated": False,
        "live_call_permitted": False,
    }
    assert create["candidate_api_contract"] == {
        **common,
        "create": {
            "method": "POST",
            "path": "/api/v2/cmdb/secret/jwt-key",
            "required_body": True,
            "body_schema_available": False,
        },
    }
    assert rotate["candidate_api_contract"] == {
        **common,
        "update": {
            "method": "PUT",
            "path": "/api/v2/cmdb/secret/jwt-key/{name}",
            "required_body": True,
            "body_schema_available": False,
        },
    }


def test_jwt_key_api_candidates_are_fresh_per_call() -> None:
    first = jwt_key_create_plan_requirements()
    second = jwt_key_create_plan_requirements()

    first_candidate = first["candidate_api_contract"]
    assert isinstance(first_candidate, dict)
    create = first_candidate["create"]
    assert isinstance(create, dict)
    create["method"] = "PUT"

    second_candidate = second["candidate_api_contract"]
    assert isinstance(second_candidate, dict)
    assert second_candidate["create"] == {
        "method": "POST",
        "path": "/api/v2/cmdb/secret/jwt-key",
        "required_body": True,
        "body_schema_available": False,
    }
