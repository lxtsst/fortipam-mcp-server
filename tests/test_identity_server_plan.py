from __future__ import annotations

from fortipam_mcp.identity_server_plan import (
    V4_LDAP_SERVER_PLAN_CONTRACT,
    V4_RADIUS_SERVER_PLAN_CONTRACT,
    V4_SAML_SERVER_PLAN_CONTRACT,
    ldap_server_plan_requirements,
    radius_server_plan_requirements,
    saml_server_plan_requirements,
)


def _assert_common_boundary(result: dict[str, object]) -> None:
    assert result["target_version"] == "1.9.1"
    assert result["target_version_validation_required"] is True
    assert result["planning_status"] == "requirements_only"
    assert result["configuration_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["external_identity_service_contacted"] is False
    assert result["protected_material_loaded"] is False
    assert result["authentication_effect_applied"] is False
    assert result["local_state_written"] is False
    assert result["raw_source_content_returned"] is False


def test_ldap_server_plan_is_version_bounded_and_non_executable() -> None:
    result = ldap_server_plan_requirements()

    _assert_common_boundary(result)
    assert result["contract"] == V4_LDAP_SERVER_PLAN_CONTRACT
    assert result["action_family"] == "ldap-server.configure"
    assert result["source_version"] == "1.8.1"
    assert "directory_bind_search_or_connection_test" in result["blocked_operations"]


def test_radius_server_plan_is_version_bounded_and_non_executable() -> None:
    result = radius_server_plan_requirements()

    _assert_common_boundary(result)
    assert result["contract"] == V4_RADIUS_SERVER_PLAN_CONTRACT
    assert result["action_family"] == "radius-server.configure"
    assert result["source_version"] == "1.8.0"
    assert "radius_request_or_connection_test" in result["blocked_operations"]


def test_saml_server_plan_is_version_bounded_and_non_executable() -> None:
    result = saml_server_plan_requirements()

    _assert_common_boundary(result)
    assert result["contract"] == V4_SAML_SERVER_PLAN_CONTRACT
    assert result["action_family"] == "saml-server.configure"
    assert result["source_version"] == "1.8.1"
    assert "browser_login_assertion_or_logout_test" in result["blocked_operations"]


def test_identity_server_plan_results_return_fresh_mutable_collections() -> None:
    first = ldap_server_plan_requirements()
    second = ldap_server_plan_requirements()
    radius = radius_server_plan_requirements()
    saml = saml_server_plan_requirements()

    first["documented_requirements"].clear()  # type: ignore[union-attr]
    radius["project_acceptance_requirements"].clear()  # type: ignore[union-attr]
    saml["blocked_operations"].clear()  # type: ignore[union-attr]

    assert second["documented_requirements"]
    assert radius_server_plan_requirements()["project_acceptance_requirements"]
    assert saml_server_plan_requirements()["blocked_operations"]


def test_identity_server_plans_report_only_fixed_non_callable_api_candidates() -> None:
    for factory, resource in (
        (ldap_server_plan_requirements, "ldap"),
        (radius_server_plan_requirements, "radius"),
        (saml_server_plan_requirements, "saml"),
    ):
        result = factory()
        assert result["candidate_api_contract"] == {
            "source": "sanitized_fndn_ui_catalog_1_9_0",
            "status": "catalogued_body_unproven",
            "create": {
                "method": "POST",
                "path": f"/api/v2/cmdb/user/{resource}",
                "required_body": True,
                "body_schema_available": False,
            },
            "detail_readback": {
                "method": "GET",
                "path": f"/api/v2/cmdb/user/{resource}/{{name}}",
                "response_schema_available": False,
            },
            "target_version_validated": False,
            "live_call_permitted": False,
        }


def test_identity_server_api_candidates_are_fresh_per_call() -> None:
    first = ldap_server_plan_requirements()
    second = ldap_server_plan_requirements()

    first_candidate = first["candidate_api_contract"]
    assert isinstance(first_candidate, dict)
    create = first_candidate["create"]
    assert isinstance(create, dict)
    create["method"] = "PUT"

    second_candidate = second["candidate_api_contract"]
    assert isinstance(second_candidate, dict)
    assert second_candidate["create"] == {
        "method": "POST",
        "path": "/api/v2/cmdb/user/ldap",
        "required_body": True,
        "body_schema_available": False,
    }
