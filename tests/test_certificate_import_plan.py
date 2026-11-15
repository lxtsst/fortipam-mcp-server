from __future__ import annotations

from fortipam_mcp.certificate_import_plan import (
    V4_CERTIFICATE_IMPORT_PLAN_CONTRACT,
    V4_CRL_IMPORT_PLAN_CONTRACT,
    certificate_import_plan_requirements,
    crl_import_plan_requirements,
)


def _assert_common_boundary(result: dict[str, object]) -> None:
    assert result["target_version"] == "1.9.1"
    assert result["planning_status"] == "requirements_only"
    assert result["configuration_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["external_service_contacted"] is False
    assert result["local_state_written"] is False
    assert result["protected_material_loaded"] is False
    assert result["raw_source_content_returned"] is False


def test_certificate_import_plan_is_source_pinned_and_non_executable() -> None:
    result = certificate_import_plan_requirements()

    _assert_common_boundary(result)
    assert result["contract"] == V4_CERTIFICATE_IMPORT_PLAN_CONTRACT
    assert result["action_family"] == "certificate.import"
    assert result["source_version"] == "1.9.1"
    assert result["target_version_validation_required"] is False
    assert "artifact_upload_download_or_content_return" in result["blocked_operations"]
    assert "certificate_binding_or_trust_change" in result["blocked_operations"]


def test_crl_import_plan_is_version_bounded_and_non_executable() -> None:
    result = crl_import_plan_requirements()

    _assert_common_boundary(result)
    assert result["contract"] == V4_CRL_IMPORT_PLAN_CONTRACT
    assert result["action_family"] == "crl.import"
    assert result["source_version"] == "1.0.3"
    assert result["target_version_validation_required"] is True
    assert "crl_import_update_delete_or_refresh" in result["blocked_operations"]
    assert "http_ldap_scep_or_ca_contact" in result["blocked_operations"]


def test_certificate_import_plan_results_return_fresh_mutable_collections() -> None:
    first_certificate = certificate_import_plan_requirements()
    second_certificate = certificate_import_plan_requirements()
    first_crl = crl_import_plan_requirements()
    second_crl = crl_import_plan_requirements()

    first_certificate["documented_requirements"].clear()  # type: ignore[union-attr]
    first_crl["project_acceptance_requirements"].clear()  # type: ignore[union-attr]

    assert second_certificate["documented_requirements"]
    assert second_crl["project_acceptance_requirements"]


def test_certificate_import_plans_report_only_fixed_non_callable_api_candidates() -> None:
    certificate = certificate_import_plan_requirements()
    crl = crl_import_plan_requirements()

    assert certificate["candidate_api_contract"] == {
        "source": "sanitized_fndn_ui_catalog_1_9_0",
        "status": "catalogued_body_unproven",
        "imports": [
            {
                "certificate_type": certificate_type,
                "method": "POST",
                "path": f"/api/v2/monitor/vpn-certificate/{certificate_type}/import",
                "required_body": True,
                "body_schema_available": False,
                "response_schema_available": False,
            }
            for certificate_type in ("ca", "local", "remote")
        ],
        "target_version_validated": False,
        "live_call_permitted": False,
    }
    assert crl["candidate_api_contract"] == {
        "source": "sanitized_fndn_ui_catalog_1_9_0",
        "status": "catalogued_body_unproven",
        "import": {
            "method": "POST",
            "path": "/api/v2/monitor/vpn-certificate/crl/import",
            "required_body": True,
            "body_schema_available": False,
            "response_schema_available": False,
        },
        "target_version_validated": False,
        "live_call_permitted": False,
    }


def test_certificate_import_api_candidates_are_fresh_per_call() -> None:
    first = certificate_import_plan_requirements()
    second = certificate_import_plan_requirements()

    first_candidate = first["candidate_api_contract"]
    assert isinstance(first_candidate, dict)
    imports = first_candidate["imports"]
    assert isinstance(imports, list)
    imports.clear()

    second_candidate = second["candidate_api_contract"]
    assert isinstance(second_candidate, dict)
    second_imports = second_candidate["imports"]
    assert isinstance(second_imports, list)
    assert len(second_imports) == 3
