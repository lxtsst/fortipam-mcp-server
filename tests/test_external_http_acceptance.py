from __future__ import annotations

import pytest

from scripts.external_http_acceptance import (
    _safe_aggregate_result,
    _assert_strict_diagnostic_schema,
    _assert_strict_no_input_schema,
    _safe_cli_result,
    _safe_diagnostic_result,
    _safe_result,
    _safe_ems_result,
    _safe_password_changer_result,
    _validate_url,
)
from fortipam_mcp.posture_contracts import OVERALL_HEALTH_COMPONENTS


def test_external_http_acceptance_allows_only_https_or_loopback_http() -> None:
    _validate_url("https://mcp.example.com/fpamcp", "/fpamcp")
    _validate_url("http://127.0.0.1:18038/fpamcp", "/fpamcp")

    with pytest.raises(ValueError, match="HTTPS or loopback"):
        _validate_url("http://mcp.example.com/fpamcp", "/fpamcp")
    with pytest.raises(ValueError, match="configured path"):
        _validate_url("https://mcp.example.com/other", "/fpamcp")


def test_external_http_acceptance_retains_only_contract_facts() -> None:
    assert _safe_result(
        {
            "status_code": 200,
            "response_body_returned": False,
            "sensitive-looking-derived-field": "not-retained",
        }
    ) == {"status_code": 200, "response_body_returned": False}

    with pytest.raises(RuntimeError, match="minimized response contract"):
        _safe_result({"status_code": 500, "response_body_returned": False})


def test_external_http_acceptance_validates_and_minimizes_aggregate() -> None:
    components = {
        name: {"evidence_state": "observed", "risk_signal": "not_assessed"}
        for name in OVERALL_HEALTH_COMPONENTS
    }
    aggregate = {
        "response_body_returned": False,
        "posture": {
            "contract": "fortipam_overall_health_posture_v1",
            "evidence_completeness": "complete",
            "risk_signal": "none_observed",
            "components": components,
            "completed_reads": 7,
            "failed_reads": 0,
            "fixed_route_count": 7,
            "response_body_returned": False,
            "raw_component_results_returned": False,
            "component_error_details_returned": False,
            "identity_values_returned": False,
            "network_values_returned": False,
            "exact_time_values_returned": False,
            "exact_capacity_values_returned": False,
        },
    }

    assert _safe_aggregate_result(aggregate) == {
        "evidence_completeness": "complete",
        "risk_signal": "none_observed",
        "completed_reads": 7,
        "failed_reads": 0,
        "fixed_route_count": 7,
        "response_body_returned": False,
        "raw_component_results_returned": False,
        "component_error_details_returned": False,
    }
    assert "components" not in _safe_aggregate_result(aggregate)

    aggregate["posture"]["identity_values_returned"] = True
    with pytest.raises(RuntimeError, match="non-disclosure"):
        _safe_aggregate_result(aggregate)


def test_external_http_acceptance_validates_password_changer_non_disclosure() -> None:
    value = {
        "status_code": 200,
        "response_body_returned": False,
        "posture": {
            "contract": "fortipam_password_changer_configuration_posture_v1",
            "changer_inventory_state": "present",
            "changer_count_band": "multiple",
            "fortios_7_6_3_documented_label_observed": True,
            "label_observation": "documented_label_observed",
            "observation_scope": "configuration_label_only",
            "target_compatibility_assessed": False,
            "job_health_assessed": False,
            "response_body_returned": False,
            "name_values_returned": False,
            "description_values_returned": False,
            "procedure_values_returned": False,
            "authentication_mode_values_returned": False,
            "reference_values_returned": False,
            "origin_values_returned": False,
            "credential_values_returned": False,
            "raw_field_values_returned": False,
        },
    }

    result = _safe_password_changer_result(value)
    assert result["fortios_7_6_3_documented_label_observed"] is True
    assert result["response_body_returned"] is False
    assert "posture" not in result

    value["posture"]["procedure_values_returned"] = True
    with pytest.raises(RuntimeError, match="non-disclosure"):
        _safe_password_changer_result(value)


def test_external_http_acceptance_validates_ems_non_disclosure() -> None:
    value = _ems_acceptance_value()

    result = _safe_ems_result(value)
    assert result["aggregate_connection_state"] == "positive"
    assert result["response_body_returned"] is False
    assert "posture" not in result

    value["posture"]["network_values_returned"] = True
    with pytest.raises(RuntimeError, match="posture contract"):
        _safe_ems_result(value)


def test_external_http_acceptance_rejects_invalid_ems_contract() -> None:
    value = _ems_acceptance_value()
    value["posture"]["private_extension"] = "private-sensitive-value"
    with pytest.raises(RuntimeError, match="posture contract"):
        _safe_ems_result(value)

    value = _ems_acceptance_value()
    posture = value["posture"]
    assert isinstance(posture, dict)
    posture.update(
        {
            "aggregate_connection_state": "negative",
            "aggregate_certificate_state": "negative",
            "risk_signal": "none_observed",
        }
    )
    with pytest.raises(RuntimeError, match="posture contract"):
        _safe_ems_result(value)

    value = _ems_acceptance_value()
    value["posture"]["connector_inventory_state"] = "none"
    with pytest.raises(RuntimeError, match="posture contract"):
        _safe_ems_result(value)


def _ems_acceptance_value() -> dict[str, object]:
    return {
        "status_code": 200,
        "response_body_returned": False,
        "posture": {
            "contract": "fortipam_ems_connection_posture_v1",
            "connector_inventory_state": "present",
            "connector_count_band": "single",
            "connection_evidence_completeness": "complete",
            "aggregate_connection_state": "positive",
            "aggregate_certificate_state": "positive",
            "risk_signal": "none_observed",
            "ztna_tag_assignment_assessed": False,
            "proxy_policy_assessed": False,
            "endpoint_posture_assessed": False,
            "secret_launch_assessed": False,
            "response_body_returned": False,
            "connector_name_values_returned": False,
            "network_values_returned": False,
            "port_values_returned": False,
            "certificate_values_returned": False,
            "tag_values_returned": False,
            "endpoint_values_returned": False,
            "raw_status_values_returned": False,
            "raw_field_values_returned": False,
        },
    }


@pytest.mark.parametrize("unsafe_value", ["private-sensitive-value", {"secret": 1}])
def test_external_http_acceptance_rejects_non_boolean_label_signal(
    unsafe_value: object,
) -> None:
    value = _password_changer_acceptance_value()
    value["posture"]["fortios_7_6_3_documented_label_observed"] = unsafe_value
    with pytest.raises(RuntimeError, match="posture contract"):
        _safe_password_changer_result(value)


def test_external_http_acceptance_rejects_contradictory_changer_state() -> None:
    value = _password_changer_acceptance_value()
    value["posture"]["label_observation"] = "not_observed"
    with pytest.raises(RuntimeError, match="posture contract"):
        _safe_password_changer_result(value)

    value = _password_changer_acceptance_value()
    value["posture"]["changer_inventory_state"] = "none"
    with pytest.raises(RuntimeError, match="posture contract"):
        _safe_password_changer_result(value)


def test_external_http_acceptance_rejects_unknown_changer_posture_key() -> None:
    value = _password_changer_acceptance_value()
    value["posture"]["private_extension"] = "private-sensitive-value"
    with pytest.raises(RuntimeError, match="posture contract"):
        _safe_password_changer_result(value)


def _password_changer_acceptance_value() -> dict[str, object]:
    return {
        "status_code": 200,
        "response_body_returned": False,
        "posture": {
            "contract": "fortipam_password_changer_configuration_posture_v1",
            "changer_inventory_state": "present",
            "changer_count_band": "multiple",
            "fortios_7_6_3_documented_label_observed": True,
            "label_observation": "documented_label_observed",
            "observation_scope": "configuration_label_only",
            "target_compatibility_assessed": False,
            "job_health_assessed": False,
            "response_body_returned": False,
            "name_values_returned": False,
            "description_values_returned": False,
            "procedure_values_returned": False,
            "authentication_mode_values_returned": False,
            "reference_values_returned": False,
            "origin_values_returned": False,
            "credential_values_returned": False,
            "raw_field_values_returned": False,
        },
    }


def test_external_http_acceptance_requires_fail_closed_live_tool_schemas() -> None:
    _assert_strict_no_input_schema(
        {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "example",
    )

    with pytest.raises(RuntimeError, match="does not reject unknown input"):
        _assert_strict_no_input_schema(
            {"type": "object", "properties": {}},
            "example",
        )


def test_external_http_acceptance_requires_closed_diagnostic_schemas() -> None:
    baseline_schema = {
        "type": "object",
        "properties": {"baseline_id": {"type": "string"}},
        "required": ["baseline_id"],
        "additionalProperties": False,
    }
    _assert_strict_diagnostic_schema(
        baseline_schema,
        "create_ha_diagnostic_baseline",
    )
    _assert_strict_diagnostic_schema(
        baseline_schema,
        "compare_ha_diagnostic_baseline",
    )
    _assert_strict_diagnostic_schema(
        {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "correlate_ha_api_cli_posture",
    )

    with pytest.raises(RuntimeError, match="schema is invalid"):
        _assert_strict_diagnostic_schema(
            {
                "type": "object",
                "properties": {"baseline_id": {"type": "string"}},
                "additionalProperties": False,
            },
            "create_ha_diagnostic_baseline",
        )
    with pytest.raises(RuntimeError, match="does not reject unknown input"):
        _assert_strict_diagnostic_schema(
            {
                "type": "object",
                "properties": {},
            },
            "correlate_ha_api_cli_posture",
        )


def test_external_http_acceptance_minimizes_closed_diagnostic_results() -> None:
    assert _safe_diagnostic_result(
        {"status": "unchanged"},
        {"unchanged", "changed"},
    ) == {"status": "unchanged"}

    with pytest.raises(RuntimeError, match="invalid closed result"):
        _safe_diagnostic_result(
            {"status": "unchanged", "baseline_id": "private"},
            {"unchanged", "changed"},
        )
    with pytest.raises(RuntimeError, match="invalid closed result"):
        _safe_diagnostic_result(
            {"status": "unexpected"},
            {"unchanged", "changed"},
        )


def test_external_http_acceptance_validates_cli_ha_configuration_non_disclosure() -> None:
    value = {
        "workflow_id": "ha_configuration",
        "execution_status": "completed",
        "evidence": {
            "evidence_status": "complete",
            "ha_mode": "standalone",
            "session_pickup": "enabled",
            "override_state": "disabled",
            "configuration_security": "enabled",
            "identity_values_returned": False,
            "network_values_returned": False,
            "group_name_returned": False,
            "password_values_returned": False,
            "priority_values_returned": False,
            "exact_checksum_returned": False,
            "raw_cli_returned": False,
        },
        "raw_cli_returned": False,
        "credential_values_returned": False,
    }
    assert _safe_cli_result("get_cli_ha_configuration_summary", value) == {
        "workflow_id": "ha_configuration",
        "execution_status": "completed",
        "evidence_status": "complete",
        "raw_cli_returned": False,
        "credential_values_returned": False,
    }
    value["evidence"]["hostname"] = "private"
    with pytest.raises(RuntimeError, match="schema"):
        _safe_cli_result("get_cli_ha_configuration_summary", value)


def test_external_http_acceptance_validates_cli_ha_and_standalone_checksum() -> None:
    ha = {
        "workflow_id": "ha_status",
        "execution_status": "completed",
        "evidence": {
            "evidence_status": "complete",
            "ha_mode": "standalone",
            "ha_health": "healthy",
            "member_count_band": "single",
            "configuration_sync": "not_applicable",
            "peer_identity_returned": False,
            "network_values_returned": False,
            "exact_time_returned": False,
            "raw_cli_returned": False,
        },
        "raw_cli_returned": False,
        "credential_values_returned": False,
    }
    checksum = {
        "workflow_id": "ha_checksum",
        "execution_status": "completed",
        "evidence": {
            "evidence_status": "complete",
            "ha_mode": "standalone",
            "checksum_assessment": "not_applicable",
            "member_count_band": "single",
            "exact_checksum_returned": False,
            "member_identity_returned": False,
            "table_name_returned": False,
            "raw_cli_returned": False,
        },
        "raw_cli_returned": False,
        "credential_values_returned": False,
    }
    assert _safe_cli_result("get_cli_ha_status_summary", ha)["evidence_status"] == "complete"
    assert _safe_cli_result("get_cli_ha_checksum_summary", checksum)["evidence_status"] == "complete"

    checksum["evidence"]["exact_checksum_returned"] = True
    with pytest.raises(RuntimeError, match="checksum contract"):
        _safe_cli_result("get_cli_ha_checksum_summary", checksum)


def test_external_http_acceptance_rejects_uncompleted_cli_workflow() -> None:
    value = {
        "workflow_id": "ha_configuration",
        "execution_status": "parser_rejected",
        "evidence": {"evidence_status": "unavailable"},
        "raw_cli_returned": False,
        "credential_values_returned": False,
    }
    with pytest.raises(RuntimeError, match="execution contract"):
        _safe_cli_result("get_cli_ha_configuration_summary", value)
