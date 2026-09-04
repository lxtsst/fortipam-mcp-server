from __future__ import annotations

import pytest

from fortipam_mcp.posture_contracts import (
    PostureContractError,
    summarize_ems_connection_posture,
    summarize_fortianalyzer_delivery_posture,
    summarize_ha_configuration_posture,
    summarize_license_support_posture,
    summarize_overall_health_posture,
    summarize_password_changer_configuration_posture,
    summarize_recording_storage_posture,
)


def _overall_components() -> dict[str, object]:
    return {
        "system_status": {"status_code": 200, "private": "must-not-escape"},
        "system_global": {"status_code": 200},
        "approval_profile": {"status_code": 200},
        "fortianalyzer_delivery": {
            "posture": {
                "enabled": True,
                "reliable_transport_enabled": True,
                "certificate_verification_enabled": True,
            }
        },
        "license_support": {
            "posture": {
                "subscription_state": "healthy",
                "subscription_expiry_band": "beyond_90_days",
                "user_capacity_state": "available",
            }
        },
        "ha_configuration": {"posture": {"ha_enabled": False}},
        "recording_storage": {
            "posture": {
                "video_usage_band": "low",
                "log_usage_band": "moderate",
            }
        },
    }


def test_overall_health_contract_separates_evidence_from_risk() -> None:
    result = summarize_overall_health_posture(_overall_components())

    assert result["evidence_completeness"] == "complete"
    assert result["risk_signal"] == "none_observed"
    assert result["completed_reads"] == 7
    assert result["failed_reads"] == 0
    assert result["components"]["system_status"] == {
        "evidence_state": "observed",
        "risk_signal": "not_assessed",
    }
    assert result["components"]["ha_configuration"]["risk_signal"] == (
        "not_applicable"
    )
    assert "must-not-escape" not in str(result)


def test_overall_health_contract_reports_partial_evidence_without_errors() -> None:
    components = _overall_components()
    components["fortianalyzer_delivery"] = None

    result = summarize_overall_health_posture(components)

    assert result["evidence_completeness"] == "partial"
    assert result["completed_reads"] == 6
    assert result["failed_reads"] == 1
    assert result["components"]["fortianalyzer_delivery"] == {
        "evidence_state": "unavailable",
        "risk_signal": "unknown",
    }
    assert result["component_error_details_returned"] is False


def test_overall_health_contract_prioritizes_critical_and_warning_signals() -> None:
    components = _overall_components()
    components["recording_storage"] = {
        "posture": {
            "video_usage_band": "critical",
            "log_usage_band": "low",
        }
    }
    components["license_support"] = {
        "posture": {"subscription_expiry_band": "within_30_days"}
    }

    result = summarize_overall_health_posture(components)

    assert result["risk_signal"] == "critical"
    assert result["components"]["recording_storage"]["risk_signal"] == "critical"
    assert result["components"]["license_support"]["risk_signal"] == "warning"


def test_overall_health_contract_handles_unavailable_evidence() -> None:
    result = summarize_overall_health_posture({})

    assert result["evidence_completeness"] == "unavailable"
    assert result["risk_signal"] == "unknown"
    assert result["completed_reads"] == 0
    assert result["failed_reads"] == 7


def test_fortianalyzer_contract_returns_posture_without_private_values() -> None:
    payload = {
        "serial": "private-appliance-serial",
        "results": {
            "status": "enable",
            "reliable": "enable",
            "certificate-verification": "enable",
            "access-config": "disable",
            "server": "private-faz.example",
            "serial": [{"name": "private-faz-serial"}],
            "certificate": "private-certificate-name",
            "preshared-key": "encrypted-private-value",
            "source-ip": "192.0.2.10",
            "interface": "private-interface",
            "upload-option": "realtime",
        },
    }

    result = summarize_fortianalyzer_delivery_posture(payload)

    assert result["enabled"] is True
    assert result["reliable_transport_enabled"] is True
    assert result["certificate_verification_enabled"] is True
    assert result["fortianalyzer_rest_access_enabled"] is False
    assert result["registered_serial_count"] == 1
    assert result["preshared_key_configured"] is True
    rendered = str(result)
    for private_value in (
        "private-appliance-serial",
        "private-faz.example",
        "private-faz-serial",
        "private-certificate-name",
        "encrypted-private-value",
        "192.0.2.10",
        "private-interface",
        "realtime",
    ):
        assert private_value not in rendered


def test_fortianalyzer_contract_handles_disabled_or_unknown_flags() -> None:
    result = summarize_fortianalyzer_delivery_posture(
        {
            "results": {
                "status": "disable",
                "reliable": "unexpected",
                "certificate-verification": None,
            }
        }
    )

    assert result["enabled"] is False
    assert result["reliable_transport_enabled"] is None
    assert result["certificate_verification_enabled"] is None


def test_fortianalyzer_contract_requires_configuration_object() -> None:
    with pytest.raises(PostureContractError):
        summarize_fortianalyzer_delivery_posture({"results": []})


def test_license_contract_returns_health_bands_without_private_values() -> None:
    now_epoch = 2_000_000_000
    payload = {
        "serial": "private-device-serial",
        "results": {
            "subscription": {
                "status": "valid",
                "expires": now_epoch + 20 * 86_400,
                "enabled_users": 85,
                "licensed_users": 100,
            },
            "forticare": {
                "status": "registered",
                "account": "private-account",
                "company": "private-company",
                "support": {
                    "enhanced": {
                        "status": "active",
                        "expires": now_epoch + 100 * 86_400,
                        "support_level": "private-contract",
                    }
                },
            },
            "vm": {
                "status": "valid",
                "valid": True,
                "closed_network": False,
                "license_platform_name": "private-platform",
            },
            "fortiguard": {
                "connected": True,
                "scheduled_updates_enabled": True,
                "server_address": "private-server",
            },
        },
    }

    result = summarize_license_support_posture(payload, now_epoch=now_epoch)

    assert result["subscription_state"] == "healthy"
    assert result["subscription_expiry_band"] == "within_30_days"
    assert result["user_capacity_state"] == "near_capacity"
    assert result["support_expiry_band"] == "beyond_90_days"
    assert result["vm_license_valid"] is True
    assert result["fortiguard_connected"] is True
    assert "private" not in str(result)
    assert result["identity_values_returned"] is False
    assert result["exact_expiry_values_returned"] is False


def test_license_contract_handles_unknown_and_expired_values() -> None:
    result = summarize_license_support_posture(
        {
            "results": {
                "subscription": {
                    "status": "vendor-new-state",
                    "expires": 1_000,
                    "enabled_users": 11,
                    "licensed_users": 10,
                }
            }
        },
        now_epoch=2_000,
    )

    assert result["subscription_state"] == "unknown"
    assert result["subscription_expiry_band"] == "expired"
    assert result["user_capacity_state"] == "over_capacity"
    assert result["vm_license_valid"] is None


def test_license_contract_requires_result_object_and_valid_clock() -> None:
    with pytest.raises(PostureContractError):
        summarize_license_support_posture({"results": []}, now_epoch=1)
    with pytest.raises(PostureContractError):
        summarize_license_support_posture({"results": {}}, now_epoch=0)


def test_ha_contract_returns_posture_without_topology_values() -> None:
    payload = {
        "serial": "private-serial",
        "results": {
            "mode": "a-p",
            "authentication": "enable",
            "encryption": "enable",
            "hbdev": "private-heartbeat-interface",
            "monitor": "private-monitored-interface",
            "ha-mgmt-status": "enable",
            "ha-mgmt-interfaces": [{"interface": "private-management"}],
            "unicast-status": "enable",
            "unicast-peers": [{"peer-ip": "192.0.2.10"}],
            "session-pickup": "enable",
            "session-pickup-connectionless": "disable",
            "override": "disable",
            "group-name": "private-cluster",
            "password": "private-password",
            "key": "private-key",
            "priority": 200,
        },
    }

    result = summarize_ha_configuration_posture(payload)

    assert result["ha_enabled"] is True
    assert result["topology_mode"] == "active_passive"
    assert result["heartbeat_authentication_enabled"] is True
    assert result["heartbeat_encryption_enabled"] is True
    assert result["management_interface_entry_count"] == 1
    assert result["unicast_peer_entry_count"] == 1
    assert result["synchronization_state"] == "not_observed"
    rendered = str(result)
    for private_value in (
        "private-serial",
        "private-heartbeat-interface",
        "private-monitored-interface",
        "private-management",
        "192.0.2.10",
        "private-cluster",
        "private-password",
        "private-key",
        "200",
    ):
        assert private_value not in rendered


def test_ha_contract_handles_standalone_and_unknown_values() -> None:
    result = summarize_ha_configuration_posture(
        {
            "results": {
                "mode": "standalone",
                "authentication": "vendor-new-state",
            }
        }
    )

    assert result["ha_enabled"] is False
    assert result["topology_mode"] == "standalone"
    assert result["heartbeat_authentication_enabled"] is None
    assert result["management_interface_entry_count"] == 0


def test_ha_contract_requires_configuration_object() -> None:
    with pytest.raises(PostureContractError):
        summarize_ha_configuration_posture({"results": []})


def test_recording_storage_contract_returns_bands_without_exact_values() -> None:
    payload = {
        "serial": "private-serial",
        "results": {
            "video_disk_total_bytes": 1_000,
            "video_used_bytes": 800,
            "video_free_bytes": 200,
            "total_bytes": 2_000,
            "used_bytes": 200,
            "free_bytes": 1_800,
            "oldest video tm_stamp": "private-oldest-timestamp",
            "newest video tm_stamp": "private-newest-timestamp",
        },
    }

    result = summarize_recording_storage_posture(payload)

    assert result["video_storage_present"] is True
    assert result["video_usage_band"] == "high"
    assert result["log_usage_band"] == "low"
    assert result["recording_history_state"] == "present"
    rendered = str(result)
    for private_value in (
        "private-serial",
        "private-oldest-timestamp",
        "private-newest-timestamp",
        "1000",
        "2000",
    ):
        assert private_value not in rendered


def test_recording_storage_contract_handles_empty_and_invalid_counters() -> None:
    result = summarize_recording_storage_posture(
        {
            "results": {
                "video_disk_total_bytes": 100,
                "video_used_bytes": 0,
                "video_free_bytes": 100,
                "total_bytes": "vendor-new-type",
                "oldest video tm_stamp": "",
                "newest video tm_stamp": None,
            }
        }
    )

    assert result["video_usage_band"] == "empty"
    assert result["log_usage_band"] == "unknown"
    assert result["log_storage_present"] is None
    assert result["recording_history_state"] == "empty"


def test_recording_storage_contract_requires_disk_usage_object() -> None:
    with pytest.raises(PostureContractError):
        summarize_recording_storage_posture({"results": []})


def test_password_changer_contract_returns_only_fixed_label_signals() -> None:
    payload = {
        "results": [
            {
                "name": "SSH Password (FortiOS 7.6.3 and higher)",
                "type": "SSH with Password",
                "description": "private-description",
                "change": "private-change-procedure",
                "verify": "private-verification-procedure",
                "change-auth-mode": "private-associated-secret",
                "q_origin_key": "private-origin",
            },
            {
                "name": "private-custom-name",
                "type": "Web-API",
                "web-change": "private-request-with-password",
                "web-verify": "private-response-token",
            },
        ]
    }

    result = summarize_password_changer_configuration_posture(payload)

    assert set(result) == {
        "contract",
        "changer_inventory_state",
        "changer_count_band",
        "fortios_7_6_3_documented_label_observed",
        "label_observation",
        "observation_scope",
        "target_compatibility_assessed",
        "job_health_assessed",
        "response_body_returned",
        "name_values_returned",
        "description_values_returned",
        "procedure_values_returned",
        "authentication_mode_values_returned",
        "reference_values_returned",
        "origin_values_returned",
        "credential_values_returned",
        "raw_field_values_returned",
    }
    assert result["changer_inventory_state"] == "present"
    assert result["changer_count_band"] == "multiple"
    assert result["fortios_7_6_3_documented_label_observed"] is True
    assert result["label_observation"] == "documented_label_observed"
    assert result["observation_scope"] == "configuration_label_only"
    assert result["target_compatibility_assessed"] is False
    assert result["job_health_assessed"] is False
    assert "private" not in str(result)
    for flag in (
        "response_body_returned",
        "name_values_returned",
        "description_values_returned",
        "procedure_values_returned",
        "authentication_mode_values_returned",
        "reference_values_returned",
        "origin_values_returned",
        "credential_values_returned",
        "raw_field_values_returned",
    ):
        assert result[flag] is False


def test_password_changer_contract_handles_empty_and_rejects_invalid_entries() -> None:
    empty = summarize_password_changer_configuration_posture({"results": []})
    assert empty["changer_inventory_state"] == "none"
    assert empty["changer_count_band"] == "none"

    with pytest.raises(PostureContractError):
        summarize_password_changer_configuration_posture({"results": {}})
    with pytest.raises(PostureContractError):
        summarize_password_changer_configuration_posture({"results": ["unsafe"]})
    with pytest.raises(PostureContractError):
        summarize_password_changer_configuration_posture(
            {
                "results": [
                    {
                        "name": "SSH Password (FortiOS 7.6.3 and higher)",
                        "type": "SSH with Password",
                        "vendor-new-sensitive-field": "must-fail-closed",
                    }
                ]
            }
        )


def test_password_changer_label_match_does_not_claim_default_or_compatibility() -> None:
    result = summarize_password_changer_configuration_posture(
        {
            "results": [
                {
                    "name": "SSH Password (FortiOS 7.6.3 and higher)",
                    "type": "Custom or modified",
                }
            ]
        }
    )

    assert result["fortios_7_6_3_documented_label_observed"] is True
    assert result["label_observation"] == "documented_label_observed"
    assert "compatible" not in result
    assert "default" not in result


def test_ems_contract_returns_only_aggregate_connection_posture() -> None:
    payload = {
        "serial": "private-device-serial",
        "results": [
            {
                "name": "private-connector-name",
                "cert_status": {"status": "success"},
                "conn_status": {
                    "ems_name": "private-ems-name",
                    "ems_status": "success",
                    "ems_status_id": 0,
                    "mgmt_ip": "192.0.2.10",
                    "mgmt_port": 443,
                },
            }
        ],
    }

    result = summarize_ems_connection_posture(payload)

    assert result["contract"] == "fortipam_ems_connection_posture_v1"
    assert result["connector_inventory_state"] == "present"
    assert result["connector_count_band"] == "single"
    assert result["aggregate_connection_state"] == "positive"
    assert result["aggregate_certificate_state"] == "positive"
    assert result["risk_signal"] == "none_observed"
    assert result["ztna_tag_assignment_assessed"] is False
    assert result["proxy_policy_assessed"] is False
    assert result["endpoint_posture_assessed"] is False
    assert result["secret_launch_assessed"] is False
    rendered = str(result)
    for private_value in (
        "private-device-serial",
        "private-connector-name",
        "private-ems-name",
        "192.0.2.10",
        "443",
        "success",
    ):
        assert private_value not in rendered


def test_ems_contract_handles_empty_and_unknown_states() -> None:
    empty = summarize_ems_connection_posture({"results": []})
    assert empty["connector_inventory_state"] == "none"
    assert empty["aggregate_connection_state"] == "not_configured"
    assert empty["risk_signal"] == "not_applicable"

    unknown = summarize_ems_connection_posture(
        {
            "results": [
                {
                    "name": "one",
                    "cert_status": {"status": "success"},
                    "conn_status": {
                        "ems_name": "one",
                        "ems_status": "success",
                        "ems_status_id": 0,
                        "mgmt_ip": "192.0.2.1",
                        "mgmt_port": 443,
                    },
                },
                {
                    "name": "two",
                    "cert_status": {"status": "vendor-new-certificate-state"},
                    "conn_status": {
                        "ems_name": "two",
                        "ems_status": "vendor-new-state",
                        "ems_status_id": 9,
                        "mgmt_ip": "192.0.2.2",
                        "mgmt_port": 443,
                    },
                },
            ]
        }
    )
    assert unknown["aggregate_certificate_state"] == "unknown"
    assert unknown["aggregate_connection_state"] == "unknown"
    assert unknown["risk_signal"] == "unknown"


def test_ems_contract_does_not_reuse_status_semantics_across_fields() -> None:
    result = summarize_ems_connection_posture(
        {
            "results": [
                {
                    "name": "private",
                    "cert_status": {"status": "connected"},
                    "conn_status": {
                        "ems_name": "private",
                        "ems_status": "authorized",
                        "ems_status_id": 0,
                        "mgmt_ip": "192.0.2.1",
                        "mgmt_port": 443,
                    },
                }
            ]
        }
    )
    assert result["aggregate_certificate_state"] == "unknown"
    assert result["aggregate_connection_state"] == "unknown"
    assert result["risk_signal"] == "unknown"


def test_ems_contract_fails_closed_on_schema_drift() -> None:
    with pytest.raises(PostureContractError):
        summarize_ems_connection_posture({"results": {}})
    with pytest.raises(PostureContractError):
        summarize_ems_connection_posture(
            {
                "results": [
                    {
                        "name": "private",
                        "cert_status": {"status": "success"},
                        "conn_status": {
                            "ems_name": "private",
                            "ems_status": "success",
                            "ems_status_id": 0,
                            "mgmt_ip": "192.0.2.1",
                            "mgmt_port": 443,
                        },
                        "vendor-new-sensitive-field": "must-fail-closed",
                    }
                ]
            }
        )
