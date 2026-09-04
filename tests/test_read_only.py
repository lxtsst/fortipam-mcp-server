from __future__ import annotations

import asyncio

from fortipam_mcp.catalog import RuntimeCatalog
from fortipam_mcp.config import (
    FORTIANALYZER_SETTING_PATH,
    EMS_STATUS_SUMMARY_PATH,
    HA_CONFIGURATION_PATH,
    LICENSE_STATUS_PATH,
    PASSWORD_CHANGER_PATH,
    RECORDING_STORAGE_PATH,
    load_config,
)
from fortipam_mcp.read_only import FortiPamCatalogTools, FortiPamReadOnlyTools
from fortipam_mcp.rest import FortiPamRequestError, ReadResponse


class _FakeClient:
    async def get_json(self, path: str) -> ReadResponse:
        if path == FORTIANALYZER_SETTING_PATH:
            return ReadResponse(
                status_code=200,
                content_type="application/json",
                data={
                    "results": {
                        "status": "enable",
                        "reliable": "enable",
                        "certificate-verification": "enable",
                        "access-config": "disable",
                        "server": "private-name",
                        "preshared-key": "must-not-escape",
                        "serial": ["private-serial"],
                    }
                },
            )
        if path == LICENSE_STATUS_PATH:
            return ReadResponse(
                status_code=200,
                content_type="application/json",
                data={
                    "results": {
                        "subscription": {
                            "status": "valid",
                            "expires": 4_102_444_800,
                            "enabled_users": 1,
                            "licensed_users": 10,
                        },
                        "forticare": {
                            "account": "private-account",
                            "company": "private-company",
                        },
                        "fortiguard": {"server_address": "private-server"},
                    }
                },
            )
        if path == HA_CONFIGURATION_PATH:
            return ReadResponse(
                status_code=200,
                content_type="application/json",
                data={
                    "results": {
                        "mode": "a-p",
                        "authentication": "enable",
                        "encryption": "enable",
                        "hbdev": "private-heartbeat-interface",
                        "monitor": "private-monitored-interface",
                        "group-name": "private-cluster",
                        "password": "must-not-escape",
                    }
                },
            )
        if path == RECORDING_STORAGE_PATH:
            return ReadResponse(
                status_code=200,
                content_type="application/json",
                data={
                    "results": {
                        "video_disk_total_bytes": 1_000,
                        "video_used_bytes": 800,
                        "video_free_bytes": 200,
                        "total_bytes": 2_000,
                        "used_bytes": 200,
                        "free_bytes": 1_800,
                        "oldest video tm_stamp": "private-oldest",
                        "newest video tm_stamp": "private-newest",
                    }
                },
            )
        if path == PASSWORD_CHANGER_PATH:
            return ReadResponse(
                status_code=200,
                content_type="application/json",
                data={
                    "results": [
                        {
                            "name": "SSH Password (FortiOS 7.6.3 and higher)",
                            "type": "SSH with Password",
                            "description": "private-description",
                            "change": "private-procedure",
                            "verify": "private-verifier",
                            "q_origin_key": "private-origin",
                        },
                        {
                            "name": "private-custom-name",
                            "type": "Web-API",
                            "web-change": "private-http-body",
                            "web-verify": "private-http-verifier",
                        },
                    ]
                },
            )
        if path == EMS_STATUS_SUMMARY_PATH:
            return ReadResponse(
                status_code=200,
                content_type="application/json",
                data={
                    "results": [
                        {
                            "name": "private-connector",
                            "cert_status": {"status": "success"},
                            "conn_status": {
                                "ems_name": "private-ems",
                                "ems_status": "success",
                                "ems_status_id": 0,
                                "mgmt_ip": "192.0.2.10",
                                "mgmt_port": 443,
                            },
                        }
                    ]
                },
            )
        return ReadResponse(
            status_code=200,
            content_type="application/json",
            data={
                "results": [{"name": "private-name"}],
                "access_token": "must-not-escape",
            },
        )


class _PartialFailureClient(_FakeClient):
    async def get_json(self, path: str) -> ReadResponse:
        if path == HA_CONFIGURATION_PATH:
            raise FortiPamRequestError("private upstream detail must not escape")
        return await super().get_json(path)


class _UnavailableClient:
    async def get_json(self, path: str) -> ReadResponse:
        raise FortiPamRequestError("private upstream detail must not escape")


def _config():
    return load_config(
        {
            "FPA_HOME_LAB_FPA1_HOST": "fortipam.lab.example",
            "FPA_HOME_LAB_FPA1_API_TOKEN": "test-token-not-a-real-secret",
        }
    )


def test_catalog_tools_never_authorize_live_calls() -> None:
    tools = FortiPamCatalogTools(RuntimeCatalog.load())

    search = tools.search("system status", method="GET")
    classified = tools.classify("GET", "/api/v2/monitor/system/status")

    assert search["network_call_executed"] is False
    assert search["live_call_permitted"] is False
    assert classified["operation"]["live_call_permitted"] is False


def test_plan_contains_only_nine_fixed_reads() -> None:
    plan = FortiPamReadOnlyTools(_config()).plan_curated_reads()

    assert len(plan["operations"]) == 9
    assert plan["network_call_executed"] is False
    assert plan["response_body_returned"] is False


def test_live_tool_returns_structure_without_object_values() -> None:
    tools = FortiPamReadOnlyTools(_config())
    tools._client = _FakeClient()  # type: ignore[assignment]

    result = asyncio.run(tools.get_system_status_summary())

    assert result["status_code"] == 200
    assert result["response_body_returned"] is False
    assert "private-name" not in str(result)
    assert "must-not-escape" not in str(result)
    assert result["summary"]["collection_counts"] == {"results": 1}


def test_fortianalyzer_tool_returns_only_minimized_posture() -> None:
    tools = FortiPamReadOnlyTools(_config())
    tools._client = _FakeClient()  # type: ignore[assignment]

    result = asyncio.run(tools.get_fortianalyzer_delivery_posture_summary())

    assert result["status_code"] == 200
    assert result["response_body_returned"] is False
    assert "private-name" not in str(result)
    assert "must-not-escape" not in str(result)
    assert result["posture"]["contract"] == "fortianalyzer_delivery_posture_v1"


def test_license_tool_returns_only_health_bands() -> None:
    tools = FortiPamReadOnlyTools(_config())
    tools._client = _FakeClient()  # type: ignore[assignment]

    result = asyncio.run(tools.get_license_support_posture_summary())

    assert result["status_code"] == 200
    assert result["response_body_returned"] is False
    assert "private" not in str(result)
    assert result["posture"]["contract"] == "fortipam_license_support_posture_v1"
    assert result["posture"]["account_values_returned"] is False
    assert result["posture"]["exact_expiry_values_returned"] is False


def test_ha_tool_returns_only_minimized_configuration_posture() -> None:
    tools = FortiPamReadOnlyTools(_config())
    tools._client = _FakeClient()  # type: ignore[assignment]

    result = asyncio.run(tools.get_ha_configuration_posture_summary())

    assert result["status_code"] == 200
    assert result["response_body_returned"] is False
    assert "private" not in str(result)
    assert "must-not-escape" not in str(result)
    assert result["posture"]["contract"] == "fortipam_ha_configuration_posture_v1"
    assert result["posture"]["topology_mode"] == "active_passive"
    assert result["posture"]["synchronization_state"] == "not_observed"


def test_recording_storage_tool_returns_only_health_bands() -> None:
    tools = FortiPamReadOnlyTools(_config())
    tools._client = _FakeClient()  # type: ignore[assignment]

    result = asyncio.run(tools.get_recording_storage_health_summary())

    assert result["status_code"] == 200
    assert result["response_body_returned"] is False
    assert "private" not in str(result)
    assert "1000" not in str(result)
    assert result["posture"]["contract"] == "fortipam_recording_storage_posture_v1"
    assert result["posture"]["video_usage_band"] == "high"
    assert result["posture"]["capacity_values_returned"] is False
    assert result["posture"]["timestamp_values_returned"] is False


def test_password_changer_tool_returns_only_label_observation_posture() -> None:
    tools = FortiPamReadOnlyTools(_config())
    tools._client = _FakeClient()  # type: ignore[assignment]

    result = asyncio.run(
        tools.get_password_changer_configuration_posture_summary()
    )

    assert result["status_code"] == 200
    assert result["response_body_returned"] is False
    assert result["posture"]["contract"] == (
        "fortipam_password_changer_configuration_posture_v1"
    )
    assert result["posture"]["fortios_7_6_3_documented_label_observed"] is True
    assert result["posture"]["target_compatibility_assessed"] is False
    assert result["posture"]["procedure_values_returned"] is False
    assert "private" not in str(result)


def test_ems_tool_returns_only_aggregate_connection_posture() -> None:
    tools = FortiPamReadOnlyTools(_config())
    tools._client = _FakeClient()  # type: ignore[assignment]

    result = asyncio.run(tools.get_ems_connection_posture_summary())

    assert result["status_code"] == 200
    assert result["response_body_returned"] is False
    assert result["posture"]["contract"] == "fortipam_ems_connection_posture_v1"
    assert result["posture"]["aggregate_connection_state"] == "positive"
    assert result["posture"]["aggregate_certificate_state"] == "positive"
    assert result["posture"]["secret_launch_assessed"] is False
    assert "private" not in str(result)
    assert "192.0.2.10" not in str(result)
    assert "443" not in str(result)


def test_overall_health_tool_aggregates_seven_reads_without_component_data() -> None:
    tools = FortiPamReadOnlyTools(_config())
    tools._client = _FakeClient()  # type: ignore[assignment]

    result = asyncio.run(tools.get_overall_health_summary())

    assert result["network_call_executed"] is True
    assert result["response_body_returned"] is False
    assert result["caller_identifiers_accepted"] is False
    assert result["posture"]["evidence_completeness"] == "complete"
    assert result["posture"]["completed_reads"] == 7
    assert result["posture"]["raw_component_results_returned"] is False
    assert "private" not in str(result)
    assert "must-not-escape" not in str(result)


def test_overall_health_tool_safely_marks_one_failed_component() -> None:
    tools = FortiPamReadOnlyTools(_config())
    tools._client = _PartialFailureClient()  # type: ignore[assignment]

    result = asyncio.run(tools.get_overall_health_summary())

    assert result["posture"]["evidence_completeness"] == "partial"
    assert result["posture"]["completed_reads"] == 6
    assert result["posture"]["failed_reads"] == 1
    assert result["posture"]["components"]["ha_configuration"] == {
        "evidence_state": "unavailable",
        "risk_signal": "unknown",
    }
    assert "private upstream detail" not in str(result)


def test_overall_health_tool_handles_all_reads_unavailable() -> None:
    tools = FortiPamReadOnlyTools(_config())
    tools._client = _UnavailableClient()  # type: ignore[assignment]

    result = asyncio.run(tools.get_overall_health_summary())

    assert result["posture"]["evidence_completeness"] == "unavailable"
    assert result["posture"]["risk_signal"] == "unknown"
    assert result["posture"]["failed_reads"] == 7
    assert "private upstream detail" not in str(result)
