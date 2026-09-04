from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import json

import pytest

from fortipam_mcp.config import HA_CONFIGURATION_PATH
from fortipam_mcp.diagnostic_profiles import (
    HA_API_CLI_CORRELATION_CONTRACT,
    DiagnosticProfileError,
    correlate_ha_api_cli,
    project_ha_api_baseline,
)


NOW = 1_700_000_000


def _api_result(*, mode: str = "standalone", enabled: object = False) -> dict[str, object]:
    return {
        "scenario": "ha_sync",
        "operation": "GET",
        "path": HA_CONFIGURATION_PATH,
        "sensitivity": "ha_configuration_posture",
        "status_code": 200,
        "content_type": "application/json; charset=utf-8",
        "response_body_returned": False,
        "posture": {
            "contract": "fortipam_ha_configuration_posture_v1",
            "ha_enabled": enabled,
            "topology_mode": mode,
            "heartbeat_authentication_enabled": True,
            "heartbeat_encryption_enabled": True,
            "heartbeat_interface_configured": True,
            "monitored_interface_configured": False,
            "dedicated_management_enabled": False,
            "management_interface_entry_count": 0,
            "unicast_heartbeat_enabled": False,
            "unicast_peer_entry_count": 0,
            "session_pickup_enabled": False,
            "connectionless_session_pickup_enabled": False,
            "override_enabled": False,
            "synchronization_state": "not_observed",
            "response_body_returned": False,
            "serial_values_returned": False,
            "network_values_returned": False,
            "interface_values_returned": False,
            "group_values_returned": False,
            "credential_values_returned": False,
            "priority_values_returned": False,
            "checksum_values_returned": False,
        },
    }


def _cli_result(*, mode: str = "standalone", evidence_status: str = "complete") -> dict[str, object]:
    return {
        "workflow_id": "ha_configuration",
        "execution_status": "completed",
        "evidence": {
            "evidence_status": evidence_status,
            "ha_mode": mode,
            "session_pickup": "disabled",
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


def _correlate(api: dict[str, object], cli: dict[str, object]) -> dict[str, str]:
    return correlate_ha_api_cli(
        api,
        cli,
        api_evidence_ref="ref-aaaaaaaa",
        cli_evidence_ref="ref-bbbbbbbb",
        tenant_scope="tenant-aaaaaaaa",
        now_epoch=NOW,
    )


def test_api_profile_accepts_only_complete_existing_tool_result() -> None:
    envelope = project_ha_api_baseline(_api_result(), NOW)
    assert envelope.contract.source_product_version == "1.9.1"
    assert envelope.contract.data_class == "C1"
    assert set(envelope.canonical["projection"]) == {"ha_enabled", "topology_mode"}
    assert envelope.canonical["projection"] == {
        "ha_enabled": False,
        "topology_mode": "standalone",
    }


def test_api_profile_accepts_timezone_aware_clock() -> None:
    envelope = project_ha_api_baseline(
        _api_result(), datetime.fromtimestamp(NOW, UTC)
    )
    assert envelope.observed_at == datetime.fromtimestamp(NOW, UTC)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scenario", "other"),
        ("operation", "POST"),
        ("path", "/api/v2/cmdb/system/global"),
        ("sensitivity", "raw"),
        ("status_code", 403),
        ("status_code", 201),
        ("status_code", True),
        ("content_type", "text/plain"),
        ("response_body_returned", True),
    ],
)
def test_api_profile_rejects_wrong_fixed_outer_contract(field: str, value: object) -> None:
    item = _api_result()
    item[field] = value
    with pytest.raises(DiagnosticProfileError):
        project_ha_api_baseline(item, NOW)


def test_api_profile_rejects_extra_outer_and_inner_fields() -> None:
    outer = _api_result()
    outer["query"] = "must-reject"
    inner = _api_result()
    posture = inner["posture"]
    assert isinstance(posture, dict)
    posture["token"] = "must-reject"
    for item in (outer, inner):
        with pytest.raises(DiagnosticProfileError):
            project_ha_api_baseline(item, NOW)


def test_api_profile_rejects_disclosure_flag_and_unknown_category() -> None:
    disclosed = _api_result()
    disclosed_posture = disclosed["posture"]
    assert isinstance(disclosed_posture, dict)
    disclosed_posture["network_values_returned"] = True
    unknown = _api_result(mode="vendor_mode", enabled=True)
    for item in (disclosed, unknown):
        with pytest.raises(DiagnosticProfileError):
            project_ha_api_baseline(item, NOW)


@pytest.mark.parametrize("value", [True, -1, 4_102_444_800, "1700000000"])
def test_api_profile_rejects_invalid_clock(value: object) -> None:
    with pytest.raises(DiagnosticProfileError):
        project_ha_api_baseline(_api_result(), value)  # type: ignore[arg-type]


def test_api_profile_rejects_incomplete_and_contradictory_mode() -> None:
    for item in (
        _api_result(mode="unknown", enabled=None),
        _api_result(mode="active_passive", enabled=False),
    ):
        with pytest.raises(DiagnosticProfileError):
            project_ha_api_baseline(item, NOW)


def test_correlation_truth_table_is_complete_and_versioned() -> None:
    assert HA_API_CLI_CORRELATION_CONTRACT.contract_version == "v1"
    assert len(HA_API_CLI_CORRELATION_CONTRACT.truth_table) == 16


@pytest.mark.parametrize(
    ("api_mode", "enabled", "cli_mode", "expected"),
    [
        ("standalone", False, "standalone", "operationally_consistent"),
        ("active_passive", True, "active_passive", "operationally_consistent"),
        ("active_passive", True, "active_active", "contradictory"),
    ],
)
def test_correlation_uses_only_compiled_mode_relationship(
    api_mode: str, enabled: bool, cli_mode: str, expected: str
) -> None:
    result = _correlate(
        _api_result(mode=api_mode, enabled=enabled),
        _cli_result(mode=cli_mode),
    )
    assert result == {
        "relationship_class": expected,
        "reason_class": "contract_signal_tuple",
    }


def test_partial_or_unknown_correlation_is_not_assessed() -> None:
    partial = _correlate(_api_result(), _cli_result(evidence_status="partial"))
    unknown = _correlate(_api_result(), _cli_result(mode="unknown"))
    contradictory_api = _correlate(
        _api_result(mode="active_passive", enabled=False),
        _cli_result(mode="active_passive"),
    )
    assert partial["relationship_class"] == "not_assessed"
    assert unknown["relationship_class"] == "not_assessed"
    assert contradictory_api["relationship_class"] == "not_assessed"


def test_cli_result_rejects_unknown_fields_categories_and_disclosure() -> None:
    extra = _cli_result()
    extra["command"] = "must-reject"
    category = _cli_result()
    category_evidence = category["evidence"]
    assert isinstance(category_evidence, dict)
    category_evidence["configuration_security"] = "vendor_state"
    disclosed = _cli_result()
    disclosed_evidence = disclosed["evidence"]
    assert isinstance(disclosed_evidence, dict)
    disclosed_evidence["raw_cli_returned"] = True
    for item in (extra, category, disclosed):
        with pytest.raises(DiagnosticProfileError):
            _correlate(_api_result(), item)


def test_correlation_output_and_errors_do_not_disclose_opaque_metadata() -> None:
    result = _correlate(_api_result(), _cli_result())
    encoded = json.dumps(result, sort_keys=True)
    assert "ref-aaaaaaaa" not in encoded
    assert "ref-bbbbbbbb" not in encoded
    assert "tenant-aaaaaaaa" not in encoded
    assert set(result) == {"relationship_class", "reason_class"}

    invalid = _cli_result()
    invalid["credential_values_returned"] = True
    with pytest.raises(DiagnosticProfileError) as captured:
        _correlate(_api_result(), invalid)
    assert "credential" not in str(captured.value).lower()


def test_product_version_and_contract_are_not_caller_inputs() -> None:
    result = _api_result()
    posture = result["posture"]
    assert isinstance(posture, dict)
    posture["contract"] = "fortipam_ha_configuration_posture_v2"
    with pytest.raises(DiagnosticProfileError):
        project_ha_api_baseline(result, NOW)


def test_input_is_not_mutated() -> None:
    api = _api_result()
    cli = _cli_result()
    before_api = deepcopy(api)
    before_cli = deepcopy(cli)
    _correlate(api, cli)
    assert api == before_api
    assert cli == before_cli
