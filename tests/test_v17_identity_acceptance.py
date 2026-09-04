from __future__ import annotations

from copy import deepcopy

import pytest

from scripts.accept_v17_identity import (
    V17_NEGATIVE_READ_PATHS,
    V17_RESIDUAL_BROAD_READ_PATHS,
    _assert_cataloged_v17_negative_reads,
    _assert_ems_projection,
)
from scripts.accept_least_privilege_identity import IdentityAcceptanceError


def _result() -> dict[str, object]:
    return {
        "status_code": 200,
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


def test_v17_negative_reads_are_fixed_cataloged_routes() -> None:
    assert V17_NEGATIVE_READ_PATHS == (
        "/api/v2/cmdb/user/group",
        "/api/v2/cmdb/router/static",
        "/api/v2/cmdb/authentication/rule",
        "/api/v2/cmdb/vpn.ssl.web/realm",
        "/api/v2/monitor/wanopt/history",
        "/api/v2/cmdb/secret/classification-tag",
        "/api/v2/cmdb/secret/client-software",
        "/api/v2/cmdb/secret/event-filter-profile",
        "/api/v2/cmdb/secret/password-policy",
        "/api/v2/cmdb/secret/dependency-updater",
        "/api/v2/cmdb/secret/launcher",
    )
    assert V17_RESIDUAL_BROAD_READ_PATHS == (
        "/api/v2/cmdb/antivirus/profile",
    )
    assert set(V17_NEGATIVE_READ_PATHS).isdisjoint(
        V17_RESIDUAL_BROAD_READ_PATHS
    )
    _assert_cataloged_v17_negative_reads()


def test_v17_ems_projection_accepts_exact_non_disclosing_contract() -> None:
    _assert_ems_projection(_result())


def test_v17_ems_projection_rejects_disclosure_or_schema_drift() -> None:
    disclosed = deepcopy(_result())
    disclosed["posture"]["network_values_returned"] = True  # type: ignore[index]
    with pytest.raises(IdentityAcceptanceError):
        _assert_ems_projection(disclosed)

    drifted = deepcopy(_result())
    drifted["posture"]["private"] = "must-fail"  # type: ignore[index]
    with pytest.raises(IdentityAcceptanceError):
        _assert_ems_projection(drifted)


def test_v17_ems_projection_rejects_contradictory_inventory_and_risk() -> None:
    contradictory_inventory = deepcopy(_result())
    posture = contradictory_inventory["posture"]
    assert isinstance(posture, dict)
    posture.update(
        {
            "connector_inventory_state": "none",
            "connector_count_band": "multiple",
            "aggregate_connection_state": "not_configured",
            "aggregate_certificate_state": "not_configured",
            "risk_signal": "not_applicable",
        }
    )
    with pytest.raises(IdentityAcceptanceError):
        _assert_ems_projection(contradictory_inventory)

    contradictory_risk = deepcopy(_result())
    posture = contradictory_risk["posture"]
    assert isinstance(posture, dict)
    posture.update(
        {
            "aggregate_connection_state": "negative",
            "aggregate_certificate_state": "negative",
            "risk_signal": "none_observed",
        }
    )
    with pytest.raises(IdentityAcceptanceError):
        _assert_ems_projection(contradictory_risk)
