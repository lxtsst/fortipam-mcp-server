from __future__ import annotations

from copy import deepcopy

import pytest

from fortipam_mcp.catalog import RuntimeCatalog
from scripts.accept_least_privilege_identity import (
    IdentityAcceptanceError,
    NEGATIVE_READ_PATHS,
    _accepted_live_result,
    _assert_cataloged_negative_reads,
    _assert_complete_aggregate,
)


def _complete_aggregate() -> dict[str, object]:
    return {
        "response_body_returned": False,
        "posture": {
            "evidence_completeness": "complete",
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


def test_negative_reads_are_fixed_cataloged_gets_across_denied_domains() -> None:
    assert NEGATIVE_READ_PATHS == (
        "/api/v2/cmdb/user/group",
        "/api/v2/cmdb/router/static",
        "/api/v2/cmdb/antivirus/profile",
        "/api/v2/cmdb/vpn.ssl.web/realm",
        "/api/v2/monitor/wanopt/history",
    )
    catalog = RuntimeCatalog.load()
    assert all(catalog.find("GET", path) is not None for path in NEGATIVE_READ_PATHS)
    _assert_cataloged_negative_reads()


def test_required_projection_accepts_only_minimized_2xx_result() -> None:
    assert _accepted_live_result(
        {"status_code": 200, "response_body_returned": False}, 1
    ) == 200

    with pytest.raises(IdentityAcceptanceError, match="minimized projection"):
        _accepted_live_result(
            {"status_code": 200, "response_body_returned": True}, 1
        )
    with pytest.raises(IdentityAcceptanceError, match="minimized projection"):
        _accepted_live_result(
            {"status_code": 403, "response_body_returned": False}, 1
        )


def test_aggregate_acceptance_fails_closed_on_incomplete_or_disclosing_result() -> None:
    _assert_complete_aggregate(_complete_aggregate())

    incomplete = deepcopy(_complete_aggregate())
    posture = incomplete["posture"]
    assert isinstance(posture, dict)
    posture["failed_reads"] = 1
    with pytest.raises(IdentityAcceptanceError, match="evidence is incomplete"):
        _assert_complete_aggregate(incomplete)

    disclosing = deepcopy(_complete_aggregate())
    posture = disclosing["posture"]
    assert isinstance(posture, dict)
    posture["identity_values_returned"] = True
    with pytest.raises(IdentityAcceptanceError, match="non-disclosure"):
        _assert_complete_aggregate(disclosing)
