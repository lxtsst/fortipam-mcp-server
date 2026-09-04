from __future__ import annotations

from copy import deepcopy

import pytest

from fortipam_mcp.server import FIXED_ROUTE_TOOLS
from scripts.live_readonly_acceptance import ACCEPTANCE_TOOLS, _validated_result
from tests.test_external_http_acceptance import _ems_acceptance_value


def test_live_acceptance_covers_every_fixed_route_and_aggregate() -> None:
    assert set(FIXED_ROUTE_TOOLS).issubset(ACCEPTANCE_TOOLS)
    assert "get_overall_health_summary" in ACCEPTANCE_TOOLS
    assert len(ACCEPTANCE_TOOLS) == len(set(ACCEPTANCE_TOOLS))


def test_live_acceptance_validates_ems_invariants() -> None:
    value = _ems_acceptance_value()
    assert _validated_result("get_ems_connection_posture_summary", value) is value

    contradictory = deepcopy(value)
    posture = contradictory["posture"]
    assert isinstance(posture, dict)
    posture.update(
        {
            "aggregate_connection_state": "negative",
            "aggregate_certificate_state": "negative",
            "risk_signal": "none_observed",
        }
    )
    with pytest.raises(RuntimeError, match="EMS acceptance contract"):
        _validated_result("get_ems_connection_posture_summary", contradictory)
