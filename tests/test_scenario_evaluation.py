from __future__ import annotations

from scripts.evaluate_scenario_routing import evaluate_scenario_routing


def test_all_operational_scenarios_have_a_passing_routing_case() -> None:
    result = evaluate_scenario_routing()

    assert result == {
        "case_count": 19,
        "passed_count": 19,
        "failed_case_ids": [],
        "network_call_executed": False,
        "live_call_permitted": False,
    }
