from __future__ import annotations

from fortipam_mcp.scenario_check import validate_scenarios


def test_scenario_check_returns_only_bounded_summary() -> None:
    result = validate_scenarios()

    assert result["source_count"] == 12
    assert result["scenario_count"] == 19
    assert result["network_call_executed"] is False
    assert result["live_call_permitted"] is False
    assert "sources" not in result
    assert "scenarios" not in result
