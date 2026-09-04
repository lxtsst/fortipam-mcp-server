from __future__ import annotations

from fortipam_mcp.knowledge import FortiPamKnowledgeTools
from fortipam_mcp.scenario_catalog import ScenarioCatalog


def test_knowledge_search_is_advisory_and_offline() -> None:
    tools = FortiPamKnowledgeTools(ScenarioCatalog.load())

    result = tools.search("gateway target")

    assert result["result_count"] >= 1
    assert "secret-gateway-path" in {
        item["scenario_id"] for item in result["results"]
    }
    assert result["advisory_only"] is True
    assert result["network_call_executed"] is False
    assert result["live_call_permitted"] is False


def test_knowledge_get_returns_evidence_plan_not_execution_authority() -> None:
    tools = FortiPamKnowledgeTools(ScenarioCatalog.load())

    result = tools.get("fortianalyzer-delivery")

    assert result["found"] is True
    assert result["scenario"]["available_tools"][-1:] == [
        "get_fortianalyzer_delivery_posture_summary"
    ]
    assert result["scenario"]["candidate_tools"] == []
    assert result["scenario"]["live_call_permitted"] is False


def test_knowledge_get_handles_unknown_identifier() -> None:
    result = FortiPamKnowledgeTools(ScenarioCatalog.load()).get("unknown-scenario")

    assert result == {
        "knowledge_version": "2026.08.22-v10",
        "found": False,
        "advisory_only": True,
        "network_call_executed": False,
        "live_call_permitted": False,
    }
