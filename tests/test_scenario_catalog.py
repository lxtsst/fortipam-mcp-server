from __future__ import annotations

from copy import deepcopy
import json
from importlib.resources import files

import pytest

from fortipam_mcp.scenario_catalog import (
    MAX_SCENARIO_SEARCH_RESULTS,
    SCENARIO_CATALOG_FILENAME,
    ScenarioCatalog,
    ScenarioCatalogError,
)
from fortipam_mcp.mcp_smoke import EXPECTED_TOOLS


def test_packaged_scenarios_are_versioned_and_source_traceable() -> None:
    catalog = ScenarioCatalog.load()
    status = catalog.status()

    assert catalog.product == "FortiPAM"
    assert catalog.knowledge_version == "2026.08.22-v10"
    assert len(catalog.sources) == 12
    assert len(catalog.scenarios) == 19
    assert status["scenario_count"] == 19
    assert status["domains"]["approval"] == 2
    assert status["domains"]["secret-session"] == 5
    assert status["network_call_executed"] is False
    assert status["live_call_permitted"] is False


def test_scenario_search_is_bounded_and_domain_aware() -> None:
    catalog = ScenarioCatalog.load()
    matches = catalog.search("self approval", domain="approval")

    assert [scenario.scenario_id for scenario in matches] == ["self-approval-control"]
    with pytest.raises(ScenarioCatalogError):
        catalog.search("approval", limit=MAX_SCENARIO_SEARCH_RESULTS + 1)


def test_community_scenarios_keep_version_and_lab_boundaries() -> None:
    catalog = ScenarioCatalog.load()

    web_launcher = catalog.get("web-launcher-permission-mismatch")
    assert web_launcher is not None
    assert web_launcher["lab_state"] == "unvalidated"
    assert web_launcher["sources"][0]["evidence_class"] == "fortinet_community_technical_tip"
    assert "Change Web Launcher Access" in web_launcher["blocked_actions"]

    parsing = catalog.get("fortianalyzer-secret-log-parsing")
    assert parsing is not None
    assert parsing["lab_state"] == "sender-tool-validated-receiver-unvalidated"
    assert "FortiPAM 1.9.1" in parsing["documented_versions"]


def test_scenario_details_preserve_version_and_execution_boundaries() -> None:
    scenario = ScenarioCatalog.load().get("password-lifecycle-failure")

    assert scenario is not None
    assert scenario["advisory_only"] is True
    assert scenario["network_call_executed"] is False
    assert scenario["live_call_permitted"] is False
    assert "Verify or change a password" in scenario["blocked_actions"]
    assert all("locator" in source for source in scenario["sources"])


def test_all_available_scenario_tools_exist_in_the_mcp_contract() -> None:
    available = {
        tool
        for scenario in ScenarioCatalog.load().scenarios
        for tool in scenario.available_tools
    }

    assert available <= set(EXPECTED_TOOLS)


def test_catalog_rejects_unknown_source_reference() -> None:
    resource = files("fortipam_mcp").joinpath("data", SCENARIO_CATALOG_FILENAME)
    payload = json.loads(resource.read_text(encoding="utf-8"))
    invalid = deepcopy(payload)
    invalid["scenarios"][0]["source_refs"][0]["source_id"] = "missing-source"

    with pytest.raises(ScenarioCatalogError, match="unknown source"):
        ScenarioCatalog.from_mapping(invalid)


def test_unknown_scenario_returns_none() -> None:
    assert ScenarioCatalog.load().get("not-a-scenario") is None
