"""Advisory-only FortiPAM operational knowledge tools."""

from __future__ import annotations

from .scenario_catalog import ScenarioCatalog


class FortiPamKnowledgeTools:
    """Search and retrieve source-traceable scenarios without device access."""

    def __init__(self, catalog: ScenarioCatalog) -> None:
        self._catalog = catalog

    def status(self) -> dict[str, object]:
        return self._catalog.status()

    def search(
        self,
        query: str,
        domain: str | None = None,
        limit: int = 5,
    ) -> dict[str, object]:
        scenarios = self._catalog.search(query, domain=domain, limit=limit)
        return {
            "knowledge_version": self._catalog.knowledge_version,
            "result_count": len(scenarios),
            "results": [scenario.summary() for scenario in scenarios],
            "advisory_only": True,
            "network_call_executed": False,
            "live_call_permitted": False,
        }

    def get(self, scenario_id: str) -> dict[str, object]:
        scenario = self._catalog.get(scenario_id)
        if scenario is None:
            return {
                "knowledge_version": self._catalog.knowledge_version,
                "found": False,
                "advisory_only": True,
                "network_call_executed": False,
                "live_call_permitted": False,
            }
        return {
            "knowledge_version": self._catalog.knowledge_version,
            "found": True,
            "scenario": scenario,
            "advisory_only": True,
            "network_call_executed": False,
            "live_call_permitted": False,
        }
