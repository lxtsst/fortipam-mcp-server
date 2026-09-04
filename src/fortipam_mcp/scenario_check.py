"""Deterministic validator for packaged FortiPAM operational scenarios."""

from __future__ import annotations

import json

from .scenario_catalog import ScenarioCatalog


def validate_scenarios() -> dict[str, object]:
    """Load the strict schema and return a bounded verification summary."""

    status = ScenarioCatalog.load().status()
    return {
        "product": status["product"],
        "knowledge_version": status["knowledge_version"],
        "source_count": status["source_count"],
        "scenario_count": status["scenario_count"],
        "domains": status["domains"],
        "network_call_executed": False,
        "live_call_permitted": False,
    }


def main() -> None:
    """Validate and print a sanitized summary."""

    print(json.dumps(validate_scenarios(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
