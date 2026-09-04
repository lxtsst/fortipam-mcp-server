#!/usr/bin/env python3
"""Evaluate deterministic routing across the FortiPAM scenario catalog."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from fortipam_mcp.scenario_catalog import ScenarioCatalog

DEFAULT_CASES = Path(__file__).resolve().parents[1] / "evals" / "scenario_routing.json"


class ScenarioEvaluationError(ValueError):
    """Raised when scenario evaluation cases are invalid or fail routing."""


def evaluate_scenario_routing(path: Path = DEFAULT_CASES) -> dict[str, object]:
    """Return a bounded pass/fail summary for every routing case."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise ScenarioEvaluationError("Scenario routing cases are unavailable or invalid.") from exc
    if not isinstance(payload, list) or not payload:
        raise ScenarioEvaluationError("Scenario routing cases must be a non-empty list.")

    catalog = ScenarioCatalog.load()
    failures: list[str] = []
    seen_case_ids: set[str] = set()
    for value in payload:
        case = _case(value)
        case_id = case["case_id"]
        if case_id in seen_case_ids:
            raise ScenarioEvaluationError("Scenario routing case identifiers must be unique.")
        seen_case_ids.add(case_id)
        matches = catalog.search(case["query"], limit=3)
        actual = matches[0].scenario_id if matches else None
        if actual != case["expected_scenario_id"]:
            failures.append(case_id)

    return {
        "case_count": len(payload),
        "passed_count": len(payload) - len(failures),
        "failed_case_ids": failures,
        "network_call_executed": False,
        "live_call_permitted": False,
    }


def _case(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ScenarioEvaluationError("Each scenario routing case must be an object.")
    if set(value) != {"case_id", "query", "expected_scenario_id"}:
        raise ScenarioEvaluationError("A scenario routing case has unexpected fields.")
    result: dict[str, str] = {}
    for key in ("case_id", "query", "expected_scenario_id"):
        item: Any = value[key]
        if not isinstance(item, str) or not item.strip():
            raise ScenarioEvaluationError(f"Scenario routing {key} must be a string.")
        result[key] = item.strip()
    return result


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Evaluate FortiPAM scenario routing.")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    args = parser.parse_args(argv)
    result = evaluate_scenario_routing(args.cases)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["failed_case_ids"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
