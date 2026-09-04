"""Validated access to the packaged FortiPAM operational scenario catalog."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from importlib.resources import files
import json
import re
from typing import Any, Mapping

SCENARIO_CATALOG_FILENAME = "fortipam_1_9_scenarios.json"
SCENARIO_SCHEMA_VERSION = "1.0"
MAX_SCENARIO_SEARCH_RESULTS = 10
_SCENARIO_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")


class ScenarioCatalogError(ValueError):
    """Raised when packaged operational knowledge is invalid."""


@dataclass(frozen=True, slots=True)
class ScenarioSource:
    """One bounded source record used by operational scenarios."""

    source_id: str
    evidence_class: str
    title: str
    product_version: str
    accessed_at: str
    locator: str
    boundary: str

    def summary(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "evidence_class": self.evidence_class,
            "title": self.title,
            "product_version": self.product_version,
            "accessed_at": self.accessed_at,
            "boundary": self.boundary,
        }

    def details(self) -> dict[str, str]:
        result = self.summary()
        result["locator"] = self.locator
        return result


@dataclass(frozen=True, slots=True)
class ScenarioSourceRef:
    """A precise source pointer for one scenario."""

    source_id: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"source_id": self.source_id, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class EvidenceStep:
    """One ordered, non-mutating evidence collection step."""

    order: int
    layer: str
    check: str
    evidence: str
    tool: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "order": self.order,
            "layer": self.layer,
            "check": self.check,
            "evidence": self.evidence,
            "tool": self.tool,
        }


@dataclass(frozen=True, slots=True)
class ScenarioValidation:
    """Review and lab state kept separate from source coverage."""

    review_state: str
    lab_state: str
    last_reviewed: str

    def as_dict(self) -> dict[str, str]:
        return {
            "review_state": self.review_state,
            "lab_state": self.lab_state,
            "last_reviewed": self.last_reviewed,
        }


@dataclass(frozen=True, slots=True)
class OperationalScenario:
    """A source-traceable FortiPAM diagnosis and evidence plan."""

    scenario_id: str
    title: str
    domain: str
    risk_class: str
    intent: str
    documented_versions: tuple[str, ...]
    version_notes: str
    source_refs: tuple[ScenarioSourceRef, ...]
    symptoms: tuple[str, ...]
    evidence_ladder: tuple[EvidenceStep, ...]
    available_tools: tuple[str, ...]
    candidate_tools: tuple[str, ...]
    blocked_actions: tuple[str, ...]
    validation: ScenarioValidation

    def summary(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "title": self.title,
            "domain": self.domain,
            "risk_class": self.risk_class,
            "intent": self.intent,
            "documented_versions": list(self.documented_versions),
            "review_state": self.validation.review_state,
            "lab_state": self.validation.lab_state,
        }


@dataclass(frozen=True, slots=True)
class ScenarioCatalog:
    """Immutable, advisory-only FortiPAM operational knowledge."""

    product: str
    knowledge_version: str
    generated_at: str
    review_after: str
    sources: tuple[ScenarioSource, ...]
    scenarios: tuple[OperationalScenario, ...]

    @classmethod
    def load(cls) -> ScenarioCatalog:
        resource = files("fortipam_mcp").joinpath("data", SCENARIO_CATALOG_FILENAME)
        try:
            payload = json.loads(resource.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            raise ScenarioCatalogError(
                "The packaged FortiPAM scenario catalog is unavailable or invalid."
            ) from exc
        return cls.from_mapping(payload)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> ScenarioCatalog:
        _require_exact_keys(
            payload,
            {
                "schema_version",
                "catalog_kind",
                "product",
                "knowledge_version",
                "generated_at",
                "review_after",
                "sources",
                "scenarios",
            },
            "scenario catalog root",
        )
        if payload["schema_version"] != SCENARIO_SCHEMA_VERSION:
            raise ScenarioCatalogError("Unsupported FortiPAM scenario schema version.")
        if payload["catalog_kind"] != "fortipam_operational_scenarios":
            raise ScenarioCatalogError("Unexpected FortiPAM scenario catalog kind.")

        sources = tuple(_parse_source(item) for item in _list(payload["sources"], "sources"))
        source_ids = {source.source_id for source in sources}
        if len(source_ids) != len(sources):
            raise ScenarioCatalogError("Scenario source identifiers must be unique.")

        scenarios = tuple(
            _parse_scenario(item) for item in _list(payload["scenarios"], "scenarios")
        )
        scenario_ids = {scenario.scenario_id for scenario in scenarios}
        if len(scenario_ids) != len(scenarios):
            raise ScenarioCatalogError("Operational scenario identifiers must be unique.")
        for scenario in scenarios:
            missing = {
                reference.source_id for reference in scenario.source_refs
            } - source_ids
            if missing:
                raise ScenarioCatalogError(
                    f"Scenario {scenario.scenario_id} references an unknown source."
                )

        return cls(
            product=_required_string(payload["product"], "product"),
            knowledge_version=_required_string(
                payload["knowledge_version"], "knowledge_version"
            ),
            generated_at=_required_string(payload["generated_at"], "generated_at"),
            review_after=_required_string(payload["review_after"], "review_after"),
            sources=sources,
            scenarios=scenarios,
        )

    def status(self) -> dict[str, object]:
        domains = Counter(scenario.domain for scenario in self.scenarios)
        risk_classes = Counter(scenario.risk_class for scenario in self.scenarios)
        lab_states = Counter(scenario.validation.lab_state for scenario in self.scenarios)
        return {
            "product": self.product,
            "knowledge_version": self.knowledge_version,
            "catalog_kind": "source_traceable_advisory_scenarios",
            "generated_at": self.generated_at,
            "review_after": self.review_after,
            "source_count": len(self.sources),
            "scenario_count": len(self.scenarios),
            "domains": dict(sorted(domains.items())),
            "risk_classes": dict(sorted(risk_classes.items())),
            "lab_states": dict(sorted(lab_states.items())),
            "sources": [source.summary() for source in self.sources],
            "network_call_executed": False,
            "live_call_permitted": False,
        }

    def search(
        self,
        query: str,
        *,
        domain: str | None = None,
        limit: int = 5,
    ) -> list[OperationalScenario]:
        normalized_query = query.strip().lower()
        if not 2 <= len(normalized_query) <= 120:
            raise ScenarioCatalogError(
                "Scenario query length must be between 2 and 120 characters."
            )
        if not 1 <= limit <= MAX_SCENARIO_SEARCH_RESULTS:
            raise ScenarioCatalogError(
                f"Scenario result limit must be between 1 and {MAX_SCENARIO_SEARCH_RESULTS}."
            )
        normalized_domain = domain.strip().lower() if domain else None
        terms = normalized_query.split()
        matches: list[tuple[int, OperationalScenario]] = []
        for scenario in self.scenarios:
            if normalized_domain and scenario.domain.lower() != normalized_domain:
                continue
            haystack = " ".join(
                (
                    scenario.scenario_id,
                    scenario.title,
                    scenario.domain,
                    scenario.intent,
                    scenario.version_notes,
                    *scenario.symptoms,
                    *scenario.available_tools,
                    *scenario.candidate_tools,
                )
            ).lower()
            if not all(term in haystack for term in terms):
                continue
            score = _search_score(normalized_query, scenario)
            matches.append((score, scenario))
        matches.sort(key=lambda item: (item[0], item[1].scenario_id))
        return [scenario for _, scenario in matches[:limit]]

    def get(self, scenario_id: str) -> dict[str, object] | None:
        normalized_id = _scenario_id(scenario_id)
        source_by_id = {source.source_id: source for source in self.sources}
        for scenario in self.scenarios:
            if scenario.scenario_id != normalized_id:
                continue
            return {
                **scenario.summary(),
                "version_notes": scenario.version_notes,
                "source_refs": [reference.as_dict() for reference in scenario.source_refs],
                "sources": [
                    source_by_id[reference.source_id].details()
                    for reference in scenario.source_refs
                ],
                "symptoms": list(scenario.symptoms),
                "evidence_ladder": [step.as_dict() for step in scenario.evidence_ladder],
                "available_tools": list(scenario.available_tools),
                "candidate_tools": list(scenario.candidate_tools),
                "blocked_actions": list(scenario.blocked_actions),
                "validation": scenario.validation.as_dict(),
                "advisory_only": True,
                "network_call_executed": False,
                "live_call_permitted": False,
            }
        return None


def _parse_source(value: object) -> ScenarioSource:
    raw = _mapping(value, "source")
    _require_exact_keys(
        raw,
        {
            "source_id",
            "evidence_class",
            "title",
            "product_version",
            "accessed_at",
            "locator",
            "boundary",
        },
        "source",
    )
    return ScenarioSource(
        source_id=_scenario_id(raw["source_id"]),
        evidence_class=_required_string(raw["evidence_class"], "evidence_class"),
        title=_required_string(raw["title"], "source title"),
        product_version=_required_string(raw["product_version"], "product_version"),
        accessed_at=_required_string(raw["accessed_at"], "accessed_at"),
        locator=_required_string(raw["locator"], "locator"),
        boundary=_required_string(raw["boundary"], "boundary"),
    )


def _parse_scenario(value: object) -> OperationalScenario:
    raw = _mapping(value, "scenario")
    _require_exact_keys(
        raw,
        {
            "scenario_id",
            "title",
            "domain",
            "risk_class",
            "intent",
            "documented_versions",
            "version_notes",
            "source_refs",
            "symptoms",
            "evidence_ladder",
            "available_tools",
            "candidate_tools",
            "blocked_actions",
            "validation",
        },
        "scenario",
    )
    source_refs = tuple(
        _parse_source_ref(item) for item in _list(raw["source_refs"], "source_refs")
    )
    evidence_ladder = tuple(
        _parse_evidence_step(item)
        for item in _list(raw["evidence_ladder"], "evidence_ladder")
    )
    if [step.order for step in evidence_ladder] != list(range(1, len(evidence_ladder) + 1)):
        raise ScenarioCatalogError("Evidence ladder order must be contiguous and start at one.")
    available_tools = _string_tuple(raw["available_tools"], "available_tools")
    candidate_tools = _string_tuple(
        raw["candidate_tools"], "candidate_tools", allow_empty=True
    )
    if set(available_tools) & set(candidate_tools):
        raise ScenarioCatalogError("Available and candidate tools must be disjoint.")
    if any(
        step.tool is not None and step.tool not in available_tools
        for step in evidence_ladder
    ):
        raise ScenarioCatalogError(
            "Evidence steps may reference only tools listed as available."
        )
    validation = _parse_validation(raw["validation"])
    return OperationalScenario(
        scenario_id=_scenario_id(raw["scenario_id"]),
        title=_required_string(raw["title"], "scenario title"),
        domain=_required_string(raw["domain"], "domain"),
        risk_class=_required_string(raw["risk_class"], "risk_class"),
        intent=_required_string(raw["intent"], "intent"),
        documented_versions=_string_tuple(raw["documented_versions"], "documented_versions"),
        version_notes=_required_string(raw["version_notes"], "version_notes"),
        source_refs=source_refs,
        symptoms=_string_tuple(raw["symptoms"], "symptoms"),
        evidence_ladder=evidence_ladder,
        available_tools=available_tools,
        candidate_tools=candidate_tools,
        blocked_actions=_string_tuple(raw["blocked_actions"], "blocked_actions"),
        validation=validation,
    )


def _parse_source_ref(value: object) -> ScenarioSourceRef:
    raw = _mapping(value, "source reference")
    _require_exact_keys(raw, {"source_id", "detail"}, "source reference")
    return ScenarioSourceRef(
        source_id=_scenario_id(raw["source_id"]),
        detail=_required_string(raw["detail"], "source reference detail"),
    )


def _parse_evidence_step(value: object) -> EvidenceStep:
    raw = _mapping(value, "evidence step")
    _require_exact_keys(raw, {"order", "layer", "check", "evidence", "tool"}, "evidence step")
    order = raw["order"]
    if not isinstance(order, int) or isinstance(order, bool) or order < 1:
        raise ScenarioCatalogError("Evidence step order must be a positive integer.")
    tool = raw["tool"]
    if tool is not None and not isinstance(tool, str):
        raise ScenarioCatalogError("Evidence step tool must be a string or null.")
    return EvidenceStep(
        order=order,
        layer=_required_string(raw["layer"], "evidence layer"),
        check=_required_string(raw["check"], "evidence check"),
        evidence=_required_string(raw["evidence"], "evidence result"),
        tool=tool,
    )


def _parse_validation(value: object) -> ScenarioValidation:
    raw = _mapping(value, "validation")
    _require_exact_keys(raw, {"review_state", "lab_state", "last_reviewed"}, "validation")
    return ScenarioValidation(
        review_state=_required_string(raw["review_state"], "review_state"),
        lab_state=_required_string(raw["lab_state"], "lab_state"),
        last_reviewed=_required_string(raw["last_reviewed"], "last_reviewed"),
    )


def _scenario_id(value: object) -> str:
    normalized = _required_string(value, "scenario identifier").lower()
    if not _SCENARIO_ID.fullmatch(normalized):
        raise ScenarioCatalogError("Scenario identifiers must use lowercase letters, digits, and hyphens.")
    return normalized


def _string_tuple(value: object, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    items = _list(value, label)
    if not allow_empty and not items:
        raise ScenarioCatalogError(f"{label} must not be empty.")
    return tuple(_required_string(item, f"{label} item") for item in items)


def _search_score(query: str, scenario: OperationalScenario) -> int:
    if query == scenario.scenario_id:
        return 0
    if query in scenario.title.lower():
        return 1
    if query == scenario.domain.lower():
        return 2
    return 3


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ScenarioCatalogError(f"{label} must be an object.")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ScenarioCatalogError(f"{label} must be a list.")
    return value


def _required_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScenarioCatalogError(f"{label} must be a non-empty string.")
    return value.strip()


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], label: str
) -> None:
    if set(value) != expected:
        raise ScenarioCatalogError(f"{label} has unexpected or missing fields.")
