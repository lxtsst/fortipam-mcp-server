from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import json

import pytest

from fortipam_mcp.baseline_drift import (
    BaselineDriftError,
    InMemoryBaselineStore,
    ProjectionContract,
    ProjectionContractRegistry,
    ProjectionFieldContract,
    canonical_digest,
    compare_baseline,
    create_baseline,
    parse_projection_envelope,
)


NOW = datetime(2026, 8, 22, 12, tzinfo=UTC)
CONTRACT = ProjectionContract(
    contract_id="ha_posture",
    version="v1",
    data_class="C1",
    source_product="FortiPAM",
    source_product_version="1.9.1",
    source_class="fortipam_api",
    scope_class="source_restricted",
    required_paths=frozenset({("ha_enabled",), ("topology", "mode")}),
    field_rules=(
        ProjectionFieldContract(("ha_enabled",), "bool", "v1"),
        ProjectionFieldContract(
            ("topology", "mode"),
            "string",
            "v1",
            enum_values=frozenset({"standalone", "cluster"}),
        ),
        ProjectionFieldContract(
            ("maintenance_state",),
            "string",
            "v1",
            enum_values=frozenset({"not_observed", "scheduled"}),
        ),
    ),
    optional_paths=frozenset({("maintenance_state",)}),
)
REGISTRY = ProjectionContractRegistry([CONTRACT])


def _envelope(**changes: object) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": "2.3",
        "data_class": "C1",
        "source": {
            "product": "FortiPAM",
            "product_version": "1.9.1",
            "source_class": "fortipam_api",
        },
        "contract": {"id": "ha_posture", "version": "v1"},
        "scope_class": "source_restricted",
        "observed_at": "2026-08-22T11:00:00Z",
        "fresh_until": "2026-08-22T13:00:00Z",
        "evidence_state": "complete",
        "projection": {"ha_enabled": True, "topology": {"mode": "standalone"}},
    }
    result.update(changes)
    return result


def _store() -> InMemoryBaselineStore:
    store = InMemoryBaselineStore()
    create_baseline(store, "ha_baseline", _envelope(), REGISTRY)
    return store


def test_canonical_digest_is_order_independent_and_baseline_is_immutable() -> None:
    first = _envelope()
    second = _envelope(projection={"topology": {"mode": "standalone"}, "ha_enabled": True})
    assert canonical_digest(first, CONTRACT) == canonical_digest(second, REGISTRY)
    store = InMemoryBaselineStore()
    create_baseline(store, "ha_baseline", first, REGISTRY)
    with pytest.raises(BaselineDriftError, match="already exists"):
        create_baseline(store, "ha_baseline", second, REGISTRY)


@pytest.mark.parametrize(
    ("current", "expected"),
    [
        (_envelope(), "unchanged"),
        (_envelope(projection={"ha_enabled": False, "topology": {"mode": "standalone"}}), "changed"),
        (_envelope(projection={"ha_enabled": True}), "missing"),
        (_envelope(projection={"ha_enabled": True, "topology": {"mode": "standalone"}, "maintenance_state": "not_observed"}), "new"),
        (_envelope(evidence_state="contradictory"), "contradictory"),
        (_envelope(fresh_until="2026-08-22T11:59:00Z"), "stale"),
    ],
)
def test_compare_returns_only_the_permitted_drift_classes(current: object, expected: str) -> None:
    result = compare_baseline(_store(), "ha_baseline", current, REGISTRY, now=NOW)
    assert result.as_dict() == {"status": expected}
    assert set(result.as_dict().values()) <= {
        "unchanged", "changed", "missing", "new", "stale", "contradictory", "not_assessed"
    }
    assert "standalone" not in json.dumps(result.as_dict())


def test_missing_baseline_and_incompatible_source_are_not_assessed() -> None:
    empty = InMemoryBaselineStore()
    assert compare_baseline(empty, "ha_baseline", _envelope(), REGISTRY, now=NOW).status == "not_assessed"
    changed = _envelope(source={"product": "FortiPAM", "product_version": "1.9.1", "source_class": "fortipam_cli"})
    with pytest.raises(BaselineDriftError, match="source"):
        compare_baseline(_store(), "ha_baseline", changed, REGISTRY, now=NOW)


def test_contract_binds_the_exact_source_product_version() -> None:
    changed = _envelope(
        source={
            "product": "FortiPAM",
            "product_version": "api_token_value",
            "source_class": "fortipam_api",
        }
    )
    with pytest.raises(BaselineDriftError, match="source"):
        parse_projection_envelope(changed, REGISTRY)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda item: item.__setitem__("unknown", True),
        lambda item: item.__setitem__("data_class", "C2"),
        lambda item: item.__setitem__("scope_class", "different_scope"),
        lambda item: item.__setitem__("contract", {"id": "unknown_contract", "version": "v1"}),
        lambda item: item.__setitem__("fresh_until", "2026-08-22T10:00:00Z"),
        lambda item: item.__setitem__("observed_at", "2026-08-22T11:00:00+00:00"),
        lambda item: item.__setitem__("projection", {"api_token_value": "forbidden"}),
        lambda item: item.__setitem__("projection", {"user_password": "forbidden"}),
        lambda item: item.__setitem__("projection", {"raw_response_body": "forbidden"}),
        lambda item: item.__setitem__("projection", {"unknown_safe_key": True}),
        lambda item: item.__setitem__("projection", {"ha_enabled": True, "topology": {"unknown_safe_key": "no"}}),
        lambda item: item.__setitem__("projection", {"status": 1.5}),
        lambda item: item.__setitem__("source", {"product": "FortiPAM", "product_version": "1.9.1", "source_class": "fortipam_api", "extra": "no"}),
    ],
)
def test_envelope_rejects_schema_c3_and_noncanonical_input(mutate) -> None:
    item = deepcopy(_envelope())
    mutate(item)
    with pytest.raises(BaselineDriftError):
        parse_projection_envelope(item, REGISTRY)


def test_comparison_never_updates_a_baseline_or_returns_digest() -> None:
    store = _store()
    changed = _envelope(projection={"ha_enabled": False, "topology": {"mode": "standalone"}})
    first = compare_baseline(store, "ha_baseline", changed, REGISTRY, now=NOW)
    second = compare_baseline(store, "ha_baseline", _envelope(), REGISTRY, now=NOW)
    assert first.status == "changed"
    assert second.status == "unchanged"
    assert set(first.as_dict()) == {"status"}


@pytest.mark.parametrize(
    "projection",
    [
        {"ha_enabled": "true", "topology": {"mode": "standalone"}},
        {"ha_enabled": True, "topology": {"mode": True}},
        {"ha_enabled": True, "topology": {"mode": "api_token_value"}},
        {"ha_enabled": True, "topology": {"mode": "x" * 257}},
        {"ha_enabled": True, "topology": {"mode": "unreviewed_state"}},
    ],
)
def test_field_rules_reject_value_leakage_wrong_types_and_unknown_enums(projection: object) -> None:
    with pytest.raises(BaselineDriftError):
        parse_projection_envelope(_envelope(projection=projection), REGISTRY)


def test_list_rules_validate_every_item_without_nested_objects() -> None:
    list_contract = ProjectionContract(
        contract_id="state_list",
        version="v1",
        data_class="C1",
        source_product="FortiPAM",
        source_product_version="1.9.1",
        source_class="fortipam_api",
        scope_class="source_restricted",
        required_paths=frozenset({("states",)}),
        field_rules=(
            ProjectionFieldContract(
                ("states",),
                "list",
                "v1",
                list_item_type="string",
                list_item_enum_values=frozenset({"ready", "not_ready"}),
                min_items=1,
                max_items=2,
            ),
        ),
    )
    registry = ProjectionContractRegistry([list_contract])
    valid = _envelope(
        contract={"id": "state_list", "version": "v1"},
        projection={"states": ["ready", "not_ready"]},
    )
    assert parse_projection_envelope(valid, registry).projection_paths == frozenset({("states",)})
    for invalid in (["ready", "token-value"], ["ready", {"state": "ready"}], ["ready", "not_ready", "ready"]):
        with pytest.raises(BaselineDriftError):
            parse_projection_envelope(valid | {"projection": {"states": invalid}}, registry)
    with pytest.raises(BaselineDriftError):
        parse_projection_envelope(valid | {"projection": {"states": []}}, registry)


def test_list_empty_policy_must_be_explicit_and_can_allow_empty() -> None:
    empty_list_contract = ProjectionContract(
        "empty_state_list", "v1", "C1", "FortiPAM", "1.9.1", "fortipam_api", "source_restricted",
        frozenset({("states",)}),
        (
            ProjectionFieldContract(
                ("states",), "list", "v1", list_item_type="string",
                list_item_enum_values=frozenset({"ready"}), min_items=0, max_items=2,
            ),
        ),
    )
    registry = ProjectionContractRegistry([empty_list_contract])
    item = _envelope(
        contract={"id": "empty_state_list", "version": "v1"}, projection={"states": []}
    )
    assert parse_projection_envelope(item, registry).projection_paths == frozenset({("states",)})


def test_contract_rejects_paths_without_rules_or_duplicate_rules() -> None:
    rule = ProjectionFieldContract(("ha_enabled",), "bool", "v1")
    with pytest.raises(BaselineDriftError, match="exactly one"):
        ProjectionContract(
            "invalid_contract", "v1", "C1", "FortiPAM", "1.9.1", "fortipam_api", "source_restricted",
            frozenset({("ha_enabled",), ("state",)}), (rule,),
        )
    with pytest.raises(BaselineDriftError, match="exactly one"):
        ProjectionContract(
            "duplicate_contract", "v1", "C1", "FortiPAM", "1.9.1", "fortipam_api", "source_restricted",
            frozenset({("ha_enabled",)}), (rule, rule),
        )


def test_strings_are_closed_enums_and_pattern_configuration_is_not_an_api() -> None:
    with pytest.raises(BaselineDriftError, match="closed enum"):
        ProjectionFieldContract(("category",), "string", "v1")
    with pytest.raises(TypeError):
        ProjectionFieldContract(("category",), "string", "v1", string_mode="pattern")  # type: ignore[call-arg]

