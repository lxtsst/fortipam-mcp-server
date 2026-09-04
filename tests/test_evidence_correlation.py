from __future__ import annotations

from collections.abc import Mapping
from typing import Callable

import pytest

from fortipam_mcp.evidence_correlation import (
    ENVELOPE_KEYS,
    MAX_EPOCH,
    OUTPUT_KEYS,
    CorrelationContract,
    CorrelationRule,
    EvidenceContract,
    EvidenceContractRegistry,
    EvidenceCorrelationError,
    correlate_evidence,
    validate_evidence_envelope,
)

NOW = 1_700_000_000
SIGNALS = frozenset({"available", "blocked", "not_assessed"})


def _registry(*, include_maybe: bool = False) -> EvidenceContractRegistry:
    signals = frozenset(set(SIGNALS) | ({"maybe"} if include_maybe else set()))
    return EvidenceContractRegistry(
        (
            EvidenceContract("contract_a", "product_a", "source_a", "v1", signals),
            EvidenceContract("contract_b", "product_b", "source_b", "v1", SIGNALS),
        )
    )


def _correlation(
    *,
    principal_policy: str = "independent_principals_allowed",
    unlisted_policy: str = "reject",
    complete: bool = True,
) -> CorrelationContract:
    rows = [
        CorrelationRule((left, right), _relation_for(left, right), "contract_signal_tuple")
        for left in SIGNALS
        for right in SIGNALS
    ]
    if not complete:
        rows = rows[:-1]
    return CorrelationContract(
        "correlation_v1",
        "v1",
        ("contract_a", "contract_b"),
        "same_tenant_only",
        2,
        tuple(rows),
        principal_policy=principal_policy,
        unlisted_policy=unlisted_policy,
    )


def _relation_for(left: str, right: str) -> str:
    if left == right and left != "not_assessed":
        return "operationally_consistent"
    if "not_assessed" in (left, right):
        return "temporally_aligned"
    return "contradictory"


def _envelope(
    *,
    contract_id: str = "contract_a",
    product: str = "product_a",
    source_class: str = "source_a",
    principal_class: str = "service_readonly",
    tenant_scope: str = "tenant-aaaaaaaa",
    signal: str = "available",
    observed_at: int = NOW - 10,
    fresh_until: int = NOW + 300,
    evidence_state: str = "observed",
    confidence_band: str = "high",
) -> dict[str, object]:
    return {
        "evidence_ref": "ref-aaaaaaaa" if contract_id == "contract_a" else "ref-bbbbbbbb",
        "contract_id": contract_id,
        "product": product,
        "source_class": source_class,
        "principal_class": principal_class,
        "tenant_scope": tenant_scope,
        "contract_version": "v1",
        "authorization_state": "independently_authorized",
        "observed_at": observed_at,
        "fresh_until": fresh_until,
        "evidence_state": evidence_state,
        "confidence_band": confidence_band,
        "signal": signal,
    }


def _second(**overrides: object) -> dict[str, object]:
    value = _envelope(
        contract_id="contract_b",
        product="product_b",
        source_class="source_b",
    )
    value.update(overrides)
    return value


def test_caller_registry_is_required_and_synthetic_contracts_are_explicit() -> None:
    registry = _registry()
    contract = _correlation()
    first = _envelope()
    second = _second()

    validate_evidence_envelope(first, registry=registry)
    result = correlate_evidence(
        [first, second],
        registry=registry,
        correlation_contract=contract,
        now_epoch=NOW,
    )

    assert result == {
        "relationship_class": "operationally_consistent",
        "reason_class": "contract_signal_tuple",
    }
    assert set(first) == ENVELOPE_KEYS
    assert set(result) == OUTPUT_KEYS


def test_truth_table_controls_semantics_without_generic_polarity() -> None:
    registry = _registry()
    contract = _correlation()
    result = correlate_evidence(
        [_envelope(signal="available"), _second(signal="blocked")],
        registry=registry,
        correlation_contract=contract,
        now_epoch=NOW,
    )

    assert result == {
        "relationship_class": "contradictory",
        "reason_class": "contract_signal_tuple",
    }


def test_distinct_principal_classes_are_allowed_by_default() -> None:
    result = correlate_evidence(
        [_envelope(principal_class="service_readonly"), _second(principal_class="operator_readonly")],
        registry=_registry(),
        correlation_contract=_correlation(),
        now_epoch=NOW,
    )

    assert result["relationship_class"] == "operationally_consistent"


def test_principal_matching_is_only_enforced_by_explicit_policy() -> None:
    result = correlate_evidence(
        [_envelope(), _second(principal_class="operator_readonly")],
        registry=_registry(),
        correlation_contract=_correlation(
            principal_policy="same_principal_class_required"
        ),
        now_epoch=NOW,
    )

    assert result == {
        "relationship_class": "not_assessed",
        "reason_class": "principal_class_mismatch",
    }


@pytest.mark.parametrize(
    ("first", "second", "reason"),
    [
        (_envelope(fresh_until=NOW - 1), _second(fresh_until=NOW + 10), "evidence_stale"),
        (
            _envelope(observed_at=NOW - 10, fresh_until=NOW + 10),
            _second(observed_at=NOW + 20, fresh_until=NOW + 30),
            "evidence_windows_do_not_overlap",
        ),
        (_envelope(evidence_state="not_assessed"), _second(), "evidence_state_not_observed"),
        (_envelope(confidence_band="medium"), _second(), "confidence_below_high"),
    ],
)
def test_time_and_evidence_gates_return_stable_not_assessed(
    first: Mapping[str, object],
    second: Mapping[str, object],
    reason: str,
) -> None:
    result = correlate_evidence(
        [first, second],
        registry=_registry(),
        correlation_contract=_correlation(),
        now_epoch=NOW,
    )

    assert result == {"relationship_class": "not_assessed", "reason_class": reason}


@pytest.mark.parametrize("value", [True, -1, MAX_EPOCH + 1, "1700000000"])
def test_rejects_invalid_now_epoch(value: object) -> None:
    with pytest.raises(EvidenceCorrelationError):
        correlate_evidence(
            [_envelope(), _second()],
            registry=_registry(),
            correlation_contract=_correlation(),
            now_epoch=value,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("field", ["observed_at", "fresh_until"])
def test_rejects_invalid_evidence_timestamp(field: str) -> None:
    value = _envelope()
    value[field] = True

    with pytest.raises(EvidenceCorrelationError):
        validate_evidence_envelope(value, registry=_registry())


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.update({"raw_payload": {"secret": "must-reject"}}),
        lambda value: value.update({"authorization_state": "caller_asserted"}),
        lambda value: value.update({"evidence_ref": "request-123"}),
        lambda value: value.update({"tenant_scope": "tenant-a"}),
        lambda value: value.update({"signal": "arbitrary_value"}),
        lambda value: value.update({"contract_id": "unknown_contract"}),
    ],
)
def test_rejects_raw_payloads_unknown_categories_and_contracts(
    mutator: Callable[[dict[str, object]], None],
) -> None:
    value = _envelope()
    mutator(value)

    with pytest.raises(EvidenceCorrelationError):
        validate_evidence_envelope(value, registry=_registry())


def test_rejects_metadata_drift_and_unknown_registry_contract() -> None:
    value = _envelope(product="product_b")
    with pytest.raises(EvidenceCorrelationError):
        validate_evidence_envelope(value, registry=_registry())

    unknown = EvidenceContractRegistry(
        (EvidenceContract("contract_z", "product_z", "source_z", "v1", SIGNALS),)
    )
    with pytest.raises(EvidenceCorrelationError):
        correlate_evidence(
            [_envelope(), _second()],
            registry=unknown,
            correlation_contract=_correlation(),
            now_epoch=NOW,
        )


def test_rejects_duplicate_sources_refs_and_cross_tenant_inputs() -> None:
    duplicate_source = _envelope()
    duplicate_source["evidence_ref"] = "ref-cccccccc"
    with pytest.raises(EvidenceCorrelationError):
        correlate_evidence(
            [_envelope(), duplicate_source],
            registry=_registry(),
            correlation_contract=_correlation(),
            now_epoch=NOW,
        )

    duplicate_ref = _second()
    duplicate_ref["evidence_ref"] = "ref-aaaaaaaa"
    with pytest.raises(EvidenceCorrelationError):
        correlate_evidence(
            [_envelope(), duplicate_ref],
            registry=_registry(),
            correlation_contract=_correlation(),
            now_epoch=NOW,
        )

    result = correlate_evidence(
        [_envelope(), _second(tenant_scope="tenant-bbbbbbbb")],
        registry=_registry(),
        correlation_contract=_correlation(),
        now_epoch=NOW,
    )
    assert result == {"relationship_class": "not_assessed", "reason_class": "tenant_scope_mismatch"}


def test_truth_table_requires_complete_coverage_or_explicit_unlisted_policy() -> None:
    with pytest.raises(EvidenceCorrelationError, match="not complete"):
        _correlation(complete=False)
        # Validation occurs at correlation time because registry membership is
        # intentionally supplied separately from the immutable policy.
        correlate_evidence(
            [_envelope(), _second()],
            registry=_registry(),
            correlation_contract=_correlation(complete=False),
            now_epoch=NOW,
        )

    partial = _correlation(
        complete=False,
        unlisted_policy="not_assessed",
    )
    result = correlate_evidence(
        [_envelope(signal="maybe"), _second(signal="available")],
        registry=_registry(include_maybe=True),
        correlation_contract=partial,
        now_epoch=NOW,
    )
    assert result == {
        "relationship_class": "not_assessed",
        "reason_class": "signal_combination_unlisted",
    }


def test_rejects_wrong_count_and_fanout() -> None:
    with pytest.raises(EvidenceCorrelationError):
        correlate_evidence(
            [_envelope()],
            registry=_registry(),
            correlation_contract=_correlation(),
            now_epoch=NOW,
        )
    with pytest.raises(EvidenceCorrelationError):
        CorrelationContract(
            "correlation_v1",
            "v1",
            ("contract_a", "contract_b"),
            "same_tenant_only",
            5,
            tuple(),
        )
    with pytest.raises(EvidenceCorrelationError, match="version"):
        CorrelationContract(
            "correlation_v1",
            "unversioned",
            ("contract_a", "contract_b"),
            "same_tenant_only",
            2,
            tuple(),
        )


def test_output_contains_no_input_values_or_sensitive_fields() -> None:
    result = correlate_evidence(
        [_envelope(), _second()],
        registry=_registry(),
        correlation_contract=_correlation(),
        now_epoch=NOW,
    )
    serialized = repr(result)

    assert set(result) == OUTPUT_KEYS
    for value in ("contract_a", "product_a", "ref-aaaaaaaa", "tenant-aaaaaaaa", "1700000000"):
        assert value not in serialized
    for field in ("observed_at", "fresh_until", "digest", "path", "id", "cause", "owner"):
        assert field not in result

