"""Closed, non-disclosing correlation of caller-authorized evidence.

The caller supplies immutable evidence contracts and an immutable correlation
contract. This module has no product defaults, transport, catalog dispatcher,
storage adapter, or device client. It compares categorical contract signals;
it does not infer causality, ownership, or remediation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
from typing import Final


class EvidenceCorrelationError(ValueError):
    """Raised when evidence or a correlation contract fails closed validation."""


MAX_FAN_OUT: Final = 4
MAX_EPOCH: Final = 4_102_444_800  # 2100-01-01 UTC; bounds malformed input.
ENVELOPE_KEYS: Final = frozenset(
    {
        "evidence_ref",
        "contract_id",
        "product",
        "source_class",
        "principal_class",
        "tenant_scope",
        "contract_version",
        "authorization_state",
        "observed_at",
        "fresh_until",
        "evidence_state",
        "confidence_band",
        "signal",
    }
)
OUTPUT_KEYS: Final = frozenset({"relationship_class", "reason_class"})
RELATIONSHIP_CLASSES: Final = frozenset(
    {"temporally_aligned", "operationally_consistent", "contradictory", "not_assessed"}
)
REASON_CLASSES: Final = frozenset(
    {
        "contract_signal_tuple",
        "tenant_scope_mismatch",
        "principal_class_mismatch",
        "evidence_stale",
        "evidence_state_not_observed",
        "confidence_below_high",
        "evidence_windows_do_not_overlap",
        "signal_combination_unlisted",
    }
)

_IDENTIFIER_PATTERN: Final = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_VERSION_PATTERN: Final = re.compile(r"^v[0-9]+(?:\.[0-9]+){0,2}$")
_REF_PATTERN: Final = re.compile(r"^ref-[a-z0-9]{8,64}$")
_TENANT_PATTERN: Final = re.compile(r"^tenant-[a-z0-9]{8,64}$")
_EVIDENCE_STATES: Final = frozenset({"observed", "not_assessed", "unavailable"})
_CONFIDENCE_BANDS: Final = frozenset({"high", "medium", "low"})
_AUTHORIZATION_STATES: Final = frozenset({"independently_authorized"})
_TENANT_POLICIES: Final = frozenset({"same_tenant_only"})
_PRINCIPAL_POLICIES: Final = frozenset(
    {"independent_principals_allowed", "same_principal_class_required"}
)
_UNLISTED_POLICIES: Final = frozenset({"not_assessed", "reject"})
_STRING_FIELDS: Final = (
    "evidence_ref",
    "contract_id",
    "product",
    "source_class",
    "principal_class",
    "tenant_scope",
    "contract_version",
    "authorization_state",
    "evidence_state",
    "confidence_band",
    "signal",
)


@dataclass(frozen=True, slots=True)
class EvidenceContract:
    """Immutable schema for one independently authorized evidence source."""

    contract_id: str
    product: str
    source_class: str
    contract_version: str
    allowed_signals: frozenset[str]

    def __post_init__(self) -> None:
        _identifier(self.contract_id, "contract_id")
        _identifier(self.product, "product")
        _identifier(self.source_class, "source_class")
        if not _VERSION_PATTERN.fullmatch(self.contract_version):
            raise EvidenceCorrelationError("Evidence contract version is invalid.")
        if not isinstance(self.allowed_signals, frozenset) or not self.allowed_signals:
            raise EvidenceCorrelationError("Evidence contract must declare signals.")
        for signal in self.allowed_signals:
            _identifier(signal, "signal")


@dataclass(frozen=True, slots=True)
class EvidenceContractRegistry:
    """Immutable caller-provided registry; no product registry is built in."""

    contracts: tuple[EvidenceContract, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.contracts, tuple) or not self.contracts:
            raise EvidenceCorrelationError("Evidence contract registry must be non-empty.")
        ids = [contract.contract_id for contract in self.contracts]
        keys = [
            (contract.product, contract.source_class, contract.contract_version)
            for contract in self.contracts
        ]
        if len(set(ids)) != len(ids) or len(set(keys)) != len(keys):
            raise EvidenceCorrelationError("Evidence contract registry contains duplicates.")

    def get(self, contract_id: str) -> EvidenceContract | None:
        """Return a registered contract without exposing registry data."""

        for contract in self.contracts:
            if contract.contract_id == contract_id:
                return contract
        return None


@dataclass(frozen=True, slots=True)
class CorrelationRule:
    """One exact categorical signal tuple and its fixed bounded result."""

    signals: tuple[str, ...]
    relationship_class: str
    reason_class: str

    def __post_init__(self) -> None:
        if not isinstance(self.signals, tuple) or not self.signals:
            raise EvidenceCorrelationError("Correlation rule must declare a signal tuple.")
        for signal in self.signals:
            _identifier(signal, "signal")
        if self.relationship_class not in RELATIONSHIP_CLASSES:
            raise EvidenceCorrelationError("Correlation relationship class is not allowed.")
        if self.reason_class not in REASON_CLASSES:
            raise EvidenceCorrelationError("Correlation reason class is not allowed.")


@dataclass(frozen=True, slots=True)
class CorrelationContract:
    """Immutable policy for one exact, ordered correlation relationship."""

    contract_id: str
    contract_version: str
    participating_contract_ids: tuple[str, ...]
    tenant_policy: str
    max_fan_out: int
    truth_table: tuple[CorrelationRule, ...]
    principal_policy: str = "independent_principals_allowed"
    unlisted_policy: str = "reject"

    def __post_init__(self) -> None:
        _identifier(self.contract_id, "correlation contract_id")
        if not _VERSION_PATTERN.fullmatch(self.contract_version):
            raise EvidenceCorrelationError("Correlation contract version is invalid.")
        if not isinstance(self.participating_contract_ids, tuple):
            raise EvidenceCorrelationError("Participating contracts must be an ordered tuple.")
        if not 2 <= len(self.participating_contract_ids) <= MAX_FAN_OUT:
            raise EvidenceCorrelationError("Correlation must declare two to four contracts.")
        if tuple(sorted(self.participating_contract_ids)) != self.participating_contract_ids:
            raise EvidenceCorrelationError("Participating contracts must be canonical order.")
        if len(set(self.participating_contract_ids)) != len(self.participating_contract_ids):
            raise EvidenceCorrelationError("Correlation contracts must be unique.")
        for contract_id in self.participating_contract_ids:
            _identifier(contract_id, "participating contract_id")
        if self.tenant_policy not in _TENANT_POLICIES:
            raise EvidenceCorrelationError("Tenant policy is not allowed.")
        if self.principal_policy not in _PRINCIPAL_POLICIES:
            raise EvidenceCorrelationError("Principal policy is not allowed.")
        if self.unlisted_policy not in _UNLISTED_POLICIES:
            raise EvidenceCorrelationError("Unlisted-signal policy is not allowed.")
        if (
            isinstance(self.max_fan_out, bool)
            or not isinstance(self.max_fan_out, int)
            or not 2 <= self.max_fan_out <= MAX_FAN_OUT
            or len(self.participating_contract_ids) > self.max_fan_out
        ):
            raise EvidenceCorrelationError("Correlation fan-out is outside the fixed bound.")
        if not isinstance(self.truth_table, tuple) or not self.truth_table:
            raise EvidenceCorrelationError("Correlation truth table must be non-empty.")
        expected_width = len(self.participating_contract_ids)
        seen: set[tuple[str, ...]] = set()
        for rule in self.truth_table:
            if len(rule.signals) != expected_width:
                raise EvidenceCorrelationError("Correlation rule width is invalid.")
            if rule.signals in seen:
                raise EvidenceCorrelationError("Correlation truth table contains duplicates.")
            seen.add(rule.signals)

    def validate_registry(self, registry: EvidenceContractRegistry) -> None:
        """Validate source membership and truth-table coverage."""

        contracts: list[EvidenceContract] = []
        for contract_id in self.participating_contract_ids:
            contract = registry.get(contract_id)
            if contract is None:
                raise EvidenceCorrelationError("Correlation references an unknown evidence contract.")
            contracts.append(contract)

        expected = {
            tuple(values)
            for values in _cartesian(tuple(contract.allowed_signals for contract in contracts))
        }
        actual = {rule.signals for rule in self.truth_table}
        if not actual.issubset(expected):
            raise EvidenceCorrelationError("Correlation truth table contains an unknown signal tuple.")
        if actual != expected and self.unlisted_policy == "reject":
            raise EvidenceCorrelationError("Correlation truth table is not complete.")


@dataclass(frozen=True, slots=True)
class _ValidatedEvidence:
    evidence_ref: str
    contract_id: str
    principal_class: str
    tenant_scope: str
    observed_at: int
    fresh_until: int
    evidence_state: str
    confidence_band: str
    signal: str


def validate_evidence_envelope(
    envelope: Mapping[str, object],
    *,
    registry: EvidenceContractRegistry,
) -> None:
    """Validate one exact envelope against a caller-provided registry."""

    _validate_envelope(envelope, registry)


def correlate_evidence(
    envelopes: Sequence[Mapping[str, object]],
    *,
    registry: EvidenceContractRegistry,
    correlation_contract: CorrelationContract,
    now_epoch: int,
) -> dict[str, str]:
    """Correlate evidence under one explicit closed contract.

    ``now_epoch`` is injected to keep freshness decisions deterministic. The
    return value contains only fixed relationship and reason classes.
    """

    _timestamp(now_epoch, "now_epoch")
    correlation_contract.validate_registry(registry)
    if isinstance(envelopes, (str, bytes)) or not isinstance(envelopes, Sequence):
        raise EvidenceCorrelationError("Evidence input must be a bounded sequence.")
    if len(envelopes) != len(correlation_contract.participating_contract_ids):
        raise EvidenceCorrelationError("Evidence count must match the correlation contract.")
    if len(envelopes) > correlation_contract.max_fan_out:
        raise EvidenceCorrelationError("Evidence fan-out exceeds the correlation contract.")

    validated = tuple(_validate_envelope(envelope, registry) for envelope in envelopes)
    refs = {item.evidence_ref for item in validated}
    if len(refs) != len(validated):
        raise EvidenceCorrelationError("Duplicate evidence references are not accepted.")
    source_contracts = {item.contract_id for item in validated}
    expected_contracts = set(correlation_contract.participating_contract_ids)
    if source_contracts != expected_contracts:
        raise EvidenceCorrelationError("Evidence contracts do not match the correlation contract.")

    by_contract = {item.contract_id: item for item in validated}
    ordered = tuple(
        by_contract[contract_id]
        for contract_id in correlation_contract.participating_contract_ids
    )
    if len({item.tenant_scope for item in ordered}) != 1:
        return _result("not_assessed", "tenant_scope_mismatch")
    if (
        correlation_contract.principal_policy == "same_principal_class_required"
        and len({item.principal_class for item in ordered}) != 1
    ):
        return _result("not_assessed", "principal_class_mismatch")
    if any(item.fresh_until < now_epoch for item in ordered):
        return _result("not_assessed", "evidence_stale")
    if any(item.evidence_state != "observed" for item in ordered):
        return _result("not_assessed", "evidence_state_not_observed")
    if any(item.confidence_band != "high" for item in ordered):
        return _result("not_assessed", "confidence_below_high")
    if max(item.observed_at for item in ordered) > min(item.fresh_until for item in ordered):
        return _result("not_assessed", "evidence_windows_do_not_overlap")

    signal_tuple = tuple(item.signal for item in ordered)
    rules = {rule.signals: rule for rule in correlation_contract.truth_table}
    rule = rules.get(signal_tuple)
    if rule is None:
        if correlation_contract.unlisted_policy == "not_assessed":
            return _result("not_assessed", "signal_combination_unlisted")
        raise EvidenceCorrelationError("Signal combination is not listed by the contract.")
    return _result(rule.relationship_class, rule.reason_class)


def _validate_envelope(
    envelope: Mapping[str, object],
    registry: EvidenceContractRegistry,
) -> _ValidatedEvidence:
    if not isinstance(envelope, Mapping):
        raise EvidenceCorrelationError("Each evidence item must be an envelope mapping.")
    if set(envelope) != ENVELOPE_KEYS:
        raise EvidenceCorrelationError("Evidence envelope keys must match the exact schema.")
    if any(not isinstance(envelope[key], str) for key in _STRING_FIELDS):
        raise EvidenceCorrelationError("Categorical envelope fields must be strings.")

    evidence_ref = envelope["evidence_ref"]
    tenant_scope = envelope["tenant_scope"]
    contract_id = envelope["contract_id"]
    if not isinstance(evidence_ref, str) or not _REF_PATTERN.fullmatch(evidence_ref):
        raise EvidenceCorrelationError("Evidence reference must be a constrained opaque token.")
    if not isinstance(tenant_scope, str) or not _TENANT_PATTERN.fullmatch(tenant_scope):
        raise EvidenceCorrelationError("Tenant scope must be a constrained opaque token.")
    if not isinstance(contract_id, str):
        raise EvidenceCorrelationError("Evidence contract_id is required.")
    _identifier(contract_id, "contract_id")
    for field in ("principal_class", "product", "source_class"):
        _identifier(str(envelope[field]), field)
    if not _VERSION_PATTERN.fullmatch(str(envelope["contract_version"])):
        raise EvidenceCorrelationError("Evidence contract version is invalid.")
    _categorical(str(envelope["evidence_state"]), _EVIDENCE_STATES, "evidence state")
    _categorical(str(envelope["confidence_band"]), _CONFIDENCE_BANDS, "confidence band")
    _categorical(
        str(envelope["authorization_state"]),
        _AUTHORIZATION_STATES,
        "authorization state",
    )

    contract = registry.get(contract_id)
    if contract is None:
        raise EvidenceCorrelationError("Evidence references an unknown contract.")
    if (
        envelope["product"] != contract.product
        or envelope["source_class"] != contract.source_class
        or envelope["contract_version"] != contract.contract_version
    ):
        raise EvidenceCorrelationError("Evidence metadata does not match its contract.")
    signal = envelope["signal"]
    if not isinstance(signal, str) or signal not in contract.allowed_signals:
        raise EvidenceCorrelationError("Signal is not allowed by the evidence contract.")
    observed_at = _timestamp(envelope["observed_at"], "observed_at")
    fresh_until = _timestamp(envelope["fresh_until"], "fresh_until")
    if observed_at > fresh_until:
        raise EvidenceCorrelationError("Evidence freshness window is inverted.")

    return _ValidatedEvidence(
        evidence_ref=evidence_ref,
        contract_id=contract_id,
        principal_class=str(envelope["principal_class"]),
        tenant_scope=tenant_scope,
        observed_at=observed_at,
        fresh_until=fresh_until,
        evidence_state=str(envelope["evidence_state"]),
        confidence_band=str(envelope["confidence_band"]),
        signal=signal,
    )


def _identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value):
        raise EvidenceCorrelationError(f"{label} must be a constrained identifier.")


def _categorical(value: str, allowed: frozenset[str], label: str) -> str:
    if value not in allowed:
        raise EvidenceCorrelationError(f"Unknown {label} category.")
    return value


def _timestamp(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_EPOCH:
        raise EvidenceCorrelationError(f"{label} must be a reasonable epoch integer.")
    return value


def _cartesian(domains: tuple[frozenset[str], ...]) -> list[tuple[str, ...]]:
    values: list[tuple[str, ...]] = [()]
    for domain in domains:
        values = [prefix + (value,) for prefix in values for value in sorted(domain)]
    return values


def _result(relationship_class: str, reason_class: str) -> dict[str, str]:
    if relationship_class not in RELATIONSHIP_CLASSES or reason_class not in REASON_CLASSES:
        raise AssertionError("Correlation output class drifted.")
    result = {"relationship_class": relationship_class, "reason_class": reason_class}
    if set(result) != OUTPUT_KEYS:
        raise AssertionError("Correlation output schema drifted.")
    return result


__all__ = [
    "CorrelationContract",
    "CorrelationRule",
    "ENVELOPE_KEYS",
    "EvidenceContract",
    "EvidenceContractRegistry",
    "EvidenceCorrelationError",
    "MAX_EPOCH",
    "MAX_FAN_OUT",
    "OUTPUT_KEYS",
    "REASON_CLASSES",
    "RELATIONSHIP_CLASSES",
    "correlate_evidence",
    "validate_evidence_envelope",
]

