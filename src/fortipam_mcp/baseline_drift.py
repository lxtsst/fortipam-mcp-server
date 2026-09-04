"""Pure local immutable baseline and drift classification for C1/C2 evidence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import re
from types import MappingProxyType
from typing import Protocol, TypeAlias, cast


ENVELOPE_SCHEMA_VERSION = "2.3"
MAX_ENVELOPE_BYTES = 32_768
MAX_NESTING_DEPTH = 8
MAX_PROJECTION_ITEMS = 128
DRIFT_STATES = frozenset(
    {"unchanged", "changed", "missing", "new", "stale", "contradictory", "not_assessed"}
)
_EVIDENCE_STATES = frozenset({"complete", "contradictory"})
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_PROJECTION_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_C3_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "bearer",
        "cookie",
        "credential",
        "credentials",
        "password",
        "passwords",
        "private_key",
        "private_keys",
        "raw_cli_output",
        "raw_response",
        "recording_content",
        "secret",
        "secrets",
        "session_content",
        "token",
        "tokens",
    }
)
_C3_TOKENS = frozenset({"password", "secret", "token", "credential", "cookie", "bearer"})
_C3_COMBINATIONS = (
    frozenset({"api", "key"}),
    frozenset({"private", "key"}),
    frozenset({"raw", "response"}),
    frozenset({"raw", "cli", "output"}),
    frozenset({"session", "content"}),
    frozenset({"recording", "content"}),
)

Path: TypeAlias = tuple[str, ...]
JsonValue: TypeAlias = None | bool | int | str | tuple["JsonValue", ...] | Mapping[str, "JsonValue"]


class BaselineDriftError(ValueError):
    """Raised when an envelope or local evidence operation is unsafe."""


@dataclass(frozen=True, slots=True)
class ProjectionFieldContract:
    """Immutable value rule for exactly one complete projection path."""

    path: Path
    value_type: str
    rule_version: str
    enum_values: frozenset[str] = frozenset()
    minimum: int | None = None
    maximum: int | None = None
    list_item_type: str | None = None
    list_item_enum_values: frozenset[str] = frozenset()
    list_item_minimum: int | None = None
    list_item_maximum: int | None = None
    min_items: int | None = None
    max_items: int | None = None

    def __post_init__(self) -> None:
        _validate_path(self.path)
        _bounded_text(self.rule_version, "The field-rule version is invalid.")
        if self.value_type not in {"bool", "int", "string", "list"}:
            raise BaselineDriftError("The field-rule value type is invalid.")
        if self.value_type == "list":
            if (
                self.list_item_type not in {"bool", "int", "string"}
                or type(self.min_items) is not int
                or type(self.max_items) is not int
                or not 0 <= self.min_items <= self.max_items <= MAX_PROJECTION_ITEMS
            ):
                raise BaselineDriftError("The list field rule is invalid.")
            self._validate_scalar(
                self.list_item_type,
                self.list_item_enum_values,
                self.list_item_minimum,
                self.list_item_maximum,
            )
            if any(value is not None for value in (self.minimum, self.maximum)) or self.enum_values:
                raise BaselineDriftError("A list field rule must use only its item rule.")
            return
        if any(value is not None for value in (self.list_item_type, self.list_item_minimum, self.list_item_maximum, self.min_items, self.max_items)) or self.list_item_enum_values:
            raise BaselineDriftError("A scalar field rule cannot define a list item rule.")
        self._validate_scalar(self.value_type, self.enum_values, self.minimum, self.maximum)

    @staticmethod
    def _validate_scalar(
        value_type: str,
        enum_values: frozenset[str],
        minimum: int | None,
        maximum: int | None,
    ) -> None:
        if value_type == "bool":
            if enum_values or minimum is not None or maximum is not None:
                raise BaselineDriftError("A boolean field rule cannot have value constraints.")
            return
        if value_type == "int":
            if enum_values or type(minimum) is not int or type(maximum) is not int or minimum > maximum:
                raise BaselineDriftError("An integer field rule needs an exact range.")
            return
        if enum_values and minimum is None and maximum is None:
            for item in enum_values:
                _bounded_text(item, "The string enum value is invalid.")
            return
        raise BaselineDriftError("A string field rule requires a closed enum.")


@dataclass(frozen=True, slots=True)
class ProjectionContract:
    """Explicit allowlist for one minimized C1/C2 projection."""

    contract_id: str
    version: str
    data_class: str
    source_product: str
    source_product_version: str
    source_class: str
    scope_class: str
    required_paths: frozenset[Path]
    field_rules: tuple[ProjectionFieldContract, ...]
    optional_paths: frozenset[Path] = frozenset()

    def __post_init__(self) -> None:
        _validated_identifier(self.contract_id, "The contract identifier is invalid.")
        _bounded_text(self.version, "The contract version is invalid.")
        if self.data_class not in {"C1", "C2"}:
            raise BaselineDriftError("Only C1 and C2 contracts are supported.")
        _bounded_text(self.source_product, "The contract source product is invalid.")
        _bounded_text(self.source_product_version, "The contract source product version is invalid.")
        _validated_identifier(self.source_class, "The contract source class is invalid.")
        _validated_identifier(self.scope_class, "The contract scope class is invalid.")
        if not self.required_paths or self.required_paths & self.optional_paths:
            raise BaselineDriftError("Projection contract paths are invalid.")
        all_paths = self.required_paths | self.optional_paths
        if len(all_paths) > MAX_PROJECTION_ITEMS or any(len(path) > MAX_NESTING_DEPTH for path in all_paths):
            raise BaselineDriftError("The projection contract has too many or too-deep paths.")
        for path in all_paths:
            _validate_path(path)
        rule_paths = tuple(rule.path for rule in self.field_rules)
        if len(rule_paths) != len(set(rule_paths)) or frozenset(rule_paths) != all_paths:
            raise BaselineDriftError("Every contract path must have exactly one value rule.")

    @property
    def allowed_paths(self) -> frozenset[Path]:
        return self.required_paths | self.optional_paths

    def rule_for(self, path: Path) -> ProjectionFieldContract:
        for rule in self.field_rules:
            if rule.path == path:
                return rule
        raise BaselineDriftError("The projection path has no value rule.")


class ProjectionContractRegistry:
    """Local explicit registry; unknown contract ID/version fails closed."""

    def __init__(self, contracts: Iterable[ProjectionContract]) -> None:
        items: dict[tuple[str, str], ProjectionContract] = {}
        for contract in contracts:
            key = (contract.contract_id, contract.version)
            if key in items:
                raise BaselineDriftError("Projection contract identifiers must be unique.")
            items[key] = contract
        if not items:
            raise BaselineDriftError("The projection contract registry is empty.")
        self._items = MappingProxyType(items)

    def resolve(self, contract_id: str, version: str) -> ProjectionContract:
        result = self._items.get((contract_id, version))
        if result is None:
            raise BaselineDriftError("The projection contract is not registered.")
        return result


ContractSource: TypeAlias = ProjectionContract | ProjectionContractRegistry


@dataclass(frozen=True, slots=True)
class ProjectionEnvelope:
    """Validated, minimized C1/C2 evidence accepted by the local core."""

    canonical: Mapping[str, JsonValue]
    contract: ProjectionContract
    comparison_digest: str
    observed_at: datetime
    fresh_until: datetime
    evidence_state: str
    projection_paths: frozenset[Path]

    @property
    def comparison_identity(self) -> tuple[JsonValue, ...]:
        return (
            self.canonical["schema_version"],
            self.canonical["data_class"],
            self.canonical["source"],
            self.contract.source_product_version,
            self.canonical["contract"],
            self.canonical["scope_class"],
        )


@dataclass(frozen=True, slots=True)
class BaselineRecord:
    """An immutable local baseline; callers never receive it from comparison."""

    envelope: ProjectionEnvelope
    digest: str


@dataclass(frozen=True, slots=True)
class DriftResult:
    """Non-disclosing comparison result."""

    status: str

    def __post_init__(self) -> None:
        if self.status not in DRIFT_STATES:
            raise BaselineDriftError("The drift status is invalid.")

    def as_dict(self) -> dict[str, str]:
        """Return the sole public result field; never return evidence values."""

        return {"status": self.status}


class BaselineStore(Protocol):
    """Caller-provided local persistence; implementations must reject overwrite."""

    def create(self, baseline_id: str, record: BaselineRecord) -> None:
        """Persist a new immutable record or raise when its ID already exists."""

    def load(self, baseline_id: str) -> BaselineRecord | None:
        """Return one immutable record without refreshing any source."""


class InMemoryBaselineStore:
    """Small caller-local store suitable for deterministic tests and embedding."""

    def __init__(self) -> None:
        self._records: MutableMapping[str, BaselineRecord] = {}

    def create(self, baseline_id: str, record: BaselineRecord) -> None:
        _validate_baseline_id(baseline_id)
        if baseline_id in self._records:
            raise BaselineDriftError("A baseline with this identifier already exists.")
        self._records[baseline_id] = record

    def load(self, baseline_id: str) -> BaselineRecord | None:
        _validate_baseline_id(baseline_id)
        return self._records.get(baseline_id)


def parse_projection_envelope(
    value: object, contracts: ContractSource, *, require_required_paths: bool = False
) -> ProjectionEnvelope:
    """Strictly validate and canonicalize one already-minimized C1/C2 envelope."""

    mapping = _mapping(value, "The projection envelope must be an object.")
    _exact_keys(
        mapping,
        {
            "schema_version",
            "data_class",
            "source",
            "contract",
            "scope_class",
            "observed_at",
            "fresh_until",
            "evidence_state",
            "projection",
        },
        "The projection envelope has an unexpected schema.",
    )
    if mapping["schema_version"] != ENVELOPE_SCHEMA_VERSION:
        raise BaselineDriftError("The projection envelope version is unsupported.")
    source = _strict_metadata(mapping["source"], {"product", "product_version", "source_class"})
    contract = _strict_metadata(mapping["contract"], {"id", "version"})
    expected = _resolve_contract(contracts, contract["id"], contract["version"])
    if mapping["data_class"] != expected.data_class:
        raise BaselineDriftError("The projection data class does not match its contract.")
    if (
        source["product"] != expected.source_product
        or source["product_version"] != expected.source_product_version
        or source["source_class"] != expected.source_class
    ):
        raise BaselineDriftError("The projection source does not match its contract.")
    if mapping["scope_class"] != expected.scope_class:
        raise BaselineDriftError("The projection scope does not match its contract.")
    _bounded_text(source["product"], "The source product is invalid.")
    _bounded_text(source["product_version"], "The source product version is invalid.")
    scope_class = _validated_identifier(mapping["scope_class"], "The scope class is invalid.")
    observed_at = _timestamp(mapping["observed_at"], "The observed timestamp is invalid.")
    fresh_until = _timestamp(mapping["fresh_until"], "The freshness timestamp is invalid.")
    if fresh_until < observed_at:
        raise BaselineDriftError("The freshness window is invalid.")
    evidence_state = mapping["evidence_state"]
    if type(evidence_state) is not str or evidence_state not in _EVIDENCE_STATES:
        raise BaselineDriftError("The evidence state is invalid.")
    projection, projection_paths = _projection(
        mapping["projection"], expected, require_required_paths
    )
    canonical: dict[str, JsonValue] = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "data_class": expected.data_class,
        "source": source,
        "contract": contract,
        "scope_class": scope_class,
        "observed_at": _format_timestamp(observed_at),
        "fresh_until": _format_timestamp(fresh_until),
        "evidence_state": evidence_state,
        "projection": projection,
    }
    _bounded_canonical(canonical)
    comparison = {
        key: canonical[key]
        for key in ("schema_version", "data_class", "source", "contract", "scope_class", "projection")
    }
    return ProjectionEnvelope(
        canonical=MappingProxyType(canonical),
        contract=expected,
        comparison_digest=_digest(comparison),
        observed_at=observed_at,
        fresh_until=fresh_until,
        evidence_state=evidence_state,
        projection_paths=projection_paths,
    )


def canonical_digest(value: object, contracts: ContractSource) -> str:
    """Return a local comparison digest after full C1/C2 envelope validation."""

    return parse_projection_envelope(value, contracts).comparison_digest


def create_baseline(
    store: BaselineStore, baseline_id: str, envelope: object, contracts: ContractSource
) -> BaselineRecord:
    """Create, never overwrite, a local baseline from a validated envelope."""

    parsed = parse_projection_envelope(envelope, contracts, require_required_paths=True)
    record = BaselineRecord(envelope=parsed, digest=parsed.comparison_digest)
    store.create(baseline_id, record)
    return record


def compare_baseline(
    store: BaselineStore,
    baseline_id: str,
    current: object,
    contracts: ContractSource,
    *,
    now: datetime | None = None,
) -> DriftResult:
    """Classify local drift without refreshes, writes, raw values, or digests."""

    parsed = parse_projection_envelope(current, contracts)
    baseline = store.load(baseline_id)
    if baseline is None or baseline.envelope.contract != parsed.contract:
        return DriftResult("not_assessed")
    current_time = _utc_now(now)
    if baseline.envelope.fresh_until < current_time or parsed.fresh_until < current_time:
        return DriftResult("stale")
    if baseline.envelope.evidence_state == "contradictory" or parsed.evidence_state == "contradictory":
        return DriftResult("contradictory")
    if baseline.envelope.comparison_identity != parsed.comparison_identity:
        return DriftResult("not_assessed")
    missing = baseline.envelope.projection_paths - parsed.projection_paths
    if missing:
        return DriftResult("missing")
    added = parsed.projection_paths - baseline.envelope.projection_paths
    if added:
        return DriftResult("new")
    if baseline.digest == parsed.comparison_digest:
        return DriftResult("unchanged")
    return DriftResult("changed")


def _mapping(value: object, message: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise BaselineDriftError(message)
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str], message: str) -> None:
    if set(value) != expected:
        raise BaselineDriftError(message)


def _strict_metadata(value: object, keys: set[str]) -> Mapping[str, JsonValue]:
    mapping = _mapping(value, "The projection metadata is invalid.")
    _exact_keys(mapping, keys, "The projection metadata has an unexpected schema.")
    result: dict[str, JsonValue] = {}
    for key in sorted(keys):
        result[key] = _bounded_text(mapping[key], "The projection metadata value is invalid.")
    return MappingProxyType(result)


def _resolve_contract(
    source: ContractSource, contract_id: object, version: object
) -> ProjectionContract:
    contract_key = _validated_identifier(contract_id, "The contract identifier is invalid.")
    contract_version = _bounded_text(version, "The contract version is invalid.")
    if isinstance(source, ProjectionContractRegistry):
        return source.resolve(contract_key, contract_version)
    if source.contract_id != contract_key or source.version != contract_version:
        raise BaselineDriftError("The projection contract is not registered.")
    return source


def _projection(
    value: object, contract: ProjectionContract, require_required_paths: bool
) -> tuple[Mapping[str, JsonValue], frozenset[Path]]:
    mapping = _mapping(value, "The minimized projection must be an object.")
    if not mapping or len(mapping) > MAX_PROJECTION_ITEMS:
        raise BaselineDriftError("The minimized projection has an invalid item count.")
    paths: set[Path] = set()
    result = _projection_mapping(mapping, (), contract, paths)
    if require_required_paths and not contract.required_paths <= paths:
        raise BaselineDriftError("The baseline projection is missing required contract paths.")
    return MappingProxyType(result), frozenset(paths)


def _projection_mapping(
    value: Mapping[str, object],
    prefix: Path,
    contract: ProjectionContract,
    paths: set[Path],
) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key in sorted(value):
        if not _PROJECTION_KEY.fullmatch(key) or _sensitive_key(key):
            raise BaselineDriftError("The minimized projection contains a prohibited key.")
        path = prefix + (key,)
        if not any(candidate[: len(path)] == path for candidate in contract.allowed_paths):
            raise BaselineDriftError("The minimized projection contains an unknown contract path.")
        item = value[key]
        if isinstance(item, Mapping):
            if path in contract.allowed_paths:
                raise BaselineDriftError("A complete contract path cannot contain nested keys.")
            result[key] = MappingProxyType(
                _projection_mapping(
                    _mapping(item, "The projection is invalid."), path, contract, paths
                )
            )
        else:
            if path not in contract.allowed_paths:
                raise BaselineDriftError("The minimized projection ends before a complete contract path.")
            result[key] = _json_value(item, contract.rule_for(path))
            paths.add(path)
    return result


def _json_value(value: object, rule: ProjectionFieldContract) -> JsonValue:
    if rule.value_type == "list":
        if (
            not isinstance(value, (list, tuple))
            or not cast(int, rule.min_items) <= len(value) <= cast(int, rule.max_items)
        ):
            raise BaselineDriftError("The list value violates its field rule.")
        return tuple(
            _scalar_value(
                item,
                cast(str, rule.list_item_type),
                rule.list_item_enum_values,
                rule.list_item_minimum,
                rule.list_item_maximum,
            )
            for item in value
        )
    return _scalar_value(
        value,
        rule.value_type,
        rule.enum_values,
        rule.minimum,
        rule.maximum,
    )


def _scalar_value(
    value: object,
    value_type: str,
    enum_values: frozenset[str],
    minimum: int | None,
    maximum: int | None,
) -> JsonValue:
    if value_type == "bool":
        if type(value) is not bool:
            raise BaselineDriftError("The value violates its boolean field rule.")
        return value
    if value_type == "int":
        if type(value) is not int or value < cast(int, minimum) or value > cast(int, maximum):
            raise BaselineDriftError("The value violates its integer field rule.")
        return value
    if type(value) is not str:
        raise BaselineDriftError("The value violates its string field rule.")
    if value in enum_values:
        return value
    raise BaselineDriftError("The value violates its string field rule.")


def _sensitive_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _C3_KEYS:
        return True
    tokens = frozenset(item for item in re.split(r"[_-]", lowered) if item)
    return bool(tokens & _C3_TOKENS) or any(combo <= tokens for combo in _C3_COMBINATIONS)


def _validate_path(path: Path) -> None:
    if not path or len(path) > MAX_NESTING_DEPTH:
        raise BaselineDriftError("The projection contract contains an invalid path.")
    if any(not _PROJECTION_KEY.fullmatch(key) or _sensitive_key(key) for key in path):
        raise BaselineDriftError("The projection contract contains an invalid path.")


def _bounded_text(value: object, message: str) -> str:
    if type(value) is not str or not value or len(value) > 256 or "\n" in value or "\r" in value:
        raise BaselineDriftError(message)
    return value


def _validated_identifier(value: object, message: str) -> str:
    text = _bounded_text(value, message)
    if not _IDENTIFIER.fullmatch(text):
        raise BaselineDriftError(message)
    return text


def _timestamp(value: object, message: str) -> datetime:
    text = _bounded_text(value, message)
    if not text.endswith("Z"):
        raise BaselineDriftError(message)
    try:
        result = datetime.fromisoformat(f"{text[:-1]}+00:00")
    except ValueError as exc:
        raise BaselineDriftError(message) from exc
    if result.tzinfo is None or result.utcoffset() != UTC.utcoffset(result):
        raise BaselineDriftError(message)
    return result.astimezone(UTC)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _bounded_canonical(value: Mapping[str, JsonValue]) -> None:
    if len(_canonical_bytes(value)) > MAX_ENVELOPE_BYTES:
        raise BaselineDriftError("The minimized projection envelope is too large.")


def _digest(value: Mapping[str, JsonValue]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _canonical_bytes(value: Mapping[str, JsonValue]) -> bytes:
    return json.dumps(
        _plain_json(value), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _plain_json(value: JsonValue) -> object:
    """Convert immutable internal containers to JSON encoder input only."""

    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(item) for item in value]
    return value


def _validate_baseline_id(value: str) -> None:
    _validated_identifier(value, "The baseline identifier is invalid.")


def _utc_now(value: datetime | None) -> datetime:
    result = datetime.now(UTC) if value is None else value
    if result.tzinfo is None:
        raise BaselineDriftError("The comparison clock must be timezone-aware.")
    return result.astimezone(UTC)

