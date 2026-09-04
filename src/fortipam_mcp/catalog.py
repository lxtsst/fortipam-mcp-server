"""Validated access to the packaged FortiPAM API metadata catalog."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
import json
from typing import Any, Iterable, Mapping

CATALOG_FILENAME = "fortipam_1_9_runtime_catalog.json"
CATALOG_SCHEMA_VERSION = "1.0"
MAX_SEARCH_RESULTS = 25
SUPPORTED_METHODS = frozenset({"GET", "POST", "PUT", "DELETE"})


class CatalogError(ValueError):
    """Raised when packaged FortiPAM catalog metadata is invalid."""


@dataclass(frozen=True, slots=True)
class CatalogParameter:
    """Sanitized parameter metadata retained from the FNDN UI catalog."""

    name: str
    location: str
    required: bool
    data_type: str | None
    schema_reference: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "location": self.location,
            "required": self.required,
            "data_type": self.data_type,
            "schema_reference": self.schema_reference,
        }


@dataclass(frozen=True, slots=True)
class CatalogOperation:
    """One non-callable FortiPAM API operation description."""

    operation_key: str
    api_family: str
    source_group: str
    method: str
    path: str
    operation_id: str | None
    risk_tier: str
    mcp_eligibility: str
    parameters: tuple[CatalogParameter, ...]
    response_codes: tuple[str, ...]

    def summary(self) -> dict[str, object]:
        """Return compact metadata suitable for bounded MCP search results."""

        return {
            "operation_key": self.operation_key,
            "api_family": self.api_family,
            "source_group": self.source_group,
            "method": self.method,
            "path": self.path,
            "risk_tier": self.risk_tier,
            "mcp_eligibility": self.mcp_eligibility,
        }

    def details(self) -> dict[str, object]:
        """Return the complete sanitized runtime metadata for this operation."""

        result = self.summary()
        result.update(
            {
                "operation_id": self.operation_id,
                "parameters": [parameter.as_dict() for parameter in self.parameters],
                "response_codes": list(self.response_codes),
                "live_call_permitted": False,
            }
        )
        return result


@dataclass(frozen=True, slots=True)
class RuntimeCatalog:
    """Immutable, validated FortiPAM API catalog used only for offline discovery."""

    product: str
    version: str
    generated_at: str
    review_after: str
    source_sha256: str
    coverage: Mapping[str, int]
    family_summary: tuple[Mapping[str, object], ...]
    unavailable_resources: tuple[Mapping[str, str], ...]
    operations: tuple[CatalogOperation, ...]

    @classmethod
    def load(cls) -> RuntimeCatalog:
        """Load the packaged catalog and fail closed on schema drift."""

        resource = files("fortipam_mcp").joinpath("data", CATALOG_FILENAME)
        try:
            payload = json.loads(resource.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            raise CatalogError("The packaged FortiPAM API catalog is unavailable or invalid.") from exc
        return cls.from_mapping(payload)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> RuntimeCatalog:
        """Validate and construct a catalog from decoded JSON."""

        _require_exact_keys(
            payload,
            {
                "schema_version",
                "catalog_kind",
                "product",
                "version",
                "generated_at",
                "review_after",
                "source",
                "coverage",
                "family_summary",
                "unavailable_resources",
                "operations",
            },
            "catalog root",
        )
        if payload["schema_version"] != CATALOG_SCHEMA_VERSION:
            raise CatalogError("Unsupported FortiPAM runtime catalog schema version.")
        if payload["catalog_kind"] != "fortipam_mcp_runtime_catalog":
            raise CatalogError("Unexpected FortiPAM runtime catalog kind.")

        source = _mapping(payload["source"], "source")
        _require_exact_keys(source, {"catalog_kind", "sha256"}, "source")
        coverage = _integer_mapping(payload["coverage"], "coverage")
        raw_operations = _list(payload["operations"], "operations")
        operations = tuple(_parse_operation(item) for item in raw_operations)
        operation_keys = {operation.operation_key for operation in operations}
        if len(operation_keys) != len(operations):
            raise CatalogError("FortiPAM runtime catalog operation keys must be unique.")
        if coverage.get("captured_operations") != len(operations):
            raise CatalogError("FortiPAM runtime catalog operation count does not match coverage.")

        family_summary = tuple(
            _mapping(item, "family_summary item")
            for item in _list(payload["family_summary"], "family_summary")
        )
        unavailable = tuple(
            _string_mapping(item, "unavailable_resources item")
            for item in _list(payload["unavailable_resources"], "unavailable_resources")
        )
        return cls(
            product=_required_string(payload["product"], "product"),
            version=_required_string(payload["version"], "version"),
            generated_at=_required_string(payload["generated_at"], "generated_at"),
            review_after=_required_string(payload["review_after"], "review_after"),
            source_sha256=_sha256(source["sha256"]),
            coverage=coverage,
            family_summary=family_summary,
            unavailable_resources=unavailable,
            operations=operations,
        )

    def status(self) -> dict[str, object]:
        """Return source, freshness, and coverage facts without a raw catalog body."""

        return {
            "product": self.product,
            "version": self.version,
            "catalog_kind": "sanitized_runtime_metadata",
            "generated_at": self.generated_at,
            "review_after": self.review_after,
            "source_sha256": self.source_sha256,
            "coverage": dict(self.coverage),
            "family_summary": [dict(item) for item in self.family_summary],
            "unavailable_resources": [dict(item) for item in self.unavailable_resources],
            "runtime_operation_count": len(self.operations),
            "live_api_exposure_from_catalog": False,
        }

    def search(
        self,
        query: str,
        *,
        api_family: str | None = None,
        method: str | None = None,
        limit: int = 10,
    ) -> list[CatalogOperation]:
        """Search sanitized metadata; this method never performs a device request."""

        normalized_query = query.strip().lower()
        if not 2 <= len(normalized_query) <= 120:
            raise CatalogError("Catalog query length must be between 2 and 120 characters.")
        if not 1 <= limit <= MAX_SEARCH_RESULTS:
            raise CatalogError(f"Catalog result limit must be between 1 and {MAX_SEARCH_RESULTS}.")
        normalized_method = _optional_method(method)
        normalized_family = api_family.strip().lower() if api_family else None
        terms = normalized_query.split()

        matches: list[tuple[int, CatalogOperation]] = []
        for operation in self.operations:
            if normalized_method and operation.method != normalized_method:
                continue
            if normalized_family and operation.api_family.lower() != normalized_family:
                continue
            haystack = " ".join(
                (
                    operation.operation_key,
                    operation.api_family,
                    operation.source_group,
                    operation.method,
                    operation.path,
                    operation.risk_tier,
                    operation.mcp_eligibility,
                )
            ).lower()
            if not all(term in haystack for term in terms):
                continue
            score = _search_score(normalized_query, operation)
            matches.append((score, operation))
        matches.sort(key=lambda item: (item[0], item[1].path, item[1].method))
        return [operation for _, operation in matches[:limit]]

    def find(self, method: str, path: str) -> CatalogOperation | None:
        """Find one exact documented operation without interpreting path parameters."""

        normalized_method = _optional_method(method)
        if normalized_method is None:
            raise CatalogError("An HTTP method is required.")
        normalized_path = _catalog_path(path)
        operation_key = f"{normalized_method} {normalized_path}"
        for operation in self.operations:
            if operation.operation_key == operation_key:
                return operation
        return None


def _parse_operation(value: object) -> CatalogOperation:
    raw = _mapping(value, "operation")
    _require_exact_keys(
        raw,
        {
            "operation_key",
            "api_family",
            "source_group",
            "method",
            "path",
            "operation_id",
            "risk_tier",
            "mcp_eligibility",
            "parameters",
            "response_codes",
        },
        "operation",
    )
    method = _optional_method(_required_string(raw["method"], "method"))
    if method is None:
        raise CatalogError("Catalog operation method is required.")
    path = _catalog_path(_required_string(raw["path"], "path"))
    operation_key = _required_string(raw["operation_key"], "operation_key")
    if operation_key != f"{method} {path}":
        raise CatalogError("Catalog operation key does not match its method and path.")
    parameters = tuple(
        _parse_parameter(item) for item in _list(raw["parameters"], "parameters")
    )
    response_codes = tuple(
        _required_string(item, "response code")
        for item in _list(raw["response_codes"], "response_codes")
    )
    operation_id = raw["operation_id"]
    if operation_id is not None and not isinstance(operation_id, str):
        raise CatalogError("operation_id must be a string or null.")
    return CatalogOperation(
        operation_key=operation_key,
        api_family=_required_string(raw["api_family"], "api_family"),
        source_group=_required_string(raw["source_group"], "source_group"),
        method=method,
        path=path,
        operation_id=operation_id,
        risk_tier=_required_string(raw["risk_tier"], "risk_tier"),
        mcp_eligibility=_required_string(raw["mcp_eligibility"], "mcp_eligibility"),
        parameters=parameters,
        response_codes=response_codes,
    )


def _parse_parameter(value: object) -> CatalogParameter:
    raw = _mapping(value, "parameter")
    _require_exact_keys(
        raw,
        {"name", "location", "required", "data_type", "schema_reference"},
        "parameter",
    )
    if not isinstance(raw["required"], bool):
        raise CatalogError("Catalog parameter required flag must be boolean.")
    data_type = raw["data_type"]
    schema_reference = raw["schema_reference"]
    if data_type is not None and not isinstance(data_type, str):
        raise CatalogError("Catalog parameter data_type must be a string or null.")
    if schema_reference is not None and not isinstance(schema_reference, str):
        raise CatalogError("Catalog parameter schema_reference must be a string or null.")
    return CatalogParameter(
        name=_required_string(raw["name"], "parameter name"),
        location=_required_string(raw["location"], "parameter location"),
        required=raw["required"],
        data_type=data_type,
        schema_reference=schema_reference,
    )


def _search_score(query: str, operation: CatalogOperation) -> int:
    if query == operation.path.lower() or query == operation.operation_key.lower():
        return 0
    if operation.path.lower().startswith(query):
        return 1
    if query == operation.source_group.lower():
        return 2
    return 3


def _catalog_path(value: str) -> str:
    path = value.strip()
    if (
        not path.startswith("/api/v2/")
        or len(path) > 300
        or "?" in path
        or "#" in path
        or "\\" in path
        or path.endswith("/")
        or any(segment in {".", ".."} for segment in path.split("/"))
    ):
        raise CatalogError("Catalog path must be an exact documented /api/v2/ path.")
    return path


def _optional_method(value: str | None) -> str | None:
    if value is None:
        return None
    method = value.strip().upper()
    if method not in SUPPORTED_METHODS:
        raise CatalogError("Catalog method must be GET, POST, PUT, or DELETE.")
    return method


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CatalogError(f"{label} must be an object.")
    if not all(isinstance(key, str) for key in value):
        raise CatalogError(f"{label} keys must be strings.")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CatalogError(f"{label} must be a list.")
    return value


def _integer_mapping(value: object, label: str) -> Mapping[str, int]:
    raw = _mapping(value, label)
    if not all(isinstance(item, int) and not isinstance(item, bool) for item in raw.values()):
        raise CatalogError(f"{label} values must be integers.")
    return raw  # type: ignore[return-value]


def _string_mapping(value: object, label: str) -> Mapping[str, str]:
    raw = _mapping(value, label)
    if not all(isinstance(item, str) for item in raw.values()):
        raise CatalogError(f"{label} values must be strings.")
    return raw  # type: ignore[return-value]


def _required_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogError(f"{label} must be a non-empty string.")
    return value.strip()


def _sha256(value: object) -> str:
    digest = _required_string(value, "source sha256").lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise CatalogError("source sha256 must be a 64-character hexadecimal digest.")
    return digest


def _require_exact_keys(
    value: Mapping[str, Any], expected: Iterable[str], label: str
) -> None:
    expected_keys = set(expected)
    actual_keys = set(value)
    if actual_keys != expected_keys:
        raise CatalogError(f"{label} contains unexpected or missing fields.")
