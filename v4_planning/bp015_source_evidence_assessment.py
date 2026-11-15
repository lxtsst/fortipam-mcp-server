"""Fail-closed offline evidence assessment for the BP015 read-contract gap.

The assessment validates packaged metadata only. It never reads a PDF or a
frontend asset, contacts an appliance, or exposes a transport operation.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final


BP015_SOURCE_EVIDENCE_CONTRACT: Final = "fortipam-bp015-source-evidence-v1"
BP015_LOCAL_SOURCE_EVIDENCE_CONTRACT: Final = "fortipam-bp015-local-source-evidence-v1"
BP015_EVIDENCE_STATE: Final = "official_product_semantics_and_frontend_shape_only"
EXPECTED_COVERAGE: Final = {
    "expected_resource_pages": 91,
    "captured_resource_pages": 88,
    "unavailable_resource_pages": 3,
    "captured_operations": 1295,
}
UNAVAILABLE_PROJECTIONS: Final = (
    "sponsored_group_current_state",
    "sponsor_admin_relation_readback",
    "member_relation_readback",
    "invited_user_readback",
    "secret_acl_readback",
)
_EXPECTED_OPERATIONS: Final = (
    ("/api/v2/cmdb/user/group", "user"),
    ("/api/v2/cmdb/user/group/{name}", "user"),
    ("/api/v2/cmdb/firewall.schedule/recurring", "firewall.schedule"),
    ("/api/v2/cmdb/firewall.schedule/recurring/{name}", "firewall.schedule"),
)
_EXPECTED_ROOT_KEYS: Final = frozenset(
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
    }
)
_EXPECTED_OPERATION_KEYS: Final = frozenset(
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
    }
)
_EXPECTED_RESPONSE_CODES: Final = (
    "200",
    "400",
    "401",
    "403",
    "404",
    "405",
    "413",
    "424",
    "429",
    "500",
)
_EXPECTED_EVIDENCE_ROOT_KEYS: Final = frozenset({
    "schema_version", "contract", "product", "evidence_state",
    "official_product_semantics", "authenticated_frontend_shape",
    "sanitized_catalog_routes", "non_promotion",
})
_EXPECTED_OFFICIAL_SEMANTICS: Final = {
    "source_type": "local_official_pdf", "product_version": "1.9.1",
    "sha256": "58ccb242e0786f84ad89e99185757f48e31932f9494618198d12b66a47142f9f",
    "covered_semantics": ("sponsored_group", "sponsor_admin", "invited_user", "secret_group_permission"),
}
_EXPECTED_FRONTEND_SHAPE: Final = {
    "source_type": "authenticated_static_frontend_asset", "product_version": "7.0.0",
    "product_build": 29,
    "sha256": "0c2bf35bb5cde1a5154012d6bf2f529d8d59e782a35aebe0bd29976ca9da434f",
    "size_bytes": 7667190,
    "observed_fields": ("group-type", "group-max-users", "sponsor-group", "user-permission", "group-permission", "inherit-permission", "secret-permission", "allowed-launcher-type"),
    "api_contract": False,
}
_EXPECTED_NON_PROMOTION: Final = {
    "source_contract_ready": False, "device_access": False, "dispatchable": False,
    "frontend_is_not_an_api_contract": True, "protected_values_stored": False,
}


class BP015SourceEvidenceError(ValueError):
    """Raised when the local catalog cannot prove the fixed assessment input."""


@dataclass(frozen=True, slots=True)
class BP015SourceEvidenceAssessment:
    """A fixed, non-executable conclusion from generic catalog metadata only."""

    catalog_sha256: str
    official_semantics_sha256: str
    frontend_shape_sha256: str
    validated_operation_keys: tuple[str, ...]

    @property
    def contract(self) -> str:
        return BP015_SOURCE_EVIDENCE_CONTRACT

    @property
    def assessment_status(self) -> str:
        return "partial"

    @property
    def evidence_state(self) -> str:
        return BP015_EVIDENCE_STATE

    @property
    def source_contract_ready(self) -> bool:
        return False

    @property
    def device_access(self) -> bool:
        return False

    @property
    def dispatchable(self) -> bool:
        return False

    @property
    def unavailable_projections(self) -> tuple[str, ...]:
        return UNAVAILABLE_PROJECTIONS

    def as_dict(self) -> dict[str, object]:
        """Render fixed conclusions without catalog bodies or product data."""

        return {
            "assessment_status": self.assessment_status,
            "catalog_sha256": self.catalog_sha256,
            "contract": self.contract,
            "device_access": self.device_access,
            "dispatchable": self.dispatchable,
            "evidence_state": self.evidence_state,
            "frontend_shape_sha256": self.frontend_shape_sha256,
            "official_semantics_sha256": self.official_semantics_sha256,
            "source_contract_ready": self.source_contract_ready,
            "unavailable_projections": list(self.unavailable_projections),
            "validated_operation_keys": list(self.validated_operation_keys),
        }


def assess_bp015_source_evidence(
    catalog: Mapping[str, object],
    local_source_evidence: Mapping[str, object],
) -> BP015SourceEvidenceAssessment:
    """Verify the exact generic read metadata without inferring BP015 semantics."""

    _require_exact_keys(catalog, _EXPECTED_ROOT_KEYS, "runtime catalog")
    if (
        catalog.get("schema_version") != "1.0"
        or catalog.get("catalog_kind") != "fortipam_mcp_runtime_catalog"
        or catalog.get("product") != "FortiPAM"
        or catalog.get("version") != "1.9.0"
    ):
        raise BP015SourceEvidenceError("BP015 catalog identity is not exact.")
    source = _mapping(catalog.get("source"), "catalog source")
    _require_exact_keys(source, frozenset({"catalog_kind", "sha256"}), "catalog source")
    if source.get("catalog_kind") != "sanitized_fndn_ui_swagger_catalog":
        raise BP015SourceEvidenceError("BP015 catalog source kind is not exact.")
    source_sha256 = source.get("sha256")
    if (
        not isinstance(source_sha256, str)
        or len(source_sha256) != 64
        or any(character not in "0123456789abcdef" for character in source_sha256)
    ):
        raise BP015SourceEvidenceError("BP015 catalog source digest is invalid.")

    coverage = _mapping(catalog.get("coverage"), "catalog coverage")
    if (
        set(coverage) != set(EXPECTED_COVERAGE)
        or any(
            type(coverage.get(key)) is not int or coverage.get(key) != expected
            for key, expected in EXPECTED_COVERAGE.items()
        )
    ):
        raise BP015SourceEvidenceError("BP015 catalog coverage is not exact.")
    operations = catalog.get("operations")
    if not isinstance(operations, list) or len(operations) != EXPECTED_COVERAGE[
        "captured_operations"
    ]:
        raise BP015SourceEvidenceError("BP015 catalog operation coverage is invalid.")

    validated = tuple(
        _validate_required_operation(operations, path=path, source_group=source_group)
        for path, source_group in _EXPECTED_OPERATIONS
    )
    official_sha256, frontend_sha256 = _validate_local_source_evidence(
        local_source_evidence, catalog_sha256=source_sha256, operation_keys=validated
    )
    return BP015SourceEvidenceAssessment(
        source_sha256, official_sha256, frontend_sha256, validated
    )


def _validate_local_source_evidence(
    evidence: Mapping[str, object], *, catalog_sha256: str, operation_keys: tuple[str, ...]
) -> tuple[str, str]:
    _require_exact_keys(evidence, _EXPECTED_EVIDENCE_ROOT_KEYS, "local source evidence")
    if (
        evidence.get("schema_version") != "1.0"
        or evidence.get("contract") != BP015_LOCAL_SOURCE_EVIDENCE_CONTRACT
        or evidence.get("product") != "FortiPAM"
        or evidence.get("evidence_state") != BP015_EVIDENCE_STATE
    ):
        raise BP015SourceEvidenceError("BP015 local evidence identity is not exact.")
    official = _mapping(evidence.get("official_product_semantics"), "official semantics")
    _require_exact_mapping(official, _EXPECTED_OFFICIAL_SEMANTICS, "official semantics")
    frontend = _mapping(evidence.get("authenticated_frontend_shape"), "frontend shape")
    _require_exact_mapping(frontend, _EXPECTED_FRONTEND_SHAPE, "frontend shape")
    routes = _mapping(evidence.get("sanitized_catalog_routes"), "catalog routes")
    _require_exact_keys(routes, frozenset({"source_type", "product_version", "sha256", "routes", "response_schema_available"}), "catalog routes")
    route_values = routes.get("routes")
    if (
        routes.get("source_type") != "sanitized_fndn_ui_swagger_catalog"
        or routes.get("product_version") != "1.9.0"
        or routes.get("sha256") != catalog_sha256
        or not isinstance(route_values, list)
        or tuple(route_values) != operation_keys
        or routes.get("response_schema_available") is not False
    ):
        raise BP015SourceEvidenceError("BP015 catalog evidence is not exact.")
    non_promotion = _mapping(evidence.get("non_promotion"), "non-promotion")
    _require_exact_mapping(non_promotion, _EXPECTED_NON_PROMOTION, "non-promotion")
    return str(official["sha256"]), str(frontend["sha256"])


def _require_exact_mapping(
    value: Mapping[str, object], expected: Mapping[str, object], label: str
) -> None:
    _require_exact_keys(value, frozenset(expected), label)
    for key, expected_value in expected.items():
        actual = value.get(key)
        if isinstance(expected_value, tuple):
            valid = isinstance(actual, list) and tuple(actual) == expected_value
        else:
            valid = actual == expected_value and type(actual) is type(expected_value)
        if not valid:
            raise BP015SourceEvidenceError(f"BP015 {label} changed.")


def _validate_required_operation(
    operations: list[object], *, path: str, source_group: str
) -> str:
    matches = [
        _mapping(operation, "catalog operation")
        for operation in operations
        if (
            isinstance(operation, Mapping)
            and operation.get("method") == "GET"
            and operation.get("path") == path
        )
    ]
    if len(matches) != 1:
        raise BP015SourceEvidenceError("BP015 required catalog route is unavailable.")
    operation = matches[0]
    _require_exact_keys(operation, _EXPECTED_OPERATION_KEYS, "catalog operation")
    operation_key = f"GET {path}"
    if (
        operation.get("operation_key") != operation_key
        or operation.get("method") != "GET"
        or operation.get("path") != path
        or operation.get("api_family") != "Configuration API"
        or operation.get("source_group") != source_group
        or operation.get("risk_tier") != "read"
        or operation.get("mcp_eligibility") != "candidate_read_only"
    ):
        raise BP015SourceEvidenceError("BP015 required catalog operation changed.")
    response_codes = operation.get("response_codes")
    if not isinstance(response_codes, list) or tuple(response_codes) != _EXPECTED_RESPONSE_CODES:
        raise BP015SourceEvidenceError("BP015 required catalog response profile changed.")
    return operation_key


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise BP015SourceEvidenceError(f"BP015 {label} is invalid.")
    return value


def _require_exact_keys(
    value: Mapping[str, object], expected: frozenset[str], label: str
) -> None:
    if set(value) != expected:
        raise BP015SourceEvidenceError(f"BP015 {label} contains unsupported metadata.")
