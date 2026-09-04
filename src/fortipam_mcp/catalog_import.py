"""Deterministic importer for the sanitized FNDN UI API catalog."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any, Mapping


class CatalogImportError(ValueError):
    """Raised when a source catalog cannot be safely normalized."""


def build_runtime_catalog(
    source: Mapping[str, Any], *, source_sha256: str
) -> dict[str, object]:
    """Flatten only the metadata required for safe discovery and classification."""

    if source.get("catalog_kind") != "sanitized_fndn_ui_swagger_catalog":
        raise CatalogImportError("Input is not the expected sanitized FNDN UI catalog.")
    if source.get("product") != "FortiPAM" or source.get("version") != "1.9.0":
        raise CatalogImportError("Input product or version is outside this project contract.")
    generated_at = _required_string(source.get("generated_at"), "generated_at")
    review_after = _review_after(generated_at)
    resource_pages = source.get("resource_pages")
    if not isinstance(resource_pages, list):
        raise CatalogImportError("resource_pages must be a list.")

    operations: list[dict[str, object]] = []
    for resource in resource_pages:
        if not isinstance(resource, Mapping):
            raise CatalogImportError("Each resource page must be an object.")
        base_path = _required_string(resource.get("base_path"), "base_path").rstrip("/")
        api_family = _required_string(resource.get("api_family"), "api_family")
        source_group = _required_string(resource.get("source_group"), "source_group")
        parameter_profiles = _profile_list(resource.get("parameter_profiles"), "parameter_profiles")
        response_profiles = _profile_list(resource.get("response_profiles"), "response_profiles")
        raw_operations = resource.get("operations")
        if not isinstance(raw_operations, list):
            raise CatalogImportError("operations must be a list.")
        for operation in raw_operations:
            if not isinstance(operation, Mapping):
                raise CatalogImportError("Each operation must be an object.")
            method = _required_string(operation.get("method"), "method").upper()
            if method not in {"GET", "POST", "PUT", "DELETE"}:
                raise CatalogImportError("Unsupported HTTP method in source catalog.")
            relative_path = _required_string(operation.get("path"), "path")
            full_path = f"{base_path}/{relative_path.lstrip('/')}"
            parameter_profile = _profile_at(
                parameter_profiles,
                operation.get("parameter_profile"),
                "parameter_profile",
            )
            response_profile = _profile_at(
                response_profiles,
                operation.get("response_profile"),
                "response_profile",
            )
            operations.append(
                {
                    "operation_key": f"{method} {full_path}",
                    "api_family": api_family,
                    "source_group": source_group,
                    "method": method,
                    "path": full_path,
                    "operation_id": _optional_string(operation.get("operation_id")),
                    "risk_tier": _required_string(operation.get("risk_tier"), "risk_tier"),
                    "mcp_eligibility": _required_string(
                        operation.get("mcp_eligibility"), "mcp_eligibility"
                    ),
                    "parameters": [_normalize_parameter(item) for item in parameter_profile],
                    "response_codes": sorted(
                        {
                            _required_string(item.get("status"), "response status")
                            for item in response_profile
                            if isinstance(item, Mapping)
                        }
                    ),
                }
            )

    operations.sort(key=lambda item: (str(item["path"]), str(item["method"])))
    operation_keys = {str(item["operation_key"]) for item in operations}
    if len(operation_keys) != len(operations):
        raise CatalogImportError("Source catalog contains duplicate method/path operations.")
    coverage = source.get("coverage")
    if not isinstance(coverage, Mapping):
        raise CatalogImportError("coverage must be an object.")
    if coverage.get("captured_operations") != len(operations):
        raise CatalogImportError("Source coverage does not match flattened operation count.")

    unavailable = source.get("unavailable_resources")
    if not isinstance(unavailable, list):
        raise CatalogImportError("unavailable_resources must be a list.")
    family_summary = source.get("api_family_summary")
    if not isinstance(family_summary, list):
        raise CatalogImportError("api_family_summary must be a list.")
    return {
        "schema_version": "1.0",
        "catalog_kind": "fortipam_mcp_runtime_catalog",
        "product": "FortiPAM",
        "version": "1.9.0",
        "generated_at": generated_at,
        "review_after": review_after,
        "source": {
            "catalog_kind": "sanitized_fndn_ui_swagger_catalog",
            "sha256": source_sha256,
        },
        "coverage": {str(key): _integer(value, f"coverage.{key}") for key, value in coverage.items()},
        "family_summary": [_normalize_family(item) for item in family_summary],
        "unavailable_resources": [_normalize_unavailable(item) for item in unavailable],
        "operations": operations,
    }


def sha256_bytes(content: bytes) -> str:
    """Return the lowercase SHA-256 digest for importer verification."""

    return hashlib.sha256(content).hexdigest()


def _normalize_parameter(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise CatalogImportError("Parameter profile entries must be objects.")
    schema = value.get("schema")
    schema_reference: str | None = None
    if isinstance(schema, Mapping):
        reference = schema.get("reference")
        if reference is not None:
            schema_reference = _required_string(reference, "schema reference")
    data_type = _optional_string(value.get("type"))
    if data_type is None:
        items = value.get("items")
        if isinstance(items, Mapping):
            data_type = _optional_string(items.get("type"))
    required = value.get("required")
    if not isinstance(required, bool):
        raise CatalogImportError("Parameter required flag must be boolean.")
    return {
        "name": _required_string(value.get("name"), "parameter name"),
        "location": _required_string(value.get("location"), "parameter location"),
        "required": required,
        "data_type": data_type,
        "schema_reference": schema_reference,
    }


def _normalize_family(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise CatalogImportError("Family summary entries must be objects.")
    return {
        "api_family": _required_string(value.get("api_family"), "api_family"),
        "resource_pages": _integer(value.get("resource_pages"), "resource_pages"),
        "operations": _integer(value.get("operations"), "operations"),
    }


def _normalize_unavailable(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise CatalogImportError("Unavailable resource entries must be objects.")
    return {
        "api_family": _required_string(value.get("api_family"), "api_family"),
        "source_group": _required_string(value.get("source_group"), "source_group"),
        "status": _required_string(value.get("status"), "status"),
    }


def _profile_list(value: object, label: str) -> list[list[object]]:
    if not isinstance(value, list) or not all(isinstance(item, list) for item in value):
        raise CatalogImportError(f"{label} must be a list of lists.")
    return value


def _profile_at(profiles: list[list[object]], index: object, label: str) -> list[object]:
    if not isinstance(index, int) or isinstance(index, bool):
        raise CatalogImportError(f"{label} must be an integer.")
    try:
        return profiles[index]
    except IndexError as exc:
        raise CatalogImportError(f"{label} is outside the available profiles.") from exc


def _review_after(generated_at: str) -> str:
    try:
        parsed = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CatalogImportError("generated_at must be ISO-8601.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (parsed + timedelta(days=90)).date().isoformat()


def _required_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogImportError(f"{label} must be a non-empty string.")
    return value.strip()


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CatalogImportError("Optional catalog strings must be strings or null.")
    return value.strip() or None


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CatalogImportError(f"{label} must be an integer.")
    return value
