"""Fail-closed V3.2 documented-but-disabled action-package metadata.

This module is intentionally separate from MCP registration and the V4/P0
administrative registry. The package records a source-backed route and fixed
schema metadata while retaining evidence gaps for a future Folder Create
contract. It never binds an adapter, accepts a device request, registers a
Tool, or contacts FortiPAM.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Mapping, cast


REGISTRY_PATH = Path(__file__).with_name("data") / "v3_action_packages.json"

_TOP_LEVEL_KEYS = {
    "registry_kind",
    "schema_version",
    "product",
    "product_version_scope",
    "status",
    "packages",
}
_PACKAGE_KEYS = {
    "id",
    "version",
    "name",
    "product",
    "object_kind",
    "scope",
    "evidence_status",
    "evidence_refs",
    "evidence_gaps",
    "lifecycle",
    "status",
    "maturity",
    "method",
    "path",
    "body",
    "executable",
    "adapter",
    "mcp_exposed",
    "registered_tool",
    "dispatchable",
    "device_access",
    "max_affected",
    "c3_material_allowed",
    "required_gates",
    "contract_status",
    "source_refs",
    "request_schema",
    "read_routes",
    "rollback_contract",
    "permission_contract",
    "projection_contract",
}
_EXPECTED_GATES = {
    "approved_product_contract",
    "fixed_minimized_current_state_projection",
    "least_privilege_identity_mapping",
    "final_intent_confirmation_and_independent_approval",
    "pre_write_reread_and_drift_check",
    "fixed_post_write_readback",
    "rollback_or_compensation_plan",
    "owner_accepted_lab_evidence",
}
_EXPECTED_SOURCES = [
    "FPA-SRC-TF-FPAM-FOLDER-F502400A",
    "FPA-SRC-TF-FPAM-UTILITY-F502400A",
    "FPA-SRC-TF-FPAM-API-SECRETFOLDER-F502400A",
    "FPA-SRC-TF-FPAM-BODY5-F502400A",
    "FPA-SRC-ADMIN-191",
    "FPA-SRC-CATALOG-190",
    "FPA-SRC-GUI-OBS-FOLDER-CREATE-READONLY",
]
_REQUEST_FIELDS = [
    "id",
    "name",
    "inherit-policy",
    "inherit-permission",
    "inherit-folder-ztna",
    "parent-folder",
    "user-permission",
    "group-permission",
]
_PROJECTION_FIELDS = [
    "exists",
    "id",
    "name",
    "parent-folder",
    "folder-type",
    "inherit-policy",
    "inherit-permission",
    "inherit-folder-ztna",
    "secret-policy",
    "user-permission-count",
    "group-permission-count",
]
_EXPECTED_GAPS = [
    "Root creation is explicitly out of scope because the owner permission-array wire encoding is unverified.",
    "The current lab V3 API identity receives HTTP 403 on folder collection read; a dedicated V4 least-privilege identity is pending.",
    "Positive authorization evidence for SecretFolder Read collection/detail and SecretFolder Read/Write child create is unvalidated.",
    "Live 1.9.1 child request/response shape, status/error mapping, and fixed post-write readback are unvalidated.",
    "Uniqueness, idempotency, concurrency, and duplicate handling remain unvalidated.",
    "Delete compensation is documented only for empty folders; rollback acceptance and ambiguous-timeout reconciliation are unvalidated.",
    "Owner-accepted isolated-lab evidence is missing.",
]


class ActionPackageValidationError(ValueError):
    """Raised when action-package metadata is unsafe or incomplete."""


def load_action_packages(path: Path = REGISTRY_PATH) -> dict[str, Any]:
    """Load and validate the local action-package registry."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ActionPackageValidationError("Unable to load action-package registry.") from exc
    if not isinstance(raw, dict):
        raise ActionPackageValidationError("Registry must be an object.")
    typed = cast(dict[str, Any], raw)
    validate_action_packages(typed)
    return typed


def validate_action_packages(registry: Mapping[str, Any]) -> None:
    """Fail closed unless the registry remains evidence-pending and inert."""

    if not isinstance(registry, Mapping):
        raise ActionPackageValidationError("Registry must be an object.")
    _require_exact_keys(registry, _TOP_LEVEL_KEYS, "registry")
    _require_const(registry, "registry_kind", "fortipam_v3_action_package_registry")
    _require_const(registry, "schema_version", "1.0.0")
    _require_const(registry, "product", "FortiPAM")
    _require_const(registry, "product_version_scope", "1.9.1")
    _require_const(registry, "status", "design_only")

    packages = registry["packages"]
    if not isinstance(packages, list) or len(packages) != 1:
        raise ActionPackageValidationError("Registry must contain exactly one action package.")
    for package in packages:
        _validate_package(package)


def get_action_package(
    action_id: str = "folder-create", version: str = "3.2.0"
) -> dict[str, Any]:
    """Return one inert package copy; no dispatch or registration is implied."""

    registry = load_action_packages()
    package = registry["packages"][0]
    if package["id"] != action_id or package["version"] != version:
        raise ActionPackageValidationError("Requested action package is not catalogued.")
    return deepcopy(package)


def _validate_package(package: object) -> None:
    if not isinstance(package, Mapping):
        raise ActionPackageValidationError("Action package must be an object.")
    _require_exact_keys(package, _PACKAGE_KEYS, "action package")

    constants = {
        "id": "folder-create",
        "version": "3.2.0",
        "name": "FortiPAM Folder Create Contract-Readiness Candidate",
        "product": "FortiPAM",
        "object_kind": "secret/folder",
        "scope": "child_only",
        "evidence_status": "evidence_pending",
        "lifecycle": "catalogued",
        "status": "disabled_by_policy",
        "maturity": "catalogued",
        "contract_status": "documented",
        "method": "POST",
        "path": "/api/v2/cmdb/secret/folder",
        "body": "folder-create-request-v2",
        "adapter": "none",
        "max_affected": 1,
    }
    for key, expected in constants.items():
        _require_const(package, key, expected)
    for key in (
        "executable",
        "mcp_exposed",
        "registered_tool",
        "dispatchable",
        "device_access",
        "c3_material_allowed",
    ):
        _require_const(package, key, False)

    evidence_refs = package["evidence_refs"]
    if package["source_refs"] != _EXPECTED_SOURCES or evidence_refs != _EXPECTED_SOURCES:
        raise ActionPackageValidationError(
            "Evidence refs must be the pinned provider and product-source set."
        )
    evidence_gaps = package["evidence_gaps"]
    if evidence_gaps != _EXPECTED_GAPS:
        raise ActionPackageValidationError("Documented contract evidence gaps changed unexpectedly.")

    request_schema = package["request_schema"]
    if not isinstance(request_schema, Mapping):
        raise ActionPackageValidationError("request_schema must be an object.")
    _require_exact_keys(request_schema, {"ref", "fields", "fixed_defaults", "bounded_inputs"}, "request_schema")
    _require_const(request_schema, "ref", "folder-create-request-v2")
    if request_schema["fields"] != _REQUEST_FIELDS:
        raise ActionPackageValidationError("request_schema fields do not match the fixed body contract.")
    if request_schema["fixed_defaults"] != {
        "id": 0,
        "inherit-policy": "enable",
        "inherit-permission": "enable",
        "inherit-folder-ztna": "enable",
        "user-permission": [],
        "group-permission": [],
    }:
        raise ActionPackageValidationError("request_schema fixed defaults changed unexpectedly.")
    if request_schema["bounded_inputs"] != {
        "name": {
            "type": "string",
            "min_length": 1,
            "max_length": 64,
            "path_separators_allowed": False,
            "control_characters_allowed": False,
        },
        "parent-folder": {
            "type": "integer",
            "minimum": 1,
            "maximum": 2_147_483_647,
        },
    }:
        raise ActionPackageValidationError("request_schema bounded inputs are incomplete.")

    read_routes = package["read_routes"]
    if not isinstance(read_routes, Mapping):
        raise ActionPackageValidationError("read_routes must be an object.")
    _require_exact_keys(read_routes, {"collection", "detail"}, "read_routes")
    for route_name, route in read_routes.items():
        if not isinstance(route, Mapping):
            raise ActionPackageValidationError(f"read_routes.{route_name} must be an object.")
        _require_exact_keys(route, {"method", "path"}, f"read_routes.{route_name}")
        _require_const(route, "method", "GET")
    _require_const(read_routes["collection"], "path", "/api/v2/cmdb/secret/folder")
    _require_const(read_routes["detail"], "path", "/api/v2/cmdb/secret/folder/{id}")

    rollback = package["rollback_contract"]
    if not isinstance(rollback, Mapping):
        raise ActionPackageValidationError("rollback_contract must be an object.")
    _require_exact_keys(rollback, {"method", "path", "status", "precondition"}, "rollback_contract")
    _require_const(rollback, "method", "DELETE")
    _require_const(rollback, "path", "/api/v2/cmdb/secret/folder/{id}")
    _require_const(rollback, "status", "documented_partial")
    _require_const(rollback, "precondition", "empty_folder_only")

    permissions = package["permission_contract"]
    if not isinstance(permissions, Mapping):
        raise ActionPackageValidationError("permission_contract must be an object.")
    _require_exact_keys(
        permissions,
        {
            "status",
            "collection_read",
            "detail_read",
            "child_create",
            "root_folder_required",
            "current_lab_evidence",
            "execution_identity_status",
            "provider_access_group",
        },
        "permission_contract",
    )
    _require_const(permissions, "status", "source_documented_lab_identity_pending")
    _require_const(permissions, "collection_read", "SecretFolder Read")
    _require_const(permissions, "detail_read", "SecretFolder Read")
    _require_const(permissions, "child_create", "SecretFolder Read/Write")
    _require_const(permissions, "root_folder_required", False)
    _require_const(
        permissions,
        "current_lab_evidence",
        "v3_api_identity_folder_collection_read_http_403",
    )
    _require_const(
        permissions,
        "execution_identity_status",
        "dedicated_v4_least_privilege_identity_pending",
    )
    _require_const(permissions, "provider_access_group", "secretgrp")

    projection = package["projection_contract"]
    if not isinstance(projection, Mapping):
        raise ActionPackageValidationError("projection_contract must be an object.")
    _require_exact_keys(projection, {"ref", "status", "fields"}, "projection_contract")
    _require_const(projection, "ref", "folder-readback-projection-v1")
    _require_const(projection, "status", "documented_partial")
    if projection["fields"] != _PROJECTION_FIELDS:
        raise ActionPackageValidationError("projection_contract fields changed unexpectedly.")

    required_gates = package["required_gates"]
    if not _non_empty_string_list(required_gates) or set(required_gates) != _EXPECTED_GATES:
        raise ActionPackageValidationError("Action package required_gates are incomplete.")


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    unknown = actual - expected
    missing = expected - actual
    if unknown:
        raise ActionPackageValidationError(
            f"{label} contains unknown field(s): {', '.join(sorted(unknown))}."
        )
    if missing:
        raise ActionPackageValidationError(
            f"{label} is missing required field(s): {', '.join(sorted(missing))}."
        )


def _require_const(value: Mapping[str, Any], key: str, expected: object) -> None:
    if value.get(key) != expected or (expected is False and value.get(key) is not False):
        raise ActionPackageValidationError(f"{key} must remain {expected!r}.")


def _non_empty_string_list(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and bool(item.strip()) for item in value
    )


__all__ = [
    "ActionPackageValidationError",
    "REGISTRY_PATH",
    "get_action_package",
    "load_action_packages",
    "validate_action_packages",
]
