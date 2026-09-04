"""Fail-closed V3.2 action-package contract-readiness metadata.

This module is intentionally separate from MCP registration and the V4/P0
administrative registry.  The packaged candidate records only evidence gaps
for a future Folder Create contract.  It never resolves an endpoint, binds an
adapter, accepts a request body, registers a Tool, or contacts FortiPAM.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Mapping, cast


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = PROJECT_ROOT / "registry" / "v3_action_packages.json"

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
        "evidence_status": "evidence_pending",
        "lifecycle": "catalogued",
        "status": "disabled_by_policy",
        "maturity": "catalogued",
        "method": "unknown",
        "path": "unknown",
        "body": "unknown",
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
    if not isinstance(evidence_refs, list) or evidence_refs:
        raise ActionPackageValidationError(
            "Evidence-pending action package must have no approved evidence refs."
        )
    evidence_gaps = package["evidence_gaps"]
    if not _non_empty_string_list(evidence_gaps):
        raise ActionPackageValidationError("Evidence-pending action package needs evidence gaps.")

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
