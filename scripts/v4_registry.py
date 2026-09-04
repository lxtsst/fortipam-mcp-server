"""Validation and loading for the dependency-free FortiPAM V4 registry.

The registry is a catalog and planning boundary only.  This module deliberately
does not expose an adapter, dispatch a request, or turn a catalog record into an
MCP tool.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = PROJECT_ROOT / "registry" / "v4_administrative_registry.json"
MATRIX_PATH = PROJECT_ROOT / "docs" / "v4" / "V4_ACTION_API_PERMISSION_COMPATIBILITY_MATRIX.yaml"
EXPECTED_COUNTS = {
    "sources": 5,
    "blueprints": 21,
    "skill_skus": 21,
    "workflow_skills": 40,
    "schemes": 16,
    "actions": 21,
}
ID_PATTERNS = {
    "sources": re.compile(r"^FPA-SRC-[A-Z0-9-]+$"),
    "blueprints": re.compile(r"^FPA-BP-[0-9]{3}$"),
    "skill_skus": re.compile(r"^FPA-SK-[0-9]{3}$"),
    "workflow_skills": re.compile(r"^fortipam-[a-z0-9-]{3,63}$"),
    "schemes": re.compile(r"^[A-Z][A-Za-z0-9]+Scheme$"),
    "actions": re.compile(r"^[a-z][a-z0-9-]{2,63}$"),
}
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
STATUS = {"design_only", "planned", "lab_accepted", "disabled_by_policy", "enabled_by_policy"}
MATURITY_ORDER = (
    "catalogued",
    "designed",
    "implemented",
    "contract_tested",
    "lab_accepted",
    "policy_enabled",
    "production_qualified",
)
MATURITY = set(MATURITY_ORDER)
LIFECYCLE = set(MATURITY_ORDER)
M2_SCHEMES = {"AccessDomainScheme", "SecretOnboardingScheme"}
INTENT_BINDINGS = {
    "authenticated_requester",
    "summary_digest",
    "summary_revision",
    "environment",
    "scope",
    "object_set",
    "action_set",
    "assumptions",
    "effects",
    "risk",
    "material_reference_metadata",
    "verification",
    "compensation",
}
INTENT_LIFECYCLE = ["read", "preview", "confirm", "reread_compare", "write", "post_read_verify"]
INTENT_DIGEST_FIELDS = {"current_state_digest", "proposed_changes_digest", "expected_state_digest"}
INTENT_INVALIDATIONS = {
    "requester_change",
    "summary_change",
    "summary_revision_change",
    "scope_change",
    "object_set_change",
    "action_set_change",
    "assumption_change",
    "effects_change",
    "risk_change",
    "material_reference_metadata_change",
    "verification_change",
    "compensation_change",
    "current_state_digest_change",
    "proposed_changes_digest_change",
    "expected_state_digest_change",
    "projection_change",
    "freshness_expired",
    "version_change",
}
MATERIAL_ALLOWED_FIELDS = {"provider_class", "purpose", "lifecycle"}
MATERIAL_FORBIDDEN_FIELDS = {"handle", "name", "account", "path", "url", "vendor_locator"}
TOP_LEVEL_KEYS = {
    "registry_kind", "schema_version", "status", "product", "product_version_scope", "data_boundary",
    *EXPECTED_COUNTS,
}
RECORD_KEYS = {
    "sources": {"id", "title", "authority"},
    "blueprints": {"id", "version", "priority", "name", "skill_sku", "workflow_skill_refs", "scheme_refs", "source_refs", "required_information", "acceptance", "action_refs", "status", "maturity", "c3_material_allowed"},
    "skill_skus": {"id", "version", "name", "blueprint_ref", "workflow_skill_refs", "scheme_refs", "source_refs", "required_information", "acceptance", "status", "maturity", "c3_material_allowed"},
    "workflow_skills": {"id", "version", "name", "category", "purpose", "blueprint_refs", "scheme_refs", "source_refs", "required_information", "status", "maturity", "c3_material_allowed"},
    "schemes": {"id", "version", "name", "purpose", "blueprint_refs", "source_refs", "lifecycle", "maturity", "c3_material_allowed", "required_sections", "intent_confirmation", "status", "implementation_evidence"},
    "actions": {"id", "version", "name", "product", "blueprint_refs", "scheme_refs", "source_refs", "risk_tier", "lifecycle", "maturity", "executable", "adapter", "max_affected", "forward", "rollback", "c3_material_allowed", "status", "intent_confirmation", "record_kind", "atomic_contract"},
}
REQUIRED_RECORD_KEYS = {name: set(keys) for name, keys in RECORD_KEYS.items()}
REQUIRED_RECORD_KEYS["schemes"].discard("implementation_evidence")
INTENT_KEYS = {
    "required", "version", "digest_algorithm", "binds", "c3_included", "invalidated_by", "lifecycle",
    "current_state_projection", "digest_fields", "read_authority_required", "pre_write_reread_required",
    "pre_write_drift_invalidates", "post_readback_required", "raw_responses_allowed", "material_reference_metadata_policy",
}
MATERIAL_POLICY_KEYS = {"allowed_fields", "forbidden_fields", "c3_values_included"}
OPERATION_KEYS = {"binding", "method", "path", "expected_current_required", "postcondition_required", "strategy"}
OPERATION_REQUIRED_KEYS = {"binding", "method", "expected_current_required", "postcondition_required"}
MATRIX_ROW_RE = re.compile(
    r"^\s+- \{registry_action_ref: ([a-z0-9-]+), coverage_status: ([a-z_]+), gap_owner: ([a-z_]+), activation: ([a-z_]+)\}\s*$",
    re.MULTILINE,
)
IMPLEMENTATION_EVIDENCE_KEYS = {
    "evidence_status", "evidence_kind", "profile_blueprint_refs", "module_refs", "test_refs", "dispatchable",
    "runtime_packaged", "mcp_exposed", "device_access",
}
IMPLEMENTATION_EVIDENCE_STATUSES = {"pending_contract_tests", "contract_tested"}
M2_MODULE_REFS = [
    "scripts/v4_planning.py",
    "v4_planning/canonical.py",
    "v4_planning/models.py",
    "v4_planning/engine.py",
    "v4_planning/__init__.py",
]
M2_TEST_REFS = ["tests/test_v4_planning.py"]
M2_PROFILE_BLUEPRINT_REFS = {
    "AccessDomainScheme": ["FPA-BP-004"],
    "SecretOnboardingScheme": ["FPA-BP-005"],
}
FORBIDDEN_MATERIAL_KEYS = {
    "password",
    "password_value",
    "secret_value",
    "token_value",
    "api_key",
    "private_key",
    "credential_value",
}


class RegistryValidationError(ValueError):
    """Raised when a registry violates the V4 catalog contract."""

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("registry validation failed: " + "; ".join(self.errors))


def load_registry(path: Path | None = None) -> dict[str, Any]:
    """Load and validate the packaged registry."""

    registry_path = path or REGISTRY_PATH
    try:
        value = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryValidationError((f"cannot load registry: {exc}",)) from exc
    if not isinstance(value, dict):
        raise RegistryValidationError(("top-level registry must be an object",))
    validate_registry(value)
    return value


def validate_registry(registry: Mapping[str, Any]) -> None:
    """Fail closed if the registry is incomplete, inconsistent, or executable."""

    errors: list[str] = []
    _check_unknown_keys(registry, TOP_LEVEL_KEYS, "top-level registry", errors)
    required_top_level = {
        "registry_kind",
        "schema_version",
        "status",
        "product",
        "product_version_scope",
        "data_boundary",
        *EXPECTED_COUNTS,
    }
    missing = sorted(required_top_level - set(registry))
    errors.extend(f"missing top-level field: {name}" for name in missing)
    if registry.get("registry_kind") != "fortipam_v4_administrative_registry":
        errors.append("registry_kind must identify the V4 administrative registry")
    if not isinstance(registry.get("schema_version"), str) or not SEMVER.fullmatch(
        str(registry.get("schema_version"))
    ):
        errors.append("schema_version must be semantic version")
    if registry.get("status") != "design_only":
        errors.append("registry status must remain design_only")
    if registry.get("product") != "FortiPAM":
        errors.append("product must be FortiPAM")
    if not isinstance(registry.get("product_version_scope"), str) or not str(
        registry.get("product_version_scope")
    ).strip():
        errors.append("product_version_scope must be a non-empty string")
    if not isinstance(registry.get("data_boundary"), str) or "C3" not in str(registry.get("data_boundary")):
        errors.append("data_boundary must state the C3 exclusion")

    collections: dict[str, list[Mapping[str, Any]]] = {}
    for name, expected_count in EXPECTED_COUNTS.items():
        raw = registry.get(name)
        if not isinstance(raw, list):
            errors.append(f"{name} must be an array")
            collections[name] = []
            continue
        collections[name] = [item for item in raw if isinstance(item, dict)]
        if len(raw) != expected_count:
            errors.append(f"{name} count must be {expected_count}, got {len(raw)}")
        if len(collections[name]) != len(raw):
            errors.append(f"{name} contains a non-object record")
        ids: list[str] = []
        for index, item in enumerate(collections[name]):
            _check_unknown_keys(item, RECORD_KEYS[name], f"{name}[{index}]", errors)
            _check_required_keys(item, REQUIRED_RECORD_KEYS[name], f"{name}[{index}]", errors)
            identifier = item.get("id")
            if not isinstance(identifier, str) or not ID_PATTERNS[name].fullmatch(identifier):
                errors.append(f"{name}[{index}] has invalid id")
            elif identifier in ids:
                errors.append(f"duplicate {name} id: {identifier}")
            else:
                ids.append(identifier)
            version = item.get("version")
            if name != "sources" and (not isinstance(version, str) or not SEMVER.fullmatch(version)):
                errors.append(f"{name}[{index}] version must be semantic version")
            if name != "sources":
                _check_status(item, name, errors)
                _require_non_empty_string(item, "name", name, errors)
                if item.get("c3_material_allowed") is not False:
                    errors.append(f"{name} {item.get('id')} must exclude C3 material")
            _check_sources(item, name, errors)
            _check_material_and_paths(item, f"{name}[{index}]", errors)

    source_ids = _ids(collections["sources"])
    blueprint_ids = _ids(collections["blueprints"])
    sku_ids = _ids(collections["skill_skus"])
    workflow_ids = _ids(collections["workflow_skills"])
    scheme_ids = _ids(collections["schemes"])
    action_ids = _ids(collections["actions"])

    for blueprint in collections["blueprints"]:
        _require_ref(blueprint, "skill_sku", sku_ids, "blueprint", errors)
        _require_refs(blueprint, "workflow_skill_refs", workflow_ids, "blueprint", errors)
        _require_refs(blueprint, "scheme_refs", scheme_ids, "blueprint", errors)
        _require_refs(blueprint, "source_refs", source_ids, "blueprint", errors)
        _require_refs(blueprint, "action_refs", action_ids, "blueprint", errors)
        if not isinstance(blueprint.get("acceptance"), list) or not blueprint["acceptance"]:
            errors.append(f"blueprint {blueprint.get('id')} needs acceptance evidence")
        _require_non_empty_string_list(blueprint, "required_information", "blueprint", errors)
        _require_non_empty_string_list(blueprint, "acceptance", "blueprint", errors)
        if blueprint.get("priority") not in {"P0", "P1", "P2"}:
            errors.append(f"blueprint {blueprint.get('id')} has invalid priority")

    for sku in collections["skill_skus"]:
        _require_ref(sku, "blueprint_ref", blueprint_ids, "skill SKU", errors)
        _require_refs(sku, "workflow_skill_refs", workflow_ids, "skill SKU", errors)
        _require_refs(sku, "scheme_refs", scheme_ids, "skill SKU", errors)
        _require_refs(sku, "source_refs", source_ids, "skill SKU", errors)
        if not isinstance(sku.get("acceptance"), list) or not sku["acceptance"]:
            errors.append(f"skill SKU {sku.get('id')} needs acceptance evidence")
        _require_non_empty_string_list(sku, "required_information", "skill SKU", errors)
        _require_non_empty_string_list(sku, "acceptance", "skill SKU", errors)

    for skill in collections["workflow_skills"]:
        _require_refs(skill, "blueprint_refs", blueprint_ids, "workflow skill", errors)
        _require_refs(skill, "scheme_refs", scheme_ids, "workflow skill", errors)
        _require_refs(skill, "source_refs", source_ids, "workflow skill", errors)
        _require_non_empty_string(skill, "category", "workflow skill", errors)
        _require_non_empty_string(skill, "purpose", "workflow skill", errors)
        _require_non_empty_string_list(skill, "required_information", "workflow skill", errors)

    for scheme in collections["schemes"]:
        _require_refs(scheme, "blueprint_refs", blueprint_ids, "scheme", errors)
        _require_refs(scheme, "source_refs", source_ids, "scheme", errors)
        _require_non_empty_string(scheme, "purpose", "scheme", errors)
        _require_non_empty_string_list(scheme, "required_sections", "scheme", errors)
        _check_intent_confirmation(scheme, "scheme", errors)
        _check_implementation_evidence(scheme, errors)

    for action in collections["actions"]:
        _require_refs(action, "blueprint_refs", blueprint_ids, "action", errors)
        _require_refs(action, "scheme_refs", scheme_ids, "action", errors)
        _require_refs(action, "source_refs", source_ids, "action", errors)
        if action.get("product") != "FortiPAM":
            errors.append(f"action {action.get('id')} product must be FortiPAM")
        if action.get("risk_tier") not in {"low", "medium", "high"}:
            errors.append(f"action {action.get('id')} has invalid risk_tier")
        if action.get("executable") is not False:
            errors.append(f"action {action.get('id')} cannot be executable in the baseline")
        if action.get("adapter") != "none":
            errors.append(f"action {action.get('id')} cannot bind an adapter in the baseline")
        if action.get("max_affected") != 1:
            errors.append(f"action {action.get('id')} max_affected must be 1")
        forward = action.get("forward")
        rollback = action.get("rollback")
        if not isinstance(forward, dict) or forward.get("binding") != "unbound" or forward.get("method") != "UNBOUND":
            errors.append(f"action {action.get('id')} forward binding must remain unbound")
        else:
            _check_operation(forward, f"action {action.get('id')} forward", errors)
        if not isinstance(rollback, dict) or rollback.get("binding") != "unbound" or rollback.get("method") != "UNBOUND":
            errors.append(f"action {action.get('id')} rollback binding must remain unbound")
        else:
            _check_operation(rollback, f"action {action.get('id')} rollback", errors)
        if action.get("record_kind") != "action_family_placeholder":
            errors.append(f"action {action.get('id')} must be an action_family_placeholder")
        if action.get("atomic_contract") is not False:
            errors.append(f"action {action.get('id')} cannot claim an atomic V3 contract")
        _check_intent_confirmation(action, "action", errors)

    referenced_workflow = {ref for bp in collections["blueprints"] for ref in _string_list(bp.get("workflow_skill_refs"))}
    if referenced_workflow != workflow_ids:
        errors.append("workflow skill reference set differs from registry records")
    referenced_schemes = {ref for bp in collections["blueprints"] for ref in _string_list(bp.get("scheme_refs"))}
    if referenced_schemes != scheme_ids:
        errors.append("scheme reference set differs from registry records")
    referenced_actions = {ref for bp in collections["blueprints"] for ref in _string_list(bp.get("action_refs"))}
    if referenced_actions != action_ids:
        errors.append("action reference set differs from registry records")

    blueprints_by_id = {item["id"]: item for item in collections["blueprints"] if isinstance(item.get("id"), str)}
    for sku in collections["skill_skus"]:
        bound_blueprint = blueprints_by_id.get(sku.get("blueprint_ref"))
        if bound_blueprint is not None and bound_blueprint.get("skill_sku") != sku.get("id"):
            errors.append(f"skill SKU {sku.get('id')} is not reciprocally bound to its blueprint")
    _check_reverse_blueprint_refs(collections["workflow_skills"], blueprints_by_id, "workflow_skill_refs", "workflow skill", errors)
    _check_reverse_blueprint_refs(collections["schemes"], blueprints_by_id, "scheme_refs", "scheme", errors)
    _check_reverse_blueprint_refs(collections["actions"], blueprints_by_id, "action_refs", "action", errors)
    _check_source_provenance(collections, source_ids, blueprints_by_id, errors)
    _check_action_matrix(action_ids, errors)

    if errors:
        raise RegistryValidationError(errors)


def _ids(records: Sequence[Mapping[str, Any]]) -> set[str]:
    return {value for record in records if isinstance(value := record.get("id"), str)}


def _string_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _require_ref(record: Mapping[str, Any], field: str, allowed: set[str], kind: str, errors: list[str]) -> None:
    value = record.get(field)
    if not isinstance(value, str) or value not in allowed:
        errors.append(f"{kind} {record.get('id')} has dangling {field}: {value!r}")


def _require_refs(record: Mapping[str, Any], field: str, allowed: set[str], kind: str, errors: list[str]) -> None:
    values = record.get(field)
    if not isinstance(values, list) or not values:
        errors.append(f"{kind} {record.get('id')} needs non-empty {field}")
        return
    if len(values) != len(set(value for value in values if isinstance(value, str))):
        errors.append(f"{kind} {record.get('id')} has duplicate {field}")
    for value in values:
        if not isinstance(value, str) or value not in allowed:
            errors.append(f"{kind} {record.get('id')} has dangling {field}: {value!r}")


def _check_status(record: Mapping[str, Any], kind: str, errors: list[str]) -> None:
    is_promoted_m2_scheme = (
        kind == "schemes"
        and record.get("id") in M2_SCHEMES
        and record.get("status") == "planned"
        and record.get("maturity") == "contract_tested"
        and record.get("lifecycle") == "contract_tested"
    )
    if record.get("status") not in STATUS:
        errors.append(f"{kind} {record.get('id')} has invalid status")
    elif record.get("status") != "design_only" and not is_promoted_m2_scheme:
        errors.append(f"{kind} {record.get('id')} cannot promote status in the design-only baseline")
    if record.get("maturity") not in MATURITY:
        errors.append(f"{kind} {record.get('id')} has invalid maturity")
    elif record.get("maturity") != "catalogued" and not is_promoted_m2_scheme:
        errors.append(f"{kind} {record.get('id')} cannot promote maturity in the design-only baseline")
    if kind in {"actions", "schemes"}:
        if record.get("lifecycle") not in LIFECYCLE:
            errors.append(f"{kind[:-1]} {record.get('id')} has invalid lifecycle")
        elif record.get("lifecycle") != "catalogued" and not is_promoted_m2_scheme:
            errors.append(f"{kind[:-1]} {record.get('id')} cannot promote lifecycle in the design-only baseline")


def _check_intent_confirmation(record: Mapping[str, Any], kind: str, errors: list[str]) -> None:
    gate = record.get("intent_confirmation")
    if not isinstance(gate, dict):
        errors.append(f"{kind} {record.get('id')} needs a final intent confirmation gate")
        return
    _check_unknown_keys(gate, INTENT_KEYS, f"{kind} {record.get('id')} intent confirmation", errors)
    _check_required_keys(gate, INTENT_KEYS, f"{kind} {record.get('id')} intent confirmation", errors)
    if gate.get("required") is not True:
        errors.append(f"{kind} {record.get('id')} intent confirmation must be required")
    if gate.get("version") != "1.0.0" or gate.get("digest_algorithm") != "sha-256":
        errors.append(f"{kind} {record.get('id')} intent confirmation version/digest is invalid")
    bindings = gate.get("binds")
    if (
        not isinstance(bindings, list)
        or len(bindings) != len(INTENT_BINDINGS)
        or set(bindings) != INTENT_BINDINGS
    ):
        errors.append(f"{kind} {record.get('id')} intent confirmation binding set is incomplete")
    if gate.get("c3_included") is not False:
        errors.append(f"{kind} {record.get('id')} intent confirmation cannot include C3 values")
    invalidated_by = gate.get("invalidated_by")
    if (
        not isinstance(invalidated_by, list)
        or len(invalidated_by) != len(INTENT_INVALIDATIONS)
        or set(invalidated_by) != INTENT_INVALIDATIONS
    ):
        errors.append(f"{kind} {record.get('id')} intent confirmation invalidation set is incomplete")
    if gate.get("lifecycle") != INTENT_LIFECYCLE:
        errors.append(f"{kind} {record.get('id')} intent confirmation lifecycle must read-preview-confirm-reread-write-verify")
    if gate.get("current_state_projection") != "fixed_minimized_non_secret_projection":
        errors.append(f"{kind} {record.get('id')} needs a safe authoritative current-state projection")
    digest_fields = gate.get("digest_fields")
    if digest_fields != [
        "current_state_digest",
        "proposed_changes_digest",
        "expected_state_digest",
    ]:
        errors.append(f"{kind} {record.get('id')} intent confirmation digest fields are incomplete")
    for field in ("read_authority_required", "pre_write_reread_required", "pre_write_drift_invalidates", "post_readback_required", "raw_responses_allowed"):
        expected = False if field == "raw_responses_allowed" else True
        if gate.get(field) is not expected:
            errors.append(f"{kind} {record.get('id')} intent confirmation field {field} is invalid")
    policy = gate.get("material_reference_metadata_policy")
    if not isinstance(policy, dict):
        errors.append(f"{kind} {record.get('id')} needs material reference metadata policy")
    else:
        _check_unknown_keys(policy, MATERIAL_POLICY_KEYS, f"{kind} {record.get('id')} material reference metadata policy", errors)
        _check_required_keys(policy, MATERIAL_POLICY_KEYS, f"{kind} {record.get('id')} material reference metadata policy", errors)
        if policy.get("allowed_fields") != ["provider_class", "purpose", "lifecycle"]:
            errors.append(f"{kind} {record.get('id')} material metadata allowed fields are invalid")
        if policy.get("forbidden_fields") != ["handle", "name", "account", "path", "url", "vendor_locator"]:
            errors.append(f"{kind} {record.get('id')} material metadata forbidden fields are incomplete")
        if policy.get("c3_values_included") is not False:
            errors.append(f"{kind} {record.get('id')} material metadata policy cannot include C3 values")


def _check_sources(record: Mapping[str, Any], kind: str, errors: list[str]) -> None:
    if kind == "sources":
        if (
            not isinstance(record.get("title"), str)
            or not record["title"].strip()
            or not isinstance(record.get("authority"), str)
            or not record["authority"].strip()
        ):
            errors.append(f"source {record.get('id')} needs title and authority")
        return
    refs = record.get("source_refs")
    if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) for ref in refs):
        errors.append(f"{kind} {record.get('id')} needs non-empty source_refs")


def _check_operation(operation: Mapping[str, Any], location: str, errors: list[str]) -> None:
    _check_unknown_keys(operation, OPERATION_KEYS, location, errors)
    _check_required_keys(operation, OPERATION_REQUIRED_KEYS, location, errors)
    if operation.get("expected_current_required") is not True:
        errors.append(f"{location} expected_current_required must be true")
    if operation.get("postcondition_required") is not True:
        errors.append(f"{location} postcondition_required must be true")
    if operation.get("path") is not None:
        errors.append(f"{location} path must remain unbound")
    if "strategy" in operation and operation.get("strategy") != "reconcile_or_manual":
        errors.append(f"{location} strategy is invalid")


def _check_unknown_keys(value: Mapping[str, Any], allowed: set[str], location: str, errors: list[str]) -> None:
    for key in sorted(set(value) - allowed):
        errors.append(f"{location} contains unknown field: {key}")


def _check_required_keys(value: Mapping[str, Any], required: set[str], location: str, errors: list[str]) -> None:
    for key in sorted(required - set(value)):
        errors.append(f"{location} is missing required field: {key}")


def _require_non_empty_string(record: Mapping[str, Any], field: str, kind: str, errors: list[str]) -> None:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{kind} {record.get('id')} needs non-empty {field}")


def _require_non_empty_string_list(record: Mapping[str, Any], field: str, kind: str, errors: list[str]) -> None:
    values = record.get(field)
    if not isinstance(values, list) or not values or any(not isinstance(value, str) or not value.strip() for value in values):
        errors.append(f"{kind} {record.get('id')} needs non-empty string list {field}")


def _check_reverse_blueprint_refs(
    records: Sequence[Mapping[str, Any]],
    blueprints: Mapping[str, Mapping[str, Any]],
    blueprint_field: str,
    kind: str,
    errors: list[str],
) -> None:
    for record in records:
        for blueprint_ref in _string_list(record.get("blueprint_refs")):
            blueprint = blueprints.get(blueprint_ref)
            if blueprint is not None and record.get("id") not in _string_list(blueprint.get(blueprint_field)):
                errors.append(f"{kind} {record.get('id')} is not reciprocally bound to blueprint {blueprint_ref}")


def _check_source_provenance(
    collections: Mapping[str, Sequence[Mapping[str, Any]]],
    source_ids: set[str],
    blueprints: Mapping[str, Mapping[str, Any]],
    errors: list[str],
) -> None:
    """Enforce source propagation and reject declared-but-unused sources.

    Propagation policy:
    * a Skill SKU and workflow Skill must include all sources of their bound
      Blueprint(s); additional source context is allowed;
    * a Scheme and Action aggregate exactly the union of sources of their bound
      Blueprints; and
    * every declared source must be used by at least one non-source record.
    """

    used_sources: set[str] = set()
    for kind, records in collections.items():
        if kind == "sources":
            continue
        for record in records:
            used_sources.update(_string_list(record.get("source_refs")))
    for source_id in sorted(source_ids - used_sources):
        errors.append(f"declared source is orphaned: {source_id}")

    for sku in collections["skill_skus"]:
        blueprint = blueprints.get(str(sku.get("blueprint_ref")))
        if blueprint is not None:
            _require_source_containment(
                sku,
                set(_string_list(blueprint.get("source_refs"))),
                "skill SKU",
                errors,
            )

    for skill in collections["workflow_skills"]:
        expected = _union_blueprint_sources(skill, blueprints)
        _require_source_containment(skill, expected, "workflow skill", errors)

    for kind in ("schemes", "actions"):
        for record in collections[kind]:
            expected = _union_blueprint_sources(record, blueprints)
            actual = set(_string_list(record.get("source_refs")))
            if actual != expected:
                errors.append(
                    f"{kind[:-1]} {record.get('id')} provenance mismatch: expected exact Blueprint source union"
                )


def _union_blueprint_sources(record: Mapping[str, Any], blueprints: Mapping[str, Mapping[str, Any]]) -> set[str]:
    expected: set[str] = set()
    for blueprint_ref in _string_list(record.get("blueprint_refs")):
        blueprint = blueprints.get(blueprint_ref)
        if blueprint is not None:
            expected.update(_string_list(blueprint.get("source_refs")))
    return expected


def _require_source_containment(
    record: Mapping[str, Any],
    expected: set[str],
    kind: str,
    errors: list[str],
) -> None:
    actual = set(_string_list(record.get("source_refs")))
    if not expected.issubset(actual):
        errors.append(f"{kind} {record.get('id')} provenance mismatch: missing Blueprint source reference")


def _check_implementation_evidence(scheme: Mapping[str, Any], errors: list[str]) -> None:
    """Validate the narrow fake-only M2 promotion gate for two Schemes."""

    scheme_id = scheme.get("id")
    evidence = scheme.get("implementation_evidence")
    if scheme_id not in M2_SCHEMES:
        if evidence is not None:
            errors.append(f"scheme {scheme_id} cannot carry M2 implementation evidence")
        return
    if not isinstance(evidence, dict):
        errors.append(f"scheme {scheme_id} needs fake-only implementation evidence")
        return
    _check_unknown_keys(evidence, IMPLEMENTATION_EVIDENCE_KEYS, f"scheme {scheme_id} implementation evidence", errors)
    _check_required_keys(evidence, IMPLEMENTATION_EVIDENCE_KEYS, f"scheme {scheme_id} implementation evidence", errors)
    if evidence.get("evidence_status") not in IMPLEMENTATION_EVIDENCE_STATUSES:
        errors.append(f"scheme {scheme_id} has invalid implementation evidence status")
    if evidence.get("evidence_kind") != "fake_only_contract":
        errors.append(f"scheme {scheme_id} evidence must be fake_only_contract")
    if evidence.get("profile_blueprint_refs") != M2_PROFILE_BLUEPRINT_REFS[scheme_id]:
        errors.append(f"scheme {scheme_id} evidence has an unsupported M2 profile Blueprint")
    evidence_refs_are_exact = (
        evidence.get("module_refs") == M2_MODULE_REFS
        and evidence.get("test_refs") == M2_TEST_REFS
    )
    if not evidence_refs_are_exact:
        errors.append(f"scheme {scheme_id} implementation evidence refs are not the restricted relative paths")
    elif any(not (PROJECT_ROOT / reference).is_file() for reference in (*M2_MODULE_REFS, *M2_TEST_REFS)):
        errors.append(f"scheme {scheme_id} implementation evidence file is unavailable")
    for field in ("dispatchable", "runtime_packaged", "mcp_exposed", "device_access"):
        if evidence.get(field) is not False:
            errors.append(f"scheme {scheme_id} evidence field {field} must be false")
    promoted = scheme.get("status") == "planned" or scheme.get("maturity") == "contract_tested" or scheme.get("lifecycle") == "contract_tested"
    if promoted and evidence.get("evidence_status") != "contract_tested":
        errors.append(f"scheme {scheme_id} promotion requires contract_tested evidence")
    if evidence.get("evidence_status") == "contract_tested" and not (
        scheme.get("status") == "planned" and scheme.get("maturity") == "contract_tested" and scheme.get("lifecycle") == "contract_tested"
    ):
        errors.append(f"scheme {scheme_id} contract_tested evidence requires exact planned/contract_tested promotion")


def _check_action_matrix(action_ids: set[str], errors: list[str]) -> None:
    """Require the compatibility matrix to cover every registry placeholder."""

    try:
        text = MATRIX_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"cannot read action compatibility matrix: {exc}")
        return
    rows = MATRIX_ROW_RE.findall(text)
    refs = {row[0] for row in rows}
    if len(rows) != len(action_ids) or refs != action_ids:
        errors.append("action compatibility matrix placeholder coverage differs from registry actions")
    for action_ref, coverage_status, gap_owner, activation in rows:
        if coverage_status != "evidence_gap" or gap_owner != "owner_required" or activation != "disabled":
            errors.append(f"action compatibility matrix row {action_ref} must remain disabled evidence_gap/owner_required")


def _check_material_and_paths(value: Any, location: str, errors: list[str], key: str | None = None) -> None:
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            if child_key in FORBIDDEN_MATERIAL_KEYS and child_value not in (None, "", [], {}):
                errors.append(f"{location} contains prohibited material field {child_key}")
            _check_material_and_paths(child_value, location, errors, child_key)
    elif isinstance(value, list):
        for child in value:
            _check_material_and_paths(child, location, errors, key)
    elif isinstance(value, str):
        if value.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", value):
            errors.append(f"{location} contains an absolute path")
