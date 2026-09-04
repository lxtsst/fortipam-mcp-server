from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Callable

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

import scripts.v4_registry as registry_module
from scripts.v4_registry import RegistryValidationError, load_registry, validate_registry


REGISTRY_FILE = Path(__file__).parents[1] / "registry/v4_administrative_registry.json"
SCHEMA_FILE = Path(__file__).parents[1] / "schemas/v4_administrative_registry.schema.json"


def _schema_validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_registry_schema_is_valid_and_accepts_the_packaged_instance() -> None:
    validator = _schema_validator()
    validator.validate(load_registry())


@pytest.mark.parametrize(
    "mutation",
    [
        lambda registry: registry.update({"unknown_root": True}),
        lambda registry: registry["actions"][0].pop("name"),
        lambda registry: registry["actions"][0].update({"executable": True}),
    ],
)
def test_schema_and_python_validator_share_closed_world_denials(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    broken = copy.deepcopy(load_registry())
    mutation(broken)
    with pytest.raises(ValidationError):
        _schema_validator().validate(broken)
    with pytest.raises(RegistryValidationError):
        validate_registry(broken)


def test_packaged_registry_is_complete_and_non_executable() -> None:
    registry = load_registry()
    assert len(registry["blueprints"]) == 21
    assert len(registry["skill_skus"]) == 21
    assert len(registry["workflow_skills"]) == 40
    assert len(registry["schemes"]) == 16
    assert len(registry["actions"]) == 21
    assert all(action["executable"] is False for action in registry["actions"])
    assert all(action["record_kind"] == "action_family_placeholder" for action in registry["actions"])
    assert all(action["atomic_contract"] is False for action in registry["actions"])


def test_duplicate_blueprint_is_denied() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    broken["blueprints"].append(copy.deepcopy(broken["blueprints"][0]))
    with pytest.raises(RegistryValidationError, match="count must be 21"):
        validate_registry(broken)


def test_ztna_access_and_secret_launch_records_are_linked_and_non_executable() -> None:
    registry = load_registry()
    blueprints = {record["id"]: record for record in registry["blueprints"]}
    skus = {record["id"]: record for record in registry["skill_skus"]}
    workflows = {record["id"]: record for record in registry["workflow_skills"]}
    actions = {record["id"]: record for record in registry["actions"]}

    blueprint = blueprints["FPA-BP-021"]
    assert blueprint["skill_sku"] == "FPA-SK-021"
    assert blueprint["workflow_skill_refs"] == [
        "fortipam-ztna-access-and-secret-launch-control"
    ]
    assert blueprint["action_refs"] == [
        "ztna-access-and-secret-launch-control-plan"
    ]
    assert skus["FPA-SK-021"]["blueprint_ref"] == "FPA-BP-021"
    assert workflows["fortipam-ztna-access-and-secret-launch-control"][
        "blueprint_refs"
    ] == ["FPA-BP-021"]

    action = actions["ztna-access-and-secret-launch-control-plan"]
    assert action["risk_tier"] == "high"
    assert action["executable"] is False
    assert action["adapter"] == "none"
    assert action["forward"]["method"] == "UNBOUND"
    assert action["rollback"]["method"] == "UNBOUND"


def test_dangling_scheme_reference_is_denied() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    broken["blueprints"][0]["scheme_refs"][0] = "MissingScheme"
    with pytest.raises(RegistryValidationError, match="dangling scheme_refs"):
        validate_registry(broken)


def test_executable_action_is_denied() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    broken["actions"][0]["executable"] = True
    with pytest.raises(RegistryValidationError, match="cannot be executable"):
        validate_registry(broken)


def test_absolute_path_and_secret_material_are_denied() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    broken["sources"][0]["local_path"] = "/private/source.pdf"
    broken["sources"][1]["password_value"] = "should-not-exist"
    with pytest.raises(RegistryValidationError) as exc_info:
        validate_registry(broken)
    assert "absolute path" in str(exc_info.value)
    assert "prohibited material field" in str(exc_info.value)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda gate: gate.update({"invalidated_by": ["requester_change"]}), "invalidation set is incomplete"),
        (lambda gate: gate.update({"binds": ["summary_digest"]}), "binding set is incomplete"),
        (lambda gate: gate.update({"c3_included": True}), "cannot include C3 values"),
    ],
)
def test_final_intent_confirmation_gate_denies_absent_stale_tampered_or_wrong_principal(
    mutation: Callable[[dict[str, object]], object], message: str
) -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    gate = broken["actions"][0]["intent_confirmation"]
    mutation(gate)
    with pytest.raises(RegistryValidationError, match=message):
        validate_registry(broken)


def test_missing_final_intent_confirmation_gate_is_denied() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    broken["actions"][0].pop("intent_confirmation")
    with pytest.raises(RegistryValidationError, match="needs a final intent confirmation gate"):
        validate_registry(broken)


def test_pre_write_reread_and_post_readback_are_mandatory() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    gate = broken["schemes"][0]["intent_confirmation"]
    gate["pre_write_reread_required"] = False
    with pytest.raises(RegistryValidationError, match="pre_write_reread_required"):
        validate_registry(broken)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda registry: registry.update({"unexpected": True}),
        lambda registry: registry["actions"][0].update({"unexpected": True}),
        lambda registry: registry["actions"][0]["intent_confirmation"].update({"unexpected": True}),
        lambda registry: registry["actions"][0]["forward"].update({"unexpected": True}),
    ],
)
def test_unknown_fields_are_denied_at_every_contract_level(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    mutation(broken)
    with pytest.raises(RegistryValidationError, match="unknown field"):
        validate_registry(broken)


def test_invalid_maturity_promotion_is_denied() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    broken["actions"][0]["maturity"] = "production_qualified"
    with pytest.raises(RegistryValidationError, match="cannot promote maturity"):
        validate_registry(broken)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("status", "enabled_by_policy", "cannot promote status"),
        ("lifecycle", "production_qualified", "cannot promote lifecycle"),
    ],
)
def test_design_only_status_and_lifecycle_cannot_be_promoted(
    field: str, value: str, message: str
) -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    broken["actions"][0][field] = value
    with pytest.raises(RegistryValidationError, match=message):
        validate_registry(broken)


def test_missing_rollback_guards_are_denied() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    broken["actions"][0]["rollback"]["postcondition_required"] = False
    with pytest.raises(RegistryValidationError, match="rollback postcondition_required"):
        validate_registry(broken)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda registry: registry["blueprints"][0].pop("name"),
        lambda registry: registry["actions"][0]["intent_confirmation"]["material_reference_metadata_policy"].pop("allowed_fields"),
        lambda registry: registry["actions"][0]["rollback"].pop("expected_current_required"),
    ],
)
def test_missing_required_contract_fields_are_denied(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    mutation(broken)
    with pytest.raises(RegistryValidationError, match="missing required field"):
        validate_registry(broken)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda registry: registry.update({"product_version_scope": ""}), "product_version_scope"),
        (lambda registry: registry["sources"][0].update({"title": ""}), "needs title and authority"),
        (lambda registry: registry["actions"][0]["intent_confirmation"]["binds"].append("scope"), "binding set is incomplete"),
        (lambda registry: registry["actions"][0]["intent_confirmation"]["invalidated_by"].append("scope_change"), "invalidation set is incomplete"),
        (lambda registry: registry["actions"][0]["intent_confirmation"]["digest_fields"].append("current_state_digest"), "digest fields are incomplete"),
    ],
)
def test_json_schema_equivalent_minimum_and_unique_constraints_are_denied(
    mutation: Callable[[dict[str, object]], object], message: str
) -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    mutation(broken)
    with pytest.raises(RegistryValidationError, match=message):
        validate_registry(broken)


def test_bound_operation_path_is_denied() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    broken["actions"][0]["forward"]["path"] = "/api/example"
    with pytest.raises(RegistryValidationError, match="path must remain unbound"):
        validate_registry(broken)


def test_reverse_blueprint_reference_mismatch_is_denied() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    skill = broken["workflow_skills"][0]
    blueprint = next(item for item in broken["blueprints"] if item["id"] == skill["blueprint_refs"][0])
    blueprint["workflow_skill_refs"].remove(skill["id"])
    with pytest.raises(RegistryValidationError, match="not reciprocally bound"):
        validate_registry(broken)


def test_missing_full_invalidation_factor_is_denied() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    broken["actions"][0]["intent_confirmation"]["invalidated_by"].remove("freshness_expired")
    with pytest.raises(RegistryValidationError, match="invalidation set is incomplete"):
        validate_registry(broken)


@pytest.mark.parametrize(
    ("field", "value"),
    [("raw_responses_allowed", True), ("post_readback_required", False)],
)
def test_unsafe_readback_controls_are_denied(field: str, value: bool) -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    broken["schemes"][0]["intent_confirmation"][field] = value
    with pytest.raises(RegistryValidationError, match=f"field {field} is invalid"):
        validate_registry(broken)


def test_metadata_validation_never_registers_tools_or_actions() -> None:
    registry = load_registry()
    validate_registry(registry)
    assert not hasattr(registry_module, "register_mcp_tool")
    assert not hasattr(registry_module, "ActionRegistry")


def test_declared_orphan_source_is_denied() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    orphan = "FPA-SRC-HOL-FEAT-19"
    for collection in ("blueprints", "skill_skus", "workflow_skills", "schemes", "actions"):
        for record in broken[collection]:
            record["source_refs"] = [source for source in record["source_refs"] if source != orphan]
    with pytest.raises(RegistryValidationError, match="declared source is orphaned"):
        validate_registry(broken)


def test_skill_sku_source_provenance_mismatch_is_denied() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    sku = broken["skill_skus"][0]
    sku["source_refs"] = [source for source in sku["source_refs"] if source != "FPA-SRC-HOL-FEAT-19"]
    with pytest.raises(RegistryValidationError, match="skill SKU .*provenance mismatch"):
        validate_registry(broken)


def test_scheme_source_provenance_must_equal_blueprint_union() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    broken["schemes"][0]["source_refs"].pop()
    with pytest.raises(RegistryValidationError, match="scheme .*provenance mismatch"):
        validate_registry(broken)


def test_m2_fake_only_evidence_can_promote_only_the_two_allowed_schemes() -> None:
    registry = load_registry()
    promoted = copy.deepcopy(registry)
    for scheme_id in ("AccessDomainScheme", "SecretOnboardingScheme"):
        scheme = next(item for item in promoted["schemes"] if item["id"] == scheme_id)
        scheme["status"] = "planned"
        scheme["maturity"] = "contract_tested"
        scheme["lifecycle"] = "contract_tested"
        scheme["implementation_evidence"]["evidence_status"] = "contract_tested"
    validate_registry(promoted)


def test_packaged_m2_promotion_is_exact_and_covers_wrapper_and_core_refs() -> None:
    registry = load_registry()
    expected_modules = [
        "scripts/v4_planning.py",
        "v4_planning/canonical.py",
        "v4_planning/models.py",
        "v4_planning/engine.py",
        "v4_planning/__init__.py",
    ]
    for scheme in registry["schemes"]:
        if scheme["id"] in {"AccessDomainScheme", "SecretOnboardingScheme"}:
            assert scheme["status"] == "planned"
            assert scheme["maturity"] == "contract_tested"
            assert scheme["lifecycle"] == "contract_tested"
            evidence = scheme["implementation_evidence"]
            assert evidence["evidence_status"] == "contract_tested"
            expected_profile = (
                ["FPA-BP-004"]
                if scheme["id"] == "AccessDomainScheme"
                else ["FPA-BP-005"]
            )
            assert evidence["profile_blueprint_refs"] == expected_profile
            assert evidence["module_refs"] == expected_modules
            assert evidence["test_refs"] == ["tests/test_v4_planning.py"]
        else:
            assert scheme["status"] == "design_only"
            assert scheme["maturity"] == "catalogued"
            assert scheme["lifecycle"] == "catalogued"


def test_m2_promotion_without_contract_tested_evidence_is_denied() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    scheme = next(item for item in broken["schemes"] if item["id"] == "AccessDomainScheme")
    scheme["status"] = "planned"
    scheme["maturity"] = "contract_tested"
    scheme["lifecycle"] = "contract_tested"
    scheme["implementation_evidence"]["evidence_status"] = "pending_contract_tests"
    with pytest.raises(RegistryValidationError, match="promotion requires contract_tested evidence"):
        validate_registry(broken)


def test_non_m2_scheme_cannot_promote_or_carry_evidence() -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    scheme = next(item for item in broken["schemes"] if item["id"] == "IdentityLifecycleScheme")
    scheme["status"] = "planned"
    scheme["maturity"] = "contract_tested"
    scheme["lifecycle"] = "contract_tested"
    with pytest.raises(RegistryValidationError, match="cannot promote status"):
        validate_registry(broken)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("dispatchable", True, "dispatchable must be false"),
        ("runtime_packaged", True, "runtime_packaged must be false"),
        ("mcp_exposed", True, "mcp_exposed must be false"),
        ("device_access", True, "device_access must be false"),
        ("module_refs", ["/absolute/path.py"], "restricted relative paths"),
        ("module_refs", ["scripts/v4_planning.py"], "restricted relative paths"),
    ],
)
def test_m2_evidence_cannot_claim_runtime_or_unbounded_refs(field: str, value: object, message: str) -> None:
    registry = load_registry()
    broken = copy.deepcopy(registry)
    evidence = next(item for item in broken["schemes"] if item["id"] == "AccessDomainScheme")["implementation_evidence"]
    evidence[field] = value
    with pytest.raises(RegistryValidationError, match=message):
        validate_registry(broken)


def test_m2_promotion_requires_all_referenced_evidence_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(registry_module, "PROJECT_ROOT", tmp_path)
    with pytest.raises(RegistryValidationError, match="evidence file is unavailable"):
        validate_registry(load_registry(REGISTRY_FILE))


def test_m2_evidence_cannot_overclaim_an_untested_blueprint_profile() -> None:
    broken = copy.deepcopy(load_registry())
    scheme = next(
        item for item in broken["schemes"] if item["id"] == "SecretOnboardingScheme"
    )
    scheme["implementation_evidence"]["profile_blueprint_refs"] = ["FPA-BP-006"]
    with pytest.raises(RegistryValidationError, match="unsupported M2 profile Blueprint"):
        validate_registry(broken)


def test_action_matrix_covers_all_registry_placeholders() -> None:
    validate_registry(load_registry())


def test_action_matrix_drift_is_denied(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    matrix = registry_module.MATRIX_PATH.read_text(encoding="utf-8")
    matrix = matrix.replace(
        "  - {registry_action_ref: secure-platform-foundation-plan, coverage_status: evidence_gap, gap_owner: owner_required, activation: disabled}\n",
        "",
        1,
    )
    matrix_path = tmp_path / "matrix.yaml"
    matrix_path.write_text(matrix, encoding="utf-8")
    monkeypatch.setattr(registry_module, "MATRIX_PATH", matrix_path)
    with pytest.raises(RegistryValidationError, match="matrix placeholder coverage differs"):
        validate_registry(load_registry())


def test_action_matrix_enablement_claim_is_denied(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    matrix = registry_module.MATRIX_PATH.read_text(encoding="utf-8")
    matrix = matrix.replace("coverage_status: evidence_gap", "coverage_status: documented", 1)
    matrix_path = tmp_path / "matrix.yaml"
    matrix_path.write_text(matrix, encoding="utf-8")
    monkeypatch.setattr(registry_module, "MATRIX_PATH", matrix_path)
    with pytest.raises(RegistryValidationError, match="must remain disabled"):
        validate_registry(load_registry())


def test_registry_file_is_valid_json() -> None:
    assert isinstance(json.loads(REGISTRY_FILE.read_text(encoding="utf-8")), dict)
