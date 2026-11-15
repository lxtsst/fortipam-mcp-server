"""Recursive supported configuration risks; no expression/command decoding."""
from __future__ import annotations

import json

import pytest

from fortipam_mcp import terraform_plan_configuration as module
from test_terraform_plan_projection import MARKER, plan as base_plan, resource as changed_resource


def configured_resource(name=MARKER, *, kind="fortipam_resource_folder", mode="managed", provider=MARKER):
    return dict(address=name, name=name, type=kind, mode=mode, provider_config_key=provider,
        schema_version=0, expressions={})


def plan():
    value = base_plan()
    value["configuration"]["root_module"] = {"resources": [configured_resource()]}
    return value


def parse(value):
    raw = bytearray(json.dumps(value).encode()) if type(value) is dict else bytearray(value)
    try: return module.project_private_terraform_configuration(raw)
    finally: assert not any(raw)


def test_nested_provisioners_and_material_resources_cannot_hide_outside_change_list(monkeypatch):
    value = plan(); root = value["configuration"]["root_module"]
    child = configured_resource("child", kind="fortipam_resource_secret")
    child["expressions"] = {"fields": [{"name": {"constant_value": MARKER}, "value": {"constant_value": MARKER}}]}
    child["provisioners"] = [{"type": kind, "expressions": {"command": {"constant_value": MARKER}}}
        for kind in ("local-exec", "remote-exec", "file")]
    data = configured_resource("data", kind="fortipam_secret", mode="data")
    data["expressions"] = {"field": {"constant_value": MARKER}}
    root["module_calls"] = {MARKER: {"source": MARKER, "module": {"resources": [child],
        "module_calls": {MARKER: {"source": MARKER, "module": {"resources": [data]}}}}}}
    root["outputs"] = {MARKER: {"sensitive": False, "expression": {"constant_value": MARKER}}}
    root["variables"] = {MARKER: {"default": MARKER, "description": MARKER, "sensitive": False}}
    def no_decoder(*args, **kwargs): raise AssertionError("No source scalar may be decoded.")
    monkeypatch.setattr(json, "loads", no_decoder)
    public = parse(value).summary()
    assert public["configuration_module_entries"] == 3 and public["configuration_resource_entries"] == 3
    assert public["configuration_material_resource_entries"] == 2 and public["material_resource_entries"] == 0
    assert public["provisioner_entry_counts"] == {"local_exec": 1, "remote_exec": 1, "file": 1}
    assert public["configuration_output_entries"] == 1 and public["configuration_provider_references_matched"] is True
    assert public["provisioner_effects_require_review"] is True
    assert "credential_plan_or_state_exposure_possible" in public["findings"]
    assert "output_values_excluded_from_review" in public["findings"]
    assert MARKER not in json.dumps(public) and "redacted" in repr(parse(value))
    assert public["configuration_and_provisioner_effects_reviewed"] is public["apply_authorized"] is public["review_complete"] is False


def test_risk_findings_combine_changes_and_configuration_without_authorizing_effects():
    value = plan()
    value["resource_changes"] = [changed_resource(("delete", "create"))]
    value["complete"] = False; value["errored"] = True; value["deferred_changes"] = [{"private": MARKER}]
    value["configuration"]["provider_config"][MARKER]["expressions"].pop("verify_ssl")
    findings = parse(value).summary()["findings"]
    assert set(findings) == {"provider_effects_and_permissions_unverified", "folder_acl_preservation_unqualified",
        "destructive_or_state_forget_effect", "plan_completion_unproven", "producer_reported_errored",
        "deferred_changes_present", "tls_verification_unproven"}


@pytest.mark.parametrize("alias", ["alias", "é", "测试", "alias😀", "quote\"slash\\", "control\n"])
def test_opaque_alias_reference_matches_equivalent_escaped_utf8_without_decoding(alias, monkeypatch):
    value = plan(); provider = value["configuration"]["provider_config"].pop(MARKER)
    value["configuration"]["provider_config"][alias] = provider
    value["configuration"]["root_module"]["resources"][0]["provider_config_key"] = alias
    raw = json.dumps(value, ensure_ascii=False).encode()
    reference = b'"provider_config_key": ' + json.dumps(alias, ensure_ascii=False).encode()
    escaped = b'"provider_config_key": ' + json.dumps(alias, ensure_ascii=True).encode()
    raw = raw.replace(reference, escaped)
    def no_decoder(*args, **kwargs): raise AssertionError
    monkeypatch.setattr(json, "loads", no_decoder)
    assert parse(raw).summary()["configuration_provider_references_matched"] is True


@pytest.mark.parametrize("fault,stage", [
    ("module-field", "module_structure"), ("missing-child", "module_structure"),
    ("call-field", "module_structure"), ("action-declaration", "module_structure"),
    ("unknown-resource", "resource_structure"), ("resource-field", "resource_structure"),
    ("schema-version", "resource_structure"), ("expression-field", "resource_structure"),
    ("duplicate-resource", "resource_structure"), ("unmatched-provider", "provider_binding"),
    ("unknown-provisioner", "provisioner_structure"), ("provisioner-field", "provisioner_structure"),
    ("data-provisioner", "provisioner_structure"), ("too-many-provisioners", "provisioner_structure"),
    ("escaped-duplicate-alias", "provider_keys"), ("unpaired-surrogate", "provider_keys"),
    ("module-source-type", "module_structure"), ("module-reference-type", "module_structure"),
    ("output-sensitive-type", "module_structure"), ("variable-sensitive-type", "module_structure"),
    ("count-reference-type", "resource_structure"), ("dependency-type", "resource_structure"),
    ("expression-type", "resource_structure"), ("provisioner-expression-type", "provisioner_structure"),
])
def test_unsupported_or_ambiguous_configuration_fails_closed_with_fixed_stage(fault, stage):
    value = plan(); root = value["configuration"]["root_module"]; item = root["resources"][0]
    if fault == "module-field": root["instruction"] = MARKER
    elif fault == "missing-child": root["module_calls"] = {MARKER: {"source": MARKER}}
    elif fault == "call-field": root["module_calls"] = {MARKER: {"module": {}, "instruction": MARKER}}
    elif fault == "action-declaration": root["actions"] = [{"type": MARKER}]
    elif fault == "unknown-resource": item["type"] = MARKER
    elif fault == "resource-field": item["instruction"] = MARKER
    elif fault == "schema-version": item["schema_version"] = 1
    elif fault == "expression-field": item["expressions"] = {"instruction": MARKER}
    elif fault == "duplicate-resource": root["resources"].append(dict(item))
    elif fault == "unmatched-provider": item["provider_config_key"] = "unbound"
    elif fault == "data-provisioner":
        item["type"] = "fortipam_secret"; item["mode"] = "data"; item["provisioners"] = []
    elif fault in ("unknown-provisioner", "provisioner-field", "too-many-provisioners"):
        item["provisioners"] = [{"type": "local-exec", "expressions": {}}]
        if fault == "unknown-provisioner": item["provisioners"][0]["type"] = MARKER
        elif fault == "provisioner-field": item["provisioners"][0]["instruction"] = MARKER
        else: item["provisioners"] *= 65
    elif fault == "unpaired-surrogate":
        provider = value["configuration"]["provider_config"].pop(MARKER)
        value["configuration"]["provider_config"]["\ud800"] = provider
    elif fault == "module-source-type": root["module_calls"] = {MARKER: {"source": {"private": MARKER}, "module": {}}}
    elif fault == "module-reference-type":
        root["module_calls"] = {MARKER: {"expressions": {MARKER: {"references": MARKER}}, "module": {}}}
    elif fault == "output-sensitive-type":
        root["outputs"] = {MARKER: {"expression": {}, "sensitive": MARKER}}
    elif fault == "variable-sensitive-type": root["variables"] = {MARKER: {"sensitive": MARKER}}
    elif fault == "count-reference-type": item["count_expression"] = {"references": [False]}
    elif fault == "dependency-type": item["depends_on"] = MARKER
    elif fault == "expression-type": item["expressions"] = {"name": MARKER}
    elif fault == "provisioner-expression-type": item["provisioners"] = [{"type": "local-exec", "expressions": {"command": MARKER}}]
    raw = json.dumps(value).encode()
    if fault == "escaped-duplicate-alias":
        provider = json.dumps(value["configuration"]["provider_config"][MARKER]).encode()
        wire = b'"' + MARKER.encode() + b'": ' + provider
        raw = raw.replace(wire, wire + b',"\\u0053' + MARKER[1:].encode() + b'": ' + provider, 1)
    with pytest.raises(module.TerraformConfigurationProjectionError) as caught: parse(raw)
    assert caught.value.stage.value == stage and MARKER not in str(caught.value)
    assert str(caught.value) == "The private Terraform configuration projection is unavailable."


def test_empty_configuration_is_structurally_checked_but_not_a_complete_review():
    value = plan(); value["configuration"]["root_module"] = {}
    result = parse(value).summary()
    assert result["configuration_module_entries"] == 1 and result["configuration_resource_entries"] == 0
    assert result["configuration_tree_structure_checked"] is True
    assert result["review_complete"] is result["source_provenance_verified"] is False


def test_new_signed_entry_joins_structural_findings_without_broad_source_or_apply_authority(tmp_path, monkeypatch):
    from test_terraform_plan_receipt import setup, capture_reads
    value = plan(); value["configuration"]["root_module"]["resources"][0]["provisioners"] = [
        {"type": "local-exec", "expressions": {"command": {"constant_value": MARKER}}}]
    reader, clock, artifact, receipt, public = setup(tmp_path,
        reader_class=module.PinnedSignedTerraformConfigurationArtifact, artifact_value=value)
    buffers, paths = capture_reads(monkeypatch)
    def no_decoder(*args, **kwargs): raise AssertionError
    monkeypatch.setattr(json, "loads", no_decoder)
    summary = reader.read_once().summary()
    assert summary["producer_receipt_signature_verified"] is summary["configuration_tree_structure_checked"] is True
    assert summary["provisioner_entry_counts"]["local_exec"] == 1 and summary["contract"] == module.CONTRACT
    assert summary["apply_authorized"] is summary["review_complete"] is summary["source_provenance_verified"] is False
    assert MARKER not in json.dumps(summary) and all(not any(raw) for raw in buffers)
    reader.close(); assert reader._closed


def test_authenticated_bad_configuration_keeps_a_fixed_failure_stage_and_clears_both_buffers(tmp_path, monkeypatch):
    from test_terraform_plan_receipt import setup, capture_reads
    value = plan(); value["configuration"]["root_module"]["unqualified"] = MARKER
    reader, clock, artifact, receipt, public = setup(tmp_path,
        reader_class=module.PinnedSignedTerraformConfigurationArtifact, artifact_value=value)
    buffers, paths = capture_reads(monkeypatch)
    with pytest.raises(module.TerraformPlanReceiptError): reader.read_once()
    assert reader._configuration_failure_stage is module.ConfigurationStage.MODULE
    assert paths == [receipt, artifact] and all(not any(raw) for raw in buffers)
    with pytest.raises(module.TerraformPlanReceiptError): reader.read_once()
    assert reader._configuration_failure_stage is module.ConfigurationStage.MODULE


@pytest.mark.parametrize("limit,stage", [("modules", "module_structure"), ("resources", "resource_structure"),
    ("outputs", "module_structure")])
def test_global_tree_budgets_cannot_be_evaded_by_splitting_nodes_across_modules(limit, stage):
    value = plan(); root = value["configuration"]["root_module"]
    if limit == "modules": root["module_calls"] = {str(i): {"module": {}} for i in range(128)}
    elif limit == "resources":
        root["resources"] = [configured_resource(str(i)) for i in range(4096)]
        root["module_calls"] = {"child": {"module": {"resources": [configured_resource("child")]}}}
    else:
        outputs = {str(i): {"expression": {"constant_value": MARKER}} for i in range(128)}
        root["outputs"] = {"root": {"expression": {"constant_value": MARKER}}}
        root["module_calls"] = {str(i): {"module": {"outputs": outputs}} for i in range(32)}
    with pytest.raises(module.TerraformConfigurationProjectionError) as caught: parse(value)
    assert caught.value.stage.value == stage


def test_structural_failure_also_clears_the_owned_base_projection_copy(monkeypatch):
    value = plan(); value["configuration"]["root_module"]["unsupported"] = MARKER
    captured = []; original = module.project_private_terraform_plan
    def observe(raw): captured.append(raw); return original(raw)
    monkeypatch.setattr(module, "project_private_terraform_plan", observe)
    with pytest.raises(module.TerraformConfigurationProjectionError): parse(value)
    assert len(captured) == 1 and not any(captured[0])
