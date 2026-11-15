"""Private Terraform projection never decodes or returns source values."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import pickle

import pytest
from v4_planning.material_provider import MaterialAccessDenied

from fortipam_mcp import terraform_plan_projection as module

MARKER = "SYNTHETIC_UNSELECTED_MATERIAL"
PROVIDER = "registry.terraform.io/fortinetdev/fortipam"


def resource(actions=("create",), *, kind="fortipam_resource_folder", mode="managed"):
    return dict(address=MARKER, name=MARKER, mode=mode, type=kind, provider_name=PROVIDER,
        change=dict(actions=list(actions), before={"secret": MARKER}, after={"fields": [{"value": MARKER}]},
            before_sensitive={}, after_sensitive={}))


def plan():
    return dict(format_version="1.2", terraform_version=MARKER, variables={MARKER: {"value": MARKER}},
        prior_state={"values": {"outputs": {MARKER: {"value": MARKER}}}}, planned_values={"root_module": {"value": MARKER}},
        configuration={"provider_config": {MARKER: {"full_name": PROVIDER, "name": "fortipam",
            "expressions": {"base_url": {"constant_value": MARKER}, "access_token": {"constant_value": MARKER},
                "verify_ssl": {"constant_value": True}}}}, "root_module": {"provisioners": {"command": MARKER}}},
        resource_changes=[resource()], applyable=True, complete=True, errored=False)


def parse(value):
    content = bytearray(json.dumps(value).encode()) if type(value) is dict else bytearray(value)
    try:
        return module.project_private_terraform_plan(content)
    finally:
        assert not any(content)


def test_complete_private_values_and_unmarked_credentials_never_reach_any_json_decoder(monkeypatch):
    value = plan()
    value["resource_changes"] += [resource(("update",), kind="fortipam_resource_secret"),
        resource(("read",), kind="fortipam_secret", mode="data")]
    value["resource_drift"] = [resource(("update",))]
    def forbidden(*args, **kwargs):
        raise AssertionError("No raw source scalar should be deserialized.")
    monkeypatch.setattr(json, "loads", forbidden)
    result = parse(value)
    public = result.summary()
    assert public["resource_change_entries"] == 3 and public["resource_drift_entries"] == 1
    assert public["material_resource_entries"] == 2 and public["folder_acl_preservation_unqualified_entries"] == 1
    assert public["tls_unproven_provider_entries"] == 0 and public["reported_applyable"] is True
    assert public["review_complete"] is public["apply_authorized"] is public["execution_ready"] is False
    assert public["configuration_and_provisioner_effects_reviewed"] is public["source_provenance_verified"] is False
    assert MARKER not in json.dumps(public) and PROVIDER not in json.dumps(public)
    assert MARKER not in repr(result) and "redacted" in repr(result)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied):
            operation(result)


@pytest.mark.parametrize("actions,category", [
    (("no-op",), "no_op"), (("create",), "create"), (("update",), "update"),
    (("delete",), "delete"), (("read",), "read"),
    (("delete", "create"), "replace_destroy_first"), (("create", "delete"), "replace_create_first"),
    (("forget",), "forget"), (("create", "forget"), "create_then_forget"),
    (("forget", "create"), "forget_then_create"),
])
def test_ordered_native_actions_keep_replacement_and_forget_distinct(actions, category):
    value = plan(); value["resource_changes"] = [resource(actions)]
    result = parse(value).summary()
    assert result["action_entry_counts"][category] == 1
    assert sum(result["action_entry_counts"].values()) == 1
    assert result["review_complete"] is False


@pytest.mark.parametrize("expression", [None, {"constant_value": False}, {"references": [MARKER]},
    {"constant_value": True, "references": [MARKER]}, {"constant_value": MARKER}])
def test_provider_default_false_dynamic_or_untrusted_tls_is_never_reported_as_enforced(expression):
    value = plan(); expressions = value["configuration"]["provider_config"][MARKER]["expressions"]
    if expression is None:
        expressions.pop("verify_ssl")
    else:
        expressions["verify_ssl"] = expression
    result = parse(value).summary()
    assert result["tls_unproven_provider_entries"] == 1
    assert result["provider_binary_verified"] is False


def test_absent_optional_flags_and_empty_change_list_do_not_authorize_apply():
    value = plan()
    for field in ("resource_changes", "applyable", "complete", "errored"):
        value.pop(field)
    public = parse(value).summary()
    assert public["resource_change_entries"] == 0 and public["reported_complete"] is None
    assert public["review_complete"] is public["apply_authorized"] is False
    value["deferred_changes"] = [{"unknown": MARKER}]
    assert parse(value).summary()["deferred_changes_present"] is True


@pytest.mark.parametrize("fault", ["state", "format", "unknown-root", "unknown-change", "foreign-provider",
    "unknown-type", "invalid-data-action", "invalid-action", "bad-flag", "no-provider", "trailing-json",
    "duplicate-root", "escaped-duplicate-root", "duplicate-action", "invalid-json", "invalid-utf8",
    "depth", "row-limit", "size"])
def test_unqualified_or_ambiguous_input_fails_closed_and_wipes_the_owned_buffer(fault):
    value = plan()
    if fault == "state": value = {"format_version": "1.2", "values": {"secret": MARKER}}
    elif fault == "format": value["format_version"] = "2.0"
    elif fault == "unknown-root": value[MARKER] = {"instruction": MARKER}
    elif fault == "unknown-change": value["resource_changes"][0]["change"][MARKER] = MARKER
    elif fault == "foreign-provider": value["resource_changes"][0]["provider_name"] = MARKER
    elif fault == "unknown-type": value["resource_changes"][0]["type"] = MARKER
    elif fault == "invalid-data-action": value["resource_changes"] = [resource(("delete",), kind="fortipam_secret", mode="data")]
    elif fault == "invalid-action": value["resource_changes"][0]["change"]["actions"] = ["update", "create"]
    elif fault == "bad-flag": value["complete"] = MARKER
    elif fault == "no-provider": value["configuration"]["provider_config"] = {}
    elif fault == "depth":
        nested = MARKER
        for _ in range(18): nested = [nested]
        value["variables"] = nested
    elif fault == "row-limit": value["resource_changes"] = [resource()] * 4097
    raw = json.dumps(value).encode()
    if fault == "trailing-json": raw += b"{}"
    elif fault == "duplicate-root": raw = raw.replace(b'"format_version": "1.2"', b'"format_version":"1.2","format_version":"1.2"')
    elif fault == "escaped-duplicate-root": raw = raw.replace(b'"format_version": "1.2"', b'"format_version":"1.2","\\u0066ormat_version":"1.2"')
    elif fault == "duplicate-action": raw = raw.replace(b'"actions": ["create"]', b'"actions":["create"],"actions":["create"]')
    elif fault == "invalid-json": raw = raw.replace(b'"actions": ["create"]', b'"actions":["create",]')
    elif fault == "invalid-utf8": raw = raw.replace(MARKER.encode(), b"\xff", 1)
    elif fault == "size": raw += b" " * module._MAX_BYTES
    with pytest.raises(module.TerraformPlanProjectionError) as caught:
        parse(raw)
    assert str(caught.value) == "The private Terraform plan projection is unavailable."
    assert MARKER not in str(caught.value)


@pytest.mark.parametrize("fault", ["none", "digest-drift", "symlink", "hardlink", "file-mode", "directory-mode", "malformed"])
def test_private_prebound_file_keeps_material_outside_results_and_consumes_failure(tmp_path, monkeypatch, fault):
    tmp_path.chmod(0o700); path = tmp_path / "private-plan.json"
    content = json.dumps(plan()).encode(); digest = hashlib.sha256(content).hexdigest()
    path.write_bytes(content); path.chmod(0o600)
    if fault == "digest-drift": path.write_bytes(content + b" ")
    elif fault == "symlink":
        alternate = tmp_path / "original.json"; path.rename(alternate); path.symlink_to(alternate)
    elif fault == "hardlink": os.link(path, tmp_path / "extra-link")
    elif fault == "file-mode": path.chmod(0o644)
    elif fault == "directory-mode": tmp_path.chmod(0o755)
    elif fault == "malformed": path.write_bytes(b"{"); digest = hashlib.sha256(b"{").hexdigest()
    captured = []; original = module._read_owned
    def read_owned(selected):
        raw, identity = original(selected); captured.append(raw); return raw, identity
    monkeypatch.setattr(module, "_read_owned", read_owned)
    reader = module.PinnedTerraformPlanArtifact(path=path, expected_sha256=digest)
    if fault == "none":
        result = reader.read_once().summary()
        assert result["resource_change_entries"] == 1 and result["source_provenance_verified"] is False
        assert MARKER not in json.dumps(result) and digest not in json.dumps(result)
    else:
        with pytest.raises(module.TerraformPlanProjectionError) as caught:
            reader.read_once()
        assert str(path) not in str(caught.value) and MARKER not in str(caught.value)
    with pytest.raises(module.TerraformPlanProjectionError): reader.read_once()
    assert path.exists() and "redacted" in repr(reader) and all(not any(raw) for raw in captured)
