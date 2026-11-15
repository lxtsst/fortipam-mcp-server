"""Hidden reference-provider effects never become value or permission approval."""
from __future__ import annotations

import json

import pytest

from fortipam_mcp import terraform_plan_effects as module
from test_terraform_plan_configuration import configured_resource, plan as configuration_plan
from test_terraform_plan_projection import MARKER, PROVIDER, resource


def plan():
    value = configuration_plan()
    value["planned_values"] = {"root_module": {"resources": []}}
    return value


def parse(value):
    raw = bytearray(json.dumps(value).encode()) if type(value) is dict else bytearray(value)
    try:
        return module.project_private_terraform_provider_effects(raw)
    finally:
        assert not any(raw)


def test_name_only_secret_update_reports_controls_absent_from_terraform_diff(monkeypatch):
    value = plan()
    value["resource_changes"] = [resource(("update",), kind="fortipam_resource_secret")]
    value["resource_changes"][0]["change"].update(before={"name": MARKER}, after={"name": MARKER + "x"})
    value["configuration"]["root_module"]["resources"] = [configured_resource(kind="fortipam_resource_secret")]
    def forbidden(*args, **kwargs):
        raise AssertionError("Private values must not be decoded.")
    monkeypatch.setattr(json, "loads", forbidden)
    result = parse(value)
    public = result.summary()
    assert "secret_update_disables_av_dlp_ssh_and_rdp_filters" in public["conditional_provider_effects"]
    assert "secret_update_does_not_preserve_complete_configuration" in public["conditional_provider_effects"]
    assert "secret_write_and_post_write_credential_read" in public["permission_requirements_to_qualify"]
    assert MARKER not in json.dumps(public)
    assert "redacted" in repr(result)
    for key in ("reference_provider_matches_input_binary_verified", "actual_values_and_effects_reviewed",
            "actual_permission_evidence_verified", "permission_verified", "review_complete",
            "apply_authorized", "execution_ready", "source_provenance_verified"):
        assert public[key] is False


@pytest.mark.parametrize("actions,write", [(("no-op",), False), (("create",), True),
    (("update",), True), (("delete",), False), (("delete", "create"), True),
    (("create", "delete"), True), (("forget",), False), (("create", "forget"), True),
    (("forget", "create"), True)])
def test_folder_action_distinguishes_acl_rewrite_from_read_or_delete(actions, write):
    value = plan()
    value["resource_changes"] = [resource(actions)]
    public = parse(value).summary()
    assert ("folder_write_enables_inheritance_and_sends_empty_acl_arrays" in public["conditional_provider_effects"]) is write
    assert sum(public["change_kind_action_entry_counts"]["folder"].values()) == 1


def test_configured_data_and_retained_state_trigger_plan_time_material_warning_without_changes():
    value = plan()
    value["resource_changes"] = []
    root = value["configuration"]["root_module"]
    root["resources"] = [configured_resource(kind="fortipam_secret", mode="data")]
    state = dict(address=MARKER, name=MARKER, mode="managed", type="fortipam_resource_secret",
        provider_name=PROVIDER, schema_version=0, values={"fields": [{"value": MARKER}]}, sensitive_values={})
    value["prior_state"] = {"values": {"root_module": {"child_modules": [{"address": MARKER, "resources": [state]}]}}}
    public = parse(value).summary()
    assert public["configured_kind_entry_counts"]["secret_data"] == 1
    assert public["state_kind_entry_counts"]["managed_secret"] == 1
    assert "credential_values_can_enter_state_and_plan" in public["conditional_provider_effects"]
    assert "refresh_or_import_can_read_before_apply" in public["conditional_provider_effects"]
    assert "secret_update_disables_av_dlp_ssh_and_rdp_filters" not in public["conditional_provider_effects"]
    assert MARKER not in json.dumps(public)


@pytest.mark.parametrize("mutation", ["provider", "kind", "schema", "unknown-resource-field",
    "unknown-state-field", "duplicate-key", "malformed", "module-depth"])
def test_unclassified_retained_state_or_invalid_input_fails_without_partial_results(mutation):
    value = plan()
    state = dict(address=MARKER, name=MARKER, mode="managed", type="fortipam_resource_folder",
        provider_name=PROVIDER, schema_version=0, values={"name": MARKER})
    root = {"resources": [state]}
    value["prior_state"] = {"values": {"root_module": root}}
    if mutation == "provider": state["provider_name"] = MARKER
    elif mutation == "kind": state["type"] = MARKER
    elif mutation == "schema": state["schema_version"] = 1
    elif mutation == "unknown-resource-field": state[MARKER] = MARKER
    elif mutation == "unknown-state-field": root[MARKER] = MARKER
    elif mutation == "module-depth":
        for _ in range(9):
            root["child_modules"] = [{}]
            root = root["child_modules"][0]
    raw = json.dumps(value).encode()
    if mutation == "duplicate-key": raw = raw.replace(b'"values":', b'"values":{},"values":', 1)
    elif mutation == "malformed": raw = raw[:-1]
    with pytest.raises(module.TerraformProviderEffectError) as caught:
        parse(raw)
    assert str(caught.value) == "The private Terraform provider-effect projection is unavailable."
    assert MARKER not in str(caught.value)


def test_import_drift_and_provisioner_are_separate_unqualified_effects():
    value = plan()
    value["resource_changes"][0]["change"]["importing"] = {"id": MARKER}
    value["resource_drift"] = [resource(("update",), kind="fortipam_resource_secret")]
    value["configuration"]["root_module"]["resources"][0]["provisioners"] = [
        {"type": "local-exec", "expressions": {"command": {"constant_value": MARKER}}}]
    public = parse(value).summary()
    assert public["importing_entries"] == 1
    assert public["drift_kind_action_entry_counts"]["managed_secret"]["update"] == 1
    assert "import_reads_existing_object_without_creation_ownership" in public["conditional_provider_effects"]
    assert "provisioner_commands_or_file_transfers_excluded" in public["conditional_provider_effects"]
    assert public["review_complete"] is False
