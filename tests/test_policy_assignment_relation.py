"""Effective relation joins never turn metadata into ownership or activity proof."""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from fortipam_mcp import policy_assignment_relation as module

SERIAL = "FPAVUNIT000001"
MARKER = "SYNTHETIC_PRIVATE_VALUE_MUST_NOT_BE_DECODED"
BINDING = module.PolicyAssignmentRelationBinding(41, "synthetic-web-account", 17,
    "942ac210-b8c8-4c32-b070-49ff5d1f86d3", "SYNTHETIC_POLICY", hashlib.sha256(SERIAL.encode()).hexdigest())


def frame(table, row):
    return dict(version="v7.0.0", build=29, path="secret", name=table, http_method="GET",
        status="OK", http_status=200, serial=SERIAL, vdom="root", results=[row])


def responses(inherited=True):
    secret = frame("database", {"id": BINDING.secret_id, "name": BINDING.secret_name,
        "folder": BINDING.folder_id, "template": "Web Account", "target": "", "uuid": BINDING.secret_uuid,
        "policy": BINDING.policy_name, "recording": "enable", "http-service-status": "down",
        "need-approval": "disable", "need-approval-job": "disable", "field": [{"value": MARKER}]})
    folder = frame("folder", {"id": BINDING.folder_id, "name": "synthetic-folder", "parent-folder": 1,
        "folder-type": "public", "inherit-policy": "enable" if inherited else "disable",
        "inherit-permission": "disable", "inherit-folder-ztna": "enable", "secret-policy": BINDING.policy_name,
        "ztna-ems-tag": [], "ztna-tags-match-logic": "all",
        "user-permission": [{"user-name": MARKER, "permission": "owner"}], "group-permission": []})
    policy = json.loads((Path(__file__).parent / "fixtures/policy_assignment_definition.synthetic.json").read_bytes())
    return dict(secret_before=secret, folder_before=folder, policy_before=policy,
        policy_after=copy.deepcopy(policy), folder_after=copy.deepcopy(folder), secret_after=copy.deepcopy(secret))


def consume(values):
    raw = {name: bytearray(json.dumps(value, separators=(",", ":")).encode()) for name, value in values.items()}
    try:
        return module.consume_policy_assignment_relation(binding=BINDING, **raw)
    finally:
        assert all(not any(content) for content in raw.values())


@pytest.mark.parametrize("inherited", [False, True])
def test_complete_bracketed_relation_binds_policy_and_acl_without_expanding_claims(inherited, monkeypatch):
    original = module.metadata._scalar
    def scalar(content, span):
        assert MARKER.encode() not in content[slice(*span)]
        return original(content, span)
    monkeypatch.setattr(module.metadata, "_scalar", scalar)
    result = consume(responses(inherited))
    public = result.summary()
    assert result.inherited is inherited
    assert public["native_secret_folder_policy_match"] is True
    assert public["complete_policy_configuration_fields"] == 54
    for key in ("complete_secret_preservation_qualified", "activity_absence_qualified", "source_provenance_qualified",
                "access_or_launch_effect_qualified", "ownership_qualified", "assignment_authorized"):
        assert public[key] is False
    assert all(value not in str(public) for value in (BINDING.secret_name, BINDING.policy_name, MARKER, result.relation_digest))
    assert "redacted" in repr(result) and "redacted" in repr(BINDING)


@pytest.mark.parametrize("fault", ["secret-reference", "folder-reference", "folder-identity", "secret-identity",
    "template", "target", "uuid", "secret-drift", "folder-acl-drift", "inheritance-drift", "policy-drift",
    "policy-reference-drift", "missing", "device", "collection", "limit"])
def test_relation_mismatch_or_any_bracket_drift_denies_and_wipes_every_input(fault):
    values = responses()
    secret = values["secret_after"]["results"][0]
    folder = values["folder_after"]["results"][0]
    policy = values["policy_after"]["results"][0]
    if fault == "secret-reference": secret["policy"] = "other-policy"
    elif fault == "folder-reference": folder["secret-policy"] = "other-policy"
    elif fault == "folder-identity": folder["id"] = True
    elif fault == "secret-identity": secret["folder"] += 1
    elif fault == "template": secret["template"] = "Unix Account"
    elif fault == "target": secret["target"] = "other-target"
    elif fault == "uuid": secret["uuid"] = "b19e5c91-ff22-43c4-9bac-6c5985897599"
    elif fault == "secret-drift": secret["need-approval"] = "enable"
    elif fault == "folder-acl-drift": folder["group-permission"] = [{"group-name": MARKER, "permission": "owner"}]
    elif fault == "inheritance-drift": folder["inherit-policy"] = "disable"
    elif fault == "policy-drift": policy["need-approval"] = "enable"
    elif fault == "policy-reference-drift": policy["q_ref"] += 1
    elif fault == "missing": del secret["need-approval-job"]
    elif fault == "device": values["folder_after"]["serial"] = "ANOTHERDEVICE"
    elif fault == "collection": values["secret_after"]["results"].append(dict(secret))
    elif fault == "limit": values["secret_after"]["limit_reached"] = True
    with pytest.raises(module.PolicyAssignmentRelationError) as caught:
        consume(values)
    assert str(caught.value) == module._ERROR


def test_unselected_material_change_is_explicitly_outside_this_metadata_contract():
    values = responses()
    baseline = consume(values)
    values["secret_after"]["results"][0]["field"][0]["value"] = "DIFFERENT_PRIVATE_VALUE"
    changed = consume(values)
    assert baseline.relation_digest == changed.relation_digest
    assert changed.summary()["complete_secret_preservation_qualified"] is False


def test_projected_details_do_not_accept_the_complete_policy_success_envelope():
    for key, status in (("secret_before", "success"), ("folder_after", "success")):
        values = responses()
        values[key]["status"] = status
        with pytest.raises(module.PolicyAssignmentRelationError): consume(values)


def test_duplicate_selected_reference_and_aliased_buffers_are_not_accepted():
    values = responses()
    for fault in ("duplicate", "alias"):
        raw = {name: bytearray(json.dumps(value, separators=(",", ":")).encode()) for name, value in values.items()}
        discarded = None
        if fault == "duplicate":
            raw["secret_after"] = raw["secret_after"].replace(b'"policy":"SYNTHETIC_POLICY"',
                b'"policy":"SYNTHETIC_POLICY","polic\\u0079":"SYNTHETIC_POLICY"')
        else:
            discarded = raw["folder_after"]
            raw["folder_after"] = raw["folder_before"]
        with pytest.raises(module.PolicyAssignmentRelationError):
            module.consume_policy_assignment_relation(binding=BINDING, **raw)
        assert all(not any(content) for content in raw.values())
        if discarded is not None:
            discarded[:] = b"\0" * len(discarded)


def test_interrupt_clears_responses_that_have_not_yet_been_read(monkeypatch):
    def interrupted(*_args): raise KeyboardInterrupt
    monkeypatch.setattr(module, "_secret", interrupted)
    with pytest.raises(KeyboardInterrupt): consume(responses())
