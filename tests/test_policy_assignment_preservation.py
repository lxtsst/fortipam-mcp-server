"""Preserve every Secret row token except its one intended Policy association."""
import hashlib
import hmac
import json

import pytest

from fortipam_mcp import policy_assignment_preservation as module
from fortipam_mcp.secret_approval_build29_totp_boundary import SecretApprovalBuild29TotpWitness
from fortipam_mcp.secret_instruction_build29_api_preservation import consume_secret_instruction_build29_credential_response

KEY = b"synthetic-policy-preservation-key01"
MARKER = "SYNTHETIC_PRIVATE_VALUE_MUST_NOT_BE_DECODED"
IDENTITY = dict(id=41, name="synthetic-web-account", folder=17, template="Web Account", target="",
    uuid="942ac210-b8c8-4c32-b070-49ff5d1f86d3")
SERIAL = "FPAVUNIT000001"
SERIAL_DIGEST = hashlib.sha256(SERIAL.encode()).hexdigest()
ENVELOPE = {"secret-id": 41, "http_method": "POST", "http_status": 200,
    "status": "OK", "msg": "Synthetic qualified clear source"}


def credential(value=MARKER):
    raw = bytearray(json.dumps({**ENVELOPE, "results": value}).encode())
    try:
        return consume_secret_instruction_build29_credential_response(raw, expected_secret_id=41,
            expected_field_id=1, http_status=200, content_type="application/json",
            expected_envelope=ENVELOPE, witness_key=KEY)
    finally:
        assert not any(raw)


def totp(value=b""):
    return SecretApprovalBuild29TotpWitness(hmac.new(KEY, value, hashlib.sha256).hexdigest(), not value)


def source(policy="synthetic-policy-a", shared=None):
    field = [{"id": ident, "q_origin_key": ident, "name": name, "type": name.lower(), "desc": "", "value": value}
        for ident, name, value in ((1, "Password", "ENC MASKED"), (2, "Username", MARKER),
            (3, "URL", "https://example.test/"))]
    return dict(version="v7.0.0", build=29, http_method="GET", http_status=200, status="OK",
        path="secret", name="database", vdom="root", serial=SERIAL,
        results=[{**IDENTITY, "instruction-profile": "", "field": field, "policy": policy,
            "totp-setting": {"status": "disable", "shared-key": shared, "totp-duration": 30},
            "recording": "enable", "http-service-status": "down", "need-approval": "disable",
            "permissions": {"approval_status": "none", "user": 4},
            "future-config": {"policy": MARKER, "nested": [MARKER]}}])


def consume(value, expected="synthetic-policy-a", **changes):
    args = dict(identity=IDENTITY, serial_digest=SERIAL_DIGEST, expected_policy_name=expected,
        credential_before=credential(), credential_after=credential(), totp_before=totp(), totp_after=totp(), witness_key=KEY)
    args.update(changes)
    raw = bytearray(json.dumps(value, separators=(",", ":")).encode())
    try:
        return module.consume_policy_assignment_preservation(raw, **args)
    finally:
        assert not any(raw)


def test_only_the_exact_root_policy_and_independently_empty_totp_render_can_change(monkeypatch):
    original = module.metadata._scalar
    def scalar(content, span):
        assert MARKER.encode() not in content[slice(*span)]
        return original(content, span)
    monkeypatch.setattr(module.metadata, "_scalar", scalar)
    first = consume(source())
    changed = consume(source("synthetic-policy-b", "ENC VOLATILE"), "synthetic-policy-b")
    restored = consume(source(shared=""))
    assert first.preservation_digest == changed.preservation_digest == restored.preservation_digest
    public = first.summary()
    assert public["complete_response_row_tokens_bound"] is True
    for name in ("source_completeness_qualified", "source_provenance_qualified", "original_ownership_qualified", "assignment_authorized"):
        assert public[name] is False
    assert MARKER not in str(public) and first.preservation_digest not in str(public)
    assert "redacted" in repr(first)


@pytest.mark.parametrize("name,value", [("recording", "disable"), ("http-service-status", "up"),
    ("need-approval", "enable"), ("permissions", {"approval_status": "required", "user": 4}),
    ("future-config", {"policy": "changed-private-value"}), ("new-unknown-field", MARKER)])
def test_other_configuration_and_unknown_or_nested_policy_like_values_are_preserved(name, value):
    baseline = consume(source())
    changed = source("synthetic-policy-b")
    changed["results"][0][name] = value
    assert consume(changed, "synthetic-policy-b").preservation_digest != baseline.preservation_digest


@pytest.mark.parametrize("index", [0, 1, 2])
def test_every_credential_slot_render_stays_in_the_full_fingerprint(index):
    baseline = consume(source())
    changed = source()
    changed["results"][0]["field"][index]["value"] = "changed-slot-render"
    assert consume(changed).preservation_digest != baseline.preservation_digest


def test_masked_password_or_null_totp_are_not_independent_material_preservation():
    baseline = consume(source())
    other = credential("changed-private-password")
    with pytest.raises(module.PolicyAssignmentPreservationError): consume(source(), credential_after=other)
    assert consume(source(), credential_before=other, credential_after=other).preservation_digest != baseline.preservation_digest
    for changes in (dict(credential_before=None), dict(totp_before=None), dict(totp_after=totp(b"ABCD")),
            dict(totp_before=totp(b"ABCD"), totp_after=totp(b"ABCD")), dict(witness_key=b"other-synthetic-policy-key-000001")):
        with pytest.raises(module.PolicyAssignmentPreservationError): consume(source(), **changes)


@pytest.mark.parametrize("fault", ["missing-policy", "wrong-policy", "nested-only", "instruction-profile", "subject", "device"])
def test_the_effect_and_full_fixed_subject_remain_exact(fault):
    value = source()
    row = value["results"][0]
    if fault == "missing-policy": del row["policy"]
    elif fault == "wrong-policy": row["policy"] = "other-policy"
    elif fault == "nested-only": row["policy"] = {"policy": "synthetic-policy-a"}
    elif fault == "instruction-profile": row["instruction-profile"] = "other-instruction"
    elif fault == "subject": row["id"] += 1
    elif fault == "device": value["serial"] = "ANOTHERDEVICE"
    with pytest.raises(module.PolicyAssignmentPreservationError) as caught: consume(value)
    assert str(caught.value) == module._ERROR


@pytest.mark.parametrize("second", ["synthetic-policy-a", "another-policy"])
def test_an_ambiguous_root_policy_is_never_an_excludable_effect(second):
    raw = bytearray(json.dumps(source(), separators=(",", ":")).encode())
    raw = raw.replace(b'"policy":"synthetic-policy-a"',
        b'"policy":"synthetic-policy-a","polic\\u0079":"' + second.encode() + b'"')
    with pytest.raises(module.PolicyAssignmentPreservationError):
        module.consume_policy_assignment_preservation(raw, identity=IDENTITY, serial_digest=SERIAL_DIGEST,
            expected_policy_name="synthetic-policy-a", credential_before=credential(), credential_after=credential(),
            totp_before=totp(), totp_after=totp(), witness_key=KEY)
    assert not any(raw)


def test_interrupt_clears_raw_and_the_internal_field_workspace(monkeypatch):
    original = module._qualify_web_detail
    workspaces = []
    def interrupted(raw, **kwargs):
        original(raw, **kwargs)
        workspaces.append(kwargs["field"])
        raise KeyboardInterrupt
    monkeypatch.setattr(module, "_qualify_web_detail", interrupted)
    with pytest.raises(KeyboardInterrupt): consume(source())
    assert workspaces and all(not any(raw) for raw in workspaces)
