"""Complete Policy retention without assigning, decoding values or ownership."""
import hashlib
import json
from pathlib import Path

import pytest

from fortipam_mcp import policy_assignment_definition as module

FIXTURE = Path(__file__).parent / "fixtures/policy_assignment_definition.synthetic.json"
SERIAL_DIGEST = hashlib.sha256(b"FPAVUNIT000001").hexdigest()
NAME = "SYNTHETIC_POLICY"
MARKER = "SYNTHETIC_OPAQUE_REFERENCE_VALUE"


def response(change=None):
    value = json.loads(FIXTURE.read_bytes())
    if change:
        change(value)
    return bytearray(json.dumps(value, separators=(",", ":")).encode())


def consume(raw):
    try:
        return module.consume_policy_assignment_definition(raw, policy_name=NAME, serial_digest=SERIAL_DIGEST)
    finally:
        assert not any(raw)


def test_noncontrol_configuration_and_reference_changes_have_distinct_full_bindings():
    baseline = consume(response())
    changed = consume(response(lambda value: value["results"][0].update({"need-approval": "enable"})))
    referenced = consume(response(lambda value: value["results"][0].update(q_ref=1)))
    assert baseline.controls == changed.controls == referenced.controls == ("disable", "disable", "disable")
    assert baseline.configuration_digest != changed.configuration_digest
    assert baseline.configuration_digest == referenced.configuration_digest
    assert baseline.state_digest != referenced.state_digest
    public = baseline.summary()
    assert public["classified_policy_field_count"] == 54
    assert public["complete_classified_policy_definition_bound"] is True
    for name in ("ownership_qualified", "secret_inheritance_qualified", "assignment_authorized", "full_policy_semantics_reviewed"):
        assert public[name] is False
    assert NAME not in str(public) and baseline.configuration_digest not in str(public)
    assert "redacted" in repr(baseline)


def test_policy_reference_values_stay_opaque_and_only_compiled_enums_are_returned(monkeypatch):
    raw = response(lambda value: value["results"][0].update({"secret-auth-server": MARKER, "recording": "enable"}))
    original = module.metadata._scalar
    def scalar(content, span):
        assert MARKER.encode() not in content[slice(*span)], "Policy reference value must not be decoded."
        return original(content, span)
    monkeypatch.setattr(module.metadata, "_scalar", scalar)
    result = consume(raw)
    assert result.controls == ("enable", "disable", "disable")
    assert result.configured_relation_count == 1
    assert MARKER not in str(result.summary()) and MARKER not in repr(result)


@pytest.mark.parametrize("fault", ["missing", "unknown-material", "container", "integer-bool", "integer-overflow",
    "control", "metadata-bool", "metadata-path", "mkey", "name", "origin", "serial", "action", "collection", "duplicate"])
def test_ambiguous_or_unclassified_definitions_fail_before_value_decoding(fault, monkeypatch):
    def change(value):
        row = value["results"][0]
        if fault == "missing": del row["password-heartbeat"]
        elif fault == "unknown-material": row["password"] = MARKER
        elif fault == "container": row["secret-auth-server"] = {"password": MARKER}
        elif fault == "integer-bool": row["q_ref"] = True
        elif fault == "integer-overflow": row["checkout-duration"] = 2147483648
        elif fault == "control": row["recording"] = "unexpected"
        elif fault == "metadata-bool": row["q_static"] = 0
        elif fault == "metadata-path": row["q_path"] = "system"
        elif fault == "mkey": value["mkey"] = "another-policy"
        elif fault == "name": row["name"] = "another-policy"
        elif fault == "origin": row["q_origin_key"] = "another-policy"
        elif fault == "serial": value["serial"] = "ANOTHERDEVICE"
        elif fault == "action": value["action"] = "default"
        elif fault == "collection": value["results"].append(dict(row))
    raw = response(change)
    if fault == "duplicate":
        raw = raw.replace(b'"recording":"disable"', b'"recording":"disable","recording":"enable"')
    original = module.metadata._scalar
    def scalar(content, span):
        assert MARKER.encode() not in content[slice(*span)]
        return original(content, span)
    monkeypatch.setattr(module.metadata, "_scalar", scalar)
    with pytest.raises(module.PolicyAssignmentDefinitionError) as caught:
        consume(raw)
    assert str(caught.value) == module._ERROR


def test_interrupt_clears_the_owned_definition_without_partial_result(monkeypatch):
    def interrupted(*_args): raise KeyboardInterrupt
    monkeypatch.setattr(module, "_token_digest", interrupted)
    raw = response()
    with pytest.raises(KeyboardInterrupt): consume(raw)
