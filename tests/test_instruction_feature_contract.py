"""Fixed feature transitions preserve complete private configuration state."""
from __future__ import annotations
import copy
import hashlib
import json
import pickle
import pytest
from fortipam_mcp import instruction_feature_contract as r
from v4_planning.material_provider import MaterialAccessDenied

SERIAL = hashlib.sha256(b"synthetic-device").hexdigest()


def envelope(results: object, *, schema: bool = False, serial: str = "synthetic-device") -> bytearray:
    return bytearray(json.dumps({"version":"v7.0.0", "build":29, "path":"secret", "name":"setting",
        "serial":serial, "http_method":"GET", "http_status":200, "status":"success", "vdom":"root",
        "action":"schema" if schema else "", "results":results}).encode())


def reverse_schema(default: object = "") -> dict[str, object]:
    return {"type": "table", "children": {
        name: {"type": "string", "default": default}
        for name in ("auto-gateway-id-whitelist", "client-ca")}}


def state(enabled: bool = False, sibling: object = "synthetic-private-value", *,
          extra_schema: bool = False, projected: bool = False,
          schema_control: str = "original") -> r.InstructionFeatureState:
    children = {"guest-instruction":{"type":"option", "options":[{"name":"enable"},{"name":"disable"}]},
                "future-field":{"type":"string"}}
    children["reverse-service-setting"] = reverse_schema()
    values: dict[str, object] = {"guest-instruction":"enable" if enabled else "disable", "future-field":sibling}
    values["reverse-service-setting"] = []
    if extra_schema:
        children["new-field"] = {"type":"string"}
        values["new-field"] = "preserved"
    if projected:
        del values["future-field"]
    schema, current = envelope({"children":children,"future-schema-control":schema_control},schema=True), envelope(values)
    try:
        return r.read_instruction_feature_state(schema,current,serial_digest=SERIAL)
    finally:
        assert not any(schema) and not any(current)


def test_enable_readback_and_restore_bind_every_field() -> None:
    original, enabled = state(), state(True)
    enable = r.InstructionFeatureTransition(original, original, phase="enable", operation_nonce="a"*64)
    assert r.build_instruction_feature_body(enable,original) == b'{"guest-instruction":"enable"}'
    r.verify_instruction_feature_readback(enable,enabled)
    restore = r.InstructionFeatureTransition(original, enabled, phase="restore", operation_nonce="b"*64)
    assert r.build_instruction_feature_body(restore,enabled) == b'{"guest-instruction":"disable"}'
    r.verify_instruction_feature_readback(restore,original)
    # Neither dispatch nor recovery may silently accept an unknown sibling change.
    for drifted in (state(sibling="changed"),state(True,sibling="changed"),state(extra_schema=True)):
        with pytest.raises(r.InstructionFeatureContractError):
            r.build_instruction_feature_body(enable,drifted)
        with pytest.raises(r.InstructionFeatureContractError):
            r.verify_instruction_feature_readback(enable,drifted)
        with pytest.raises(r.InstructionFeatureContractError):
            r.InstructionFeatureTransition(original,drifted,phase="restore",operation_nonce="c"*64)


def test_schema_projection_and_device_mismatch_refuse_partial_state() -> None:
    with pytest.raises(r.InstructionFeatureContractError):
        state(projected=True)
    schema = envelope({"children":{"guest-instruction":{"type":"option","options":[]}}},schema=True)
    current = envelope({"guest-instruction":"disable"},serial="other-device")
    with pytest.raises(r.InstructionFeatureContractError):
        r.read_instruction_feature_state(schema,current,serial_digest=SERIAL)
    assert not any(schema) and not any(current)


def test_schema_root_change_refuses_existing_plan_and_restore() -> None:
    baseline = state()
    plan = r.InstructionFeatureTransition(baseline,baseline,phase="enable",operation_nonce="f"*64)
    changed = state(schema_control="changed")
    with pytest.raises(r.InstructionFeatureContractError):
        r.build_instruction_feature_body(plan,changed)
    with pytest.raises(r.InstructionFeatureContractError):
        r.InstructionFeatureTransition(baseline,state(True,schema_control="changed"),phase="restore",operation_nonce="a"*64)


def test_wrong_buffer_type_still_returns_categorical_failure() -> None:
    current = bytearray(b"{}")
    with pytest.raises(r.InstructionFeatureContractError, match="^The private Instruction feature contract is unavailable.$"):
        r.read_instruction_feature_state(b"{}",current,serial_digest=SERIAL)  # type: ignore[arg-type]
    assert not any(current)


def test_private_values_are_not_decoded_and_structural_order_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    original_loads = json.loads
    def keys_or_compiled_flag_only(raw: object, *args: object, **kwargs: object) -> object:
        assert b"synthetic-private-value" not in bytes(raw)  # type: ignore[arg-type]
        return original_loads(raw,*args,**kwargs)  # type: ignore[arg-type]
    monkeypatch.setattr(r.json,"loads",keys_or_compiled_flag_only)
    first = state(sibling={"a":"synthetic-private-value","b":[1,2]})
    second = state(sibling={"b":[1,2],"a":"synthetic-private-value"})
    assert first._state == second._state


@pytest.mark.parametrize("duplicate", [b'"future-field":"one","future-field":"two"',
    b'"future-field":{"a":1,"\\u0061":2}'])
def test_duplicates_in_preserved_fields_are_rejected_and_wiped(duplicate: bytes) -> None:
    schema = envelope({"children":{"guest-instruction":{"type":"option","options":[{"name":"enable"},{"name":"disable"}]},"future-field":{"type":"string"},"reverse-service-setting":reverse_schema()}},schema=True)
    current = envelope({"guest-instruction":"disable", "future-field":"placeholder", "reverse-service-setting":[]})
    current[:] = bytes(current).replace(b'"future-field": "placeholder"',duplicate)
    with pytest.raises(r.InstructionFeatureContractError):
        r.read_instruction_feature_state(schema,current,serial_digest=SERIAL)
    assert not any(schema) and not any(current)


def test_carriers_are_opaque_immutable_and_do_not_authorize_shared_changes() -> None:
    original = state()
    plan = r.InstructionFeatureTransition(original, original, phase="enable", operation_nonce="d"*64)
    for item in (original,plan):
        assert "synthetic-private-value" not in repr(item)
        for operation in (copy.copy,copy.deepcopy,pickle.dumps):
            with pytest.raises(MaterialAccessDenied):
                operation(item)
        with pytest.raises(r.InstructionFeatureContractError):
            setattr(item,"_state","e"*64)
    with pytest.raises(r.InstructionFeatureContractError):
        r.InstructionFeatureTransition(state(True),state(True),phase="enable",operation_nonce="e"*64)


def semantic_state(default: object = "", *, schema_change: str = "",
                   current_default: str = "original") -> r.InstructionFeatureState:
    reverse = reverse_schema(default)
    children = reverse["children"]
    assert isinstance(children, dict)
    selected = children["client-ca"]
    if schema_change == "missing":
        del selected["default"]
    elif schema_change == "missing-parent":
        del children["client-ca"]
    elif schema_change == "metadata-type":
        selected["type"] = "integer"
    elif schema_change == "other-default":
        children["other-field"] = {"type": "string", "default": "changed"}
    elif schema_change == "other-property":
        selected["max-length"] = 32
    schema = envelope({"children": {
        "guest-instruction": {"type": "option", "options": [{"name": "enable"}, {"name": "disable"}]},
        "reverse-service-setting": reverse}}, schema=True)
    current = envelope({"guest-instruction": "disable", "reverse-service-setting": {
        "children": {name: {"default": current_default} for name in children}}})
    if schema_change == "duplicate":
        schema[:] = bytes(schema).replace(b'"default": ""', b'"default": "", "default": "changed"', 1)
    elif schema_change == "invalid-utf8":
        schema[:] = bytes(schema).replace(b'"default": ""', b'"default": "\xff"', 1)
    try:
        return r.read_instruction_feature_state(schema, current, serial_digest=SERIAL)
    finally:
        assert not any(schema) and not any(current)


def test_v2_ignores_only_exact_valid_string_defaults_and_preserves_current() -> None:
    baseline = semantic_state()
    plan = r.InstructionFeatureTransition(baseline, baseline, phase="enable", operation_nonce="a"*64)
    changed = semantic_state("valid-but-unstable-default")
    assert baseline._schema == changed._schema and baseline._state == changed._state
    assert r.build_instruction_feature_body(plan, changed) == b'{"guest-instruction":"enable"}'
    for drift in (semantic_state(schema_change="other-default"),
                  semantic_state(schema_change="other-property"),
                  semantic_state(current_default="changed")):
        with pytest.raises(r.InstructionFeatureContractError):
            r.build_instruction_feature_body(plan, drift)
    assert semantic_state(current_default="changed")._preserved != baseline._preserved


@pytest.mark.parametrize("default,change", [(None, ""), (1, ""), (False, ""), ([], ""), ({}, ""),
    ("", "missing"), ("", "missing-parent"), ("", "metadata-type"),
    ("", "duplicate"), ("", "invalid-utf8")])
def test_v2_never_normalizes_missing_malformed_or_changed_type(default: object, change: str) -> None:
    with pytest.raises(r.InstructionFeatureContractError):
        semantic_state(default, schema_change=change)
