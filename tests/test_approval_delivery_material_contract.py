"""Synthetic full-slot codec only; no device, mailbox or real material."""
from array import array
from contextlib import ExitStack, contextmanager
import copy
from dataclasses import replace
import json
import pickle

import pytest

from fortipam_mcp import approval_delivery_contract as source
from fortipam_mcp import approval_delivery_material_contract as contract
from test_approval_delivery_contract import state
from test_mutable_json_buffer import _allocations
from v4_planning.material_provider import MaterialAccessDenied

ROLES = ("username", "credential", "client-secret")
BINDINGS = dict(zip(ROLES, ("1" * 64, "2" * 64, "3" * 64)))
SYNTHETIC = {"username": b"SYNTHETIC_PRIVATE_LOGIN_VALUE", "credential": b"SYNTHETIC_PASSWORD",
             "client-secret": b"SYNTHETIC_CLIENT_SECRET"}


def draft(protocol="imaps", enabled=True, values=None, bindings=None):
    return contract.prepare_material_approval_delivery(state(protocol) if values is None else values,
        enabled=enabled, material_binding_digests=BINDINGS if bindings is None else bindings)


@contextmanager
def material(overrides=None):
    raw = {key: bytearray(value) for key, value in (SYNTHETIC | (overrides or {})).items()}
    try:
        with ExitStack() as stack:
            views = {key: stack.enter_context(memoryview(value).toreadonly()) for key, value in raw.items()}
            yield raw, views
    finally:
        for value in raw.values():
            value[:] = b"\0" * len(value)


def encode(prepared, views, bindings=None):
    return contract.build_approval_delivery_material_body(prepared,
        username=views["username"], credential=views["credential"], client_secret=views["client-secret"],
        material_binding_digests=BINDINGS if bindings is None else bindings)


@pytest.mark.parametrize("protocol", ["imaps", "ms-graph"])
@pytest.mark.parametrize("enabled", [True, False])
def test_full_sdk_shape_forwards_all_three_material_slots_and_preserves_inactive_fields(protocol, enabled):
    values = state(protocol)
    prepared = draft(protocol, enabled, values)
    with material() as (raw, views):
        output = encode(prepared, views)
        try:
            result = json.loads(output)
            assert tuple(result) == ("approval-email-setting",)
            payload = result["approval-email-setting"]
            assert tuple(payload) == source._FIELDS and "enabled" not in payload
            assert all(payload[key] == value.decode() for key, value in SYNTHETIC.items())
            assert all(payload[key] == ("" if not enabled and key in ("server", "email-pulling-server") else value)
                       for key, value in values.items())
            assert all(raw[key] == value for key, value in SYNTHETIC.items())
        finally:
            output[:] = b"\0" * len(output)


@pytest.mark.parametrize("protocol", ["imaps", "ms-graph"])
def test_inactive_material_may_be_explicitly_empty_and_active_material_is_required(protocol):
    active = "credential" if protocol == "imaps" else "client-secret"
    inactive = "client-secret" if protocol == "imaps" else "credential"
    prepared = draft(protocol)
    with material({inactive: b""}) as (_, views):
        output = encode(prepared, views)
        try:
            assert json.loads(output)["approval-email-setting"][inactive] == ""
        finally:
            output[:] = b"\0" * len(output)
    for role in ("username", active):
        with material({role: b""}) as (_, views), pytest.raises(ValueError):
            encode(prepared, views)


def test_disabled_request_still_requires_explicit_views_but_accepts_empty_material_slots():
    prepared = draft(enabled=False)
    with material(dict.fromkeys(ROLES, b"")) as (_, views):
        output = encode(prepared, views)
        try:
            payload = json.loads(output)["approval-email-setting"]
            assert all(payload[key] == "" for key in ROLES)
        finally:
            output[:] = b"\0" * len(output)
    with material() as (_, views), pytest.raises(TypeError):
        contract.build_approval_delivery_material_body(prepared, username=views["username"],
            credential=views["credential"], material_binding_digests=BINDINGS)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("bad", ["text", "bytes", None, "mutable", "immutable", "strided", "wide", "invalid-utf8", "oversize", "released"])
def test_only_explicit_bounded_readonly_mutable_backed_utf8_views_are_accepted(role, bad):
    with material() as (_, views), ExitStack() as stack:
        value = {"text": "SYNTHETIC", "bytes": b"SYNTHETIC", None: None}.get(bad)
        if bad == "mutable": value = stack.enter_context(memoryview(bytearray(b"SYNTHETIC")))
        if bad == "immutable": value = stack.enter_context(memoryview(b"SYNTHETIC"))
        if bad == "strided": value = stack.enter_context(memoryview(bytearray(b"SYNTHETIC"))[::2].toreadonly())
        if bad == "wide": value = stack.enter_context(memoryview(array("H", [65])).toreadonly())
        if bad == "invalid-utf8": value = stack.enter_context(memoryview(bytearray(b"\xff")).toreadonly())
        if bad == "oversize": value = stack.enter_context(memoryview(bytearray(b"A" * 4097)).toreadonly())
        if bad == "released":
            value = memoryview(bytearray(b"SYNTHETIC")).toreadonly()
            value.release()
        views[role] = value
        with pytest.raises(ValueError) as error:
            encode(draft(), views)
        assert str(error.value) == contract._ERROR and "SYNTHETIC" not in str(error.value)


@pytest.mark.parametrize("role", ROLES)
def test_generic_json_escaping_retains_valid_unicode_and_control_bytes_without_a_material_hash(role, monkeypatch):
    value = bytes(range(128)) + "合成材料".encode()
    prepared = draft()
    with material({role: value}) as (raw, views):
        def forbidden(*args, **kwargs):
            raise AssertionError("The codec must not hash material or decode a JSON response.")
        with monkeypatch.context() as patch:
            patch.setattr(contract.hashlib, "sha256", forbidden)
            patch.setattr(json, "loads", forbidden)
            output = encode(prepared, views)
        try:
            assert json.loads(output)["approval-email-setting"][role].encode() == value
            assert raw[role] == value
        finally:
            output[:] = b"\0" * len(output)


@pytest.mark.parametrize("role", ROLES)
def test_local_allocation_bound_is_inclusive_without_claiming_native_material_size_semantics(role):
    with material({role: b"A" * 4096}) as (_, views):
        output = encode(draft(), views)
        try:
            assert len(json.loads(output)["approval-email-setting"][role]) == 4096
        finally:
            output[:] = b"\0" * len(output)


@pytest.mark.parametrize("key", ["REQUEST_SOURCE_SHA256", "SCHEMA_METADATA_SHA256", "NORMALIZER_SOURCE_SHA256"])
def test_source_pin_drift_rejects_prepared_input_before_material_encoding(key, monkeypatch):
    prepared = draft()
    monkeypatch.setattr(source, key, "0" * 64)
    monkeypatch.setattr(contract, "_append_material", lambda *args: pytest.fail("Material touched after source drift"))
    with material() as (_, views), pytest.raises(ValueError):
        encode(prepared, views)


@pytest.mark.parametrize("change", ["missing", "extra", "swapped", "malformed"])
def test_exact_role_bindings_are_required_at_preparation_and_compilation(change):
    supplied = dict(BINDINGS)
    if change == "missing": del supplied["client-secret"]
    if change == "extra": supplied["password"] = "4" * 64
    if change == "swapped": supplied["credential"], supplied["client-secret"] = supplied["client-secret"], supplied["credential"]
    if change == "malformed": supplied["username"] = "SYNTHETIC_LOCATOR"
    if change != "swapped":
        with pytest.raises(ValueError): draft(bindings=supplied)
    with material() as (_, views), pytest.raises(ValueError):
        encode(draft(), views, supplied)


@pytest.mark.parametrize("protocol,field", [("imaps", "server"), ("imaps", "email-pulling-server"),
    ("ms-graph", "server"), ("ms-graph", "tenant-id"), ("ms-graph", "app-id")])
def test_known_active_nonmaterial_requirements_are_checked_without_claiming_full_frontend_validation(protocol, field):
    values = state(protocol); values[field] = ""
    with pytest.raises(ValueError): draft(protocol, values=values)
    draft(protocol, enabled=False, values=values)


@pytest.mark.parametrize("bad", [0, 1, None, "true"])
def test_enabled_intent_requires_an_explicit_boolean(bad):
    with pytest.raises(ValueError): draft(enabled=bad)


@pytest.mark.parametrize("changes", [{"enabled": False}, {"protocol": "ms-graph"}, {}])
def test_factory_drafts_cannot_be_relabelled_or_cloned_by_dataclasses_replace(changes):
    with pytest.raises((ValueError, TypeError, MaterialAccessDenied)):
        replace(draft(), **changes)


@pytest.mark.parametrize("with_attributes", [True, False])
def test_direct_construction_cannot_create_an_unvalidated_draft(with_attributes):
    original = draft()
    attributes = {name: getattr(original, name) for name in original.__dataclass_fields__} if with_attributes else {}
    with pytest.raises((ValueError, TypeError)):
        contract.ApprovalDeliveryMaterialDraft(**attributes)


@pytest.mark.parametrize("marker", ["%0%", "%1%"])
def test_disabled_server_and_certificate_input_changes_remain_bound_even_when_request_matches(marker):
    values = state(); values["server-cert"] = marker
    first = draft(enabled=False, values=values)
    values["server-cert"] = ""; values["server"] = "other.example.test"
    second = draft(enabled=False, values=values)
    assert first.input_nonmaterial_digest != second.input_nonmaterial_digest
    assert first.request_nonmaterial_digest == second.request_nonmaterial_digest
    changed = draft(enabled=False, values=values, bindings=BINDINGS | {"credential": "9" * 64})
    assert changed.request_nonmaterial_digest != second.request_nonmaterial_digest


@pytest.mark.parametrize("failure", [ValueError, KeyboardInterrupt, SystemExit])
def test_partial_encoding_erases_owned_allocations_and_leaves_original_lease_buffers_owned_by_caller(monkeypatch, failure):
    allocations = _allocations(monkeypatch)
    original = contract._append_material
    def interrupted(target, value):
        original(target, value)
        raise failure("SYNTHETIC_INTERRUPTION")
    monkeypatch.setattr(contract, "_append_material", interrupted)
    with material() as (raw, views):
        with pytest.raises(ValueError if failure is ValueError else failure):
            encode(draft(), views)
        assert allocations and all(not any(value) for value in allocations)
        assert all(raw[key] == value for key, value in SYNTHETIC.items())


def test_draft_is_value_private_and_material_values_never_enter_its_metadata():
    prepared = draft()
    before = (prepared.input_nonmaterial_digest, prepared.request_nonmaterial_digest, prepared._tokens)
    with material() as (_, views):
        output = encode(prepared, views)
        output[:] = b"\0" * len(output)
    assert before == (prepared.input_nonmaterial_digest, prepared.request_nonmaterial_digest, prepared._tokens)
    assert all(value not in repr(prepared).encode() and value not in b"".join(t or b"" for t in prepared._tokens)
               for value in SYNTHETIC.values())
    assert "example.test" not in repr(prepared)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied): operation(prepared)
    facts = contract.approval_delivery_material_boundary()
    assert facts["explicit_protected_slots"] == 3 and facts["sdk_field_count"] == 14
    assert facts["inactive_material_slots_forwarded"] is True
    assert all(facts[key] is False for key in (
        "material_values_decoded_or_hashed", "native_material_size_units_qualified",
        "complete_frontend_validation_qualified", "material_source_or_lease_qualified",
        "backend_material_masking_or_preservation_qualified", "complete_current_baseline_qualified",
        "singleton_partial_put_merge_qualified", "independent_restore_qualified", "polling_or_approval_effect_qualified",
        "source_or_request_grants_authority", "material_provider_registered", "http_transport_registered",
        "mcp_tool_registered", "execution_authorized", "device_contacted"))
    assert not any(digest in json.dumps(facts) for digest in BINDINGS.values())
