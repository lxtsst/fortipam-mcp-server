"""Synthetic supplied frames; no current configuration or credential access."""
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import pickle
from threading import Barrier

import pytest

from fortipam_mcp import approval_delivery_material_contract as codec
from fortipam_mcp import approval_delivery_material_projection as projection
from fortipam_mcp import approval_delivery_contract as request
from test_approval_delivery_contract import state
from test_approval_delivery_material_contract import BINDINGS, ROLES, SYNTHETIC
from test_approval_delivery_projection import SERIAL, CANARY, response, encoded
from test_mutable_json_buffer import _allocations
from v4_planning.material_provider import MaterialAccessDenied


def frame(protocol="imaps", values=None):
    document = response(protocol)
    document["results"]["approval-email-setting"].update(
        {key: value.decode() for key, value in SYNTHETIC.items()} if values is None else values)
    return document


def project(document=None):
    raw = encoded(frame() if document is None else document)
    result = projection.project_material_approval_delivery(raw, expected_serial=SERIAL,
        material_binding_digests=BINDINGS)
    assert not any(raw)
    return result


@pytest.mark.parametrize("protocol", ["imaps", "ms-graph"])
@pytest.mark.parametrize("enabled", [True, False])
def test_full_projection_feeds_one_complete_sdk_body_then_clears_source_and_releases_views(protocol, enabled):
    with project(frame(protocol)) as observed:
        owned = list(observed._buffers.values())
        draft = observed._prepare_request(state(protocol), enabled=enabled)
        body = observed._compile_once(draft)
        try:
            payload = json.loads(body)["approval-email-setting"]
            assert tuple(payload) == request._FIELDS
            assert all(payload[key].encode() == value for key, value in SYNTHETIC.items())
            assert payload["server"] == ("example.test" if enabled else "")
            assert payload["email-pulling-server"] == ("imap.example.test" if enabled else "")
            assert all(not any(value) for value in owned) and observed.summary()["closed"] is True
            with pytest.raises(ValueError): observed._compile_once(draft)
            with pytest.raises(ValueError): observed._prepare_request(state(protocol), enabled=enabled)
        finally:
            body[:] = b"\0" * len(body)


@pytest.mark.parametrize("ascii_wire", [True, False])
@pytest.mark.parametrize("value", ["", "********", "ENC SYNTHETIC_OPAQUE", 'SYNTHETIC"\\/\b\f\n\r\t\0',
    "SYNTHETIC_合成\U0001f512", "\x7f\u0080\u07ff\u0800\ud7ff\ue000\uffff\U00010000\U0010ffff"])
def test_unicode_escapes_controls_and_mask_like_values_roundtrip_only_as_json_values(ascii_wire, value):
    raw = bytearray(json.dumps(frame(values=dict.fromkeys(ROLES, value)), ensure_ascii=ascii_wire).encode())
    with projection.project_material_approval_delivery(raw, expected_serial=SERIAL,
            material_binding_digests=BINDINGS) as observed:
        draft = observed._prepare_request(state(), enabled=False)
        body = observed._compile_once(draft)
        try:
            result = json.loads(body)["approval-email-setting"]
            assert all(result[role] == value for role in ROLES)
            assert observed.summary()["backend_masking_or_material_preservation_qualified"] is False
        finally:
            body[:] = b"\0" * len(body)
    assert not any(raw)


@pytest.mark.parametrize("code", [0, 31, 127, 128, 2047, 2048, 0xD7FF, 0xE000, 0xFFFF, 0x10000, 0x10FFFF])
def test_mutable_decoder_covers_unicode_width_boundaries_without_python_material_strings(code):
    value = chr(code)
    wire = json.dumps(value, ensure_ascii=True).encode()
    with memoryview(wire) as token:
        decoded = projection._decode_material(token)
    try:
        assert decoded == value.encode()
    finally:
        decoded[:] = b"\0" * len(decoded)


@pytest.mark.parametrize("wire", [b'"\\ud800"', b'"\\udfff"', b'"\\ud800\\u0041"', b'"\\ud800A"',
    b'"\\ud800\\ud800"', b'"\\uZZZZ"', b'"\\x20"', b'"\xff"', b'"\xc0\x80"', b'"\xed\xa0\x80"', b'"\0"'])
def test_invalid_material_unicode_never_publishes_a_decoded_buffer(wire, monkeypatch):
    allocations = _allocations(monkeypatch)
    with memoryview(wire) as token, pytest.raises(ValueError):
        projection._decode_material(token)
    assert all(not any(value) for value in allocations)


@pytest.mark.parametrize("role", ROLES)
def test_local_decoded_byte_bound_is_inclusive_and_oversize_frame_is_consumed(role):
    with project(frame(values={role: "A" * 4096})) as observed:
        assert len(observed._buffers[role]) == 4096
    raw = encoded(frame(values={role: "A" * 4097}))
    with pytest.raises(ValueError):
        projection.project_material_approval_delivery(raw, expected_serial=SERIAL, material_binding_digests=BINDINGS)
    assert not any(raw)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("value", [None, 7, True, {"material": "SYNTHETIC_PRIVATE"}])
def test_all_protected_slots_are_classified_before_any_nonmaterial_decode(role, value, monkeypatch):
    raw = encoded(frame(values={role: value}))
    monkeypatch.setattr(json, "loads", lambda *args, **kwargs: pytest.fail("Unclassified material reached decoding"))
    with pytest.raises(ValueError):
        projection.project_material_approval_delivery(raw, expected_serial=SERIAL, material_binding_digests=BINDINGS)
    assert not any(raw)


def test_material_and_unselected_values_are_never_passed_to_string_decoder_or_hash(monkeypatch):
    raw = encoded(frame())
    original = json.loads
    def safe(value, *args, **kwargs):
        text = bytes(value) if isinstance(value, (bytes, bytearray, memoryview)) else value.encode()
        assert CANARY.encode() not in text and not any(secret in text for secret in SYNTHETIC.values())
        return original(value, *args, **kwargs)
    def forbidden(*args, **kwargs):
        pytest.fail("Projection must not hash a material frame")
    monkeypatch.setattr(json, "loads", safe)
    monkeypatch.setattr(codec.hashlib, "sha256", forbidden)
    with projection.project_material_approval_delivery(raw, expected_serial=SERIAL,
            material_binding_digests=BINDINGS) as observed:
        assert observed.summary()["model_field_count"] == 14
    assert not any(raw)


@pytest.mark.parametrize("field,value", [("action", "schema"), ("build", True), ("serial", "SYNTHETIC02"),
    ("path", "system"), ("name", "email-server"), ("http_method", "PUT"), ("status", "error"), ("error", -1)])
def test_wrong_or_schema_envelope_never_captures_material(field, value, monkeypatch):
    data = frame(); data[field] = value; raw = encoded(data)
    monkeypatch.setattr(projection, "_decode_material", lambda *_: pytest.fail("Wrong source frame accepted"))
    with pytest.raises(ValueError):
        projection.project_material_approval_delivery(raw, expected_serial=SERIAL, material_binding_digests=BINDINGS)
    assert not any(raw)


@pytest.mark.parametrize("change", ["missing", "extra", "duplicate", "alias-duplicate", "nested", "late-material", "boolean-port"])
def test_selected_subtree_failures_clear_input_and_every_owned_allocation(change, monkeypatch):
    data = frame(); setting = data["results"]["approval-email-setting"]
    if change == "missing": del setting["credential"]
    if change == "extra": setting["unclassified"] = CANARY
    if change == "nested": setting["email-folder"] = {"material": CANARY}
    if change == "late-material": setting["client-secret"] = "\ud800"
    if change == "boolean-port": setting["port"] = True
    raw = encoded(data)
    if change in ("duplicate", "alias-duplicate"):
        key = b'"credential"' if change == "duplicate" else b'"\\u0063redential"'
        raw = raw.replace(b'"credential":', key + b':"SYNTHETIC_DUP", "credential":', 1)
    allocations = _allocations(monkeypatch)
    with pytest.raises(ValueError) as error:
        projection.project_material_approval_delivery(raw, expected_serial=SERIAL, material_binding_digests=BINDINGS)
    assert not any(raw) and all(not any(value) for value in allocations)
    assert "SYNTHETIC" not in str(error.value)


@pytest.mark.parametrize("failure", [ValueError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("stage", ["metadata", "before-input-clear", "after-input-clear"])
def test_late_failures_and_control_interruptions_clear_unpublished_material(failure, stage, monkeypatch):
    raw = encoded(frame()); allocations = _allocations(monkeypatch)
    original = projection._zeroize_mutable
    if stage == "metadata":
        def interrupt(*args): raise failure("SYNTHETIC_INTERRUPTION")
        monkeypatch.setattr(projection.metadata, "_scalar", interrupt)
    else:
        interrupted = False
        def wipe(buffer):
            nonlocal interrupted
            if buffer is raw and not interrupted:
                interrupted = True
                if stage == "after-input-clear": original(buffer)
                raise failure("SYNTHETIC_INTERRUPTION")
            original(buffer)
        monkeypatch.setattr(projection, "_zeroize_mutable", wipe)
    with pytest.raises(ValueError if failure is ValueError else failure):
        projection.project_material_approval_delivery(raw, expected_serial=SERIAL, material_binding_digests=BINDINGS)
    assert not any(raw) and allocations and all(not any(value) for value in allocations)


@pytest.mark.parametrize("failure", [ValueError, KeyboardInterrupt, SystemExit])
def test_compiler_failure_releases_views_and_clears_projection_and_partial_body(failure, monkeypatch):
    observed = project(); held = list(observed._buffers.values()); views = []
    draft = observed._prepare_request(state(), enabled=True)
    allocations = _allocations(monkeypatch)
    original = codec._append_material
    def interrupt(target, view):
        views.append(view)
        original(target, view)
        raise failure("SYNTHETIC_INTERRUPTION")
    monkeypatch.setattr(codec, "_append_material", interrupt)
    with pytest.raises(ValueError if failure is ValueError else failure): observed._compile_once(draft)
    assert all(not any(value) for value in held + allocations) and observed.summary()["closed"] is True
    for view in views:
        with pytest.raises(ValueError): view.tobytes()


def test_reentrant_close_during_compilation_refuses_publication_and_erases_completed_body(monkeypatch):
    observed = project(); draft = observed._prepare_request(state(), enabled=True)
    original = projection.build_approval_delivery_material_body; captured = []
    def close_after_encoding(*args, **kwargs):
        body = original(*args, **kwargs)
        captured.append(body)
        observed.close()
        return body
    monkeypatch.setattr(projection, "build_approval_delivery_material_body", close_after_encoding)
    with pytest.raises(ValueError): observed._compile_once(draft)
    assert captured and not any(captured[0])


def test_concurrent_compilers_cannot_borrow_the_same_projection_twice():
    observed = project(); draft = observed._prepare_request(state(), enabled=True); barrier = Barrier(2)
    def consume():
        barrier.wait(timeout=3)
        try: return observed._compile_once(draft)
        except ValueError: return None
    with ThreadPoolExecutor(2) as pool:
        outputs = [future.result(timeout=5) for future in (pool.submit(consume), pool.submit(consume))]
    bodies = [body for body in outputs if body is not None]
    try:
        assert len(bodies) == 1 and observed.summary()["closed"] is True
    finally:
        for body in bodies: body[:] = b"\0" * len(body)


@pytest.mark.parametrize("failure", [ValueError, MemoryError, KeyboardInterrupt, SystemExit])
def test_all_cleanup_finishes_before_publishing_a_completed_body(failure, monkeypatch):
    observed = project(); draft = observed._prepare_request(state(), enabled=True)
    original_encode = projection.build_approval_delivery_material_body
    original_wipe = projection._zeroize_mutable
    captured = []
    calls = 0
    def capture(*args, **kwargs):
        body = original_encode(*args, **kwargs); captured.append(body); return body
    def interrupt_redundant_cleanup(buffer):
        nonlocal calls
        calls += 1
        if calls == 4: raise failure("SYNTHETIC_CLEANUP_FAILURE")
        original_wipe(buffer)
    monkeypatch.setattr(projection, "build_approval_delivery_material_body", capture)
    monkeypatch.setattr(projection, "_zeroize_mutable", interrupt_redundant_cleanup)
    body = None
    try:
        try: body = observed._compile_once(draft)
        except (ValueError, MemoryError, KeyboardInterrupt, SystemExit):
            assert captured and not any(captured[0])
        else:
            assert body is captured[0] and calls == 3
    finally:
        for value in captured: value[:] = b"\0" * len(value)


@pytest.mark.parametrize("failure", [ValueError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("index", [0, 1, 2])
def test_close_attempts_every_slot_and_clears_failed_slot_before_propagating(failure, index, monkeypatch):
    observed = project(); owned = list(observed._buffers.values()); attempted = []
    original = projection._zeroize_mutable
    def interrupt(buffer):
        attempted.append(id(buffer))
        if buffer is owned[index]: raise failure("SYNTHETIC_CLEANUP_FAILURE")
        original(buffer)
    monkeypatch.setattr(projection, "_zeroize_mutable", interrupt)
    with pytest.raises(ValueError if issubclass(failure, Exception) else failure): observed.close()
    assert set(attempted) == {id(buffer) for buffer in owned}
    assert all(not any(buffer) for buffer in owned)


@pytest.mark.parametrize("failure", [ValueError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("index", [0, 1, 2])
def test_necessary_source_cleanup_failure_erases_the_unpublished_body_and_all_slots(failure, index, monkeypatch):
    observed = project(); owned = list(observed._buffers.values())
    draft = observed._prepare_request(state(), enabled=True); captured = []
    original_encode = projection.build_approval_delivery_material_body
    original_wipe = projection._zeroize_mutable
    def capture(*args, **kwargs):
        body = original_encode(*args, **kwargs); captured.append(body); return body
    def interrupt(buffer):
        if buffer is owned[index]: raise failure("SYNTHETIC_SOURCE_CLEANUP_FAILURE")
        original_wipe(buffer)
    monkeypatch.setattr(projection, "build_approval_delivery_material_body", capture)
    monkeypatch.setattr(projection, "_zeroize_mutable", interrupt)
    with pytest.raises(ValueError if issubclass(failure, Exception) else failure): observed._compile_once(draft)
    assert captured and not any(captured[0]) and all(not any(buffer) for buffer in owned)


@pytest.mark.parametrize("failure", [ValueError, MemoryError, KeyboardInterrupt, SystemExit])
def test_failed_unpublished_cleanup_still_erases_all_decoded_material(failure, monkeypatch):
    raw = encoded(frame()); owned = []; original_decode = projection._decode_material
    original_wipe = projection._zeroize_mutable
    def capture(token):
        buffer = original_decode(token); owned.append(buffer); return buffer
    def reject_metadata(*args): raise ValueError("SYNTHETIC_LATE_FAILURE")
    def interrupt(buffer):
        if owned and buffer is owned[0]: raise failure("SYNTHETIC_CLEANUP_FAILURE")
        original_wipe(buffer)
    monkeypatch.setattr(projection, "_decode_material", capture)
    monkeypatch.setattr(projection.metadata, "_scalar", reject_metadata)
    monkeypatch.setattr(projection, "_zeroize_mutable", interrupt)
    with pytest.raises(ValueError if issubclass(failure, Exception) else failure):
        projection.project_material_approval_delivery(raw, expected_serial=SERIAL, material_binding_digests=BINDINGS)
    assert not any(raw) and len(owned) == 3 and all(not any(buffer) for buffer in owned)


@pytest.mark.parametrize("failure", [ValueError, MemoryError, KeyboardInterrupt, SystemExit])
def test_failed_body_wipe_uses_in_place_erasure_before_propagating(failure, monkeypatch):
    observed = project(); draft = observed._prepare_request(state(), enabled=True)
    original_encode = projection.build_approval_delivery_material_body
    original_wipe = projection._zeroize_mutable; captured = []
    def close_after(*args, **kwargs):
        body = original_encode(*args, **kwargs); captured.append(body); observed.close(); return body
    def interrupt(buffer):
        if captured and buffer is captured[0]: raise failure("SYNTHETIC_BODY_CLEANUP_FAILURE")
        original_wipe(buffer)
    monkeypatch.setattr(projection, "build_approval_delivery_material_body", close_after)
    monkeypatch.setattr(projection, "_zeroize_mutable", interrupt)
    with pytest.raises(ValueError if issubclass(failure, Exception) else failure): observed._compile_once(draft)
    assert captured and not any(captured[0])


def test_role_or_source_drift_clears_original_input_without_minting_a_new_source(monkeypatch):
    for drift in ("role", "pin"):
        observed = project(); held = list(observed._buffers.values())
        bindings = BINDINGS | {"credential": "9" * 64} if drift == "role" else BINDINGS
        draft = codec.prepare_material_approval_delivery(state(), enabled=True, material_binding_digests=bindings)
        with monkeypatch.context() as patch:
            if drift == "pin": patch.setattr(request, "SCHEMA_METADATA_SHA256", "0" * 64)
            with pytest.raises(ValueError): observed._compile_once(draft)
        assert all(not any(value) for value in held)
        with pytest.raises(ValueError): observed._prepare_request(state(), enabled=True)


def test_projection_is_opaque_closes_without_compiling_and_grants_no_source_or_recovery_authority():
    observed = project(); held = list(observed._buffers.values()); facts = observed.summary()
    assert not any(secret.decode() in repr(observed) for secret in SYNTHETIC.values())
    assert CANARY not in repr(facts) and SERIAL not in repr(facts) and "example.test" not in repr(facts)
    assert all(facts[key] is False for key in (
        "material_values_decoded_to_strings_or_hashed", "native_current_response_contract_qualified",
        "backend_masking_or_material_preservation_qualified", "material_binding_is_provenance",
        "provider_lease_or_operation_replay_protection", "whole_setting_baseline_verified",
        "partial_put_merge_qualified", "restore_authorized", "execution_authorized", "device_contacted"))
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied): operation(observed)
    with pytest.raises(ValueError): projection.ApprovalDeliveryMaterialProjection()
    with observed: pass
    assert all(not any(value) for value in held)
