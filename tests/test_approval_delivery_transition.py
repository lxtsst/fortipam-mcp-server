"""Provided synthetic source frames; no real current values or write dispatch."""
from copy import copy, deepcopy
import hashlib
import json
import pickle

import pytest

from fortipam_mcp import approval_delivery_transition as module
from fortipam_mcp.approval_delivery_material_projection import ApprovalDeliveryMaterialProjection
from fortipam_mcp.approval_delivery_source import ApprovalDeliverySource
from test_approval_delivery_contract import state
from test_approval_delivery_material_contract import BINDINGS, SYNTHETIC
from test_approval_delivery_projection import CANARY, SERIAL
from test_approval_delivery_source import ACTOR, COOKIE, candidate  # noqa: F401
from v4_planning.material_provider import MaterialAccessDenied


@pytest.fixture
def package(candidate):
    sources, transitions = [], []
    def make(protocol="imaps", *, proposed=None, enabled=False, change_original=None):
        peer, original, owner = candidate(protocol)
        if change_original:
            peer.payload["results"]["approval-email-setting"].update(change_original)
        document = deepcopy(peer.payload)
        original.read()
        transition = module.prepare_approval_delivery_transition(original,
            state(protocol) if proposed is None else proposed, enabled=enabled)
        transitions.append(transition)
        def fresh(value=None, *, bindings=BINDINGS, guard=None, serial=SERIAL):
            peer.payload = deepcopy(document if value is None else value)
            observed = ApprovalDeliverySource(owner, expected_actor=ACTOR, expected_serial=serial,
                material_binding_digests=bindings, source_guard=original._guard if guard is None else guard)
            sources.append(observed)
            observed.read()
            return observed
        return peer, original, transition, fresh, document
    yield make
    for transition in transitions:
        transition.close()
    for source in sources:
        source.close()


@pytest.mark.parametrize("original_protocol", ["imaps", "ms-graph"])
@pytest.mark.parametrize("enabled", [True, False])
def test_complete_local_comparison_cycle_retains_one_original_without_material_copy(package, original_protocol, enabled):
    proposed = state("ms-graph" if original_protocol == "imaps" else "imaps")
    proposed.update(port=993, **{"check-interval": 17})
    peer, original, transition, fresh, document = package(original_protocol, proposed=proposed, enabled=enabled)
    buffers = dict(original._projection._buffers)
    identities = {role: id(buffer) for role, buffer in buffers.items()}
    preview = transition.preview()
    current = fresh()
    body = transition.compile_unchanged(current)
    try:
        expected = json.loads(body)["approval-email-setting"]
        assert all(expected[role].encode() == material for role, material in SYNTHETIC.items())
        assert current._closed and not original._closed
        assert {role: id(buffer) for role, buffer in original._projection._buffers.items()} == identities
        assert all(any(buffer) for buffer in buffers.values())
        assert preview["Proposed Changes"]["changed_nonmaterial_fields"] == sorted(
            key for key, value in state(original_protocol).items() if value != expected[key])
        applied = deepcopy(document)
        applied["results"]["approval-email-setting"] = expected
        after = fresh(applied)
        assert transition.verify_applied(after) is None and after._closed
        assert preview["Expected State"]["local_sdk_inverse_available"] is True
        inverse = transition.compile_restore(fresh(applied))
        try:
            assert json.loads(inverse)["approval-email-setting"] == document["results"]["approval-email-setting"]
        finally:
            inverse[:] = b"\0" * len(inverse)
        restored = fresh()
        assert transition.verify_restored(restored) is None and restored._closed
        assert len(peer.calls) == 5
        assert all(call[0] == "GET" for call in peer.calls)
        assert preview["Expected State"]["backend_material_preservation_qualified"] is False
        assert preview["independent_restore_authorized"] is False
        transition.close()
        assert all(not any(buffer) for buffer in buffers.values())
        assert not any(original._cookie)
    finally:
        body[:] = b"\0" * len(body)


def test_preview_and_comparison_never_decode_hash_or_return_material_or_identifiers(package, monkeypatch):
    peer, original, transition, fresh, _ = package()
    current = fresh()
    decode, digest = json.loads, hashlib.sha256
    comparisons, compare = [], module.hmac.compare_digest
    def check(value):
        raw = value.encode() if isinstance(value, str) else value
        assert not any(secret in raw for secret in [COOKIE.encode(), CANARY.encode(), *SYNTHETIC.values()])
    def safe_decode(value, *args, **kwargs):
        check(value)
        return decode(value, *args, **kwargs)
    def safe_digest(value=b"", *args, **kwargs):
        check(value)
        return digest(value, *args, **kwargs)
    def byte_compare(left, right):
        if isinstance(left, memoryview) and isinstance(right, memoryview):
            comparisons.append((left.obj, right.obj))
        return compare(left, right)
    monkeypatch.setattr(json, "loads", safe_decode)
    monkeypatch.setattr(hashlib, "sha256", safe_digest)
    monkeypatch.setattr(module.hmac, "compare_digest", byte_compare)
    preview = transition.preview()
    body = transition.compile_unchanged(current)
    try:
        assert len(comparisons) == 3
        assert all(any(before is buffer for buffer in original._projection._buffers.values()) for before, _ in comparisons)
        rendered = repr(preview)
        assert all(value not in rendered for value in [COOKIE, CANARY, ACTOR, SERIAL, "example.test", *BINDINGS.values()])
        assert all(secret.decode() not in rendered for secret in SYNTHETIC.values())
    finally:
        body[:] = b"\0" * len(body)


_DRIFT = {"approval-email-protocol": "ms-graph", "email-pulling-server": "different.example.test",
    "server": "different.example.test", "port": 994, "server-cert": "different-cert",
    "email-folder": "different-folder", "ssl-min-version": "tls-1.3", "check-interval": 18,
    "tenant-id": "different-tenant", "app-id": "different-app", "user-id": "different-user"}


@pytest.mark.parametrize("field", sorted(_DRIFT))
def test_every_nonmaterial_drift_refuses_compilation_and_clears_both_sources(package, monkeypatch, field):
    _, original, transition, fresh, document = package()
    document["results"]["approval-email-setting"][field] = _DRIFT[field]
    current = fresh(document)
    retained = [*original._projection._buffers.values(), *current._projection._buffers.values()]
    monkeypatch.setattr(ApprovalDeliveryMaterialProjection, "_compile_once",
        lambda *_args: pytest.fail("A drifted observation must not reach encoding."))
    with pytest.raises(ValueError, match="^The private approval-delivery transition is unavailable.$"):
        transition.compile_unchanged(current)
    assert original._closed and current._closed and transition._closed
    assert all(not any(buffer) for buffer in retained)


@pytest.mark.parametrize("protocol", ["imaps", "ms-graph"])
@pytest.mark.parametrize("role", sorted(SYNTHETIC))
def test_protected_drift_including_inactive_roles_refuses_without_material_hash(package, protocol, role):
    _, original, transition, fresh, document = package(protocol)
    document["results"]["approval-email-setting"][role] = "SYNTHETIC_CHANGED_SLOT"
    current = fresh(document)
    retained = [*original._projection._buffers.values(), *current._projection._buffers.values()]
    with pytest.raises(ValueError):
        transition.compile_unchanged(current)
    assert all(not any(buffer) for buffer in retained)


@pytest.mark.parametrize("binding", ["guard", "roles", "serial", "owner"])
def test_unrelated_valid_source_cannot_supply_drift_or_readback_evidence(package, candidate, binding):
    _, original, transition, fresh, document = package()
    if binding == "guard":
        current = fresh(guard=lambda: True)
    elif binding == "roles":
        current = fresh(bindings={**BINDINGS, "credential": "f" * 64})
    elif binding == "serial":
        document["serial"] = "SYNTHETIC_OTHER_DEVICE"
        current = fresh(document, serial=document["serial"])
    else:
        _, current, _ = candidate()
        current._guard = current._guard_pin = original._guard
        current.read()
    with pytest.raises(ValueError):
        transition.compile_unchanged(current)
    assert original._closed and current._closed


def test_fresh_read_does_not_extend_original_deadline(package):
    peer, original, transition, fresh, _ = package()
    peer.time += 4
    current = fresh()
    assert current._deadline > original._deadline
    peer.time = original._deadline
    with pytest.raises(ValueError):
        transition.compile_unchanged(current)
    assert current._closed and original._closed


@pytest.mark.parametrize("method", ["verify_applied", "verify_restored"])
def test_no_readback_comparison_before_private_compilation(package, method):
    _, original, transition, fresh, _ = package()
    current = fresh()
    with pytest.raises(ValueError):
        getattr(transition, method)(current)
    assert current._closed and original._closed


def test_private_compilation_is_once_and_second_attempt_cannot_reopen_original(package):
    _, original, transition, fresh, _ = package()
    body = transition.compile_unchanged(fresh())
    try:
        current = fresh()
        with pytest.raises(ValueError):
            transition.compile_unchanged(current)
        assert current._closed and original._closed
    finally:
        body[:] = b"\0" * len(body)


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_observation_close_failure_after_encoding_clears_pending_body_and_original(package, monkeypatch, error_type):
    _, original, transition, fresh, _ = package()
    current, pending, calls = fresh(), [], []
    close_original, compile_original = current.close, current._compile_once
    def close():
        close_original()
        calls.append(True)
        # The source closes itself first. Fail during the transition's final
        # observation cleanup, after its private compiler returned the body.
        if len(calls) == 2:
            raise error_type("SYNTHETIC_PRIVATE_CLOSE")
    def compile_once(draft):
        body = compile_original(draft)
        pending.append(body)
        return body
    monkeypatch.setattr(current, "close", close)
    monkeypatch.setattr(current, "_compile_once", compile_once)
    expected = ValueError if issubclass(error_type, Exception) else error_type
    with pytest.raises(expected) as error:
        transition.compile_unchanged(current)
    if expected is ValueError:
        assert "SYNTHETIC_PRIVATE_CLOSE" not in str(error.value)
    assert pending and not any(pending[0]) and original._closed
    assert all(not any(buffer) for buffer in original._projection._buffers.values())
    monkeypatch.setattr(current, "close", close_original)


def test_expiry_after_final_observation_cleanup_cancels_body_handoff(package, monkeypatch):
    peer, original, transition, fresh, _ = package()
    current, pending, calls = fresh(), [], []
    close_original, compile_original = current.close, current._compile_once
    def close():
        close_original()
        calls.append(True)
        if len(calls) == 2:
            peer.time = original._deadline
    def compile_once(draft):
        body = compile_original(draft)
        pending.append(body)
        return body
    monkeypatch.setattr(current, "close", close)
    monkeypatch.setattr(current, "_compile_once", compile_once)
    with pytest.raises(ValueError):
        transition.compile_unchanged(current)
    assert pending and not any(pending[0]) and original._closed


@pytest.mark.parametrize("marker", ["%0%", "%1%"])
def test_native_empty_certificate_marker_is_not_assumed_exact_restoration(package, marker, monkeypatch):
    proposed = {**state(), "server-cert": marker}
    _, original, transition, fresh, _ = package(proposed=proposed, change_original={"server-cert": marker})
    preview = transition.preview()
    assert preview["Expected State"]["local_sdk_inverse_available"] is False
    assert "server-cert" in preview["Proposed Changes"]["request_normalized_fields"]
    monkeypatch.setattr(ApprovalDeliveryMaterialProjection, "_compile_once",
        lambda *_args: pytest.fail("An unrepresentable baseline must not reach body encoding."))
    current = fresh()
    with pytest.raises(ValueError):
        transition.compile_unchanged(current)
    assert current._closed and original._closed


def test_unselected_setting_changes_do_not_become_whole_singleton_qualification(package):
    _, _, transition, fresh, document = package()
    document["results"]["unselected-setting"] = {"password": "SYNTHETIC_UNCLASSIFIED_CHANGED_VALUE"}
    body = transition.compile_unchanged(fresh(document))
    try:
        preview = transition.preview()
        assert preview["Current State"]["whole_singleton_baseline_verified"] is False
        assert preview["partial_put_merge_qualified"] is False
    finally:
        body[:] = b"\0" * len(body)


def test_factory_only_opaque_transition_and_source_disposal_ownership(package):
    _, original, transition, _, _ = package()
    with pytest.raises(ValueError):
        module.ApprovalDeliveryTransition()
    for operation in (copy, deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied):
            operation(transition)
    transition.close()
    assert original._closed and all(not any(value) for value in original._projection._buffers.values())


def test_context_entry_failure_disposes_expired_original(package):
    peer, original, transition, _, _ = package()
    peer.time = original._deadline
    with pytest.raises(ValueError, match="^The private approval-delivery transition is unavailable.$"):
        with transition:
            pytest.fail("Expired context must not be entered.")
    assert original._closed and all(not any(value) for value in original._projection._buffers.values())


def test_factory_refuses_unread_source_without_attempting_io(candidate):
    peer, original, _ = candidate()
    with pytest.raises(ValueError):
        module.prepare_approval_delivery_transition(original, state(), enabled=False)
    assert not peer.calls and original._closed and not any(original._cookie)


@pytest.mark.parametrize("which", ["transition", "original", "observed"])
def test_lock_acquisition_cancellation_disposes_consumed_fresh_and_original(package, which):
    _, original, transition, fresh, _ = package()
    observed = fresh()
    retained = [*original._projection._buffers.values(), *observed._projection._buffers.values()]
    target = {"transition": transition, "original": original, "observed": observed}[which]
    actual = target._lock
    class InterruptedLock:
        armed = True
        def __enter__(self):
            if self.armed:
                self.armed = False
                raise KeyboardInterrupt
            return actual.__enter__()
        def __exit__(self, *args):
            return actual.__exit__(*args)
    target._lock = InterruptedLock()
    with pytest.raises(KeyboardInterrupt):
        transition.compile_unchanged(observed)
    assert original._closed and observed._closed and transition._closed
    assert all(not any(buffer) for buffer in retained)


def test_lock_exit_cancellation_after_compilation_erases_pending_body(package, monkeypatch):
    _, original, transition, fresh, _ = package()
    observed, pending = fresh(), []
    actual, compile_original = transition._lock, observed._compile_once
    class InterruptedExit:
        armed = True
        def __enter__(self):
            return actual.__enter__()
        def __exit__(self, *args):
            result = actual.__exit__(*args)
            if self.armed:
                self.armed = False
                raise KeyboardInterrupt
            return result
    def compile_once(draft):
        body = compile_original(draft)
        pending.append(body)
        return body
    transition._lock = InterruptedExit()
    monkeypatch.setattr(observed, "_compile_once", compile_once)
    with pytest.raises(KeyboardInterrupt):
        transition.compile_unchanged(observed)
    assert pending and not any(pending[0])
    assert original._closed and observed._closed and transition._closed
    assert all(not any(buffer) for buffer in original._projection._buffers.values())


@pytest.mark.parametrize("protocol", ["imaps", "ms-graph"])
def test_disabled_original_has_an_exact_separate_restore_body(package, protocol):
    _, _, transition, fresh, document = package(protocol, enabled=True,
        change_original={"server": "", "email-pulling-server": ""})
    body = transition.compile_unchanged(fresh())
    inverse = bytearray()
    try:
        proposed = deepcopy(document)
        proposed["results"]["approval-email-setting"] = json.loads(body)["approval-email-setting"]
        inverse = transition.compile_restore(fresh(proposed))
        restored = json.loads(inverse)["approval-email-setting"]
        assert restored == document["results"]["approval-email-setting"]
        assert restored["server"] == restored["email-pulling-server"] == ""
        transition.verify_restored(fresh())
    finally:
        body[:] = b"\0" * len(body)
        inverse[:] = b"\0" * len(inverse)


@pytest.mark.parametrize("protocol,change", [
    ("imaps", {"server": ""}), ("imaps", {"email-pulling-server": ""}),
    ("ms-graph", {"server": ""}), ("ms-graph", {"tenant-id": ""}),
    ("imaps", {"username": ""}), ("imaps", {"credential": ""}),
    ("ms-graph", {"client-secret": ""}),
])
def test_parseable_but_unrepresentable_original_is_previewable_and_denies_forward_body(package, protocol, change, monkeypatch):
    _, original, transition, fresh, _ = package(protocol, change_original=change)
    preview = transition.preview()
    assert preview["Expected State"]["local_sdk_inverse_available"] is False
    assert preview["execution_authorized"] is False
    monkeypatch.setattr(ApprovalDeliveryMaterialProjection, "_compile_once",
        lambda *_args: pytest.fail("An unavailable inverse must deny forward compilation."))
    observed = fresh()
    retained = [*original._projection._buffers.values(), *observed._projection._buffers.values()]
    with pytest.raises(ValueError):
        transition.compile_unchanged(observed)
    assert observed._closed and original._closed and all(not any(value) for value in retained)


def test_restore_requires_prior_forward_compilation(package):
    _, original, transition, fresh, _ = package()
    observed = fresh()
    with pytest.raises(ValueError):
        transition.compile_restore(observed)
    assert observed._closed and original._closed


def test_restore_requires_proposed_state_and_every_material_slot(package):
    _, original, transition, fresh, document = package()
    body = transition.compile_unchanged(fresh())
    try:
        # The unchanged original frame is not the proposed disabled frame.
        observed = fresh(document)
        with pytest.raises(ValueError):
            transition.compile_restore(observed)
        assert observed._closed and original._closed
    finally:
        body[:] = b"\0" * len(body)


def test_inactive_slot_drift_cannot_be_adopted_for_restore(package):
    _, original, transition, fresh, document = package()
    body = transition.compile_unchanged(fresh())
    try:
        document["results"]["approval-email-setting"] = json.loads(body)["approval-email-setting"]
        document["results"]["approval-email-setting"]["client-secret"] = "SYNTHETIC_CHANGED_INACTIVE_SLOT"
        observed = fresh(document)
        with pytest.raises(ValueError):
            transition.compile_restore(observed)
        assert observed._closed and original._closed
    finally:
        body[:] = b"\0" * len(body)


def test_private_restore_body_is_once_without_claiming_operation_replay_protection(package):
    _, original, transition, fresh, document = package()
    forward = transition.compile_unchanged(fresh())
    inverse = bytearray()
    try:
        document["results"]["approval-email-setting"] = json.loads(forward)["approval-email-setting"]
        inverse = transition.compile_restore(fresh(document))
        assert transition.preview()["operation_replay_protection"] is False
        with pytest.raises(ValueError):
            transition.compile_restore(fresh(document))
        assert original._closed
    finally:
        forward[:] = b"\0" * len(forward)
        inverse[:] = b"\0" * len(inverse)


def test_restore_expiry_after_cleanup_erases_pending_inverse(package, monkeypatch):
    peer, original, transition, fresh, document = package()
    forward = transition.compile_unchanged(fresh())
    try:
        document["results"]["approval-email-setting"] = json.loads(forward)["approval-email-setting"]
        observed, pending, calls = fresh(document), [], []
        close_original, compile_original = observed.close, observed._compile_once
        def close():
            close_original()
            calls.append(True)
            if len(calls) == 2: peer.time = original._deadline
        def compile_once(draft):
            body = compile_original(draft)
            pending.append(body)
            return body
        monkeypatch.setattr(observed, "close", close)
        monkeypatch.setattr(observed, "_compile_once", compile_once)
        with pytest.raises(ValueError): transition.compile_restore(observed)
        assert pending and not any(pending[0]) and observed._closed and original._closed
        assert all(not any(value) for value in original._projection._buffers.values())
    finally:
        forward[:] = b"\0" * len(forward)


def test_inverse_preflight_never_decodes_or_hashes_material(candidate, monkeypatch):
    _, original, _ = candidate()
    original.read()
    retained = dict(original._projection._buffers)
    decode, digest = json.loads, hashlib.sha256
    def check(value):
        raw = value.encode() if isinstance(value, str) else value
        assert not any(secret in raw for secret in SYNTHETIC.values())
    def safe_decode(value, *args, **kwargs):
        check(value)
        return decode(value, *args, **kwargs)
    def safe_digest(value=b"", *args, **kwargs):
        check(value)
        return digest(value, *args, **kwargs)
    monkeypatch.setattr(json, "loads", safe_decode)
    monkeypatch.setattr(hashlib, "sha256", safe_digest)
    with module.prepare_approval_delivery_transition(original, state(), enabled=False) as transition:
        assert transition.preview()["Expected State"]["local_sdk_inverse_available"] is True
        assert all(original._projection._buffers[role] is value for role, value in retained.items())
    assert all(not any(value) for value in retained.values())
