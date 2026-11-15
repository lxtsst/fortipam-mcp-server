"""Synthetic independent bundles with the real coordinator and material ledger."""
from copy import copy, deepcopy
from dataclasses import replace
import json
import pickle

import pytest

from fortipam_mcp import approval_delivery_material as module
from fortipam_mcp.approval_delivery_material_contract import (
    prepare_material_approval_delivery, build_approval_delivery_material_body, _ROLES,
)
from test_approval_delivery_contract import state
from test_approval_delivery_material_contract import BINDINGS, SYNTHETIC
from test_system_email_m4_adapter import Clock
from test_v4_material_persistence import _store, _ExternalMaterialCheckpoint
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import (
    MaterialAccessDenied, MaterialBindingStatus, MaterialLease, MaterialLeaseRequest,
    MaterialProviderClass, MaterialPurpose, MaterialRevocationReason,
)
from v4_planning.material_runtime import (
    MaterialLeaseCoordinator, MaterialRuntimeOutcome, MaterialUseOutcome,
)

CANARY = "SYNTHETIC_PRIVATE_RESOLVER_ERROR"


class Resolver:
    def __init__(self, reference):
        self.binding_digest = reference
        self.status = MaterialBindingStatus.AVAILABLE
        self.values = tuple(SYNTHETIC[role] for role in _ROLES)
        self.buffers, self.loads, self.checks = [], 0, 0
        self.on_load = self.on_validate = self.transform = None
    def validate_prebound(self):
        self.checks += 1
        if self.on_validate: self.on_validate()
        return self.status
    def load_approval_material_once(self):
        self.loads += 1
        values = tuple(bytearray(value) if type(value) is bytes else value for value in self.values)
        self.buffers.extend(value for value in values if type(value) is bytearray)
        try:
            if self.on_load: self.on_load()
            return self.transform(values) if self.transform else values
        except BaseException:
            # Failed resolver calls never transfer ownership to the provider.
            for value in values:
                if type(value) is bytearray: value[:] = b"\0" * len(value)
            raise


def make(protocol="imaps", restore=False, enabled=True, **changes):
    draft = prepare_material_approval_delivery(state(protocol), enabled=enabled, material_binding_digests=BINDINGS)
    binding = module.ApprovalDeliveryMaterialBinding(draft, restore=restore)
    request = MaterialLeaseRequest(binding.action_id, "1.0.0", "1" * 64, "2" * 64, "3" * 64, "4" * 64, "5" * 64,
        MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE, MaterialPurpose.JIT_DELIVERY, 1000, 1060)
    if changes: request = replace(request, **changes)
    resolver, clock = Resolver(binding.material_binding_digest), Clock()
    provider = module.ApprovalDeliveryMaterialProvider(resolver, binding, request, clock=clock)
    return provider, resolver, binding, request, clock, draft


@pytest.mark.parametrize("protocol", ["imaps", "ms-graph"])
@pytest.mark.parametrize("restore", [False, True])
def test_exact_three_slot_lease_feeds_codec_once_then_clears_and_releases(protocol, restore):
    provider, resolver, binding, request, _, draft = make(protocol, restore)
    borrowed, bodies = [], []
    assert binding.action_id == "approval-delivery-" + ("restore" if restore else "configure")
    assert binding.purpose is MaterialPurpose.JIT_DELIVERY and resolver.loads == 0
    def consumer(lease):
        def use(username, credential, client_secret):
            views = (username, credential, client_secret)
            assert all(view.readonly and view.obj is owner for view, owner in zip(views, resolver.buffers, strict=True))
            borrowed.extend(views)
            bodies.append(build_approval_delivery_material_body(draft, username=username, credential=credential,
                client_secret=client_secret, material_binding_digests=BINDINGS))
            return MaterialUseOutcome.VERIFIED
        return provider.consume(binding, lease, request, use)
    try:
        outcome = MaterialLeaseCoordinator(provider).execute_once(binding, request, consumer, now_epoch=1000)
        assert outcome is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
        payload = json.loads(bodies[0])["approval-email-setting"]
        assert all(payload[role].encode() == value for role, value in SYNTHETIC.items())
        assert resolver.loads == 1 and all(not any(buffer) for buffer in resolver.buffers)
        for view in borrowed:
            with pytest.raises(ValueError): bytes(view)
        with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding, request)
    finally:
        for body in bodies: body[:] = b"\0" * len(body)
        provider.close()


@pytest.mark.parametrize("protocol,enabled,values", [
    ("imaps", True, (b"SYNTHETIC_USER", b"SYNTHETIC_PASSWORD", b"")),
    ("ms-graph", True, (b"SYNTHETIC_USER", b"", b"SYNTHETIC_APP_SECRET")),
    ("imaps", False, (b"", b"", b"")),
])
def test_inactive_or_disabled_empty_slots_remain_explicit_owners(protocol, enabled, values):
    provider, resolver, binding, request, _, _ = make(protocol, enabled=enabled)
    resolver.values = values
    lease = provider.acquire_lease(binding, request)
    assert provider.consume(binding, lease, request, lambda *views:
        MaterialUseOutcome.VERIFIED if all(view == value for view, value in zip(views, values, strict=True))
        else MaterialUseOutcome.FAILED) is MaterialUseOutcome.VERIFIED
    assert provider.release_lease(lease) is module.MaterialLeaseCompletion.RELEASED
    assert all(not any(buffer) for buffer in resolver.buffers)


@pytest.mark.parametrize("changes", [dict(action_id="scim-client-disable"), dict(action_version="2.0.0"),
    dict(purpose=MaterialPurpose.INITIAL_ONBOARDING), dict(purpose=MaterialPurpose.CREDENTIAL_ROTATION),
    dict(provider_class=MaterialProviderClass.EXTERNAL_VAULT_LEASE),
    dict(provider_class=MaterialProviderClass.FORTIPAM_MANAGED_MATERIAL), dict(expires_at=1061)])
def test_foreign_action_version_purpose_source_or_window_is_not_relabelled(changes):
    with pytest.raises(MaterialAccessDenied): make(**changes)


def test_foreign_binding_request_or_lease_has_no_source_or_owner_side_effects():
    provider, resolver, binding, request, _, draft = make()
    foreign_binding = module.ApprovalDeliveryMaterialBinding(draft)
    assert provider.validate_binding(foreign_binding, request) is MaterialBindingStatus.INCOMPATIBLE
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(foreign_binding, request)
    for field in ("plan_digest", "policy_decision_digest", "authorization_digest", "scope_digest", "audience_digest"):
        foreign_request = replace(request, **{field: "f" * 64})
        assert provider.validate_binding(binding, foreign_request) is MaterialBindingStatus.INCOMPATIBLE
        with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding, foreign_request)
    assert not resolver.loads and not resolver.checks and not provider._closed
    lease = provider.acquire_lease(binding, request)
    checks = resolver.checks
    for b, handle, req in ((foreign_binding, lease, request), (binding, MaterialLease(), request),
            (binding, lease, replace(request, audience_digest="f" * 64))):
        assert provider.consume(b, handle, req, lambda *_: pytest.fail("Foreign use must not reach material.")) is MaterialUseOutcome.FAILED
    assert resolver.checks == checks and not provider._consumed and all(any(value) for value in resolver.buffers)
    with pytest.raises(MaterialAccessDenied): provider.revoke_lease(lease, reason="cancelled")
    with pytest.raises(MaterialAccessDenied): provider.release_lease(MaterialLease())
    assert not provider._closed
    assert provider.consume(binding, lease, request, lambda *_: MaterialUseOutcome.VERIFIED) is MaterialUseOutcome.VERIFIED
    provider.close()


@pytest.mark.parametrize("status", [False, True, "available", MaterialBindingStatus.UNAVAILABLE])
def test_source_status_is_authoritative_and_never_coerced(status):
    provider, resolver, binding, request, _, _ = make()
    resolver.status = status
    assert provider.validate_binding(binding, request) is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding, request)
    assert not resolver.loads


@pytest.mark.parametrize("fault", ["short", "list", "dict", "alias", "wrong-slot", "utf8", "oversize", "empty-active"])
def test_invalid_transfer_clears_every_transferred_buffer_without_second_load(fault):
    provider, resolver, binding, request, _, _ = make()
    if fault == "short": resolver.values = (b"SYNTHETIC_ONLY_ONE_SLOT",)
    elif fault == "list": resolver.transform = list
    elif fault == "dict": resolver.transform = lambda values: dict(zip(_ROLES, values, strict=True))
    elif fault == "alias":
        resolver.values = (b"SYNTHETIC_SHARED_OWNER",)
        resolver.transform = lambda values: (values[0],) * 3
    elif fault == "wrong-slot": resolver.values = (b"SYNTHETIC_USER", "SYNTHETIC_WRONG_TYPE", b"SYNTHETIC_APP")
    elif fault == "utf8": resolver.values = (b"SYNTHETIC_USER", b"\xff", b"SYNTHETIC_APP")
    elif fault == "oversize": resolver.values = (b"SYNTHETIC_USER", b"x" * 4097, b"SYNTHETIC_APP")
    else: resolver.values = (b"", b"SYNTHETIC_PASSWORD", b"SYNTHETIC_APP")
    with pytest.raises(MaterialAccessDenied) as error: provider.acquire_lease(binding, request)
    assert CANARY not in str(error.value)
    assert resolver.loads == 1 and all(not any(buffer) for buffer in resolver.buffers)
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding, request)
    assert resolver.loads == 1


@pytest.mark.parametrize("fault", ["expired", "rollback", "reference", "revoked", "closed"])
def test_changed_context_after_loading_does_not_publish_lease(fault):
    provider, resolver, binding, request, clock, _ = make()
    def change():
        if fault == "expired": clock.value = 1060
        elif fault == "rollback": clock.value = 999
        elif fault == "reference": resolver.binding_digest = "f" * 64
        elif fault == "revoked": resolver.status = MaterialBindingStatus.UNAVAILABLE
        else: provider.close()
    resolver.on_load = change
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding, request)
    assert resolver.loads == 1 and all(not any(buffer) for buffer in resolver.buffers)


@pytest.mark.parametrize("error_type", [MemoryError, KeyboardInterrupt, SystemExit])
def test_lease_allocation_failure_clears_loaded_bundle(error_type, monkeypatch):
    provider, resolver, binding, request, _, _ = make()
    def unavailable(): raise error_type(CANARY)
    monkeypatch.setattr(module, "_ApprovalDeliveryLease", unavailable)
    with pytest.raises(MaterialAccessDenied if issubclass(error_type, Exception) else error_type):
        provider.acquire_lease(binding, request)
    assert all(not any(buffer) for buffer in resolver.buffers) and provider._closed


@pytest.mark.parametrize("fault", ["exception", "interrupt", "system-exit", "invalid-result", "expired", "revoked", "close-callback"])
def test_use_failure_revocation_and_interruption_release_views_and_erase_all_slots(fault):
    provider, resolver, binding, request, clock, _ = make()
    lease, borrowed = provider.acquire_lease(binding, request), []
    def use(*views):
        borrowed.extend(views)
        if fault == "exception": raise RuntimeError(CANARY)
        if fault == "interrupt": raise KeyboardInterrupt(CANARY)
        if fault == "system-exit": raise SystemExit(CANARY)
        if fault == "expired": clock.value = 1060
        if fault == "revoked": resolver.status = MaterialBindingStatus.UNAVAILABLE
        if fault == "close-callback": resolver.on_validate = provider.close
        return True if fault == "invalid-result" else MaterialUseOutcome.VERIFIED
    if fault in ("exception", "interrupt", "system-exit"):
        expected = {"exception": MaterialAccessDenied, "interrupt": KeyboardInterrupt, "system-exit": SystemExit}[fault]
        with pytest.raises(expected): provider.consume(binding, lease, request, use)
    else:
        result = provider.consume(binding, lease, request, use)
        assert result is (MaterialUseOutcome.TIMED_OUT if fault == "expired" else MaterialUseOutcome.FAILED)
    assert all(not any(value) for value in resolver.buffers)
    for view in borrowed:
        with pytest.raises(ValueError): bytes(view)
    assert provider.consume(binding, lease, request, use) is MaterialUseOutcome.FAILED
    provider.close()


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_all_three_wipes_are_attempted_even_when_every_primary_wipe_fails(error_type, monkeypatch):
    provider, resolver, binding, request, _, _ = make()
    lease = provider.acquire_lease(binding, request)
    original, erased = module._erase_transfer_storage, []
    def erase(buffer):
        original(buffer)
        erased.append(id(buffer))
        raise error_type(CANARY)
    monkeypatch.setattr(module, "_erase_transfer_storage", erase)
    with pytest.raises(MaterialAccessDenied if issubclass(error_type, Exception) else error_type):
        provider.consume(binding, lease, request, lambda *_: MaterialUseOutcome.VERIFIED)
    assert set(erased) == {id(buffer) for buffer in resolver.buffers}
    assert all(not any(buffer) for buffer in resolver.buffers)


@pytest.mark.parametrize("method", ["validate", "consume", "revoke", "close"])
def test_lock_entry_cancellation_clears_owned_unused_lease(method):
    provider, resolver, binding, request, _, _ = make()
    lease, actual = provider.acquire_lease(binding, request), provider._lock
    class InterruptedLock:
        armed = True
        def __enter__(self):
            if self.armed:
                self.armed = False
                raise KeyboardInterrupt
            return actual.__enter__()
        def __exit__(self, *args): return actual.__exit__(*args)
    provider._lock = InterruptedLock()
    invoke = {"validate": lambda: provider.validate_binding(binding, request),
        "consume": lambda: provider.consume(binding, lease, request, lambda *_: MaterialUseOutcome.VERIFIED),
        "revoke": lambda: provider.revoke_lease(lease, reason=MaterialRevocationReason.CANCELLED), "close": provider.close}
    with pytest.raises(KeyboardInterrupt): invoke[method]()
    assert provider._closed and all(not any(buffer) for buffer in resolver.buffers)


@pytest.mark.parametrize("verified", [False, True])
def test_persistent_claim_survives_provider_and_store_recreation_without_reload(tmp_path, verified):
    provider, resolver, binding, request, _, draft = make()
    checkpoint = _ExternalMaterialCheckpoint()
    store = _store(tmp_path, monotonic_checkpoint=checkpoint, checkpoint_store_ref=checkpoint.tail.store_ref)
    wanted = MaterialUseOutcome.VERIFIED if verified else MaterialUseOutcome.AMBIGUOUS
    first = MaterialLeaseCoordinator(provider, store).execute_once(binding, request,
        lambda lease: provider.consume(binding, lease, request, lambda *_: wanted), now_epoch=1000)
    assert first is (MaterialRuntimeOutcome.VERIFIED_AND_RELEASED if verified else MaterialRuntimeOutcome.RECONCILIATION_REQUIRED)
    fresh_binding = module.ApprovalDeliveryMaterialBinding(draft)
    fresh_resolver = Resolver(fresh_binding.material_binding_digest)
    fresh_provider = module.ApprovalDeliveryMaterialProvider(fresh_resolver, fresh_binding, request, clock=lambda: 1000)
    reopened = PersistentMaterialUseStateStore(tmp_path / "material-state" / "material.db",
        tmp_path / "material-state" / "material.key", monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=checkpoint.tail.store_ref)
    replay = MaterialLeaseCoordinator(fresh_provider, reopened).execute_once(fresh_binding, request,
        lambda _: pytest.fail("Consumed or ambiguous material request must not run again."), now_epoch=1000)
    assert replay is first and resolver.loads == 1 and fresh_resolver.loads == 0
    assert all(not any(buffer) for buffer in resolver.buffers)
    persisted = (tmp_path / "material-state" / "material.db").read_bytes()
    assert not any(secret in persisted for secret in SYNTHETIC.values())
    fresh_provider.close()


def test_interrupted_persistent_claim_remains_uncertain_without_loading_on_reopen(tmp_path):
    provider, resolver, binding, request, _, draft = make()
    checkpoint = _ExternalMaterialCheckpoint()
    store = _store(tmp_path, monotonic_checkpoint=checkpoint, checkpoint_store_ref=checkpoint.tail.store_ref)
    def interrupted(*_): raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        MaterialLeaseCoordinator(provider, store).execute_once(binding, request,
            lambda lease: provider.consume(binding, lease, request, interrupted), now_epoch=1000)
    assert resolver.loads == 1 and all(not any(buffer) for buffer in resolver.buffers)
    fresh_binding = module.ApprovalDeliveryMaterialBinding(draft)
    fresh_resolver = Resolver(fresh_binding.material_binding_digest)
    fresh_provider = module.ApprovalDeliveryMaterialProvider(fresh_resolver, fresh_binding, request, clock=lambda: 1000)
    reopened = _store(tmp_path, monotonic_checkpoint=checkpoint, checkpoint_store_ref=checkpoint.tail.store_ref)
    result = MaterialLeaseCoordinator(fresh_provider, reopened).execute_once(fresh_binding, request,
        lambda _: pytest.fail("An interrupted claim must remain reconciliation-only."), now_epoch=1000)
    assert result is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED and fresh_resolver.loads == 0
    fresh_provider.close()


def test_binding_is_opaque_factory_derived_and_restore_has_independent_context():
    provider, _, binding, request, _, draft = make()
    restore = module.ApprovalDeliveryMaterialBinding(draft, restore=True)
    assert binding.intent_digest != restore.intent_digest and binding.action_id != restore.action_id
    assert binding.material_binding_digest == restore.material_binding_digest
    for value in (provider, binding):
        for operation in (copy, deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied): operation(value)
    with pytest.raises((TypeError, MaterialAccessDenied)):
        replace(binding, action_id=restore.action_id)
    with pytest.raises(MaterialAccessDenied):
        module.ApprovalDeliveryMaterialProvider(Resolver(restore.material_binding_digest), restore, request)
    provider.close()


@pytest.mark.parametrize("entry", ["acquire", "validate"])
def test_source_validation_cannot_reenter_loading_or_displace_owned_bundle(entry):
    provider, resolver, binding, request, _, _ = make()
    entered, nested, denied = [], [], []
    def reenter():
        if entered: return
        entered.append(True)
        try: nested.append(provider.acquire_lease(binding, request))
        except MaterialAccessDenied: denied.append(True)
    resolver.on_validate = reenter
    try:
        if entry == "validate":
            assert provider.validate_binding(binding, request) is MaterialBindingStatus.AVAILABLE
            assert resolver.loads == 0
        lease = provider.acquire_lease(binding, request)
        assert denied == [True] and nested == [] and resolver.loads == 1
        assert provider.consume(binding, lease, request, lambda *_: MaterialUseOutcome.VERIFIED) is MaterialUseOutcome.VERIFIED
    finally:
        provider.close()
    assert all(not any(buffer) for buffer in resolver.buffers)
