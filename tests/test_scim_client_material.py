"""One-use SCIM material: synthetic buffers, real shared lease coordinator."""
from dataclasses import replace

import pytest

from fortipam_mcp.scim_client_material import ScimMaterialBinding, ScimMaterialProvider
from test_scim_client_contract import prepared, OLD, NEW
from test_system_email_m4_adapter import Clock
from v4_planning.material_provider import (MaterialAccessDenied, MaterialBindingStatus, MaterialLease,
    MaterialLeaseRequest, MaterialProviderClass, MaterialPurpose, MaterialRevocationReason)
from v4_planning.material_runtime import MaterialLeaseCoordinator, MaterialRuntimeOutcome, MaterialUseOutcome


class Resolver:
    def __init__(self, binding=NEW, material=b'synthetic-new-secret'):
        self.binding_digest = binding; self.material = material; self.loads = 0; self.buffers = []
        self.status = MaterialBindingStatus.AVAILABLE; self.on_load = None
    def validate_prebound(self): return self.status
    def load_scim_material_once(self):
        self.loads += 1
        value = bytearray(self.material); self.buffers.append(value)
        if self.on_load: self.on_load()
        return value


def make(operation='rotate', restore=False, **changes):
    transition, _, _ = prepared(operation)
    binding = ScimMaterialBinding(transition, restore=restore)
    request = MaterialLeaseRequest(binding.action_id, '1.0.0', '3'*64, '4'*64, '5'*64, '6'*64, '7'*64,
        MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE, binding.purpose, 1000, 1060)
    if changes: request = replace(request, **changes)
    resolver = Resolver(binding.material_binding_digest); clock = Clock()
    provider = ScimMaterialProvider(resolver, binding, request, clock=clock)
    return provider, resolver, binding, request, clock


@pytest.mark.parametrize('operation,restore,purpose', [('create', False, MaterialPurpose.INITIAL_ONBOARDING),
    ('rotate', False, MaterialPurpose.CREDENTIAL_ROTATION), ('rotate', True, MaterialPurpose.CREDENTIAL_ROTATION),
    ('disable', False, MaterialPurpose.JIT_DELIVERY), ('disable', True, MaterialPurpose.JIT_DELIVERY)])
def test_exact_scim_purpose_and_single_private_readonly_consumption(operation, restore, purpose):
    provider, resolver, binding, request, _ = make(operation, restore)
    assert request.purpose is purpose and binding.material_binding_digest == (OLD if restore or operation == 'disable' else NEW)
    views = []
    def consumer(lease):
        def use(view):
            assert view.readonly and bytes(view) == b'synthetic-new-secret'
            views.append(view)
            return MaterialUseOutcome.VERIFIED
        return provider.consume(binding, lease, request, use)
    coordinator = MaterialLeaseCoordinator(provider)
    assert coordinator.execute_once(binding, request, consumer, now_epoch=1000) is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert resolver.loads == 1 and all(not any(buffer) for buffer in resolver.buffers)
    with pytest.raises(ValueError): bytes(views[0])
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding, request)


@pytest.mark.parametrize('changes', [dict(action_id='scim-client-create'), dict(action_version='2.0.0'),
    dict(purpose=MaterialPurpose.INITIAL_ONBOARDING), dict(expires_at=1061),
    dict(provider_class=MaterialProviderClass.EXTERNAL_VAULT_LEASE)])
def test_foreign_action_purpose_source_or_long_window_cannot_load_material(changes):
    with pytest.raises(MaterialAccessDenied): make(**changes)


@pytest.mark.parametrize('status', [False, True, 'available', MaterialBindingStatus.UNAVAILABLE])
def test_non_authoritative_or_unavailable_resolver_status_is_not_availability(status):
    provider, resolver, binding, request, _ = make(); resolver.status = status
    assert provider.validate_binding(binding, request) is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding, request)
    assert resolver.loads == 0


@pytest.mark.parametrize('fault', ['expired-load', 'rollback-load', 'source-drift', 'bad-bytes', 'oversize'])
def test_failed_loading_attempt_clears_material_and_never_reloads(fault):
    provider, resolver, binding, request, clock = make()
    if fault == 'expired-load': resolver.on_load = lambda: setattr(clock, 'value', 1060)
    elif fault == 'rollback-load': resolver.on_load = lambda: setattr(clock, 'value', 999)
    elif fault == 'source-drift': resolver.on_load = lambda: setattr(resolver, 'binding_digest', OLD)
    elif fault == 'bad-bytes': resolver.material = b'bad\x00material'
    else: resolver.material = b'a'*60
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding, request)
    assert resolver.loads == 1 and all(not any(buffer) for buffer in resolver.buffers)
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding, request)
    assert resolver.loads == 1


def test_expired_unused_lease_is_cleared_on_the_next_boundary_check():
    provider, resolver, binding, request, clock = make()
    lease = provider.acquire_lease(binding, request); assert any(resolver.buffers[0])
    clock.value = 1060
    assert provider.validate_binding(binding, request) is not MaterialBindingStatus.AVAILABLE
    assert not any(resolver.buffers[0])
    assert provider.consume(binding, lease, request, lambda view: MaterialUseOutcome.VERIFIED) is not MaterialUseOutcome.VERIFIED


@pytest.mark.parametrize('fault', ['exception', 'interrupt', 'invalid-return', 'expired-use'])
def test_consumption_failure_always_releases_the_view_and_clears_the_buffer(fault):
    provider, resolver, binding, request, clock = make()
    lease = provider.acquire_lease(binding, request); views = []
    def use(view):
        views.append(view)
        if fault == 'exception': raise RuntimeError('synthetic-failure')
        if fault == 'interrupt': raise KeyboardInterrupt
        if fault == 'expired-use': clock.value = 1060; return MaterialUseOutcome.VERIFIED
        return True
    if fault in ('exception', 'interrupt'):
        with pytest.raises(RuntimeError if fault == 'exception' else KeyboardInterrupt): provider.consume(binding, lease, request, use)
    else: assert provider.consume(binding, lease, request, use) is not MaterialUseOutcome.VERIFIED
    assert not any(resolver.buffers[0])
    with pytest.raises(ValueError): bytes(views[0])
    assert provider.consume(binding, lease, request, use) is MaterialUseOutcome.FAILED
    provider.revoke_lease(lease, reason=MaterialRevocationReason.RECONCILIATION_REQUIRED)


def test_foreign_lease_does_not_consume_owned_material_but_wrong_owned_context_is_terminal():
    provider, resolver, binding, request, _ = make(); lease = provider.acquire_lease(binding, request)
    assert provider.consume(binding, MaterialLease(), request, lambda view: MaterialUseOutcome.VERIFIED) is MaterialUseOutcome.FAILED
    assert any(resolver.buffers[0])
    assert provider.consume(binding, lease, replace(request, audience_digest='8'*64),
        lambda view: MaterialUseOutcome.VERIFIED) is MaterialUseOutcome.FAILED
    assert not any(resolver.buffers[0])


def test_unexpected_pair_return_clears_transferred_buffers_without_accepting_a_legacy_loader():
    provider, resolver, binding, request, _ = make()
    buffers = (bytearray(b'synthetic-username'), bytearray(b'synthetic-password'))
    resolver.load_scim_material_once = lambda: buffers
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding, request)
    assert all(not any(buffer) for buffer in buffers)
