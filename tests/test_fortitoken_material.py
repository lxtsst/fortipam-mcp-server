"""Private FortiToken leases with synthetic selectors and actual durable claims."""
from copy import copy, deepcopy
from dataclasses import replace
import json
import pickle

import pytest

from fortipam_mcp.fortitoken_material import FortitokenMaterialBinding, FortitokenMaterialProvider
from fortipam_mcp.fortitoken_user_contract import FortitokenUserPlan
from test_fortitoken_user_contract import TOKEN, NAME
from test_fortitoken_user_source import Peer
from test_v4_material_persistence import _ExternalMaterialCheckpoint
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import (MaterialAccessDenied, MaterialBindingStatus, MaterialLease,
    MaterialLeaseRequest, MaterialProviderClass, MaterialPurpose, MaterialRevocationReason)
from v4_planning.material_runtime import MaterialLeaseCoordinator, MaterialRuntimeOutcome, MaterialUseOutcome


class Resolver:
    def __init__(self, reference='a'*64):
        self.binding_digest = reference; self.status = MaterialBindingStatus.AVAILABLE
        self.loads = 0; self.buffers = []; self.material = TOKEN; self.on_load = None
    def validate_prebound(self): return self.status
    def load_token_once(self):
        self.loads += 1; value = bytearray(self.material); self.buffers.append(value)
        if self.on_load: self.on_load()
        return value


def make(operation='assign', **changes):
    peer = Peer(operation); source = peer.reader(); plan = FortitokenUserPlan(source.read().state,operation)
    binding = FortitokenMaterialBinding(plan)
    request = MaterialLeaseRequest(binding.action_id,'1.0.0','1'*64,'2'*64,'3'*64,'4'*64,'5'*64,
        MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE,binding.purpose,1000,1060)
    if changes: request = replace(request,**changes)
    resolver = Resolver(); provider = FortitokenMaterialProvider(resolver,binding,request,clock=peer.clock)
    return peer,source,plan,provider,resolver,binding,request


@pytest.mark.parametrize('operation,purpose', [('assign',MaterialPurpose.INITIAL_ONBOARDING),('revoke',MaterialPurpose.JIT_DELIVERY)])
def test_exact_action_purpose_one_readonly_use_and_cleared_buffers(operation,purpose):
    peer,_,_,provider,resolver,binding,request = make(operation); views = []
    assert binding.purpose is purpose and binding.token_reference_digest == 'a'*64
    def consumer(lease):
        def use(view):
            assert view.readonly and view == TOKEN; views.append(view)
            return MaterialUseOutcome.VERIFIED
        return provider.consume(binding,lease,request,use)
    assert MaterialLeaseCoordinator(provider).execute_once(binding,request,consumer,
        now_epoch=peer.clock()) is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert resolver.loads == 1 and all(not any(raw) for raw in resolver.buffers)
    with pytest.raises(ValueError): bytes(views[0])
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding,request)


@pytest.mark.parametrize('operation,purpose', [('assign',MaterialPurpose.JIT_DELIVERY),('revoke',MaterialPurpose.INITIAL_ONBOARDING)])
def test_restore_material_action_and_purpose_are_separate_from_the_consumed_forward_request(operation,purpose):
    _,_,intent,_,_,_,_ = make(operation)
    binding = FortitokenMaterialBinding(intent,restore=True)
    assert binding.action_id == 'fortitoken-user-'+operation+'-restore' and binding.purpose is purpose
    assert binding.intent_digest != intent.digest and binding.token_reference_digest == 'a'*64


@pytest.mark.parametrize('changes', [dict(action_id='scim-client-disable'),dict(action_version='2.0.0'),
    dict(purpose=MaterialPurpose.CREDENTIAL_ROTATION),dict(expires_at=1061),
    dict(provider_class=MaterialProviderClass.EXTERNAL_VAULT_LEASE)])
def test_foreign_action_purpose_source_or_window_cannot_load(changes):
    with pytest.raises(MaterialAccessDenied): make(**changes)


@pytest.mark.parametrize('status', [False,True,'available',MaterialBindingStatus.UNAVAILABLE])
def test_source_status_must_be_authoritative(status):
    _,_,_,provider,resolver,binding,request = make(); resolver.status = status
    assert provider.validate_binding(binding,request) is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding,request)
    assert resolver.loads == 0


@pytest.mark.parametrize('fault', ['expire','rollback','reference','source-status','bad-bytes','oversize'])
def test_loading_failure_clears_the_transfer_and_never_reloads(fault):
    peer,_,_,provider,resolver,binding,request = make()
    if fault == 'expire': resolver.on_load = lambda:setattr(peer.clock,'value',1060)
    elif fault == 'rollback': resolver.on_load = lambda:setattr(peer.clock,'value',999)
    elif fault == 'reference': resolver.on_load = lambda:setattr(resolver,'binding_digest','f'*64)
    elif fault == 'source-status': resolver.on_load = lambda:setattr(resolver,'status',MaterialBindingStatus.UNAVAILABLE)
    elif fault == 'bad-bytes': resolver.material = b'bad\x00selector'
    else: resolver.material = b'x'*129
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding,request)
    assert resolver.loads == 1 and all(not any(raw) for raw in resolver.buffers)
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding,request)
    assert resolver.loads == 1


@pytest.mark.parametrize('fault', ['exception','interrupt','invalid-result','expire','source-revoked'])
def test_consumer_failure_revokes_views_and_clears_owned_material(fault):
    peer,_,_,provider,resolver,binding,request = make(); lease = provider.acquire_lease(binding,request); views = []
    def use(view):
        views.append(view)
        if fault == 'exception': raise RuntimeError('SYNTHETIC_FAILURE')
        if fault == 'interrupt': raise KeyboardInterrupt
        if fault == 'expire': peer.clock.value = 1060
        if fault == 'source-revoked': resolver.status = MaterialBindingStatus.UNAVAILABLE
        return True if fault == 'invalid-result' else MaterialUseOutcome.VERIFIED
    if fault in ('exception','interrupt'):
        with pytest.raises(RuntimeError if fault == 'exception' else KeyboardInterrupt): provider.consume(binding,lease,request,use)
    else: assert provider.consume(binding,lease,request,use) is not MaterialUseOutcome.VERIFIED
    assert all(not any(raw) for raw in resolver.buffers)
    with pytest.raises(ValueError): bytes(views[0])
    assert provider.consume(binding,lease,request,use) is MaterialUseOutcome.FAILED


def test_expiry_and_source_revocation_clear_an_unused_lease_on_the_next_boundary():
    for expired in (True,False):
        peer,_,_,provider,resolver,binding,request = make(); provider.acquire_lease(binding,request)
        if expired: peer.clock.value = 1060
        else: resolver.status = MaterialBindingStatus.UNAVAILABLE
        assert provider.validate_binding(binding,request) is not MaterialBindingStatus.AVAILABLE
        assert all(not any(raw) for raw in resolver.buffers)


def test_foreign_lease_is_not_consumed_and_wrong_owned_context_is_terminal():
    _,_,_,provider,resolver,binding,request = make(); lease = provider.acquire_lease(binding,request)
    assert provider.consume(binding,MaterialLease(),request,lambda view:MaterialUseOutcome.VERIFIED) is MaterialUseOutcome.FAILED
    assert any(resolver.buffers[0])
    assert provider.consume(binding,lease,replace(request,audience_digest='6'*64),
        lambda view:MaterialUseOutcome.VERIFIED) is MaterialUseOutcome.FAILED
    assert not any(resolver.buffers[0])


def test_unexpected_loader_pair_and_private_objects_are_cleared_or_opaque():
    _,_,_,provider,resolver,binding,request = make()
    buffers = (bytearray(TOKEN),bytearray(b'SYNTHETIC_OTHER'))
    resolver.load_token_once = lambda:buffers
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding,request)
    assert all(not any(raw) for raw in buffers)
    for value in (provider,binding):
        assert NAME not in repr(value) and TOKEN.decode('ascii') not in repr(value)
        for transform in (copy,deepcopy,pickle.dumps):
            with pytest.raises(MaterialAccessDenied): transform(value)


@pytest.mark.parametrize('operation,fault', [('assign',None),('revoke',None),('assign','wrong-token'),
    ('assign','lost-ack'),('revoke','normalization'),('assign','preservation'),('assign','interrupt')])
def test_durable_material_claim_joins_real_codec_reads_and_strict_local_postcondition_without_replay(tmp_path,operation,fault):
    peer,source,plan,provider,resolver,binding,request = make(operation)
    key = tmp_path/'material.key'; key.write_bytes(b'm'*32); key.chmod(0o600)
    store = PersistentMaterialUseStateStore(tmp_path/'material.db',key,
        monotonic_checkpoint=_ExternalMaterialCheckpoint('ftk-material-local'),checkpoint_store_ref='ftk-material-local')
    bodies = []; sends = []
    def consume(lease):
        def use(view):
            body = source.compile_body(plan,token_reference_digest=binding.token_reference_digest,token=view); bodies.append(body)
            try:
                # The synthetic product retains omitted fields; this is a
                # strict local expectation, never native normalization evidence.
                values = json.loads(body)
                for name,value in values.items():
                    if name == '$originalName': continue
                    if name == 'webauthn': peer.user[name].update(value)
                    else: peer.user[name] = value
                sends.append(True)
                if fault == 'lost-ack': raise TimeoutError('SYNTHETIC_PRIVATE_ACK_LOSS')
                if fault == 'interrupt': raise KeyboardInterrupt
                if fault == 'wrong-token': peer.user['fortitoken'] = 'SYNTHETIC_OTHER_TOKEN'
                if fault == 'normalization': peer.user['two-factor-authentication'] = 'email'
                if fault == 'preservation': peer.user['gui-custom-conf'] = 'enable'
                observed = source.read_matching_token(token_reference_digest=binding.token_reference_digest,token=view)\
                    if operation == 'assign' else source.read()
                source.verify_postcondition(plan,observed)
                return MaterialUseOutcome.VERIFIED
            finally: body[:] = b'\0'*len(body)
        return provider.consume(binding,lease,request,use)
    coordinator = MaterialLeaseCoordinator(provider,store)
    if fault == 'interrupt':
        with pytest.raises(KeyboardInterrupt): coordinator.execute_once(binding,request,consume,now_epoch=1000)
        outcome = MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    else: outcome = coordinator.execute_once(binding,request,consume,now_epoch=1000)
    assert (outcome is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED) is (fault is None)
    assert len(sends) == resolver.loads == store.claim_count == 1
    renewed = Resolver(); other = FortitokenMaterialProvider(renewed,binding,request,clock=peer.clock)
    replay = MaterialLeaseCoordinator(other,store).execute_once(binding,request,
        lambda lease:pytest.fail('A consumed material request must not run again.'),now_epoch=1000)
    assert replay is outcome and renewed.loads == 0 and store.claim_count == 1
    assert all(not any(raw) for raw in bodies+resolver.buffers+peer.buffers)
    assert all(resource.closed for resource in peer.resources)
    for path in tmp_path.iterdir():
        if path.is_file():
            data = path.read_bytes(); assert TOKEN not in data and NAME.encode() not in data
