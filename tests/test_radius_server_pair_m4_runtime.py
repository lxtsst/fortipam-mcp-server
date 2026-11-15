"""Real M4/C3/source-pipe joins with synthetic authority, HTTP and fixtures."""
from __future__ import annotations

from dataclasses import replace
from contextvars import copy_context
import os
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.radius_server_pair_contract import ACTION_ID, ACTION_VERSION
from fortipam_mcp.radius_server_pair_material_provider import RadiusServerPairMaterialProvider
from fortipam_mcp.radius_server_pair_m4_runtime import (
    ADAPTER_REF, TARGET_REF, RadiusPairM4ExecutionBinding, RadiusPairM4Guard,
    ProtectedRadiusPairM4Runtime, expected_state_digest,
)
from v4_planning import M4AdapterDenied, M4AuthorizationDenied, M4ExecutionPlan, canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import MaterialAccessDenied, MaterialBindingStatus
from test_ldap_server_m4_runtime import _authorization
from test_radius_server_material_runtime import request as primary_request
from test_radius_server_pair_http_transport import Peer, transport
from test_radius_pair_fixture_material_worker import fixture
from test_radius_pair_fixture_material_loader import Factory, client, peer_script


class Authority:
    def __init__(self,issued: RadiusPairM4ExecutionBinding) -> None:
        self.issued=issued;self.denied=False
    def resolve_execution_binding(self,reference: str) -> RadiusPairM4ExecutionBinding:
        return self.issued
    def verify(self,plan: Any,auth: Any,*,now_epoch: int) -> None:
        if (self.denied or plan is not self.issued.plan or auth is not self.issued.authorization
                or not 100 <= now_epoch < 160):raise M4AuthorizationDenied('Synthetic policy denied.')


def plan_for(peer: Peer,current: str) -> M4ExecutionPlan:
    values=dict(plan_ref='pair-plan-synthetic-01',revision=1,action_id=ACTION_ID,action_version=ACTION_VERSION,
        adapter_ref=ADAPTER_REF,target_ref=TARGET_REF,requester_digest='1'*64,summary_digest='2'*64,
        confirmation_digest='3'*64,approval_digest='4'*64,parameters_digest=peer.binding.parameters_digest,
        expected_current_digest=current,expected_state_digest=expected_state_digest(peer.binding),
        idempotency_digest='5'*64,expires_at=160,compensation_ref=None)
    return M4ExecutionPlan(**values,plan_digest=canonical_digest(values))


def store(root: Path,role: str,m4: bool=False) -> Any:
    d=root/role;d.mkdir(mode=0o700,exist_ok=True)
    key=d/'key'
    if not key.exists():key.write_bytes(os.urandom(32));key.chmod(0o600)
    cls=PersistentM4ExecutionStateStore if m4 else PersistentMaterialUseStateStore
    return cls(d/'ledger.sqlite',key)


def setup(root: Path,*,enabled: bool=True,lose_primary: bool=False) -> tuple[Any,...]:
    peer=Peer();now=[100];state=root/'http'
    current=transport(state,peer).inspect_create()
    p=plan_for(peer,current.state_digest);auth=_authorization(p)
    req=replace(primary_request(),action_id=ACTION_ID,plan_digest=p.plan_digest,
        authorization_digest=auth.authorization_digest)
    issued=RadiusPairM4ExecutionBinding(p,auth,peer.binding,req,req.policy_decision_digest,req.scope_digest,req.audience_digest)
    authority=Authority(issued);guard=RadiusPairM4Guard()
    incoming,inspections,_=fixture(root/'fixture')
    factory=Factory(peer_script(root/'fixture',inspections,lose_primary_reply=lose_primary))
    source=client(root,factory,selected=peer.binding,digest=incoming['source_policy_digest'],guard=guard,
        acquisition_guard=guard.authorize_acquisition,now=now)
    execution,usage,group=store(root,'m4',True),store(root,'usage'),store(root,'group')
    provider=RadiusServerPairMaterialProvider(source,binding=peer.binding,request=req,
        source_policy_digest=incoming['source_policy_digest'],source_reservation_store=group,
        execution_guard=guard,acquisition_enabled=True,clock=lambda:now[0])
    writer=transport(state,peer,execution_enabled=True,execution_request=req,
        expected_current_digest=current.state_digest,create_authorizer=guard.authorize_create,clock=lambda:now[0])
    runtime=ProtectedRadiusPairM4Runtime(authority,authority,execution,usage,provider,writer,
        authenticated_requester_digest='1'*64,execution_enabled=enabled,clock=lambda:now[0])
    return runtime,peer,source,factory,issued,authority,now,execution,usage,group


def test_original_kernel_acquisition_scope_reaches_both_sources_and_one_pair_post(tmp_path: Path) -> None:
    runtime,peer,source,factory,issued,authority,now,m4,usage,group=setup(tmp_path)
    assert source.validate_prebound(peer.binding,issued.lease_request,source._source_digest) is MaterialBindingStatus.UNAVAILABLE
    assert not factory.calls
    result=runtime.execute_bound(issued.authorization.authorization_ref)
    assert result.outcome=='succeeded' and result.verification=='verified'
    assert peer.posts==m4.claim_count==usage.claim_count==group.claim_count==1 and len(factory.calls)==4
    assert runtime._transport.inspect_owned() and all(not any(b) for b in peer.bodies)
    count=len(factory.calls);connections=len(peer.connections)
    replay=runtime.execute_bound(issued.authorization.authorization_ref)
    assert replay.idempotent_replay and peer.posts==1 and len(factory.calls)==count and len(peer.connections)==connections
    with pytest.raises(M4AuthorizationDenied):runtime._guard(peer.binding,issued.lease_request)
    runtime.close()
    assert not runtime._enabled and not source._enabled and not runtime._provider._enabled and not runtime._transport._execution_enabled


@pytest.mark.parametrize('fault',['gate','authority','requester','origin','source_policy','guard','loader','store','key','native_gate'])
def test_gate_authority_or_namespace_drift_cannot_reach_source_or_post(tmp_path: Path,fault: str) -> None:
    runtime,peer,source,factory,issued,authority,now,m4,usage,group=setup(tmp_path,enabled=fault!='gate')
    original_key=usage._key
    if fault=='native_gate':runtime._transport._owned_connect_enabled=True
    elif fault=='authority':authority.denied=True
    elif fault=='requester':runtime._requester_digest='f'*64
    elif fault=='origin':runtime._transport._config=replace(runtime._transport._config,base_url='https://other.example')
    elif fault=='source_policy':source._source_digest='f'*64
    elif fault=='guard':source._guard=lambda *a:None
    elif fault=='loader':runtime._provider._loader=object()
    elif fault=='store':runtime._material_store=group
    elif fault=='key':runtime._material_store._key=group._key
    with pytest.raises((M4AdapterDenied,M4AuthorizationDenied)):runtime.execute_bound(issued.authorization.authorization_ref)
    usage._key=original_key
    assert not factory.calls and peer.posts==usage.claim_count==group.claim_count==0
    assert m4.claim_count==int(fault=='authority')


@pytest.mark.parametrize('fault',['primary_reply','lost_ack','full_state','drift_before_http','close_before_http'])
def test_partial_or_uncertain_create_keeps_all_claims_and_never_reacquires(tmp_path: Path,fault: str) -> None:
    runtime,peer,source,factory,issued,authority,now,m4,usage,group=setup(tmp_path,lose_primary=fault=='primary_reply')
    if fault=='lost_ack':peer.lost_post_ack=True
    elif fault=='full_state':peer.failed_readback=True
    elif fault in {'drift_before_http','close_before_http'}:
        original=source.load_endpoint_once
        def changed(*args: Any,**kwargs: Any) -> bytearray:
            value=original(*args,**kwargs)
            if args[2]=='secondary':
                if fault=='drift_before_http':peer.defaults['timeout']=15
                else:runtime.close()
            return value
        # Replace only the exact source instance's class method; the concrete
        # original source still performs every pipe/worker check first.
        from unittest.mock import patch
        with patch.object(type(source),'load_endpoint_once',lambda self,*a,**k:changed(*a,**k)):
            result=runtime.execute_bound(issued.authorization.authorization_ref)
    if fault not in {'drift_before_http','close_before_http'}:
        result=runtime.execute_bound(issued.authorization.authorization_ref)
    assert result.outcome=='reconciliation_required' and result.verification=='unknown'
    assert m4.claim_count==usage.claim_count==group.claim_count==1
    assert peer.posts==int(fault in {'lost_ack','full_state'})
    assert all(not any(body) for body in peer.bodies)
    before=len(factory.calls)
    if runtime._enabled:
        assert runtime.execute_bound(issued.authorization.authorization_ref).idempotent_replay
    assert len(factory.calls)==before
    with pytest.raises(M4AuthorizationDenied):runtime._guard(peer.binding,issued.lease_request)


def test_persisted_in_progress_cannot_reconstitute_original_source_ownership(tmp_path: Path) -> None:
    runtime,peer,source,factory,issued,authority,now,m4,usage,group=setup(tmp_path)
    p,a=issued.plan,issued.authorization
    m4.claim(plan_ref=p.plan_ref,requester_digest=p.requester_digest,idempotency_digest=p.idempotency_digest,
        authorization_digest=a.authorization_digest,context_digest=canonical_digest({
            'authorization_digest':a.authorization_digest,'plan_digest':p.plan_digest,'revision':p.revision}))
    runtime._active_binding=issued
    with pytest.raises(M4AuthorizationDenied):runtime._guard(peer.binding,issued.lease_request)
    runtime._active_binding=None
    result=runtime.execute_bound(a.authorization_ref)
    assert result.outcome=='reconciliation_required' and not factory.calls and peer.posts==usage.claim_count==group.claim_count==0


def test_material_guard_requires_the_acquisition_slot_even_inside_original_dispatch(tmp_path: Path) -> None:
    from v4_planning.execution_kernel import M4ExecutionKernel,_reserve_m4_material_acquisition
    runtime,peer,source,factory,issued,authority,now,m4,usage,group=setup(tmp_path)
    seen=[]
    class Adapter:
        def read_current(self,plan: Any) -> str:return plan.expected_current_digest
        def dispatch(self,plan: Any) -> None:
            runtime._active_binding=issued
            with pytest.raises(M4AuthorizationDenied):runtime._guard(peer.binding,issued.lease_request)
            _reserve_m4_material_acquisition(plan,issued.authorization,m4)
            runtime._guard(peer.binding,issued.lease_request);seen.append(True)
            with pytest.raises(MaterialAccessDenied):
                source.load_endpoint_once(peer.binding,issued.lease_request,'primary',source._source_digest)
            assert not factory.calls
            runtime._active_binding=None
        def read_postcondition(self,plan: Any) -> str:return plan.expected_state_digest
    result=M4ExecutionKernel(Adapter(),authority,m4,clock=lambda:100).execute(issued.plan,issued.authorization)
    assert result.outcome=='succeeded' and seen==[True] and not factory.calls and peer.posts==0


def test_foreign_request_scope_is_rejected_before_any_claim_or_source(tmp_path: Path) -> None:
    runtime,peer,source,factory,issued,authority,now,m4,usage,group=setup(tmp_path)
    altered=replace(issued.lease_request,scope_digest='f'*64)
    authority.issued=RadiusPairM4ExecutionBinding(issued.plan,issued.authorization,issued.material_binding,
        altered,altered.policy_decision_digest,altered.scope_digest,altered.audience_digest)
    with pytest.raises(M4AuthorizationDenied):runtime.execute_bound(issued.authorization.authorization_ref)
    assert not factory.calls and peer.posts==m4.claim_count==usage.claim_count==group.claim_count==0


def test_copied_original_dispatch_context_cannot_revive_material_guard_after_success(tmp_path: Path) -> None:
    runtime,peer,source,factory,issued,authority,now,m4,usage,group=setup(tmp_path)
    contexts=[]
    def capture() -> None:
        if runtime._active_binding is not None:contexts.append(copy_context())
    peer.on_connect=capture
    assert runtime.execute_bound(issued.authorization.authorization_ref).outcome=='succeeded' and contexts
    runtime._active_binding=issued
    with pytest.raises(M4AuthorizationDenied):contexts[0].run(runtime._guard,peer.binding,issued.lease_request)
    runtime._active_binding=None
    assert len(factory.calls)==4 and peer.posts==1
