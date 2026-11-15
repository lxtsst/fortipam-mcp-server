"""Real persistent C3 claims with synthetic guarded paired sources and consumers."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import copy
import json
from pathlib import Path
import pickle
from typing import Any

import pytest

from fortipam_mcp.radius_server_contract import RadiusServerCreateOutcome
from fortipam_mcp.radius_server_pair_contract import ACTION_ID, pair_create_body
from fortipam_mcp.radius_server_pair_material_provider import RadiusServerPairMaterialProvider, RadiusServerPairLeaseTransport
from fortipam_mcp.secret_metadata_http_transport import _zeroize_mutable
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import (
    MaterialAccessDenied, MaterialBindingStatus, MaterialContractError, MaterialLease,
    MaterialLeaseCompletion, MaterialProviderClass, MaterialPurpose, MaterialRevocationReason,
)
from v4_planning.material_runtime import MaterialLeaseCoordinator, MaterialRuntimeOutcome, MaterialUseOutcome
from test_radius_server_pair_contract import binding
from test_radius_server_material_runtime import request as primary_request


def store(root: Path, name: str) -> PersistentMaterialUseStateStore:
    d=root/name;d.mkdir(mode=0o700,exist_ok=True)
    key=d/'key'
    if not key.exists():key.write_bytes(b'K'*32);key.chmod(0o600)
    return PersistentMaterialUseStateStore(d/'ledger.sqlite',key)


class Loader:
    def __init__(self) -> None:
        self.calls: list[str]=[];self.buffers: list[bytearray]=[]
        self.fault: str | None=None;self.on_load: Any=None;self.provider: Any=None
        self.validations=0

    def validate_prebound(self, b: Any, r: Any, source: str) -> MaterialBindingStatus:
        assert b is self.provider._binding and r==self.provider._request and source=='b'*64
        self.validations+=1
        return MaterialBindingStatus.AVAILABLE

    def load_endpoint_once(self, b: Any, r: Any, ordinal: str, source: str) -> Any:
        assert b is self.provider._binding and r==self.provider._request and source=='b'*64
        assert self.provider._store.claim_count==1
        self.calls.append(ordinal)
        value=bytearray((b'A' if ordinal=='primary' else b'B')*32)
        self.buffers.append(value)
        try:
            if self.on_load:self.on_load(ordinal)
            if ordinal=='secondary':
                if self.fault=='exception':raise RuntimeError('SYNTHETIC_PRIVATE')
                if self.fault=='short':value.pop()
                if self.fault=='same_value':value[:]=b'A'*32
                if self.fault=='alias':return self.buffers[0]
                if self.fault=='primary_drift':self.buffers[0][0]=0
                if self.fault=='malformed':return [value]
            return value
        except BaseException:
            _zeroize_mutable(value)
            raise
        finally:
            if ordinal=='secondary' and self.fault=='alias':_zeroize_mutable(value)


class Consumer:
    def __init__(self) -> None:
        self.calls=0;self.views: list[memoryview]=[];self.callback: Any=None
        self.result: Any=RadiusServerCreateOutcome.VERIFIED_CREATED

    def _create_and_verify_pair_material(self, b: Any, r: Any, p: memoryview, s: memoryview) -> Any:
        self.calls+=1
        assert p.readonly and s.readonly and bytes(p)==b'A'*32 and bytes(s)==b'B'*32
        self.views.extend((p[:],s[:]))
        body=pair_create_body(b,p,s)
        try:
            assert len(json.loads(body))==7
            if self.callback:self.callback()
            if isinstance(self.result,BaseException):raise self.result
            return self.result
        finally:_zeroize_mutable(body)


def setup(root: Path, *, enabled: bool=True, loader: Loader | None=None,
          now: list[int] | None=None, group: PersistentMaterialUseStateStore | None=None,
          request: Any=None, binding_value: Any=None, guard: Any=None) -> tuple[Any,...]:
    selected=binding() if binding_value is None else binding_value
    req=replace(primary_request(),action_id=ACTION_ID) if request is None else request
    clock=[100] if now is None else now
    source=Loader() if loader is None else loader
    reservations=store(root,'source-group') if group is None else group
    p=RadiusServerPairMaterialProvider(source,binding=selected,request=req,source_policy_digest='b'*64,
        source_reservation_store=reservations,execution_guard=guard or (lambda b,r:None),
        acquisition_enabled=enabled,clock=lambda:clock[0])
    source.provider=p
    return p,source,selected,req,clock,reservations


def run(root: Path,p: Any,b: Any,r: Any,c: Consumer) -> MaterialRuntimeOutcome:
    return MaterialLeaseCoordinator(p,store(root,'usage')).execute_once(b,r,
        RadiusServerPairLeaseTransport(p,c).consume,now_epoch=100)


def cleared(loader: Loader, consumer: Consumer) -> None:
    assert all(not any(value) for value in loader.buffers)
    assert all(not any(value) for value in consumer.views)


def test_atomic_handoff_finalizes_two_durable_ledgers_and_denies_rebuilt_or_renewed_intake(tmp_path: Path) -> None:
    p,loader,b,r,now,group=setup(tmp_path);c=Consumer()
    assert run(tmp_path,p,b,r,c) is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert loader.calls==['primary','secondary'] and c.calls==1
    assert group.claim_count==store(tmp_path,'usage').claim_count==1
    cleared(loader,c)
    for req in (r,replace(r,authorization_digest='f'*64,plan_digest='e'*64),
                replace(r,requested_at=101,expires_at=161)):
        rebuilt,other,b2,_,_,_=setup(tmp_path,request=req,binding_value=b,now=[req.requested_at])
        assert rebuilt.validate_binding(b,req) is MaterialBindingStatus.UNAVAILABLE
        with pytest.raises(MaterialAccessDenied):rebuilt.acquire_lease(b,req)
        assert other.calls==[] and other.validations==0
    assert loader.calls==['primary','secondary']


@pytest.mark.parametrize('fault',['exception','short','same_value','alias','primary_drift','malformed'])
def test_second_source_failure_or_invalid_pair_clears_every_returned_buffer_and_cannot_retry(tmp_path: Path,fault: str) -> None:
    p,loader,b,r,now,group=setup(tmp_path);loader.fault=fault;c=Consumer()
    assert run(tmp_path,p,b,r,c) is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert c.calls==0 and loader.calls==['primary','secondary'] and group.claim_count==1
    cleared(loader,c)
    with pytest.raises(MaterialAccessDenied):p.acquire_lease(b,r)
    assert loader.calls==['primary','secondary']


@pytest.mark.parametrize('stage',['reserved','primary','secondary','consume'])
def test_close_or_expiry_during_each_phase_prevents_verified_handoff(tmp_path: Path,stage: str) -> None:
    group=store(tmp_path,'source-group');holder=[]
    def guard(b: Any,r: Any) -> None:
        if stage=='reserved' and group.claim_count:holder[0].close()
    p,loader,b,r,now,_=setup(tmp_path,group=group,guard=guard);holder.append(p);c=Consumer()
    def loaded(ordinal: str) -> None:
        if stage==ordinal:now[0]=160
    loader.on_load=loaded
    if stage=='consume':c.callback=p.close
    assert run(tmp_path,p,b,r,c) is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert c.calls==int(stage=='consume') and group.claim_count==1
    cleared(loader,c)


@pytest.mark.parametrize('result',[RadiusServerCreateOutcome.RECONCILIATION_REQUIRED,
    TimeoutError('SYNTHETIC_PRIVATE'),RuntimeError('SYNTHETIC_PRIVATE'),'untrusted-success'])
def test_transport_uncertainty_consumes_pair_and_wipes_retained_views(tmp_path: Path,result: Any) -> None:
    p,loader,b,r,now,group=setup(tmp_path);c=Consumer();c.result=result
    assert run(tmp_path,p,b,r,c) is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert c.calls==1 and group.claim_count==1
    cleared(loader,c)
    assert p.validate_binding(b,r) is MaterialBindingStatus.UNAVAILABLE


def test_disabled_wrong_binding_and_clock_rollback_never_load_sources(tmp_path: Path) -> None:
    p,loader,b,r,now,group=setup(tmp_path,enabled=False)
    assert p.validate_binding(b,r) is MaterialBindingStatus.UNAVAILABLE
    assert p.validate_binding(binding(),r) is MaterialBindingStatus.INCOMPATIBLE
    with pytest.raises(MaterialAccessDenied):p.acquire_lease(b,r)
    assert loader.calls==[] and loader.validations==group.claim_count==0
    q,source,b,r,clock,_=setup(tmp_path)
    assert q.validate_binding(b,r) is MaterialBindingStatus.AVAILABLE
    clock[0]=99
    assert q.validate_binding(b,r) is MaterialBindingStatus.UNAVAILABLE
    clock[0]=100
    assert q.validate_binding(b,r) is MaterialBindingStatus.UNAVAILABLE
    assert source.calls==[]


def test_guard_denial_and_uncertain_reservation_commit_precede_material(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    p,loader,b,r,now,group=setup(tmp_path)
    original=PersistentMaterialUseStateStore.claim
    def lost(self: Any,**kwargs: Any) -> Any:
        original(self,**kwargs)
        raise RuntimeError('SYNTHETIC_PRIVATE')
    monkeypatch.setattr(PersistentMaterialUseStateStore,'claim',lost)
    with pytest.raises(MaterialAccessDenied):p.acquire_lease(b,r)
    assert group.claim_count==1 and loader.calls==[]
    q,other,_,_,_,_=setup(tmp_path,binding_value=b)
    assert q.validate_binding(b,r) is MaterialBindingStatus.UNAVAILABLE and other.validations==0


def test_invalid_guard_result_never_reserves_or_reads(tmp_path: Path) -> None:
    p,loader,b,r,now,group=setup(tmp_path,guard=lambda b,r:False)
    assert p.validate_binding(b,r) is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied):p.acquire_lease(b,r)
    assert group.claim_count==0 and loader.validations==0 and loader.calls==[]


def test_failed_finalization_preserves_consumption_and_clears_material(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    p,loader,b,r,now,group=setup(tmp_path);c=Consumer()
    def fail(self: Any,**kwargs: Any) -> None:raise RuntimeError('SYNTHETIC_PRIVATE')
    monkeypatch.setattr(PersistentMaterialUseStateStore,'finalize',fail)
    assert run(tmp_path,p,b,r,c) is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert group.claim_count==1 and c.calls==1
    cleared(loader,c)
    q,source,_,_,_,_=setup(tmp_path,binding_value=b)
    assert q.validate_binding(b,r) is MaterialBindingStatus.UNAVAILABLE and source.calls==[]


def test_post_acquisition_material_drift_is_not_handed_to_transport(tmp_path: Path) -> None:
    p,loader,b,r,now,group=setup(tmp_path);lease=p.acquire_lease(b,r);c=Consumer()
    loader.buffers[0][0]=0
    assert RadiusServerPairLeaseTransport(p,c).consume(lease) is MaterialUseOutcome.FAILED
    assert c.calls==0
    assert p.release_lease(lease) is MaterialLeaseCompletion.UNKNOWN
    cleared(loader,c)


def test_only_one_racing_provider_can_acquire_the_bound_pair(tmp_path: Path) -> None:
    a,one,b,r,now,group=setup(tmp_path)
    other_request=replace(r,authorization_digest='f'*64,plan_digest='e'*64)
    z,two,_,_,_,_=setup(tmp_path,request=other_request,binding_value=b)
    def acquire(p: Any,request: Any) -> Any:
        try:return p.acquire_lease(b,request)
        except MaterialAccessDenied:return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures=[pool.submit(acquire,a,r),pool.submit(acquire,z,other_request)]
        leases=[f.result(timeout=5) for f in futures]
    assert sum(lease is not None for lease in leases)==1
    assert len(one.calls)+len(two.calls)==2 and group.claim_count==1
    a.close();z.close();cleared(one,Consumer());cleared(two,Consumer())


def test_expired_or_unconsumed_lease_cannot_be_released_as_success(tmp_path: Path) -> None:
    p,loader,b,r,now,group=setup(tmp_path)
    lease=p.acquire_lease(b,r)
    assert p.release_lease(lease) is MaterialLeaseCompletion.UNKNOWN
    cleared(loader,Consumer())
    with pytest.raises(MaterialAccessDenied):p.release_lease(lease)


def test_opaque_lease_foreign_use_and_expiry_clear_owned_buffers(tmp_path: Path) -> None:
    p,loader,b,r,now,group=setup(tmp_path);lease=p.acquire_lease(b,r);c=Consumer()
    for value in (p,lease,RadiusServerPairLeaseTransport(p,c)):
        for operation in (copy.copy,copy.deepcopy,pickle.dumps):
            with pytest.raises(MaterialAccessDenied):operation(value)
        with pytest.raises(TypeError):json.dumps(value)
    assert RadiusServerPairLeaseTransport(p,c).consume(MaterialLease()) is MaterialUseOutcome.FAILED
    assert c.calls==0 and any(loader.buffers[0])
    now[0]=160
    assert p.validate_binding(b,r) is MaterialBindingStatus.EXPIRED
    cleared(loader,c)


def test_clock_exception_revokes_buffers_and_remains_failed_after_clock_recovers(tmp_path: Path) -> None:
    p,loader,b,r,now,group=setup(tmp_path);lease=p.acquire_lease(b,r)
    def failed_clock() -> int:raise OSError('SYNTHETIC_PRIVATE')
    p._clock=failed_clock
    assert p.validate_binding(b,r) is MaterialBindingStatus.UNAVAILABLE
    cleared(loader,Consumer())
    p._clock=lambda:100
    assert p.validate_binding(b,r) is MaterialBindingStatus.UNAVAILABLE
    assert p.release_lease(lease) is MaterialLeaseCompletion.UNKNOWN


def test_expired_lease_reports_timeout_without_entering_consumer(tmp_path: Path) -> None:
    p,loader,b,r,now,group=setup(tmp_path);lease=p.acquire_lease(b,r);c=Consumer()
    now[0]=160
    assert RadiusServerPairLeaseTransport(p,c).consume(lease) is MaterialUseOutcome.TIMED_OUT
    assert c.calls==0
    cleared(loader,c)
    assert p.revoke_lease(lease,reason=MaterialRevocationReason.PROVIDER_TIMEOUT) is MaterialLeaseCompletion.REVOKED


@pytest.mark.parametrize('change',[{'action_id':'radius-other-create'},{'action_version':'1.0.1'},
    {'purpose':MaterialPurpose.CREDENTIAL_ROTATION},{'expires_at':161}])
def test_shared_owned_source_contract_remains_exactly_bounded(change: dict[str,Any]) -> None:
    request=replace(primary_request(),action_id=ACTION_ID)
    with pytest.raises(MaterialContractError):replace(request,**change)


def test_primary_provider_does_not_accept_pair_action(tmp_path: Path) -> None:
    from fortipam_mcp.radius_server_material_provider import RadiusServerMaterialProvider
    from test_radius_server_contract import binding as primary_binding
    from test_radius_server_material_runtime import Loader as PrimaryLoader
    selected=primary_binding()
    with pytest.raises(MaterialAccessDenied):
        RadiusServerMaterialProvider(PrimaryLoader(selected),binding=selected,
            request=replace(primary_request(),action_id=ACTION_ID))


def test_default_provider_and_original_worker_remain_closed_for_pair_action(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    from fortipam_mcp import radius_fixture_material_worker as worker
    from v4_planning.material_provider import DenyAllMaterialProvider
    r=replace(primary_request(),action_id=ACTION_ID);b=binding()
    assert DenyAllMaterialProvider().validate_binding(b,r) is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied):DenyAllMaterialProvider().acquire_lease(b,r)
    monkeypatch.setattr(worker,'_directory',lambda *a:pytest.fail('Original worker opened a source for pair action'))
    with pytest.raises(ValueError):
        worker._handle(tmp_path/'unopened',{'contract':worker.CONTRACT,'operation':'acquire',
            'parameters_digest':b.parameters_digest,'source_policy_digest':'b'*64,'request':asdict(r)},
            clock=lambda:100,inspector=lambda _:pytest.fail('Original worker inspected a container'))
