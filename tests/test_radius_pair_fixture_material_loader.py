"""Concrete paired pipe protocol and worker/C3 integration, entirely synthetic."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from fortipam_mcp.radius_pair_fixture_material_loader import RadiusPairFixtureMaterialLoader
from fortipam_mcp.radius_server_pair_contract import ACTION_ID
from fortipam_mcp.radius_server_pair_material_provider import RadiusServerPairMaterialProvider, RadiusServerPairLeaseTransport
from v4_planning.material_provider import MaterialAccessDenied, MaterialBindingStatus
from v4_planning.material_runtime import MaterialLeaseCoordinator, MaterialRuntimeOutcome
from test_radius_server_pair_contract import binding
from test_radius_server_pair_material_provider import Consumer, store
from test_radius_server_material_runtime import request as primary_request
from test_radius_pair_fixture_material_worker import fixture, write


class Factory:
    def __init__(self,script: str) -> None:self.script=script;self.calls: list[Any]=[]
    def __call__(self,args: list[str],**kwargs: Any) -> Any:
        self.calls.append(args)
        assert args[:4]==['/usr/bin/ssh','-F','/dev/null','-T'] and args[-1]=='fixture.example'
        assert 'fp-radius-pair-material' in args and 'fp-radius-material' not in args
        assert all(value in args for value in ('IdentityAgent=none','IdentitiesOnly=yes','StrictHostKeyChecking=yes',
            'ClearAllForwardings=yes','PasswordAuthentication=no','GlobalKnownHostsFile=/dev/null'))
        assert kwargs['stderr'] is subprocess.DEVNULL
        return subprocess.Popen([sys.executable,'-c',self.script],**kwargs)


def client(root: Path,factory: Factory,*,selected: Any=None,digest: str='b'*64,guard: Any=lambda *a:None,
           enabled: bool=True,now: list[int] | None=None,acquisition_guard: Any=lambda *a:None) -> RadiusPairFixtureMaterialLoader:
    for name in ('identity','known_hosts'):write(root/name,b'synthetic-file')
    clock=[100] if now is None else now
    return RadiusPairFixtureMaterialLoader(binding() if selected is None else selected,host='fixture.example',
        identity_file=(root/'identity').resolve(),known_hosts_file=(root/'known_hosts').resolve(),source_policy_digest=digest,
        execution_guard=guard,acquisition_guard=acquisition_guard,acquisition_enabled=enabled,clock=lambda:clock[0],process_factory=factory)


def test_enabled_source_requires_a_separate_value_acquisition_guard(tmp_path: Path) -> None:
    factory=Factory('raise AssertionError("must not start")')
    with pytest.raises(MaterialAccessDenied):
        client(tmp_path,factory,acquisition_guard=None)
    assert factory.calls==[]


def peer_script(root: Path,inspections: Any,*,lose_primary_reply: bool=False) -> str:
    return ('import json,os,sys;from pathlib import Path;from fortipam_mcp import radius_pair_fixture_material_worker as w;'
        'incoming=json.load(sys.stdin);value=w._handle(Path('+repr(str(root))+'),incoming,clock=lambda:100,'
        'inspector=lambda key:'+repr(inspections)+'[key],owner_uid=os.getuid(),config_uid=os.getuid());'
        'sys.stdout.buffer.write(value);sys.stdout.flush();w._wipe(value);'
        'sys.exit(1 if '+repr(lose_primary_reply)+" and incoming['operation']=='acquire' and incoming['ordinal']=='primary' else 0)")


@pytest.mark.parametrize('lose_primary_reply',[False,True])
def test_real_pipe_worker_provider_and_persistent_pair_claims(tmp_path: Path,lose_primary_reply: bool) -> None:
    root=tmp_path/'fixture';incoming,inspections,_=fixture(root)
    b=binding();request=replace(primary_request(),action_id=ACTION_ID);active=[False]
    def guard(selected: Any,r: Any) -> None:
        assert selected is b and r==request
        if not active[0]:raise ValueError('SYNTHETIC_PRIVATE')
    factory=Factory(peer_script(root,inspections,lose_primary_reply=lose_primary_reply))
    source=client(tmp_path,factory,selected=b,digest=incoming['source_policy_digest'],guard=guard)
    assert source.validate_prebound(b,request,incoming['source_policy_digest']) is MaterialBindingStatus.UNAVAILABLE
    assert factory.calls==[]
    active[0]=True
    group=store(tmp_path,'source-group');usage=store(tmp_path,'usage')
    provider=RadiusServerPairMaterialProvider(source,binding=b,request=request,
        source_policy_digest=incoming['source_policy_digest'],source_reservation_store=group,
        execution_guard=guard,acquisition_enabled=True,clock=lambda:100)
    consumer=Consumer()
    result=MaterialLeaseCoordinator(provider,usage).execute_once(b,request,
        RadiusServerPairLeaseTransport(provider,consumer).consume,now_epoch=100)
    assert group.claim_count==usage.claim_count==1
    assert all(not any(v) for v in consumer.views)
    assert (root/'create-material.claim.json').exists() and (root/'primary/create-material.claim.json').exists()
    assert (root/'primary/material-ready.ack.json').exists()
    if lose_primary_reply:
        assert result is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED and consumer.calls==0
        assert len(factory.calls)==3 and not (root/'secondary/create-material.claim.json').exists()
        with pytest.raises(MaterialAccessDenied):source.load_endpoint_once(b,request,'secondary',incoming['source_policy_digest'])
    else:
        assert result is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED and consumer.calls==1
        assert len(factory.calls)==4 and (root/'secondary/material-ready.ack.json').exists()
    count=len(factory.calls)
    for ordinal in ('primary','secondary'):
        with pytest.raises(MaterialAccessDenied):source.load_endpoint_once(b,request,ordinal,incoming['source_policy_digest'])
    assert len(factory.calls)==count
    source.close();provider.close()


@pytest.mark.parametrize('failure',['short','excess','invalid','nonzero','empty'])
def test_primary_pipe_failure_is_terminal_for_both_ordinals(tmp_path: Path,failure: str) -> None:
    output={'short':b'A'*31,'excess':b'A'*33,'invalid':b'!'*32,'nonzero':b'A'*32,'empty':b''}[failure]
    factory=Factory('import sys;sys.stdin.buffer.read();sys.stdout.buffer.write('+repr(output)+');sys.stdout.flush();sys.exit('+str(int(failure=='nonzero'))+')')
    source=client(tmp_path,factory);r=replace(primary_request(),action_id=ACTION_ID)
    for ordinal in ('primary','secondary','primary'):
        with pytest.raises(MaterialAccessDenied):source.load_endpoint_once(source._binding,r,ordinal,'b'*64)
    assert len(factory.calls)==1


@pytest.mark.parametrize('failure',['gate','guard','key','known_hosts','request','policy','ordinal','order','clock'])
def test_invalid_context_never_starts_ssh(tmp_path: Path,failure: str) -> None:
    factory=Factory('raise AssertionError')
    def deny(*a: Any) -> None:raise ValueError
    source=client(tmp_path,factory,enabled=failure!='gate',guard=deny if failure=='guard' else lambda *a:None)
    r=replace(primary_request(),action_id=ACTION_ID);policy='b'*64;ordinal='primary'
    if failure=='key':write(tmp_path/'identity',b'changed')
    elif failure=='known_hosts':write(tmp_path/'known_hosts',b'changed')
    elif failure=='request':
        source._check(source._binding,r,policy);r=replace(r,authorization_digest='f'*64)
    elif failure=='policy':policy='f'*64
    elif failure=='ordinal':ordinal='../secondary'
    elif failure=='order':ordinal='secondary'
    elif failure=='clock':source._clock=lambda:99
    with pytest.raises(MaterialAccessDenied):source.load_endpoint_once(source._binding,r,ordinal,policy)  # type: ignore[arg-type]
    assert factory.calls==[]


def test_close_during_pipe_response_clears_value_and_blocks_secondary(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    from fortipam_mcp import radius_pair_fixture_material_loader as module
    factory=Factory('import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b"A"*32)')
    source=client(tmp_path,factory);r=replace(primary_request(),action_id=ACTION_ID)
    raw=[];original=module.os.readv
    def close_after_read(fd: int,buffers: Any) -> int:
        count=original(fd,buffers)
        if count:
            raw.append(buffers[0].obj);source.close()
        return count
    monkeypatch.setattr(module.os,'readv',close_after_read)
    with pytest.raises(MaterialAccessDenied):source.load_endpoint_once(source._binding,r,'primary','b'*64)
    assert raw and all(not any(b) for b in raw)
    with pytest.raises(MaterialAccessDenied):source.load_endpoint_once(source._binding,r,'secondary','b'*64)
    assert len(factory.calls)==1


def test_secondary_response_cannot_be_retried_after_primary_success(tmp_path: Path) -> None:
    factory=Factory('import json,sys;r=json.load(sys.stdin);sys.stdout.buffer.write(b"A"*(32 if r["ordinal"]=="primary" else 31))')
    source=client(tmp_path,factory);r=replace(primary_request(),action_id=ACTION_ID)
    value=source.load_endpoint_once(source._binding,r,'primary','b'*64)
    value[:]=bytes(len(value));value.clear()
    for _ in range(2):
        with pytest.raises(MaterialAccessDenied):source.load_endpoint_once(source._binding,r,'secondary','b'*64)
    assert len(factory.calls)==2


def test_absolute_pipe_deadline_kills_child_and_consumes_primary_attempt(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    from fortipam_mcp import radius_pair_fixture_material_loader as module
    factory=Factory('import time;time.sleep(10)')
    source=client(tmp_path,factory);r=replace(primary_request(),action_id=ACTION_ID)
    ticks=iter((0.0,16.0))
    monkeypatch.setattr(module.time,'monotonic',lambda:next(ticks,16.0))
    with pytest.raises(MaterialAccessDenied):source.load_endpoint_once(source._binding,r,'primary','b'*64)
    with pytest.raises(MaterialAccessDenied):source.load_endpoint_once(source._binding,r,'secondary','b'*64)
    assert len(factory.calls)==1
