"""Independent recovery authority, real M4/SQL custody and synthetic EMS HTTP."""
from dataclasses import replace
import hashlib
import json
import time
import http.client

import pytest
from v4_planning import M4AdapterDenied, M4AuthorizationDenied, M4ExecutionKernel

from fortipam_mcp.ems_tag_contract import DisabledLinuxProcessTag
from fortipam_mcp.ems_tag_custody import EmsTagOriginalActorBinding
from fortipam_mcp.ems_tag_http_transport import NativeEmsTagHttpTransport
from fortipam_mcp.ems_tag_recovery_authority import EmsTagRecoveryAuthority
from fortipam_mcp.ems_tag_recovery_contract import EmsTagOwnedRecoveryScope
from fortipam_mcp.ems_tag_recovery_custody import EmsTagRecoveryCustody, EmsTagRecoveryCustodyError
from fortipam_mcp.ems_tag_recovery_m4_adapter import NativeEmsTagRecoveryM4Adapter
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_ems_tag_contract import envelope, full_scope
from test_ems_tag_http_transport import make as http_transport, reply, framed
from test_ems_tag_recovery_contract import make as recovery_source
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF

LAB = dict(environment_ref="ems-disposable-lab",scope_ref="original-ems-tag-recovery",audience_ref="private-ems-recovery-client")


def assemble(root,scope,*,enabled=True,authority_enabled=True,key=b"r"*32,store_key=b"n"*32,witness_key=b"w"*32,clock=None):
    root.mkdir(mode=0o700)
    (root/'custody').mkdir(mode=0o700)
    for name,value in(('execution.key',store_key),('custody.key',witness_key)):
        (root/name).write_bytes(value);(root/name).chmod(0o600)
    authority=EmsTagRecoveryAuthority(scope,authority_key=key,execution_enabled=authority_enabled,clock=clock,**LAB)
    observed=scope.observe_owned()
    caller=dict(requester_digest=scope._requester,transport_digest=scope._caller_transport)
    preview=authority.preview(observed,**caller)
    if not authority_enabled:return authority,preview,observed,caller
    issued=authority.issue(preview,observed,**caller)
    store=PersistentM4ExecutionStateStore(root/'execution.sqlite',root/'execution.key',
        monotonic_checkpoint=_ExternalM4Checkpoint(),checkpoint_store_ref=CHECKPOINT_STORE_REF)
    actor=EmsTagOriginalActorBinding(scope._session,scope._caller_transport,hashlib.sha256(key).hexdigest())
    custody=EmsTagRecoveryCustody(root/'custody',root/'custody.key',scope._original,scope._context,actor,
        issued.plan,issued.authorization,store,clock=clock)
    adapter=NativeEmsTagRecoveryM4Adapter(scope=scope,authority=authority,issued=issued,store=store,
        custody=custody,execution_enabled=enabled)
    kernel=M4ExecutionKernel(adapter,authority,store,clock=clock)
    return authority,issued,store,custody,adapter,kernel


def make(tmp_path,monkeypatch,*,enabled=True,fault=None):
    original,transport,source,channel,connections,caller=recovery_source(tmp_path,monkeypatch)
    scope=EmsTagOwnedRecoveryScope(transport=transport,sources=source,original=original,**caller)
    items=assemble(tmp_path/'recovery',scope,enabled=enabled)
    underlying=transport._connect;writes=[];bodies=[]
    def connect():
        connection=underlying()
        send,receive,close=connection.request,connection.getresponse,connection.close
        def request(method,path,*,body,headers):
            send(method,path,body=body,headers=headers)
            if path=='/api/v1/tags/zero_trust/delete':
                assert method=='POST'and json.loads(body)=={'ids':[101]}
                writes.append((method,path));bodies.append(body)
        def response():
            if connection.path!='/api/v1/tags/zero_trust/delete':return receive()
            if fault not in('unchanged','lost_no_effect'):channel.scope=full_scope(prior_change=fault=='prior_drift')
            if fault in('lost_response','lost_no_effect'):raise http.client.RemoteDisconnected()
            answer={'result':{'retval':1,'message':'Deleted'}}
            if fault=='partial_frame':
                raw=json.dumps(answer).encode();return framed(f'Content-Length: {len(raw)+1}\r\n'.encode(),raw)
            if fault=='duplicate_json':return reply(body=b'{"result":{"retval":1,"retval":0,"message":null}}')
            return reply(answer)
        def end():
            close()
            if fault=='close_failure'and getattr(connection,'path',None)=='/api/v1/tags/zero_trust/delete':raise OSError
        connection.request,connection.getresponse,connection.close=request,response,end
        return connection
    monkeypatch.setattr(transport,'_connect',connect)
    return scope,transport,source,channel,connections,writes,bodies,items


def test_original_owned_recovery_posts_once_reopens_readonly_after_close_and_preserves_create_ledger(tmp_path,monkeypatch):
    scope,transport,source,_,connections,writes,bodies,items=make(tmp_path,monkeypatch)
    authority,issued,store,custody,adapter,kernel=items
    original_ledger=scope._original._store._path.read_bytes()
    original_records={p.name:p.read_bytes()for p in scope._original._directory.iterdir()}
    result=kernel.execute(issued.plan,issued.authorization)
    assert result.outcome=='succeeded'and result.verification=='verified'and len(writes)==1
    assert all(not b for b in bodies)
    seal=custody.inspect_restored()
    assert seal.restored_api_scope_digest==scope._original._baseline
    with pytest.raises(EmsTagRecoveryCustodyError):
        custody.capture_postcondition_failure(stage='fpa_postcondition',error_type='ValueError')
    count=len(connections);replayed=kernel.execute(issued.plan,issued.authorization)
    assert replayed.idempotent_replay and len(writes)==1 and len(connections)==count
    assert scope._original._store._path.read_bytes()==original_ledger
    assert original_records=={p.name:p.read_bytes()for p in scope._original._directory.iterdir()}
    data=b''.join(p.read_bytes()for p in custody._directory.iterdir())
    assert source._draft._name.encode()not in data
    assert transport.close().next_session_check_401
    adapter.close();authority.close();scope.close();source.close()
    readonly=PersistentM4ExecutionStateStore(store._path,store._key_path,read_only=True,
        monotonic_checkpoint=store._monotonic_checkpoint,checkpoint_store_ref=store._checkpoint_store_ref)
    reopened=EmsTagRecoveryCustody(custody._directory,custody._key_file,scope._original,custody._binding,
        custody._actor,issued.plan,issued.authorization,readonly,clock=lambda:int(time.time())+1000)
    assert reopened.inspect_restored()==seal
    with pytest.raises(EmsTagRecoveryCustodyError):reopened.capture_restored(scope)


@pytest.mark.parametrize('fault',['partial_frame','duplicate_json','lost_response','unchanged','prior_drift','close_failure'])
def test_unknown_recovery_cannot_gain_late_restoration_or_redispatch(tmp_path,monkeypatch,fault):
    scope,transport,source,_,connections,writes,_,items=make(tmp_path,monkeypatch,fault=fault)
    _,issued,_,custody,_,kernel=items
    result=kernel.execute(issued.plan,issued.authorization)
    assert result.outcome=='reconciliation_required'and result.verification=='unknown'and len(writes)==1
    with pytest.raises(EmsTagRecoveryCustodyError):custody.inspect_restored()
    with pytest.raises(EmsTagRecoveryCustodyError):custody.capture_restored(scope)
    failed=json.loads((custody._directory/'recover.failure.json').read_bytes())
    assert failed['request_replayable']is False
    if fault=='partial_frame':
        assert failed['response_error_type']=='ValueError'
        assert failed['original_ack_attempt']['json_object_complete']is True
        assert failed['original_ack_attempt']['native_envelope_valid']is True
        assert failed['original_ack_attempt']['reply_complete']is False
    if fault=='close_failure':assert custody.inspect_restored(require_verified_recovery=False).verification=='unknown'
    before={p.name:p.read_bytes()for p in custody._directory.iterdir()};count=len(connections)
    replayed=kernel.execute(issued.plan,issued.authorization)
    assert replayed.idempotent_replay and len(writes)==1 and len(connections)==count
    assert before=={p.name:p.read_bytes()for p in custody._directory.iterdir()}
    assert transport.close().next_session_check_401
    source.close()


def test_recovery_issuer_defaults_closed_and_refuses_original_or_shared_keys(tmp_path,monkeypatch):
    original,transport,source,_,_,caller=recovery_source(tmp_path,monkeypatch)
    scope=EmsTagOwnedRecoveryScope(transport=transport,sources=source,original=original,**caller)
    authority=EmsTagRecoveryAuthority(scope,authority_key=b'r'*32,**LAB)
    observed=scope.observe_owned();identity=dict(requester_digest=scope._requester,transport_digest=scope._caller_transport)
    preview=authority.preview(observed,**identity)
    with pytest.raises(M4AuthorizationDenied):authority.issue(preview,observed,**identity)
    for key in(source._key,original._key,original._store._key,b'k'*32):
        with pytest.raises(M4AuthorizationDenied):EmsTagRecoveryAuthority(scope,authority_key=key,**LAB)
    assert transport.close().next_session_check_401


def test_recovery_preview_issue_identity_expiry_and_copy_are_separate_from_create(tmp_path,monkeypatch):
    scope,transport,source,_,_,_,_,items=make(tmp_path,monkeypatch)
    authority,issued,_,_,_,_=items
    authority.verify(issued.plan,issued.authorization,now_epoch=int(time.time()))
    for plan,auth in((replace(issued.plan),issued.authorization),(issued.plan,replace(issued.authorization))):
        with pytest.raises(M4AuthorizationDenied):authority.verify(plan,auth,now_epoch=int(time.time()))
    with pytest.raises(M4AuthorizationDenied):authority.preview(scope._current,requester_digest=scope._requester,transport_digest=scope._caller_transport)
    authority._clock=lambda:issued.plan.expires_at
    with pytest.raises(M4AuthorizationDenied):authority.verify(issued.plan,issued.authorization,now_epoch=issued.plan.expires_at)
    assert transport.close().next_session_check_401


def test_expiry_after_success_ack_and_full_restored_graph_never_seals_or_replays(tmp_path,monkeypatch):
    scope,transport,source,_,connections,writes,_,items=make(tmp_path,monkeypatch)
    authority,issued,_,custody,_,kernel=items
    now=[max(authority._last,source._last,issued.authorization.issued_at)]
    for item in (authority,source,custody,kernel):item._clock=lambda:now[0]
    underlying=transport._connect
    def connect():
        connection=underlying();receive=connection.getresponse
        def response():
            if connection.path=='/api/v1/tags/zero_trust/delete':now[0]=issued.authorization.expires_at-8
            return receive()
        connection.getresponse=response;return connection
    monkeypatch.setattr(transport,'_connect',connect)
    observe=scope.observe_restored_api_graph
    def restored_then_expired():
        result=observe();now[0]=issued.authorization.expires_at;return result
    monkeypatch.setattr(scope,'observe_restored_api_graph',restored_then_expired)
    result=kernel.execute(issued.plan,issued.authorization)
    assert result.outcome=='reconciliation_required' and result.verification=='unknown' and len(writes)==1
    assert custody.inspect_ack_attempt()['http_status']==200
    failed=json.loads((custody._directory/'recover.failure.json').read_bytes())
    assert failed['stage']=='original_restoration_seal' and failed['request_replayable']is False
    assert not(custody._directory/'recover.restored.json').exists()
    with pytest.raises(EmsTagRecoveryCustodyError):custody.inspect_restored()
    count=len(connections)
    with pytest.raises(M4AuthorizationDenied):kernel.execute(issued.plan,issued.authorization)
    assert len(connections)==count and len(writes)==1
    assert transport.close().next_session_check_401


def test_recovery_adapter_defaults_closed_and_direct_dispatch_has_no_kernel_scope(tmp_path,monkeypatch):
    scope,transport,_,_,connections,writes,_,items=make(tmp_path,monkeypatch,enabled=False)
    _,issued,_,_,adapter,kernel=items
    count=len(connections);result=kernel.execute(issued.plan,issued.authorization)
    assert result.outcome=='denied'and len(connections)==count and not writes
    with pytest.raises(M4AdapterDenied):adapter.dispatch(issued.plan)
    assert len(connections)==count
    assert transport.close().next_session_check_401


@pytest.mark.parametrize('fault',['signed_context','foreign_adapter_scope'])
def test_recovery_live_authority_rejects_context_or_scope_substitution(tmp_path,monkeypatch,fault):
    scope,transport,source,_,connections,writes,_,items=make(tmp_path,monkeypatch)
    authority,_,_,_,adapter,kernel=items
    if fault=='signed_context':source._source='0'*64
    else:adapter._scope=object()
    count=len(connections)
    try:
        if fault=='signed_context':
            with pytest.raises(M4AuthorizationDenied):kernel.execute(items[1].plan,items[1].authorization)
        else:
            result=kernel.execute(items[1].plan,items[1].authorization)
            assert result.outcome=='denied'
        assert not writes and len(connections)==count
    finally:
        adapter.close();authority.close();scope.close();source.close();assert transport.close().next_session_check_401


def test_original_object_marker_blocks_new_plan_store_directory_and_session_after_unknown(tmp_path,monkeypatch):
    scope,transport,source,_,_,writes,_,items=make(tmp_path,monkeypatch,fault='lost_no_effect')
    _,issued,_,first,_,kernel=items
    assert kernel.execute(issued.plan,issued.authorization).verification=='unknown'and len(writes)==1
    marker=first._origin_parent/first._reservation;original_marker=marker.read_bytes()
    assert transport.close().next_session_check_401
    new,channel,connections,_,_,_=http_transport(tmp_path,monkeypatch)
    channel.session_value='third-synthetic-session';channel.scope=full_scope(add=True);new.authenticate()
    new_source=new.make_sources(DisabledLinuxProcessTag('a'*32),source_key=source._key);new_source.observe()
    second_scope=EmsTagOwnedRecoveryScope(transport=new,sources=new_source,original=scope._original,
        requester_digest=scope._requester,caller_transport_digest='d'*64)
    second=assemble(tmp_path/'second-recovery',second_scope,key=b'z'*32,store_key=b'y'*32,witness_key=b'x'*32)
    _,second_issue,_,second_custody,_,second_kernel=second
    assert second_issue.plan.plan_digest!=issued.plan.plan_digest
    result=second_kernel.execute(second_issue.plan,second_issue.authorization)
    assert result.outcome=='denied'and not any(getattr(c,'path',None)=='/api/v1/tags/zero_trust/delete'for c in connections)
    assert marker.read_bytes()==original_marker
    assert not(second_custody._directory/'recover.claim.json').exists()
    assert new.close().next_session_check_401


def test_copied_recovery_actor_binding_cannot_authorize_writer(tmp_path,monkeypatch):
    scope,transport,_,_,connections,writes,_,items=make(tmp_path,monkeypatch)
    authority,issued,store,custody,_,_=items;count=len(connections)
    changed=EmsTagRecoveryCustody(custody._directory,custody._key_file,scope._original,custody._binding,
        replace(custody._actor,caller_transport_digest='f'*64),issued.plan,issued.authorization,store)
    with pytest.raises(M4AdapterDenied):
        NativeEmsTagRecoveryM4Adapter(scope=scope,authority=authority,issued=issued,store=store,custody=changed,execution_enabled=True)
    assert len(connections)==count and not writes
    assert transport.close().next_session_check_401


@pytest.mark.parametrize('fault',['copied_directory','tampered_seal'])
def test_verified_recovery_does_not_accept_copied_or_modified_custody(tmp_path,monkeypatch,fault):
    scope,transport,_,_,_,writes,_,items=make(tmp_path,monkeypatch)
    _,issued,store,custody,_,kernel=items
    assert kernel.execute(issued.plan,issued.authorization).outcome=='succeeded'and len(writes)==1
    if fault=='copied_directory':
        copied=tmp_path/'copied-custody';copied.mkdir(mode=0o700)
        for p in custody._directory.iterdir():
            (copied/p.name).write_bytes(p.read_bytes());(copied/p.name).chmod(0o600)
        changed=EmsTagRecoveryCustody(copied,custody._key_file,scope._original,custody._binding,
            custody._actor,issued.plan,issued.authorization,store)
    else:
        record=custody._directory/'recover.restored.json';value=json.loads(record.read_bytes())
        value['restored_api_scope_digest']='f'*64;record.write_text(json.dumps(value))
        changed=custody
    with pytest.raises(EmsTagRecoveryCustodyError):changed.inspect_restored()
    assert transport.close().next_session_check_401
