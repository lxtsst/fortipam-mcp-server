"""Concrete Folder sources join real original M4 custody and synthetic peers."""
from contextlib import asynccontextmanager
from dataclasses import replace
import json

import httpx
import pytest
from v4_planning import canonical_digest

import fortipam_mcp.folder_namespace_ssh_reader as folder_cli
import fortipam_mcp.folder_archive_reference_ssh_transport as folder_refs
import fortipam_mcp.windows_execution_policy_cli_source as policy_cli
from fortipam_mcp.isolated_folder_http_transport import IsolatedFolderHttpTransport
from fortipam_mcp.windows_execution_folder_contract import (
    FIELDS, WindowsExecutionFolderBinding, compile_windows_execution_folder,
)
from fortipam_mcp.windows_execution_folder_sources import WindowsExecutionFolderSources, WindowsFolderSourceError
from test_windows_execution_folder_contract import NAME, OWNER, sources as folder_sources, native_state
from test_windows_execution_policy_contract import SERIAL, BINDING, envelope, backend_normalized_state
from test_windows_execution_policy_sources import make as policy_sources
from test_windows_execution_policy_lifecycle import Native, lifecycle

ROOT = b'FPA-SYNTHETIC #'
FOLDER = b'FPA-SYNTHETIC (folder) #'


def frame(command, rows, prompt):
    return command.encode()+b'\r\r\n'+b''.join(row+b'\r\n' for row in rows)+prompt


def parent_row():
    row=json.loads(native_state())['results'][0]
    row.update(id=17,name='Root',**{'parent-folder':0,'secret-policy':'default','q_origin_key':17})
    return row


class Api:
    def __init__(self,base):
        self.base=base;self.original=base.respond;self.present=False;self.failure=None
        self.policy_cli_count=None;self.folder_has_reference=False;self.false_parent_control=False
        self.hidden_name=False;self.parent_changed=False;self.bad_policy_type=False
        self.row_reads=0;self.namespace_reads=0

    def rows(self):
        return [(17,'Root',0),(23,'Collector',17),(28,'Other',17)]+([(41,NAME,17)] if self.present else [])

    def respond(self,request):
        path=request.url.path
        if path=='/XX/YY/ZZ/AUTH':
            response=self.original(request)
            response.headers['set-cookie']='ccsrftoken="synthetic-csrf"; Secure; Path=/'
            return response
        if path=='/api/v2/cmdb/secret/folder/41' and request.method=='DELETE':
            assert hasattr(self,'owner_delete_handler')
            return self.owner_delete_handler(request)
        if path=='/api/v2/cmdb/system/accprofile/synthetic-role':
            raw=envelope([dict(name='synthetic-role',secretgrp='custom',**{'secretgrp-permission':{
                'secret-policy':'read-write','folder-table':'read' if self.failure=='folder-role' else 'read-write'}})],
                path='system',name='accprofile')
        elif path=='/api/v2/cmdb/secret/folder' and request.url.params.get('action') in ('schema','default'):
            raw=folder_sources()[0 if request.url.params['action']=='schema' else 1]
            if self.failure=='defaults' and request.url.params['action']=='default':
                value=json.loads(raw);value['results'][0]['ztna-tags-match-logic']='and';raw=bytearray(json.dumps(value).encode())
        elif path=='/api/v2/cmdb/secret/folder':
            self.namespace_reads+=1
            assert set(request.url.params['format'].split('|'))==FIELDS
            assert request.url.params['count']=='512' and request.url.params['start']=='0'
            rows=[]
            for identifier,name,parent in self.rows():
                row=json.loads(native_state())['results'][0]
                row.update(id=identifier,name=name,**{'parent-folder':parent,'q_origin_key':identifier})
                rows.append(row)
            if self.failure=='namespace-drift' and self.namespace_reads==2:
                row=dict(rows[-1]);row.update(id=61,name='OtherNew',q_origin_key=61);rows.append(row)
            if self.failure=='sparse-namespace':
                rows=[{key:row[key] for key in ('id','name','parent-folder')} for row in rows]
            raw=envelope(rows,name='folder',status='OK',matched_count=len(rows),limit_reached=False)
        elif path=='/api/v2/cmdb/secret/folder/17':
            row=parent_row()
            if self.parent_changed:row['inherit-policy']='enable'
            raw=envelope([row],name='folder',status='OK',mkey=17)
        elif path=='/api/v2/cmdb/secret/folder/41':
            self.row_reads+=1
            raw=native_state()
            if self.failure=='row-drift' and self.row_reads==2:
                value=json.loads(raw);value['results'][0]['user-permission'][0].update(id=4,q_origin_key=4)
                raw=bytearray(json.dumps(value).encode())
        elif path=='/api/v2/cmdb/secret/policy/'+BINDING.name and self.base.present:
            value=json.loads(backend_normalized_state());value['results'][0]['q_ref']=1 if self.present else 0
            if self.bad_policy_type:value['results'][0]['q_type']=99
            raw=bytearray(json.dumps(value).encode())
        else:return self.original(request)
        self.base.calls.append((request.method,path,'authorization' in request.headers))
        return httpx.Response(200,stream=httpx.ByteStream(bytes(raw)),headers={'content-type':'application/json'})


class FolderPeer:
    def __init__(self,api):
        self.api=api;self.closed=self.connections=0;self.commands=[]

    @asynccontextmanager
    async def _connection(self):
        try:yield self
        finally:self.connections+=1

    async def _open_cli(self,connection):
        assert connection is self
        return self,ROOT,1000

    async def dynamic(self,process,command,prompt,deadline):
        self.commands.append(command)
        assert command in ('config secret folder','end')
        return FOLDER if command=='config secret folder' else ROOT

    async def read(self,process,command,prompt,deadline):
        self.commands.append(command)
        if command==folder_cli._SERIAL_COMMAND:rows=[b'Serial-Number: '+SERIAL.encode()]
        elif command==folder_cli._VERSION_COMMAND:rows=[b'Version: FortiPAM-VM v7.0.0,build0029, synthetic']
        elif command==folder_cli._NAME_PROJECTION:
            names=[row[1] for row in self.api.rows()]+([NAME] if self.api.hidden_name else [])
            rows=[b'    set name "'+name.encode()+b'"' for name in names]
        elif command==folder_refs._PARENT_PROJECTION:
            values=[row[2] for row in self.api.rows()]+([17] if self.api.hidden_name else [])
            rows=[b'    set parent-folder '+str(value).encode() for value in values]
        elif command=='diagnose sys cmdb refcnt show secret.folder.id 17':
            rows=[] if self.api.false_parent_control else [b'entry used by secret.database:folder']
        elif command=='diagnose sys cmdb refcnt show secret.folder.id 41':
            rows=[b'entry used by secret.database:folder'] if self.api.folder_has_reference else []
        else:pytest.fail('Uncompiled Folder SSH command.')
        return frame(command,rows,prompt)

    async def close(self,process):self.closed+=1


def make(tmp_path,monkeypatch,*,unknown_policy=False):
    digest=canonical_digest({key:parent_row()[key] for key in FIELDS})
    policy,base,ssh,now,hosts=policy_sources(tmp_path,monkeypatch,canonical=True,parent_digest=digest)
    api=Api(base);base.respond=api.respond
    policy._folder._transport=IsolatedFolderHttpTransport(policy._config,parent_path='Root',child_name='Collector',
        owner_name=OWNER,owner_credentials=policy._credentials)
    native=Native(base,ssh)
    create,store,_=lifecycle(tmp_path,policy,native)
    create.issue(create.preview())
    if unknown_policy:
        dispatch=create.dispatch
        def expire_after_full_read(plan):
            dispatch(plan)
            now[0]=130.0
        monkeypatch.setattr(create,'dispatch',expire_after_full_read)
    result=create.execute()
    assert str(result.outcome)==('reconciliation_required' if unknown_policy else 'succeeded')
    assert str(result.verification)==('unknown' if unknown_policy else 'verified')
    original=create.original_creation();seal=original.inspect_created_state();create.close()
    assert store.claim_count==1 and seal.created_state_digest
    binding=WindowsExecutionFolderBinding(NAME,17,OWNER,digest,policy._request,seal.custody_digest,
        seal.created_state_digest,seal.source_context_digest)
    request=compile_windows_execution_folder(*folder_sources(),binding=binding)
    peers=[]
    def factory(config):
        peer=FolderPeer(api);peer._config=config;peers.append(peer);return peer
    monkeypatch.setattr(folder_cli,'FortiPamTargetReferenceSshTransport',factory)
    monkeypatch.setattr(folder_refs,'FortiPamTargetReferenceSshTransport',factory)
    async def read(process,command,prompt,deadline):return await process.read(process,command,prompt,deadline)
    async def dynamic(process,command,prompt,deadline):return await process.dynamic(process,command,prompt,deadline)
    async def close(process):return await process.close(process)
    for module in (folder_cli,folder_refs):
        monkeypatch.setattr(module,'_send_and_read',read);monkeypatch.setattr(module,'_send_and_read_dynamic_prompt',dynamic)
        monkeypatch.setattr(module,'_close_cli',close)
    try:
        source=WindowsExecutionFolderSources(request=request,policy_sources=policy,original_policy=original)
    except Exception:
        policy.close()
        raise
    monkeypatch.setattr(source._policy_cli._ssh,'_connection',ssh.connect)
    original_read=ssh.read
    async def policy_read(process,command,prompt,deadline):
        if command==policy_cli._REFERENCE+'"'+BINDING.name+'"':
            count=api.policy_cli_count if api.policy_cli_count is not None else int(api.present)
            ssh.commands.append(command)
            return frame(command,[b'entry used by secret.folder:41']*count,prompt)
        return await original_read(process,command,prompt,deadline)
    monkeypatch.setattr(policy_cli,'_send_and_read',policy_read)
    return source,api,policy,original,now,hosts,peers


@pytest.mark.parametrize('present',[False,True])
def test_actual_original_policy_custody_joins_fresh_folder_scope_and_zero_or_one_refs(tmp_path,monkeypatch,present):
    source,api,policy,original,_,_,peers=make(tmp_path,monkeypatch)
    before={p.name:p.read_bytes() for p in original._directory.iterdir()}
    api.present=present
    observed=source.observe_candidate_presence(41) if present else source.observe_absence()
    source.check_current(observed)
    assert observed.absent is not present and observed.policy_reference_count==int(present)
    assert (observed.state_digest is not None) is present
    assert source.logout_verified and all(peer.closed==peer.connections for peer in peers)
    assert {p.name:p.read_bytes() for p in original._directory.iterdir()}==before
    assert all(client.is_closed and not client.cookies for client in api.base.clients)
    assert not hasattr(source,'execute') and not hasattr(source,'issue')
    source.close()
    assert not any(source._raw)
    assert policy.source_context_digest==original.inspect_created_state().source_context_digest
    with pytest.raises(WindowsFolderSourceError):source.check_current(observed)
    policy.close()


@pytest.mark.parametrize('failure',['folder-role','defaults','namespace-drift','row-drift','sparse-namespace'])
def test_live_role_defaults_namespace_or_full_state_drift_poison_source(tmp_path,monkeypatch,failure):
    source,api,policy,_,_,_,_=make(tmp_path,monkeypatch)
    api.present=True;api.failure=failure
    with pytest.raises(WindowsFolderSourceError):source.observe_candidate_presence(41)
    assert source._failed and source._current is None and not any(source._raw)
    api.failure=None
    with pytest.raises(WindowsFolderSourceError):source.observe_candidate_presence(41)
    source.close();policy.close()


@pytest.mark.parametrize('failure',['hidden','hidden-present','parent','policy-type','cli-reference','folder-reference','false-control'])
def test_actual_global_namespace_and_reference_guards_cannot_be_replaced_by_api_zero(tmp_path,monkeypatch,failure):
    source,api,policy,_,_,_,_=make(tmp_path,monkeypatch)
    if failure=='hidden':api.hidden_name=True
    elif failure=='hidden-present':api.hidden_name=True;api.present=True
    elif failure=='parent':api.parent_changed=True
    elif failure=='policy-type':api.bad_policy_type=True
    else:
        api.present=True
        if failure=='cli-reference':api.policy_cli_count=0
        if failure=='folder-reference':api.folder_has_reference=True
        if failure=='false-control':api.false_parent_control=True
    with pytest.raises(WindowsFolderSourceError):
        source.observe_candidate_presence(41) if api.present else source.observe_absence()
    source.close();policy.close()


def test_fresh_observation_identity_snapshot_expiry_and_current_source_pins(tmp_path,monkeypatch):
    source,api,policy,_,now,hosts,_=make(tmp_path,monkeypatch)
    first=source.observe_absence()
    with pytest.raises(WindowsFolderSourceError):source.check_current(replace(first))
    second=source.observe_absence()
    with pytest.raises(WindowsFolderSourceError):source.check_current(first)
    object.__setattr__(second,'current_digest','f'*64)
    with pytest.raises(WindowsFolderSourceError):source.check_current(second)
    third=source.observe_absence();now[0]=third.expires_at
    with pytest.raises(WindowsFolderSourceError):source.check_current(third)
    now[0]+=1
    fourth=source.observe_absence();hosts.write_text('changed pin\n')
    with pytest.raises(WindowsFolderSourceError):source.check_current(fourth)
    source.close();policy.close()


def test_synthetic_custody_marker_and_wrong_parent_fail_before_more_network_io(tmp_path,monkeypatch):
    source,api,policy,original,_,_,_=make(tmp_path,monkeypatch)
    count=len(api.base.calls)
    for changes in ({'policy_custody_digest':'d'*64},{'parent_folder_id':18}):
        binding=replace(source._request.binding,**changes)
        request=compile_windows_execution_folder(*folder_sources(),binding=binding)
        with pytest.raises(WindowsFolderSourceError):
            WindowsExecutionFolderSources(request=request,policy_sources=policy,original_policy=original)
        assert len(api.base.calls)==count
    source.close();policy.close()


def test_new_folder_dependency_refuses_a_real_unknown_policy_even_with_full_seal(tmp_path,monkeypatch):
    with pytest.raises(WindowsFolderSourceError):
        make(tmp_path,monkeypatch,unknown_policy=True)


def test_missing_original_full_seal_cannot_be_replaced_by_a_bound_state_digest(tmp_path,monkeypatch):
    source,api,policy,original,_,_,_=make(tmp_path,monkeypatch)
    count=len(api.base.calls)
    (original._directory/'created-state.json').unlink()
    with pytest.raises(WindowsFolderSourceError):
        WindowsExecutionFolderSources(request=source._request,policy_sources=policy,original_policy=original)
    assert len(api.base.calls)==count
    source.close();policy.close()


@pytest.mark.parametrize('field',['folder-name','folder-witness','reference-config'])
def test_fixed_cli_scope_and_actual_connection_config_cannot_drift_before_io(tmp_path,monkeypatch,field):
    source,api,policy,_,_,_,_=make(tmp_path,monkeypatch)
    count=len(api.base.calls)
    if field=='folder-name':source._folder_cli._candidate_name='mcp-v4-other'
    if field=='folder-witness':source._folder_cli._witness_names=('Other','Collector')
    if field=='reference-config':source._references._ssh._config=replace(policy._cli._config,host='other.example')
    with pytest.raises(WindowsFolderSourceError):source.observe_absence()
    assert len(api.base.calls)==count
    source.close();policy.close()
