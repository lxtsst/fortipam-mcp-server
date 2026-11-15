"""Live fixed-source composition uses real signed Folder receipts and fake peers."""
import json

import httpx
import pytest

from fortipam_mcp.isolated_folder_live_workflow import IsolatedFolderLiveWorkflow
from fortipam_mcp.isolated_folder_m4_adapter import IsolatedFolderBinding
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig, SYSTEM_STATUS_PATH
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig
from fortipam_mcp.windows_execution_policy_sources import WindowsExecutionPolicySources, WindowsPolicySourceError
from test_isolated_folder_creation_ownership import SnapshotTransport, authorize, REQUESTER
from test_windows_execution_policy_contract import (compile_request, sources, envelope, state, SERIAL, BINDING,
    backend_normalized_state, compile_windows_execution_policy, CANONICAL_PROFILE)
from test_windows_execution_policy_cli_source import Peer
import fortipam_mcp.windows_execution_policy_cli_source as cli


class Api:
    def __init__(self, request, *, failure=None):
        self.request, self.failure = request, failure
        self.active = False
        self.present = False
        self.calls = []
        self.clients = []

    def factory(self, **kwargs):
        client=httpx.Client(**kwargs,transport=httpx.MockTransport(self.respond))
        self.clients.append(client)
        return client

    def respond(self, request):
        path=request.url.path
        api='authorization' in request.headers
        self.calls.append((request.method,path,api))
        if path=='/remote/login':return httpx.Response(200,text='<form action="/XX/YY/ZZ/AUTH">')
        if path=='/XX/YY/ZZ/AUTH':
            self.active=True
            return httpx.Response(303,headers={'location':'/'})
        if path=='/':return httpx.Response(200)
        if path=='/logout':
            self.active=self.failure=='logout'
            return httpx.Response(200)
        if not api and not self.active:return httpx.Response(401)
        if path==SYSTEM_STATUS_PATH:return httpx.Response(200,json=dict(version='v7.0.0',build=29))
        if path=='/api/v2/monitor/web-ui/state':
            name='synthetic-api' if api else 'synthetic-owner'
            profile='synthetic-role' if api else 'super_admin'
            admin=dict(name=name,login_name=name,sponsored_group_name='',guest_admin=False,
                global_admin=True,super_admin=not api,profile={'name':profile})
            if not api and self.failure=='owner':admin['super_admin']=False
            raw=envelope(dict(admin=admin,vdom_mode='enabled' if self.failure=='vdom' else '',
                maintenance_mode={'mode':'enable' if self.failure=='maintenance' else 'disable'}),path='web-ui',name='state')
        elif path=='/api/v2/cmdb/system/api-user/synthetic-api':
            raw=envelope([dict(name='synthetic-api',accprofile='synthetic-role')],path='system',name='api-user')
        elif path=='/api/v2/cmdb/system/accprofile/synthetic-role':
            raw=envelope([dict(name='synthetic-role',secretgrp='custom',**{'secretgrp-permission':{
                'secret-policy':'read' if self.failure=='role' else 'read-write'}})],path='system',name='accprofile')
        elif path=='/api/v2/cmdb/system/admin/synthetic-owner':
            raw=envelope([dict(name='synthetic-owner',accprofile='super_admin',status='enable',
                **{'remote-auth':'disable','wildcard':'disable'})],path='system',name='admin')
        elif path=='/api/v2/cmdb/secret/policy' and request.url.params.get('action') in ('schema','default'):
            raw=sources(native=self.request.profile==CANONICAL_PROFILE)[0 if request.url.params['action']=='schema' else 1]
            if self.failure=='defaults' and request.url.params['action']=='default':
                value=json.loads(raw);value['results'][0]['heartbeat-interval']=61;raw=bytearray(json.dumps(value).encode())
        elif path=='/api/v2/cmdb/secret/policy/default':
            raw=envelope([dict(name='default',q_ref=0 if self.failure=='control' else 2)])
        elif path=='/api/v2/cmdb/secret/policy/'+BINDING.name:
            if self.present:
                raw=backend_normalized_state() if self.request.profile==CANONICAL_PROFILE else state(self.request)
            else:
                value=json.loads(envelope(None,status='error',http_status=404,mkey=BINDING.name))
                del value['results']
                return httpx.Response(404,stream=httpx.ByteStream(json.dumps(value).encode()),headers={'content-type':'application/json'})
        elif path=='/api/v2/cmdb/secret/policy':
            names=['default','other-policy']+([BINDING.name] if self.present else [])
            raw=envelope([{'name':name} for name in names])
        else:pytest.fail('Uncompiled source route.')
        return httpx.Response(200,stream=httpx.ByteStream(bytes(raw)),headers={'content-type':'application/json'})


def make(tmp_path,monkeypatch,*,failure=None,canonical=False,parent_digest=None):
    tmp_path.chmod(0o700)
    transport=SnapshotTransport();transport.serial=SERIAL
    transport.folder['secret-policy']='default'
    transport.read_creation_device_serial=lambda:SERIAL
    if parent_digest is not None:
        transport.read_parent_digest=lambda identifier:parent_digest
    key=tmp_path/'folder.key';key.write_bytes(b'f'*32);key.chmod(0o600)
    workflow=IsolatedFolderLiveWorkflow(tmp_path/'folder.sqlite',key,transport,
        binding=IsolatedFolderBinding('Collector',17,'synthetic-owner',parent_digest or 'a'*64,empty_inactive_policy=False),
        ownership_expected_serial=SERIAL,clock=lambda:1000)
    preview,auth=authorize(workflow)
    assert workflow.execute(auth,requester_digest=REQUESTER)['outcome']=='succeeded'
    request=(compile_windows_execution_policy(*sources(native=True),binding=BINDING,profile=CANONICAL_PROFILE)
        if canonical else compile_request())
    peer=Api(request,failure=failure)
    config=SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',30,None)
    hosts=tmp_path/'known-hosts';hosts.write_text('synthetic-pin\n');hosts.chmod(0o600)
    ssh=TargetSshTransportConfig('pam.example',22,'synthetic-owner','synthetic-password',hosts,30)
    now=[100.0]
    source=WindowsExecutionPolicySources(config,request=request,folder_workflow=workflow,folder_preview_ref=preview,
        folder_requester_digest=REQUESTER,ssh=ssh,owner_credentials=lambda:('synthetic-owner','synthetic-password'),
        client_factory=peer.factory,clock=lambda:now[0])
    ssh_peer=Peer()
    monkeypatch.setattr(source._cli._ssh,'_connection',ssh_peer.connect)
    monkeypatch.setattr(cli,'_complete_pre_login',ssh_peer.login)
    monkeypatch.setattr(cli,'_send_and_read',ssh_peer.read)
    monkeypatch.setattr(cli,'_send_and_read_dynamic_prompt',ssh_peer.dynamic)
    return source,peer,ssh_peer,now,hosts


def test_fixed_join_proves_absence_and_refreshes_without_configuration_writes(tmp_path,monkeypatch):
    source,peer,ssh,now,_=make(tmp_path,monkeypatch)
    first=source.observe_absence()
    assert first.absent is True and first.state_digest is None and source.logout_verified
    assert first.source_context_digest==source.source_context_digest
    source.check_current(first)
    second=source.observe_absence()
    assert second.current_digest==first.current_digest
    with pytest.raises(WindowsPolicySourceError):source.check_current(first)
    assert all(client.is_closed and not client.cookies for client in peer.clients)
    assert all(method=='GET' or path=='/XX/YY/ZZ/AUTH' for method,path,_ in peer.calls)
    assert ssh.connected==ssh.closed==ssh.waited==ssh.aborted==2
    source.close()
    assert not any(source._raw)
    with pytest.raises(WindowsPolicySourceError):source.check_current(second)


@pytest.mark.parametrize('failure',['role','owner','vdom','maintenance','defaults','control','logout'])
def test_missing_permission_or_wrong_source_stops_without_partial_proof(tmp_path,monkeypatch,failure):
    source,peer,ssh,_,_=make(tmp_path,monkeypatch,failure=failure)
    with pytest.raises(WindowsPolicySourceError):source.observe_absence()
    assert source._current is None and not any(source._raw)
    before=list(peer.calls)
    with pytest.raises(WindowsPolicySourceError):source.observe_absence()
    assert peer.calls==before
    assert all(client.is_closed and not client.cookies for client in peer.clients)


def test_present_policy_cannot_be_adopted_and_pin_drift_denies_before_io(tmp_path,monkeypatch):
    source,peer,ssh,_,hosts=make(tmp_path,monkeypatch)
    peer.present=True
    with pytest.raises(WindowsPolicySourceError):source.observe_absence()
    assert not ssh.connected
    assert all(client.is_closed for client in peer.clients)


def test_invalid_original_custody_cannot_trigger_owned_reads(tmp_path,monkeypatch):
    source,peer,_,_,_=make(tmp_path,monkeypatch)
    with pytest.raises(WindowsPolicySourceError):source.observe_owned(object())
    assert peer.calls==[]


def test_presence_reconciliation_without_ack_grants_no_ownership(tmp_path,monkeypatch):
    source,peer,ssh,_,_=make(tmp_path,monkeypatch)
    peer.present=True;ssh.names=tuple(sorted((*ssh.names,BINDING.name)))
    observed=source.observe_candidate_presence()
    assert not observed.absent and observed.state_digest and source.logout_verified
    with pytest.raises(WindowsPolicySourceError):source.observe_owned(object())
    source.close()
