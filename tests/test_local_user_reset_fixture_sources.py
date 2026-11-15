"""Concrete C/P/E joins actual HTTP readers and fixed two-session CLI controls."""
from dataclasses import replace
import hashlib
import json

import httpx
import pytest

from fortipam_mcp.local_user_reset_fixture_sources import LocalResetFixtureSources
import fortipam_mcp.local_user_reset_fixture_sources as source_module
from fortipam_mcp.local_user_reset_fixture_preflight import _PROFILE
from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport, SYSTEM_STATUS_PATH
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig
from fortipam_mcp import local_user_reset_namespace as namespace
from fortipam_mcp import local_user_reset_references as references
from test_local_user_reset_fixture_state import Harness as StateHarness
from test_local_user_reset_fixture_custody import NAME, SERIAL
from test_local_user_reset_name_reader import _payload
from test_local_user_reset_namespace import Peer as NamespacePeer
from test_folder_namespace_ssh_reader import Peer as BasePeer, frame

OWNER = "synthetic-owner"


def envelope(value, *, path="system", name="admin"):
    return dict(version="v7.0.0",build=29,http_status=200,http_method="GET",status="success",
        serial=SERIAL,vdom="root",path=path,name=name,results=value)


class Network(StateHarness):
    def __init__(self, root):
        super().__init__(root)
        self.complete = self.source
        actor=json.loads(self.actor);actor.update(serial=SERIAL,vdom="root")
        actor["results"].update(vdom_mode="",maintenance_mode={"mode":"disable"})
        actor["results"]["admin"].update(profile={"name":"api-role"},global_admin=True,super_admin=False)
        self.actor=bytearray(json.dumps(actor).encode())
        self.clients=[];self.http_calls=[];self.active=False;self.failure=None;self.present=False
        self.guest_reads=0;self.writer_reads=0

    def connect(self,*args,**kwargs):
        connection=super().connect(*args,**kwargs);original=connection.request
        def request(method,path,*,headers,body=None):
            if method=="POST":
                assert headers['X-HTTP-Method-Override']=='GET' and path.endswith('?format=name&with_meta=true')
                table="api-user" if "/api-user?" in path else "admin"
                names=[self.principal] if table=="api-user" else [OWNER]
                connection.response.raw=_payload(table,names,serial=SERIAL)
                self.calls.append(path)
            elif path==_PROFILE:
                connection.response.raw=bytearray(json.dumps(envelope({"name":"Guest"},name="accprofile")).encode())
                self.calls.append(path)
            else:original(method,path,headers=headers)
        connection.request=request
        return connection

    def factory(self,**kwargs):
        client=httpx.Client(**kwargs,transport=httpx.MockTransport(self.respond));self.clients.append(client);return client

    def respond(self,request):
        path=request.url.path;bearer='authorization' in request.headers
        self.http_calls.append((request.method,path,bearer))
        if path=='/remote/login':return httpx.Response(200,text='<form action="/XX/YY/ZZ/AUTH">')
        if path=='/XX/YY/ZZ/AUTH':
            self.active=True;return httpx.Response(303,headers={'location':'/','set-cookie':'ccsrftoken="synthetic"; Secure; Path=/'})
        if path=='/':return httpx.Response(200)
        if path=='/logout':self.active=self.failure=='logout';return httpx.Response(200)
        if not bearer and not self.active:return httpx.Response(401)
        if path==SYSTEM_STATUS_PATH:return httpx.Response(200,json={'version':'v7.0.0','build':29})
        if path=='/api/v2/monitor/web-ui/state':
            value=json.loads(self.actor)
            if not bearer:
                value['results']['admin'].update(name=OWNER,login_name=OWNER,super_admin=self.failure!='owner',profile={'name':'super_admin'})
            elif self.failure=='actor':value['results']['admin']['login_name']='foreign'
            if self.failure=='vdom':value['results']['vdom_mode']='enable'
        elif path=='/api/v2/cmdb/system/api-user/'+self.principal:
            value=envelope({'name':self.principal,'accprofile':'api-role','api-key':'SYNTHETIC_NEVER_DECODE'},name='api-user')
        elif path=='/api/v2/cmdb/system/accprofile/api-role':
            self.writer_reads+=1
            group='read-write' if self.failure!='role' else 'read'
            if self.failure=='role-drift' and self.writer_reads==2:group='read'
            value=envelope({'name':'api-role','sysgrp':group,'sysgrp-permission':{'admin':'none'}},name='accprofile')
        elif path=='/api/v2/cmdb/system/accprofile/Guest':
            self.guest_reads+=1
            value=envelope({'name':'Guest','sysgrp':'read-write' if self.failure=='guest-write' else 'none',
                'sysgrp-permission':{'admin':'none','cfg':'none'},'comments':'changed' if self.failure=='guest-drift' and self.guest_reads==2 else '',
                'q_ref':self.guest_reads},name='accprofile')
        elif path=='/api/v2/monitor/web-ui/object-urls':
            value=envelope({'by_type':{'7':{'path':'system.admin','read_access':True,
                'write_access':1 if self.failure=='hint-type' else self.failure!='hint-denied'}}},path='web-ui',name='object-urls')
            value['path']='synthetic-route-token';value.pop('http_status')
            if self.failure=='hint-path':value['path']='foreign-route-token'
        else:
            assert path=='/api/v2/cmdb/system/admin/'+OWNER
            value=envelope({'name':OWNER,'accprofile':'super_admin','status':'enable','remote-auth':'disable',
                'wildcard':'disable','q_ref':37,'password':'SYNTHETIC_NEVER_DECODE'})
        return httpx.Response(200,stream=httpx.ByteStream(json.dumps(value).encode()),headers={'content-type':'application/json'})


class ReferencePeer(BasePeer):
    def __init__(self,config,network):
        super().__init__();self._config=config;self.network=network
        self.serial=frame(references._SERIAL_COMMAND,[b'Serial-Number: '+SERIAL.encode()])
    async def read(self,process,command,prompt,deadline):
        if command in (references._SERIAL_COMMAND,references._VERSION_COMMAND):return await super().read(process,command,prompt,deadline)
        assert command.startswith('diagnose sys cmdb refcnt show system.admin.name ')
        self.commands.append(command)
        count=36 if command.endswith(' '+OWNER) else int(self.network.failure=='references')
        return frame(command,[b"entry used by table synthetic.field '"+str(i).encode()+b"'" for i in range(count)])


def make(root,monkeypatch):
    monkeypatch.setattr(source_module,'_HINT_PATH_TOKEN',hashlib.sha256(b'"synthetic-route-token"').hexdigest())
    network=Network(root)
    owner=OwnerSessionMetadataTransport(network.config,owner_name=OWNER,credentials=lambda:(OWNER,'synthetic-password'),
        folder_path='ReadOnly',secret_name='ReadOnly',target_name='ReadOnly',witness=FortiPamSecretMetadataHttpTransport(network.config),
        client_factory=network.factory,clock=lambda:network.now)
    known=root/'known_hosts';known.write_text('Synthetic pinned peer');known.chmod(0o600)
    ssh=TargetSshTransportConfig('pam.example.test',22,OWNER,'synthetic-password',known,30)
    peers=[]
    def ns_factory(config):
        peer=NamespacePeer();peer._config=config
        peer.serial=frame(namespace._SERIAL_COMMAND,[b'Serial-Number: '+SERIAL.encode()])
        peer.rows={'admin':(OWNER,'Other hidden User')+((NAME,) if network.present or network.failure=='hidden-collision' else ()),
            'api-user':(network.principal,)+((NAME,) if network.failure=='api-collision' else ())}
        peers.append(peer);return peer
    def ref_factory(config):
        peer=ReferencePeer(config,network);peers.append(peer);return peer
    async def read(process,command,prompt,deadline):return await process.read(process,command,prompt,deadline)
    async def dynamic(process,command,prompt,deadline):return await process.dynamic(process,command,prompt,deadline)
    async def close(process):return await process.close(process)
    monkeypatch.setattr(namespace,'FortiPamTargetReferenceSshTransport',ns_factory)
    monkeypatch.setattr(references,'FortiPamTargetReferenceSshTransport',ref_factory)
    for module in (namespace,references):
        monkeypatch.setattr(module,'_send_and_read',read);monkeypatch.setattr(module,'_close_cli',close)
    monkeypatch.setattr(namespace,'_send_and_read_dynamic_prompt',dynamic)
    source=LocalResetFixtureSources(state_reader=network.complete,owner=owner,ssh=ssh,expected_serial=SERIAL,
        client_factory=network.factory,clock=lambda:network.now)
    return source,network,peers


@pytest.mark.parametrize('present',[False,True])
def test_real_fixed_components_join_permissions_namespace_and_references_without_writes(tmp_path,monkeypatch,present):
    source,network,peers=make(tmp_path,monkeypatch);network.present=present
    original=json.loads
    def safe_loads(raw,*args,**kwargs):
        if isinstance(raw,(bytes,bytearray)):assert b'SYNTHETIC_NEVER_DECODE' not in raw
        return original(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',safe_loads)
    observed=source.observe_presence() if present else source.observe_absence()
    source.check_current(observed)
    assert observed.absent is not present and (observed.state_digest is None) is not present
    assert source.logout_verified and all(client.is_closed and not client.cookies for client in network.clients)
    assert all(p.closed==p.connection_closed==1 for p in peers if p.commands)
    assert all(resource.closed for resource in network.resources) and all(not any(raw) for raw in network.buffers)
    assert all(method=='GET' or path=='/XX/YY/ZZ/AUTH' for method,path,_ in network.http_calls)
    assert NAME not in repr(observed)
    with pytest.raises(ValueError):source.check_current(replace(observed))
    source.close()


@pytest.mark.parametrize('fault',['actor','vdom','role','role-drift','guest-write','guest-drift','hint-type','hint-denied',
    'hint-path','owner','hidden-collision','api-collision','references','logout'])
def test_unqualified_permissions_graph_or_session_fail_closed(tmp_path,monkeypatch,fault):
    source,network,peers=make(tmp_path,monkeypatch);network.failure=fault
    with pytest.raises(ValueError):source.observe_absence()
    assert source._failed and source._current is None and source._last_failure_stage
    assert all(client.is_closed and not client.cookies for client in network.clients)
    assert all(p.closed==p.connection_closed==1 for p in peers if p.commands)
    calls=len(network.calls)+len(network.http_calls)
    with pytest.raises(ValueError):source.observe_absence()
    assert calls==len(network.calls)+len(network.http_calls)


def test_cached_source_does_not_accept_changed_namespace_columns(tmp_path,monkeypatch):
    source,network,_=make(tmp_path,monkeypatch)
    observed=source.observe_absence();source._admin_names+=('unqualified',)
    with pytest.raises(ValueError):source.check_current(observed)
    assert source._failed


def test_cached_source_rechecks_the_original_wire_digest(tmp_path,monkeypatch):
    source,network,_=make(tmp_path,monkeypatch)
    observed=source.observe_absence()
    object.__setattr__(source._state._draft,'_wire',b'{}')
    with pytest.raises(ValueError):source.check_current(observed)
    assert source._failed
