"""Real source/session guards with synthetic bounded HTTP and CLI peers."""
from dataclasses import replace
import json
import logging

import httpx
import pytest

from fortipam_mcp import windows_service_credential_target_references as r
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig
from fortipam_mcp.windows_service_credential_owner_auth import service_credential_owner_binding
from test_windows_service_credential_owner_auth import Login, OWNER
from test_windows_service_credential_target_sources import Harness, NAME, ADDRESS, SERIAL, DIGEST, envelope

CONTROL = "Unit Existing Linux"


class Peer:
    def __init__(self, fault=None):
        self.fault=fault;self.requests=[];self.clients=[];self.commands=[]
        self.name_reads=self.control_reads=self.serial_reads=0
        self.process_closed=self.connection_closed=False
    def rows(self):
        def row(name,address,template,count):
            return dict(name=name,address=address,domain="",url="",template=template,
                permissions=dict(user="owner"),q_ref=count,priv_acct=0)
        rows=[row(NAME,ADDRESS,"Windows Machine",0),row(CONTROL,"192.0.2.2",r.DEFAULT_TEMPLATE,2)]
        if self.fault=='empty-address':rows.append(row('Unit Web Target','','Web Account',0))
        if self.fault=='many-targets':
            rows.extend(row('Unit Host '+str(index),'192.0.2.'+str(index),'Other',0) for index in range(3,72))
        if self.fault=="privilege":rows[0]['priv_acct']=True
        if self.fault=="references":rows[0]['q_ref']=1
        if self.fault=="missing-references":del rows[0]['q_ref']
        if self.fault=="duplicate-address":rows[1]['address']=ADDRESS
        if self.fault=="no-control":rows[1]['q_ref']=0
        if self.fault=="missing-target":rows[0]['name']='other-target'
        if self.fault=="duplicate-name":rows[1]['name']=NAME
        if self.fault=="catalog-drift" and len(self.requests)==2:rows[1]['q_ref']=3
        return rows
    def handle(self,request):
        self.requests.append(request)
        logging.getLogger('httpcore.http11').debug('PRIVATE_CATALOG_LOG_SENTINEL')
        assert request.method=='POST' and request.url.path=='/api/v2/cmdb/secret/target'
        assert request.content==r._BODY and request.headers['X-HTTP-Method-Override']=='GET'
        assert 'PRIVATE_COOKIE_SENTINEL' in request.headers['Cookie'] and 'Authorization' not in request.headers
        rows=self.rows();response=envelope(rows,runtime=True)
        response.update(size=len(rows),filtered_count=len(rows),next_idx=0,limit_reached=False)
        if self.fault=='size':response['size']=3
        if self.fault=='paging':response['has_more']=False
        if self.fault=='cursor':response['next_idx']=3
        if self.fault=='serial':response['serial']='OTHER-DEVICE'
        raw=json.dumps(response).encode();headers={'content-type':'application/json','content-length':str(len(raw))}
        if self.fault=='encoding':headers['content-encoding']='gzip'
        if self.fault=='length':headers['content-length']=str(len(raw)+1)
        if self.fault=='transfer':headers['transfer-encoding']='chunked'
        return httpx.Response(200,stream=httpx.ByteStream(raw),headers=headers)
    def factory(self,**options):
        assert options['verify'].check_hostname and options['trust_env'] is False
        client=httpx.Client(transport=httpx.MockTransport(self.handle),**options);self.clients.append(client);return client
    async def connect(self):
        peer=self
        class Process:
            stdout=object();stdin=object()
            def close(self):peer.process_closed=True
            async def wait_closed(self):
                if peer.fault=='process-close':raise OSError('PRIVATE_CLOSE_SENTINEL')
        class Connection:
            async def create_process(self,**options):return Process()
            def abort(self):peer.connection_closed=True
            async def wait_closed(self):
                if peer.fault=='connection-close':raise OSError('PRIVATE_CLOSE_SENTINEL')
        return Connection()
    async def prompt(self,*args,**kwargs):return b'unit #'
    async def dynamic(self,process,text,root,deadline):
        self.commands.append(text)
        return root[:-2]+b' (target) #' if text=='config secret target' else root
    async def command(self,process,text,prompt,deadline):
        self.commands.append(text);body=[]
        if text==r.frames._SERIAL:
            self.serial_reads+=1
            serial='OTHER' if self.fault=='cli-serial' or self.fault=='late-cli-serial' and self.serial_reads==2 else SERIAL
            body=[b'Serial-Number: '+serial.encode()]
        elif text==r.frames._VERSION:
            body=[b'Version: FortiPAM v7.0.0,build'+(b'30' if self.fault=='build' else b'29')]
        elif text==r.names._NAMES:
            self.name_reads+=1
            body=[b'    edit "'+row['name'].encode()+b'"' for row in self.rows()]
            if self.fault=='namespace':body.pop()
            if self.fault=='namespace-drift' and self.name_reads==2:body.reverse()
        elif text==r.frames._REFERENCE+'"'+CONTROL+'"':
            self.control_reads+=1
            count=0 if self.fault=='empty-control' else 3 if self.fault=='control-drift' and self.control_reads==2 else 2
            body=[b'entry used by synthetic-table: opaque' for _ in range(count)]
        elif text==r.frames._REFERENCE+'"'+NAME+'"':
            if self.fault=='selected-reference':body=[b'entry used by synthetic-table: opaque']
            if self.fault=='cli-error':body=[b'Permission denied']
        else:raise AssertionError('Unexpected command')
        return text.encode()+b'\r\n'+b''.join(line+b'\r\n' for line in body)+prompt


def setup(tmp_path,monkeypatch,*,fault=None,enabled=True):
    target_peer=Harness();source=target_peer.reader();observed=source.read_once()
    config=source._config
    binding=service_credential_owner_binding(config,owner_name=OWNER,serial_digest=DIGEST,folder_context_digest='f'*64)
    login=Login(host='synthetic.invalid',serial=SERIAL);session=login.session(config,binding)
    pin=tmp_path/'known_hosts';pin.write_text('synthetic-known-host');pin.chmod(0o600)
    ssh=TargetSshTransportConfig('192.0.2.3',22,OWNER,'PRIVATE_SSH_SENTINEL',pin,30)
    peer=Peer(fault)
    monkeypatch.setattr(r.FortiPamTargetReferenceSshTransport,'_connection',lambda self:peer.connect())
    monkeypatch.setattr(r,'_complete_pre_login',peer.prompt)
    monkeypatch.setattr(r,'_send_and_read',peer.command)
    monkeypatch.setattr(r,'_send_and_read_dynamic_prompt',peer.dynamic)
    reader=r.WindowsServiceCredentialTargetReferences(source,target_observation=observed,owner_session=session,
        ssh=ssh,read_enabled=enabled,client_factory=peer.factory,clock=lambda:target_peer.now)
    return reader,peer,target_peer,source,observed,session,login


def test_complete_owner_catalog_and_fixed_cli_control_bracket_is_current_only_inside_borrowed_sources(tmp_path,monkeypatch,caplog):
    caplog.set_level(logging.DEBUG)
    reader,peer,target_peer,source,borrowed,session,login=setup(tmp_path,monkeypatch)
    with session.authenticated():
        observed=reader.read_once();reader.check_current(observed)
        assert (observed.global_target_count,observed.positive_reference_count,observed.selected_reference_count)==(2,2,0)
        assert observed.target_reference_context_digest==borrowed.target_reference_context_digest
        assert len(peer.commands)==11 and len(peer.requests)==2
        assert peer.process_closed and peer.connection_closed and all(c.is_closed and not c.cookies for c in peer.clients)
        assert len(target_peer.requests)==6 and not source._closed
        assert not hasattr(reader,'execute') and not hasattr(reader,'issue')
        assert NAME not in repr(observed) and CONTROL not in repr(reader)
    assert session.logout_verified and 'PRIVATE_CATALOG_LOG_SENTINEL' not in caplog.text
    with pytest.raises(r.WindowsServiceTargetReferenceError):reader.check_current(observed)
    reader.close();assert not reader._key and not source._closed


@pytest.mark.parametrize('fault',['privilege','references','missing-references','duplicate-address','no-control','missing-target',
    'duplicate-name','catalog-drift','size','paging','cursor','serial','encoding','length','transfer',
    'cli-serial','late-cli-serial','build','namespace','namespace-drift','empty-control','control-drift',
    'selected-reference','cli-error','process-close','connection-close'])
def test_incomplete_drifted_or_unqualified_window_is_consumed_without_replay(tmp_path,monkeypatch,fault):
    reader,peer,_,_,_,session,_=setup(tmp_path,monkeypatch,fault=fault)
    with session.authenticated():
        with pytest.raises(r.WindowsServiceTargetReferenceError):reader.read_once()
        counts=(len(peer.requests),len(peer.commands))
        with pytest.raises(r.WindowsServiceTargetReferenceError):reader.read_once()
        assert counts==(len(peer.requests),len(peer.commands)) and reader._current is None
    assert all(c.is_closed and not c.cookies for c in peer.clients)
    if peer.commands:assert peer.process_closed and peer.connection_closed


@pytest.mark.parametrize('fault',['copy','tamper','expired','rollback','source-close','factory','clock','ssh','trust','borrowed-copy','owner-purpose','closed'])
def test_observation_and_all_borrowed_context_drift_refuse(tmp_path,monkeypatch,fault):
    reader,peer,h,source,_,session,_=setup(tmp_path,monkeypatch)
    with session.authenticated():
        observed=reader.read_once()
        if fault=='copy':observed=replace(observed)
        elif fault=='tamper':object.__setattr__(observed,'selected_reference_count',1)
        elif fault=='expired':h.now=observed.expires_at
        elif fault=='rollback':h.now-=1
        elif fault=='source-close':source.close()
        elif fault=='factory':reader._factory=lambda **kwargs:None
        elif fault=='clock':reader._clock=lambda:10
        elif fault=='ssh':object.__setattr__(reader._ssh,'password','changed-password')
        elif fault=='trust':reader._ssh.known_hosts_file.write_text('changed-key')
        elif fault=='borrowed-copy':reader._ssh=replace(reader._ssh)
        elif fault=='owner-purpose':session._purpose='recovery'
        elif fault=='closed':reader.close()
        before=len(peer.requests),len(peer.commands)
        with pytest.raises(r.WindowsServiceTargetReferenceError):reader.check_current(observed)
        assert before==(len(peer.requests),len(peer.commands))
        if fault=='owner-purpose':session._purpose='create'


def test_default_closed_and_nonlive_owner_perform_no_additional_source_io(tmp_path,monkeypatch):
    reader,peer,_,_,_,session,_=setup(tmp_path,monkeypatch,enabled=False)
    with session.authenticated():
        with pytest.raises(r.WindowsServiceTargetReferenceError):reader.read_once()
    assert not peer.requests and not peer.commands
    other=tmp_path/'other';other.mkdir()
    reader,peer,_,_,_,_,_=setup(other,monkeypatch)
    with pytest.raises(r.WindowsServiceTargetReferenceError):reader.read_once()
    assert not peer.requests and not peer.commands


@pytest.mark.parametrize('shape,count',[('empty-address',3),('many-targets',71)])
def test_private_native_directory_fingerprint_is_not_restricted_to_plan_scalar_limits(tmp_path,monkeypatch,shape,count):
    reader,peer,_,_,_,session,_=setup(tmp_path,monkeypatch,fault=shape)
    with session.authenticated():
        observed=reader.read_once();reader.check_current(observed)
        assert observed.global_target_count==count and observed.selected_reference_count==0
    assert len(peer.requests)==2 and len(peer.commands)==11
