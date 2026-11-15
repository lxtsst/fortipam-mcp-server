"""Genuine borrowed source/session guards with synthetic configuration peers."""
from dataclasses import replace
import json
import logging

import httpx
import pytest

from fortipam_mcp import windows_service_credential_association_sources as r
from test_windows_service_credential_target_references import CONTROL, setup as parent_setup
from test_windows_service_credential_target_sources import NAME, SERIAL, envelope

PROPOSED = 'MCPV4SvcCred20261025R88'


class Peer:
    def __init__(self, fault=None):
        self.fault=fault;self.requests=[];self.clients=[];self.commands=[];self.group_reads=0
    def values(self):
        rows=[dict(id=11,name='Visible Linux',target=CONTROL,dependency=[]),
            dict(id=12,name='Visible Web',target='',dependency=[]),
            dict(id=13,name='Other Owner Secret',target='Other Host',dependency=[])]
        if self.fault=='hidden-related':rows[2]['target']=NAME
        if self.fault=='visible-related':rows[0]['target']=NAME
        if self.fault=='collision':rows[2]['name']=PROPOSED
        if self.fault=='hidden-dependency':rows[2]['dependency']=[dict(id=1,target=NAME,updater='Synthetic Updater')]
        if self.fault=='unrelated-dependency':rows[2]['dependency']=[dict(id=1,target='Another Host',updater='Synthetic Updater')]
        return rows
    def handle(self,request):
        self.requests.append(request)
        assert request.method=='POST' and request.url.path=='/api/v2/cmdb/secret/database'
        assert request.content==r._BODY and request.headers['X-HTTP-Method-Override']=='GET'
        assert 'Authorization'not in request.headers and 'PRIVATE_COOKIE_SENTINEL'in request.headers['Cookie']
        logging.getLogger('httpcore.http11').debug('PRIVATE_ASSOCIATION_LOG_SENTINEL')
        rows=self.values()[:2]
        for item in rows:
            item['permissions']=dict(user='owner')
            item['field']=[dict(name='Password',value='DO_NOT_DECODE_SENTINEL')]
        if self.fault=='view-not-global-subset':rows[1]['id']=14
        if self.fault=='view-name':rows[0]['name']='mismatch'
        if self.fault=='view-target':rows[0]['target']='mismatch'
        if self.fault=='view-dependency':rows[0]['dependency']=[dict(id=1,target='Another Host',updater='Synthetic Updater')]
        if self.fault=='view-drift'and len(self.requests)==2:rows.reverse()
        if self.fault=='duplicate-visible':rows[1]['id']=rows[0]['id']
        data=envelope(rows,runtime=True);data.update(name='database',size=3,filtered_count=2,next_idx=0,limit_reached=False)
        if self.fault=='page-capacity':data['size']=1000
        if self.fault=='paging':data['has_more']=False
        if self.fault=='serial':data['serial']='OTHER-DEVICE'
        if self.fault=='cursor':data['next_idx']=1
        raw=json.dumps(data).encode();headers={'content-type':'application/json','content-length':str(len(raw))}
        if self.fault=='encoding':headers['content-encoding']='gzip'
        if self.fault=='length':headers['content-length']=str(len(raw)+1)
        if self.fault=='transfer':headers['transfer-encoding']='chunked'
        return httpx.Response(200,stream=httpx.ByteStream(raw),headers=headers)
    def factory(self,**options):
        assert options['verify'].check_hostname and options['trust_env']is False
        client=httpx.Client(transport=httpx.MockTransport(self.handle),**options);self.clients.append(client);return client
    async def prompt(self,*args,**kwargs):return b'unit #'
    async def dynamic(self,process,text,root,deadline):
        self.commands.append(text)
        return root[:-2]+b' (database) #'if text=='config secret database'else root
    async def command(self,process,text,prompt,deadline):
        self.commands.append(text);body=[];rows=self.values()
        if text==r.frames._SERIAL:body=[b'Serial-Number: '+(b'OTHER'if self.fault=='cli-serial'else SERIAL.encode())]
        elif text==r.frames._VERSION:body=[b'Version: FortiPAM v7.0.0,build'+(b'30'if self.fault=='build'else b'29')]
        elif text==r.GROUPED_COMMAND:
            self.group_reads+=1;body=[b'config secret database']
            for item in rows:
                body += [f"    edit {item['id']}".encode(),b'        set name "'+item['name'].encode()+b'"',
                    b'        set target "'+item['target'].encode()+b'"']
                if item['dependency']:
                    body.append(b'        config dependency')
                    for dependency in item['dependency']:
                        body += [f"            edit {dependency['id']}".encode(),b'                set target "'+dependency['target'].encode()+b'"',
                            b'                set updater "'+dependency['updater'].encode()+b'"',b'            next']
                    body.append(b'        end')
                body.append(b'    next')
            body.append(b'end')
            if self.fault=='group-drift'and self.group_reads==2:body[2]=b'        set name "Changed"'
            if self.fault=='group-incomplete':body.pop()
        elif text==r.anchors._EDIT_PROJECTION:
            body=[f"    edit {item['id']}".encode()for item in rows]
            if self.fault=='anchors':body.pop()
        elif text==r.namespace._NAME_PROJECTION:
            body=[b'        set name "'+item['name'].encode()+b'"'for item in rows]
            if self.fault=='names':body.reverse()
        else:raise AssertionError('unexpected command')
        return text.encode()+b'\r\n'+b''.join(line+b'\r\n'for line in body)+prompt


def setup(tmp_path,monkeypatch,fault=None):
    parent,parent_peer,target_peer,target,borrowed,session,login=parent_setup(tmp_path,monkeypatch)
    peer=Peer(fault)
    monkeypatch.setattr(r,'_complete_pre_login',peer.prompt)
    monkeypatch.setattr(r,'_send_and_read',peer.command)
    monkeypatch.setattr(r,'_send_and_read_dynamic_prompt',peer.dynamic)
    return parent,parent_peer,target_peer,target,session,peer


def reader(parent,observed,peer,enabled=True):
    return r.WindowsServiceCredentialAssociationSources(parent,observation=observed,
        proposed_secret_name=PROPOSED,read_enabled=enabled,client_factory=peer.factory)


@pytest.mark.parametrize('fault',[None,'page-capacity','unrelated-dependency'])
def test_scope_closes_without_reading_unrelated_hidden_metadata(tmp_path,monkeypatch,caplog,fault):
    caplog.set_level(logging.DEBUG)
    parent,parent_peer,target_peer,target,session,peer=setup(tmp_path,monkeypatch,fault)
    with session.authenticated():
        reference=parent.read_once();source=reader(parent,reference,peer)
        observed=source.read_once();source.check_current(observed)
        assert(observed.global_secret_count,observed.visible_secret_count,observed.unrelated_not_read_count)==(3,2,1)
        assert observed.positive_target_matches==1 and len(peer.commands)==10 and len(peer.requests)==2
        assert observed.target_reference_context_digest==reference.target_reference_context_digest
        assert observed.summary()['selected_precreate_configuration_scope_closed']
        assert observed.summary()['original_secret_runtime_association_qualified']is False
        assert observed.summary()['activity_qualified']is observed.summary()['execution_authorized']is False
        assert all(client.is_closed and not client.cookies for client in peer.clients)
        assert 'Other Owner'not in repr(source)and 'Other Owner'not in repr(observed)
        assert not hasattr(source,'execute')and not hasattr(source,'issue')
        source.close();assert not source._key and not parent._closed and not target._closed
    assert session.logout_verified and 'PRIVATE_ASSOCIATION_LOG_SENTINEL'not in caplog.text
    parent.close();target.close()


@pytest.mark.parametrize('fault',['hidden-related','hidden-dependency','visible-related','collision',
    'view-not-global-subset','view-name','view-target','view-dependency','view-drift','duplicate-visible',
    'paging','serial','cursor','encoding','length','transfer','cli-serial','build','group-drift',
    'group-incomplete','anchors','names'])
def test_relevant_or_unqualified_rows_refuse_instead_of_being_excluded(tmp_path,monkeypatch,fault):
    parent,_,_,target,session,peer=setup(tmp_path,monkeypatch,fault)
    with session.authenticated():
        reference=parent.read_once();source=reader(parent,reference,peer)
        with pytest.raises(r.WindowsServiceAssociationSourceError):source.read_once()
        before=(len(peer.requests),len(peer.commands))
        with pytest.raises(r.WindowsServiceAssociationSourceError):source.read_once()
        assert before==(len(peer.requests),len(peer.commands))and source._current is None
        assert all(request.method=='POST'and request.url.path=='/api/v2/cmdb/secret/database'for request in peer.requests)
        source.close()
    parent.close();target.close()


@pytest.mark.parametrize('fault',['copy','disabled'])
def test_default_closed_and_copied_parent_evidence_cannot_start_io(tmp_path,monkeypatch,fault):
    parent,_,_,target,session,peer=setup(tmp_path,monkeypatch)
    with session.authenticated():
        reference=parent.read_once()
        if fault=='copy':
            with pytest.raises(r.WindowsServiceAssociationSourceError):reader(parent,replace(reference),peer)
        else:
            source=reader(parent,reference,peer,False)
            with pytest.raises(r.WindowsServiceAssociationSourceError):source.read_once()
            source.close()
        assert not peer.requests and not peer.commands
    parent.close();target.close()


@pytest.mark.parametrize('fault',['copy','tamper','expiry','parent-close','factory','owner-close'])
def test_current_evidence_remains_bound_to_live_borrowed_context(tmp_path,monkeypatch,fault):
    parent,_,target_peer,target,session,peer=setup(tmp_path,monkeypatch)
    with session.authenticated():
        reference=parent.read_once();source=reader(parent,reference,peer);observed=source.read_once()
        if fault=='copy':observed=replace(observed)
        if fault=='tamper':object.__setattr__(observed,'visible_secret_count',0)
        if fault=='expiry':target_peer.now=41
        if fault=='parent-close':parent.close()
        if fault=='factory':source._factory=lambda**options:httpx.Client(**options)
        if fault!='owner-close':
            with pytest.raises(r.WindowsServiceAssociationSourceError):source.check_current(observed)
            source.close()
    if fault=='owner-close':
        with pytest.raises(r.WindowsServiceAssociationSourceError):source.check_current(observed)
        source.close()
    parent.close();target.close()


def test_unselected_material_never_reaches_scalar_decoder(tmp_path,monkeypatch):
    parent,_,_,target,session,peer=setup(tmp_path,monkeypatch)
    original=r.metadata._scalar
    def guarded(raw,span):
        assert b'DO_NOT_DECODE_SENTINEL'not in raw[span[0]:span[1]]
        return original(raw,span)
    monkeypatch.setattr(r.metadata,'_scalar',guarded)
    with session.authenticated():
        source=reader(parent,parent.read_once(),peer);source.read_once();source.close()
    parent.close();target.close()


def test_child_transport_close_failure_cannot_publish_observation(tmp_path,monkeypatch):
    parent,parent_peer,_,target,session,peer=setup(tmp_path,monkeypatch)
    with session.authenticated():
        reference=parent.read_once();source=reader(parent,reference,peer)
        parent_peer.fault='connection-close'
        with pytest.raises(r.WindowsServiceAssociationSourceError):source.read_once()
        assert source._current is None and all(client.is_closed for client in peer.clients)
        source.close()
    parent.close();target.close()
