"""Distinct native Owner input provenance with genuine borrowed source objects."""
import copy
from dataclasses import replace
import json
import logging
import pickle

import httpx
import pytest

from fortipam_mcp import windows_service_credential_owner_inputs as r
from fortipam_mcp.windows_service_credential_owner_auth import service_credential_owner_binding
from test_windows_service_credential_creation_inputs import Harness as MetadataHarness
from test_windows_service_credential_owner_auth import Login, OWNER
from test_windows_service_credential_contract import binding
from test_windows_service_credential_target_sources import Body, NAME, ADDRESS, DIGEST, SERIAL
from v4_planning.material_provider import MaterialAccessDenied


class Harness(MetadataHarness):
    def __init__(self, *, same_template=False):
        super().__init__(same_template=same_template)
        self.owner_mode=False
        self.owner_requests=[]
        actor=copy.deepcopy(self.inputs[0])
        actor['results']['admin'].update(name=OWNER,login_name=OWNER,super_admin=True,
            profile=dict(name='super_admin',secretgrp='read-write',**{'secretgrp-permission':dict.fromkeys(('folder-table','secret-table','target','template'),'read-write')}))
        if same_template:
            values=[actor,self.values[1],self.values[2],self.inputs[1],self.inputs[2],self.inputs[3],
                self.inputs[4],self.inputs[5],self.inputs[6],self.values[3],self.values[4],actor]
        else:
            values=[actor,self.values[1],self.values[2],self.inputs[1],self.inputs[2],self.inputs[3],self.inputs[4],
                self.inputs[5],self.inputs[6],self.inputs[7],self.inputs[8],self.values[3],self.values[4],actor]
        self.owner_values=[copy.deepcopy(value) for value in values]

    def handle(self, request):
        if not self.owner_mode:return super().handle(request)
        index=len(self.owner_requests);self.owner_requests.append(request)
        assert 'authorization' not in request.headers and 'PRIVATE_COOKIE_SENTINEL' in request.headers['cookie']
        if request.method=='POST':
            assert request.headers['X-HTTP-Method-Override']=='GET' and request.headers['X-CSRFTOKEN']=='PRIVATE_CSRF_SENTINEL'
            assert json.loads(request.content)['json_filter'][0]['filters'][0]['operator']=='exact'
        else:assert request.method=='GET' and not request.content
        logging.getLogger('httpcore.http11').debug('PRIVATE_OWNER_INPUT_SENTINEL')
        data=json.dumps(self.owner_values[index]).encode()
        headers={'content-type':'application/json','set-cookie':'synthetic-owner-reader=PRIVATE_RESPONSE_COOKIE'}
        status=200
        if index==4:
            if self.fault=='oversize':data=b'x'*1048577
            if self.fault=='truncated':data=data[:-1]
            if self.fault=='length':headers['content-length']=str(len(data)+1)
            if self.fault=='status':status=403
            if self.fault=='redirect':status=302;headers['location']='https://other.invalid/private'
            if self.fault=='late-headers':self.now=40.0
        stream=Body(data,self,2 if index==4 else 0);self.streams.append(stream)
        return httpx.Response(status,headers=headers,stream=stream)

    def metadata(self):
        target,reference,source=self.prepare()
        observation=source.read_once()
        config=source._config
        owner_binding=service_credential_owner_binding(config,owner_name=OWNER,serial_digest=DIGEST,
            folder_context_digest=binding().folder_context_digest)
        login=Login(host=httpx.URL(config.base_url).host,serial=SERIAL)
        session=login.session(config,owner_binding)
        self.owner_mode=True
        return source,observation,session,login


@pytest.mark.parametrize('same_template',[False,True])
def test_owner_bracket_binds_real_provenance_without_relaxing_the_bearer_reader(monkeypatch,caplog,same_template):
    h=Harness(same_template=same_template);metadata,api,session,login=h.metadata();buffers=[]
    caplog.set_level(logging.DEBUG)
    with session.authenticated():
        source=r.WindowsServiceCredentialOwnerInputs(metadata_sources=metadata,metadata_observation=api,owner_session=session)
        receive=source._receive
        def track(*args,**kwargs):
            raw=receive(*args,**kwargs);buffers.append(raw);return raw
        monkeypatch.setattr(source,'_receive',track)
        observed=source.read_once();source.check_current(observed)
        profile=replace(binding(),target_name=NAME,target_address=ADDRESS,serial_digest=DIGEST,
            target_reference_context_digest=observed.target_reference_context_digest)
        source.check_profile(observed,profile)
        assert observed.target_reference_context_digest!=api.target_reference_context_digest
        assert observed.metadata_source_context_digest==api.source_context_digest
        assert observed.owner_binding_digest==session.binding.binding_digest
        assert observed.full_row_fields==api.full_row_fields and observed.defaults==api.defaults
        assert observed.expires_at==api.expires_at and observed.configuration==metadata._target_observed.configuration
        assert len(h.owner_requests)==(12 if same_template else 14)
        with pytest.raises(r.WindowsServiceCredentialOwnerInputError):source.read_once()
        for value in (source,observed):
            assert NAME not in repr(value)
            for operation in (copy.copy,copy.deepcopy,pickle.dumps):
                with pytest.raises(MaterialAccessDenied):operation(value)
        source.close();metadata.check_current(api)
        assert not metadata._closed and session._active
    assert session.logout_verified
    assert all(not raw for raw in buffers) and all(stream.closed for stream in h.streams)
    assert all(client.is_closed and not client.cookies for client in h.clients+login.clients)
    assert 'PRIVATE_' not in caplog.text
    assert all('/secret-clear-text' not in request.url.path for request in h.owner_requests)
    assert all(request.url.params.get('action') in ('default','schema') for request in h.owner_requests if request.url.path.endswith('/database'))


@pytest.mark.parametrize('index',range(14))
def test_every_owner_response_is_bound_to_the_same_native_device(index):
    h=Harness();metadata,api,session,_=h.metadata();h.owner_values[index]['serial']='OTHER'
    with session.authenticated():
        source=r.WindowsServiceCredentialOwnerInputs(metadata_sources=metadata,metadata_observation=api,owner_session=session)
        with pytest.raises(r.WindowsServiceCredentialOwnerInputError):source.read_once()
    assert len(h.owner_requests)==index+1


@pytest.mark.parametrize('fault',['factory','oversize','truncated','length','status','redirect','late-headers','stream','interrupt','response-close','client-close'])
def test_owner_transport_failures_clear_resources_and_do_not_replay(fault,monkeypatch):
    h=Harness();metadata,api,session,_=h.metadata();buffers=[]
    with session.authenticated():
        source=r.WindowsServiceCredentialOwnerInputs(metadata_sources=metadata,metadata_observation=api,owner_session=session)
        h.fault=fault;receive=source._receive
        def track(*args,**kwargs):
            raw=receive(*args,**kwargs);buffers.append(raw);return raw
        monkeypatch.setattr(source,'_receive',track)
        with pytest.raises(KeyboardInterrupt if fault=='interrupt' else r.WindowsServiceCredentialOwnerInputError):source.read_once()
        count=len(h.owner_requests)
        with pytest.raises(r.WindowsServiceCredentialOwnerInputError):source.read_once()
        assert len(h.owner_requests)==count and all(not raw for raw in buffers)
    assert all(client.is_closed and not client.cookies for client in h.clients)


@pytest.mark.parametrize('fault',['different-target','runtime-privilege','runtime-permission','runtime-drift','defaults','schema-missing',
    'schema-drift','template-permission','template-drift','actor','actor-drift','scope'])
def test_owner_current_state_guard_template_and_actor_drift_are_not_metadata_observer_proofs(fault):
    h=Harness();metadata,api,session,_=h.metadata()
    if fault=='different-target':h.owner_values[1]['results'][0]['address']='192.0.2.99'
    if fault=='runtime-privilege':h.owner_values[2]['results'][0]['priv_acct']=70
    if fault=='runtime-permission':h.owner_values[2]['results'][0]['permissions']['user']='view'
    if fault=='runtime-drift':h.owner_values[11]['results'][0]['opaque_extra']='changed'
    if fault=='defaults':h.owner_values[3]['results']['password-changer']='enable'
    if fault=='schema-missing':del h.owner_values[4]['results']['children']['field']
    if fault=='schema-drift':h.owner_values[9]['results']['children']['name']['type']='integer'
    if fault=='template-permission':h.owner_values[6]['results'][0]['permissions']['user']='none'
    if fault=='template-drift':h.owner_values[7]['results'][0]['opaque']='changed'
    if fault=='actor':h.owner_values[0]['results']['admin']['name']='other-owner'
    if fault=='actor-drift':h.owner_values[13]['results']['admin']['profile']['secretgrp']='none'
    if fault=='scope':h.owner_values[4]['vdom']='other'
    with session.authenticated():
        source=r.WindowsServiceCredentialOwnerInputs(metadata_sources=metadata,metadata_observation=api,owner_session=session)
        with pytest.raises(r.WindowsServiceCredentialOwnerInputError):source.read_once()


@pytest.mark.parametrize('drift',['factory','config','tls','target','schema-fields','default-fields','cookie','owner-closed'])
def test_observation_and_borrowed_runtime_pins_remain_required_after_read(drift):
    h=Harness();metadata,api,session,_=h.metadata()
    with session.authenticated():
        source=r.WindowsServiceCredentialOwnerInputs(metadata_sources=metadata,metadata_observation=api,owner_session=session)
        observed=source.read_once()
        if drift=='factory':source._factory=lambda **kwargs:None
        if drift=='config':source._config=replace(source._config,bearer_token='other-token')
        if drift=='tls':source._tls=object()
        if drift=='target':source._target=object()
        if drift=='schema-fields':source._schema_fields=frozenset({'other'})
        if drift=='default-fields':source._default_fields=frozenset({'other'})
        if drift=='cookie':session._cookie_pin='changed'
        if drift=='owner-closed':session._active=False
        with pytest.raises(r.WindowsServiceCredentialOwnerInputError):source.check_current(observed)
        # Restore only the local test session bookkeeping so its independent
        # identity/logout checks can complete; the source stays consumed.
        session._active=True
        session._cookie_pin=session._cookies_digest()
