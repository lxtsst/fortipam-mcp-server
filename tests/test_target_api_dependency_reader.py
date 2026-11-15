"""Fixed-route reader tests with synthetic responses and no network."""
import copy
from dataclasses import replace
import json
import logging
import pickle
import ssl

import httpx
import pytest

from fortipam_mcp import target_api_dependency_reader as r
from v4_planning.material_provider import MaterialAccessDenied
from test_target_lifecycle_dependencies import api_payloads, ACTOR, DIGEST, COORDINATES


class Body(httpx.SyncByteStream):
    def __init__(self, value, eof=lambda: None):
        self.value=value; self.eof=eof; self.closed=False
    def __iter__(self):
        yield self.value
        self.eof()
    def close(self):self.closed=True


class Harness:
    def __init__(self, *, fault=None):
        self.now=10.0; self.requests=[]; self.streams=[]; self.clients=[]; self.options=[]
        self.values=api_payloads();self.fault=fault
    def handle(self, request):
        index=len(self.requests)%8;self.requests.append(request)
        logging.getLogger('httpcore.http11').debug('PRIVATE_HEADER_SENTINEL')
        data=json.dumps(self.values[index]).encode()
        if self.fault=='oversize' and index==3:data=b'x'*(r.m._MAX_BYTES+1)
        if self.fault=='malformed' and index==4:data=b'{'
        def eof():
            if self.fault=='late_eof' and index==0:self.now+=31
            if self.fault=='rollback' and index==0:self.now-=1
        stream=Body(data,eof);self.streams.append(stream)
        headers={'content-type':'text/html' if self.fault=='type' else 'application/json',
                 'content-encoding':'gzip' if self.fault=='encoding' else 'identity',
                 'location':'https://other.invalid/PRIVATE_SENTINEL'}
        status=302 if self.fault=='redirect' else 403 if self.fault=='status' else 200
        if self.fault=='late_headers':self.now+=31
        return httpx.Response(status,headers=headers,stream=stream)
    def factory(self, **kwargs):
        self.options.append(kwargs)
        if self.fault=='factory':raise RuntimeError('PRIVATE_FACTORY_SENTINEL')
        harness=self
        class Client(httpx.Client):
            def __exit__(self, *args):
                super().__exit__(*args)
                if harness.fault=='late_close':harness.now+=31
        client=Client(transport=httpx.MockTransport(self.handle),**kwargs)
        self.clients.append(client);return client
    def reader(self, **changes):
        config=r.SecretMetadataHttpTransportConfig('https://synthetic.invalid','synthetic-token',30,None)
        if changes:config=replace(config,**changes)
        return r.TargetApiDependencyReader(config,serial_digest=DIGEST,
            clock=lambda:self.now,client_factory=self.factory)


def test_complete_fixed_chain_and_owned_wipe(monkeypatch,caplog):
    h=Harness();reader=h.reader();owned=[]
    original=reader._receive
    def track(*args,**kwargs):
        body=original(*args,**kwargs);owned.append(body);return body
    monkeypatch.setattr(reader,'_receive',track)
    caplog.set_level(logging.DEBUG)
    observed=reader.observe(COORDINATES)
    reader.check_current(observed)
    assert len(h.requests)==8 and observed.observed_at==10 and observed.expires_at==40
    assert all(not any(body) for body in owned) and all(s.closed for s in h.streams)
    assert all(client.is_closed for client in h.clients)
    assert [request.method for request in h.requests]==['GET','GET','GET','POST','GET','GET','GET','GET']
    assert h.requests[3].url.path=='/api/v2/cmdb/secret/template'
    assert h.requests[3].content==b'{"json_filter":[]}'
    assert h.requests[3].headers['x-http-method-override']=='GET'
    assert str(h.requests[4].url).endswith(r._SCHEMA)
    assert all(request.headers['authorization']=='Bearer synthetic-token' for request in h.requests)
    assert all(request.headers['accept-encoding']=='identity' for request in h.requests)
    assert h.requests[0].url==h.requests[7].url and h.requests[1].url==h.requests[6].url and h.requests[2].url==h.requests[5].url
    assert not h.options[0]['trust_env'] and not h.options[0]['follow_redirects']
    context=h.options[0]['verify'];assert context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED
    assert 'synthetic' not in caplog.text and 'PRIVATE_' not in caplog.text
    for value in (reader,observed):
        assert ACTOR not in repr(value)
        for operation in (copy.copy,copy.deepcopy,pickle.dumps):
            with pytest.raises(MaterialAccessDenied):operation(value)


@pytest.mark.parametrize('fault',['redirect','status','type','encoding','oversize','malformed',
    'late_headers','late_eof','late_close','rollback','factory'])
def test_failure_closes_and_wipes_and_revokes(fault,monkeypatch):
    h=Harness();reader=h.reader();prior=reader.observe(COORDINATES);h.fault=fault;owned=[]
    original=reader._receive
    def track(*args,**kwargs):
        value=original(*args,**kwargs);owned.append(value);return value
    monkeypatch.setattr(reader,'_receive',track)
    before=len(h.requests)
    with pytest.raises(r.TargetApiDependencyReadError) as error:reader.observe(COORDINATES)
    assert str(error.value)==r._ERROR and error.value.__suppress_context__
    assert len(h.requests)-before<=8
    assert all(not any(body) for body in owned)
    assert all(s.closed for s in h.streams) and all(c.is_closed for c in h.clients)
    with pytest.raises(r.TargetApiDependencyReadError):reader.check_current(prior)


@pytest.mark.parametrize('index',range(8))
def test_every_response_device_binding(index):
    h=Harness();h.values[index]['serial']='OTHER'
    with pytest.raises(r.TargetApiDependencyReadError):h.reader().observe(COORDINATES)


@pytest.mark.parametrize('fault',['profile','api','actor','template','schema','selector'])
def test_dependency_drift_and_qualification(fault):
    h=Harness()
    if fault=='profile':h.values[5]['results']['secretgrp-permission']['target']='read'
    elif fault=='api':h.values[6]['results']['unknown']='changed'
    elif fault=='actor':h.values[7]['results']['admin']['guest_admin']=True
    elif fault=='template':h.values[3]['results'][0]['permissions']['user']='none'
    elif fault=='schema':h.values[4]['results']['children']['address']['readonly']=True
    elif fault=='selector':h.values[1]['results']['accprofile']='../other'
    with pytest.raises(r.TargetApiDependencyReadError):h.reader().observe(COORDINATES)
    if fault=='selector':assert len(h.requests)==2


def test_expiry_supersession_foreign_close_and_rollback():
    h=Harness();reader=h.reader();a=reader.observe(COORDINATES);b=reader.observe(COORDINATES)
    with pytest.raises(r.TargetApiDependencyReadError):reader.check_current(a)
    with pytest.raises(r.TargetApiDependencyReadError):h.reader().check_current(b)
    with pytest.raises(r.TargetApiDependencyReadError):reader.check_current(replace(b))
    h.now=40
    with pytest.raises(r.TargetApiDependencyReadError):reader.check_current(b)
    h.now=41;c=reader.observe(COORDINATES);h.now=40
    with pytest.raises(r.TargetApiDependencyReadError):reader.check_current(c)
    h.now=42
    with pytest.raises(r.TargetApiDependencyReadError):reader.observe(COORDINATES)
    reader.close();before=len(h.requests)
    with pytest.raises(r.TargetApiDependencyReadError):reader.observe(COORDINATES)
    assert len(h.requests)==before


def test_ca_bytes_snapshotted_once_and_source_context_bound(tmp_path,monkeypatch):
    path=tmp_path/'ca.pem';path.write_text('SYNTHETIC_CA_A')
    calls=[];original=ssl.create_default_context
    def context(*,cadata=None):calls.append(cadata);return original()
    monkeypatch.setattr(r.ssl,'create_default_context',context)
    h=Harness();reader=h.reader(ca_file=str(path));first=reader.observe(COORDINATES)
    path.write_text('SYNTHETIC_CA_B');second=reader.observe(COORDINATES)
    assert calls==['SYNTHETIC_CA_A'] and first.source_context_digest==second.source_context_digest
    assert h.options[0]['verify'] is h.options[1]['verify']
    third=h.reader(ca_file=str(path)).observe(COORDINATES)
    assert third.source_context_digest!=second.source_context_digest
    fourth=h.reader(bearer_token='different-synthetic-token').observe(COORDINATES)
    assert fourth.source_context_digest!=second.source_context_digest


def test_log_filter_restores_other_filters():
    h=Harness(fault='factory');logger=logging.getLogger('httpx');existing=logging.Filter()
    logger.addFilter(existing);before=list(logger.filters)
    try:
        with pytest.raises(r.TargetApiDependencyReadError):h.reader().observe(COORDINATES)
        assert logger.filters==before
    finally:logger.removeFilter(existing)


@pytest.mark.parametrize('coordinates',[(),[],(object(),)])
def test_invalid_coordinates_no_requests(coordinates):
    h=Harness()
    with pytest.raises(r.TargetApiDependencyReadError):h.reader().observe(coordinates)
    assert not h.requests


def test_private_log_filter_keeps_other_thread_messages(caplog, monkeypatch):
    from threading import Thread
    caplog.set_level(logging.DEBUG, logger='httpx')
    logger=logging.getLogger('httpx')
    monkeypatch.setattr(logger, 'disabled', False)
    monkeypatch.setattr(logger, 'propagate', True)
    previous_disable = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    try:
        with r._private_http_logs():
            logger.info('SUPPRESSED_PRIVATE_SENTINEL')
            worker=Thread(target=lambda:logger.info('UNRELATED_THREAD_MESSAGE'))
            worker.start();worker.join()
    finally:
        logging.disable(previous_disable)
    assert 'SUPPRESSED_PRIVATE_SENTINEL' not in caplog.text
    assert 'UNRELATED_THREAD_MESSAGE' in caplog.text


@pytest.mark.parametrize('path,template', [('/other',False),(r._TEMPLATES,False),
    (r._MONITOR,True),('/api/v2/cmdb/system/api-user/../admin?format=name%7Caccprofile&with_meta=true&vdom=root',False)])
def test_internal_fixed_route_boundary(path,template):
    h=Harness();reader=h.reader()
    with pytest.raises(ValueError):reader._receive(None,path,40,template=template)
    assert not h.requests
