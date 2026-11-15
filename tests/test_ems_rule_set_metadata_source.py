"""Synthetic borrowed sessions and unknown response values; no native qualification."""
import hashlib
import json
from types import SimpleNamespace

import pytest

from fortipam_mcp.ems_rule_set_contract import INDEX_PATH,rule_set_detail_path
from fortipam_mcp.ems_rule_set_metadata_source import (EmsRuleSetMetadataSource,consume_rule_set_response_metadata)
from fortipam_mcp.ems_tag_contract import DisabledLinuxProcessTag
from fortipam_mcp.ems_tag_http_transport import EmsTagHttpError
from test_ems_tag_http_transport import make as owner_for,reply

PRIVATE='SYNTHETIC_RULE_SET_PRIVATE_VALUE_MUST_NEVER_DECODE_OR_HASH'


def payload(data=None):
    return {'data':{'id':735,'tag':793,'status':False,'comments':PRIVATE,'rules':[{'content':PRIVATE}],
        'use_custom_logic':False,'unknown':{'password':PRIVATE}} if data is None else data,
        'result':{'retval':1,'message':PRIVATE}}


def test_metadata_projects_only_compiled_types_without_decoding_or_hashing_unselected_values(monkeypatch):
    raw=bytearray(json.dumps(payload()).encode()); decode,digest=json.loads,hashlib.sha256
    def checked_decode(value,*args,**kwargs):
        encoded=value.encode() if isinstance(value,str) else value
        assert PRIVATE.encode() not in encoded; return decode(value,*args,**kwargs)
    def checked_digest(value=b'',*args,**kwargs):
        assert PRIVATE.encode() not in value; return digest(value,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    result=consume_rule_set_response_metadata(raw).summary()
    assert not any(raw) and result['selected_types']['comments']=='string' and result['selected_types']['rules']=='array'
    assert result['unclassified_member_occurrences']==1 and PRIVATE not in json.dumps(result)
    assert not result['response_contract_verified'] and not result['complete_or_unfiltered_state_verified'] and not result['identity_or_relation_verified']


@pytest.mark.parametrize('retval',[1,PRIVATE,'1',{'password':PRIVATE},[PRIVATE],None,True,1.0,0])
def test_result_control_is_validated_as_bytes_before_any_decode_or_hash(monkeypatch,retval):
    body=payload(); body['result']['retval']=retval; raw=bytearray(json.dumps(body).encode()); calls=[]
    def denied(*_args,**_kwargs): calls.append('forbidden-value-operation'); raise AssertionError()
    monkeypatch.setattr(json,'loads',denied); monkeypatch.setattr(hashlib,'sha256',denied)
    if type(retval) is int and retval==1:
        assert not consume_rule_set_response_metadata(raw).summary()['response_contract_verified']
    else:
        with pytest.raises(ValueError) as error: consume_rule_set_response_metadata(raw)
        assert PRIVATE not in str(error.value)
    assert calls==[] and not any(raw)


@pytest.mark.parametrize('data',[[],[{}]*33,{},None])
def test_metadata_empty_unknown_or_overflow_shapes_never_establish_completeness(data):
    body=payload(); body['data']=data; raw=bytearray(json.dumps(body).encode()); result=consume_rule_set_response_metadata(raw).summary()
    assert result['observed_array_length']==(len(data) if type(data) is list else None)
    assert result['local_catalog_bound_exceeded']==(type(data) is list and len(data)>32)
    assert not result['complete_or_unfiltered_state_verified'] and not any(raw)


@pytest.mark.parametrize('fault',['root-extra','retval-bool','retval-error','message-object','result-extra','data-scalar','overflow',
    'duplicate-root','duplicate-result','duplicate-data','escaped-key','invalid-utf8','truncated'])
def test_unknown_or_ambiguous_frames_refuse_and_clear(fault):
    body=payload()
    if fault=='root-extra': body['password']=PRIVATE
    elif fault=='retval-bool': body['result']['retval']=True
    elif fault=='retval-error': body['result']['retval']=0
    elif fault=='message-object': body['result']['message']={'password':PRIVATE}
    elif fault=='result-extra': body['result']['password']=PRIVATE
    elif fault=='data-scalar': body['data']=PRIVATE
    elif fault=='overflow': body['data']=[{}]*34
    raw=bytearray(json.dumps(body).encode())
    if fault=='duplicate-root': raw=bytearray(b'{"data":{},'+raw[1:])
    elif fault=='duplicate-result': raw=bytearray(b'{"data":{},"result":{"retval":1,"retval":1,"message":null}}')
    elif fault=='duplicate-data': raw=bytearray(b'{"data":{"id":1,"id":2},"result":{"retval":1,"message":null}}')
    elif fault=='escaped-key': raw=bytearray(b'{"d\\u0061ta":{},"result":{"retval":1,"message":null}}')
    elif fault=='invalid-utf8': raw=bytearray(b'{"data":{"comments":"\xff"},"result":{"retval":1,"message":null}}')
    elif fault=='truncated': del raw[-1]
    with pytest.raises(ValueError) as error: consume_rule_set_response_metadata(raw)
    assert PRIVATE not in str(error.value) and not any(raw)


def assemble(root,monkeypatch,*,guarded=True):
    owner,channel,connections,_,_,_=owner_for(root,monkeypatch)
    connect=owner._connect; clock=[10.0]; fault=[None]; buffers=[]; calls=[]; resources=[]
    class Socket:
        def __init__(self): self.closed=False; self.timeouts=[]
        def settimeout(self,value): assert value>0; self.timeouts.append(value)
        def close(self):
            self.closed=True
            if fault[0]=='socket-close': raise RuntimeError(PRIVATE)
    def connected(*,timeout_seconds=10):
        connection=connect(); connection.sock=Socket(); resources.append(connection.sock)
        request,getresponse,close=connection.request,connection.getresponse,connection.close
        def requested(method,path,*,body,headers):
            if path.startswith('/api/v1/tag_rules/'):
                assert method=='GET' and body is None; calls.append(path)
                assert any(key.lower()=='cookie' for key in headers) and all(key.lower()!='authorization' for key in headers)
                assert next(value for key,value in headers.items() if key.lower()=='ems-call-type') in ('1','2')
            return request(method,path,body=body,headers=headers)
        def response():
            if not connection.path.startswith('/api/v1/tag_rules/'): return getresponse()
            if fault[0]=='lost-response': raise TimeoutError(PRIVATE)
            body=payload({'rule_sets':[{'id':735,'secret':PRIVATE}],'total':1}) if connection.path==INDEX_PATH else payload()
            if fault[0]=='retval-value': body['result']['retval']=PRIVATE
            result=reply(body,
                status=500 if fault[0]=='status' else 200,content_type='text/html' if fault[0]=='html' else 'application/json',
                extra=b'Content-Encoding: gzip\r\n' if fault[0]=='encoding' else b'')
            readinto,response_close=result.readinto,result.close
            def read(view):
                if all(raw is not view.obj for raw in buffers): buffers.append(view.obj)
                count=readinto(view)
                if fault[0]=='read-interrupt': raise KeyboardInterrupt()
                if fault[0]=='read-late': clock[0]+=21
                if fault[0]=='cookie':
                    for cookie in owner._jar:
                        if cookie.name=='sessionid': cookie.value='SYNTHETIC_CHANGED_SESSION'
                return count
            def closed():
                response_close()
                if fault[0]=='response-close': raise RuntimeError(PRIVATE)
            result.readinto=read; result.close=closed
            if fault[0]=='detached': connection.sock=None
            if fault[0]=='swapped': connection.sock=Socket(); resources.append(connection.sock)
            return result
        def closed():
            close()
            if connection.sock is not None: connection.sock.close()
            if fault[0]=='connection-close': raise RuntimeError(PRIVATE)
        connection.request=requested; connection.getresponse=response; connection.close=closed
        if fault[0]=='connect-late': clock[0]+=21
        return connection
    monkeypatch.setattr(owner,'_connect',connected)
    owner.authenticate(); source=owner.make_sources(DisabledLinuxProcessTag('a'*32),source_key=b's'*32)
    epoch=[1000]; source._clock=lambda:epoch[0]; current=source.observe()
    metadata=EmsRuleSetMetadataSource(owner,source,current,source_guard=(lambda:True) if guarded else None,http_clock=lambda:clock[0])
    return SimpleNamespace(owner=owner,source=source,current=current,metadata=metadata,clock=clock,epoch=epoch,
        fault=fault,buffers=buffers,calls=calls,connections=connections,resources=resources)


@pytest.fixture
def candidate(monkeypatch):
    values=[]
    def create(root,**kwargs):
        value=assemble(root,monkeypatch,**kwargs); values.append(value); return value
    yield create
    for value in values:
        value.fault[0]=None; value.owner._connect=value.metadata._connect
        value.owner._headers=value.metadata._headers
        value.metadata.close(); value.source.close(); value.owner.close()


def test_one_fixed_pass_uses_original_reference_ids_and_preserves_producer_window(candidate,tmp_path):
    value=candidate(tmp_path); ids=tuple(sorted({v for v in value.current.full_scope._rule_sets().values() if v is not None}))
    before=len(value.connections); result=value.metadata.read_once()
    assert value.calls==[INDEX_PATH,*(rule_set_detail_path(identifier) for identifier in ids)] and len(value.connections)-before==1+len(ids)
    assert result['metadata_read_count']==len(value.calls) and not result['cleanup_authorized'] and not result['native_response_contract_verified']
    assert value.owner._live and not value.owner._closed and not value.source._closed
    assert all(not any(raw) for raw in value.buffers) and all(resource.closed for resource in value.resources[before:])
    assert PRIVATE not in json.dumps(result) and 'synthetic_owner' not in json.dumps(result)
    before=len(value.connections)
    with pytest.raises(ValueError): value.metadata.read_once()
    assert len(value.connections)==before and value.owner._live
    assert not any(value.metadata._cookie) and list(value.owner._jar)


def test_default_guard_and_direct_fetch_cannot_open_rule_set_connections(candidate,tmp_path):
    value=candidate(tmp_path,guarded=False); before=len(value.connections)
    with pytest.raises(ValueError): value.metadata._fetch(INDEX_PATH,30)
    with pytest.raises(ValueError): value.metadata.read_once()
    assert value.calls==[] and len(value.connections)==before and value.owner._live


@pytest.mark.parametrize('fault',['status','html','encoding','lost-response','response-close','connection-close','socket-close',
    'connect-late','read-late','cookie','swapped','read-interrupt','retval-value'])
def test_every_partial_or_uncertain_read_consumes_source_clears_buffers_and_keeps_original_logout_owner(candidate,tmp_path,fault):
    value=candidate(tmp_path); value.fault[0]=fault
    with pytest.raises(KeyboardInterrupt if fault=='read-interrupt' else ValueError): value.metadata.read_once()
    assert value.metadata._used and value.metadata._closed and not any(value.metadata._cookie)
    assert all(not any(raw) for raw in value.buffers) and value.owner._live
    before=list(value.calls)
    with pytest.raises(ValueError): value.metadata.read_once()
    assert value.calls==before


def test_detached_connection_still_closes_the_original_socket_handle(candidate,tmp_path):
    value=candidate(tmp_path); value.fault[0]='detached'; value.metadata.read_once()
    assert all(resource.closed for resource in value.resources) and all(not any(raw) for raw in value.buffers)


@pytest.mark.parametrize('fault',['expiry','clock-backwards','foreign-cookie','foreign-owner','source-replaced','paths-expanded',
    'connector-replaced','source-getter','source-clock','headers','account-profile'])
def test_original_observation_identity_window_and_route_drift_refuse_before_connect(candidate,tmp_path,fault):
    value=candidate(tmp_path); before=len(value.connections)
    if fault=='expiry': value.epoch[0]=value.current.expires_at
    elif fault=='clock-backwards': value.metadata._now(); value.clock[0]-=1
    elif fault=='foreign-cookie':
        for cookie in value.owner._jar:
            if cookie.name=='sessionid': cookie.value='SYNTHETIC_FOREIGN_SESSION'
    elif fault=='foreign-owner': value.owner._owner='synthetic_other_owner'
    elif fault=='source-replaced': value.metadata._source=object()
    elif fault=='paths-expanded': value.metadata._paths+=(rule_set_detail_path(999),)
    elif fault=='connector-replaced': value.owner._connect=lambda **kwargs:pytest.fail('Replaced connector must never run.')
    elif fault=='source-getter': value.source._get=lambda *_:pytest.fail('A foreign getter must never run.')
    elif fault=='source-clock': value.source._clock=lambda:1000
    elif fault=='headers': value.owner._headers=lambda *_:pytest.fail('A foreign header provider must never run.')
    else: value.source._original_account=object()
    with pytest.raises(ValueError): value.metadata.read_once()
    assert value.calls==[] and len(value.connections)==before and not any(value.metadata._cookie)


def test_one_owner_window_cannot_rebind_another_metadata_source(candidate,tmp_path):
    value=candidate(tmp_path)
    with pytest.raises(ValueError): EmsRuleSetMetadataSource(value.owner,value.source,value.current,source_guard=lambda:True)
    assert getattr(value.owner,'_rule_set_metadata_source') is value.metadata


def test_legacy_get_json_still_refuses_the_new_routes(candidate,tmp_path):
    value=candidate(tmp_path); before=len(value.connections)
    with pytest.raises(EmsTagHttpError): value.owner.get_json(INDEX_PATH)
    assert len(value.connections)==before
