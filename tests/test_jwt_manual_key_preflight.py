"""Bounded JWT absence, namespace and fixed-source reader evidence."""
import copy
import io
import json
import ssl
from dataclasses import replace

import pytest

from fortipam_mcp import jwt_manual_key_preflight as c
from fortipam_mcp import jwt_manual_key_preflight_reader as r
from fortipam_mcp.jwt_manual_key_contract import DEFAULT_FIELDS, _default_digest, _digest, JwtManualCreatePlan, JwtManualPublicKey
from fortipam_mcp.jwt_manual_key_request_contract import JwtManualCreateRequest
from fortipam_mcp.jwt_manual_key_response_custody import jwt_manual_create_current_digest
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_jwt_manual_key_actor_evidence import inputs as actor_inputs, SERIAL
from test_jwt_manual_key_contract import defaults, synthetic_key, public_pem

NAME='mcp-v4-jwt-synthetic'
SCHEMA={key:{'type':'synthetic-string'} for key in DEFAULT_FIELDS}
SCHEMA_DIGEST=_digest(SCHEMA)
DEFAULTS_DIGEST=_default_digest(defaults())


def packet(table,result,**changes):
    value=dict(version='v7.0.0',build=29,serial='SYNTHETIC_SERIAL',http_method='GET',http_status=200,
        status='success',path='system'if table=='api-user'else'secret',name=table,vdom='root',results=result)
    value.update(changes);return value


def inputs():
    return [packet('jwt-key',{'children':copy.deepcopy(SCHEMA)},action='schema'),
        packet('jwt-key',defaults(),action='default'),packet('jwt-key',[],size=0,matched_count=0,next_idx=0),
        packet('api-user',[dict(name='synthetic-api',type='token',**{'jwt-key':''})],size=1,matched_count=1,next_idx=0),
        packet('jwt-key',None,status='error',http_status=404,mkey=NAME,message='SYNTHETIC_PRIVATE_NOTE')]


def raw(value):return bytearray(json.dumps(value,separators=(',',':')).encode())


def consume(values):
    buffers=[raw(value)for value in values]
    try:
        return c.consume_jwt_manual_key_preflight(*buffers,name=NAME,serial_digest=SERIAL,
            expected_schema_digest=SCHEMA_DIGEST,expected_defaults_digest=DEFAULTS_DIGEST)
    finally:assert all(not value for value in buffers)


def test_source_pinned_inputs_prove_only_actor_visible_empty_namespace_and_exact_absence(monkeypatch):
    scalar=c.parser._scalar
    def selected_only(data,span):
        assert b'SYNTHETIC_PRIVATE_NOTE'not in data[slice(*span)]
        return scalar(data,span)
    monkeypatch.setattr(c.parser,'_scalar',selected_only)
    first=consume(inputs());second=consume(inputs())
    assert first==second and first.schema_digest==SCHEMA_DIGEST and first.defaults_digest==DEFAULTS_DIGEST
    assert NAME not in repr(first)and 'synthetic-api'not in repr(first)


@pytest.mark.parametrize('fault',['schema-drift','extra-schema-field','default-drift','extra-default-field','schema-error',
    'existing-key','jwt-user','key-selector','duplicate-user','missing-counter','boolean-counter','truncated-counter',
    'bad-next-index','missing-next-index','paged-view','limited','wrong-serial','wrong-mkey','wrong-status','wrong-http','results-present','error-code'])
def test_incomplete_drifting_or_nonempty_inputs_never_prove_creation_readiness(fault):
    values=inputs()
    if fault=='schema-drift':values[0]['results']['children']['name']['type']='changed'
    if fault=='extra-schema-field':values[0]['results']['children']['unknown']={'type':'string'}
    if fault=='default-drift':values[1]['results']['check-interval']=25
    if fault=='extra-default-field':values[1]['results']['q_origin_key']=''
    if fault=='schema-error':values[0]['schema_errors']=[]
    if fault=='existing-key':values[2].update(results=[dict(name=NAME,type='manually')],size=1,matched_count=1)
    if fault=='jwt-user':values[3]['results'][0]['type']='jwt'
    if fault=='key-selector':values[3]['results'][0]['jwt-key']=NAME
    if fault=='duplicate-user':values[3]['results']*=2;values[3].update(size=2,matched_count=2)
    if fault=='missing-counter':del values[3]['matched_count']
    if fault=='boolean-counter':values[3]['matched_count']=True
    if fault=='truncated-counter':values[3]['matched_count']=2
    if fault=='bad-next-index':values[3]['next_idx']=True
    if fault=='missing-next-index':del values[3]['next_idx']
    if fault=='paged-view':values[3]['start']=0
    if fault=='limited':values[2]['limit_reached']=True
    if fault=='wrong-serial':values[4]['serial']='FOREIGN'
    if fault=='wrong-mkey':values[4]['mkey']='mcp-v4-jwt-other'
    if fault=='wrong-status':values[4]['status']='success'
    if fault=='wrong-http':values[4]['http_status']=403
    if fault=='results-present':values[4]['results']=[{'name':NAME}]
    if fault=='error-code':values[4]['error']=-3
    with pytest.raises(c.JwtManualKeyPreflightError,match='^The private manual JWT-key preflight is unavailable.$'):
        consume(values)


def test_native_complete_collections_keep_their_opaque_index_and_all_counter_checks():
    values=inputs()
    values[3]['results']=[dict(name='synthetic-api-'+str(i),type='token',**{'jwt-key':''})for i in range(6)]
    values[3].update(size=6,matched_count=6,next_idx=5)
    first=consume(values)
    values[3]['results'].reverse()
    assert consume(values)==first
    values[3]['limit_reached']=False
    assert consume(values).state_digest!=first.state_digest
    values[3]['matched_count']=7
    with pytest.raises(c.JwtManualKeyPreflightError):consume(values)


class Harness:
    def __init__(self,tmp_path,monkeypatch):
        self.calls=[];self.resources=[];self.buffers=[];self.fail='';self.source=True
        self.responses=actor_inputs()+inputs()
        self.ca=tmp_path/'synthetic-ca.pem';self.ca.write_bytes(b'SYNTHETIC_CA_BINDING')
        monkeypatch.setattr(r,'_ssl_context',lambda config:ssl.create_default_context())
        config=SecretMetadataHttpTransportConfig('https://pam.example.test:9443','synthetic-bearer',30,str(self.ca))
        self.reader=r.JwtManualKeyPreflightReader(config,name=NAME,expected_actor='synthetic-api',expected_profile='synthetic-role',
            serial_digest=SERIAL,schema_digest=SCHEMA_DIGEST,defaults_digest=DEFAULTS_DIGEST,
            source_guard=lambda:self.source,connection_factory=self.connect,http_clock=lambda:0)

    def connect(self,host,port,**kwargs):
        assert(host,port)==('pam.example.test',9443)
        assert kwargs['context'].check_hostname and kwargs['context'].verify_mode==ssl.CERT_REQUIRED
        harness=self;index=len(self.calls)
        class Response:
            status=200 if index<8 else 404
            closed=False
            def __init__(self):self.stream=io.BytesIO(bytes(raw(harness.responses[index])))
            def getheader(self,key,default=''):
                return {'content-type':'text/html'if harness.fail=='media'else'application/json',
                    'content-encoding':'gzip'if harness.fail=='encoding'else'identity'}.get(key,default)
            def readinto(self,destination):
                harness.buffers.append(destination)
                if harness.fail=='timeout':raise TimeoutError('SYNTHETIC_PRIVATE_NOTE')
                if harness.fail=='count':return True
                if harness.fail=='interrupt':raise KeyboardInterrupt
                return self.stream.readinto(destination)
            def close(self):
                self.closed=True
                if harness.fail=='close':raise OSError('SYNTHETIC_PRIVATE_NOTE')
        class Connection:
            closed=False
            def __init__(self):self.response=Response();harness.resources.append(self)
            def connect(self):
                if harness.fail=='source-after-tls':harness.source=False
            def request(self,method,path,*,headers):
                assert method=='GET' and 'key-name'not in path and 'key|'not in path
                assert headers['Authorization']=='Bearer synthetic-bearer'
                harness.calls.append(path)
            def getresponse(self):harness.resources.append(self.response);return self.response
            def close(self):self.closed=True
        return Connection()


def test_reader_uses_only_nine_fixed_gets_erases_buffers_and_closes_every_resource(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch)
    value=h.reader.observe()
    assert h.calls==list(h.reader._paths)and len(h.calls)==9 and len(h.resources)==18
    assert all(resource.closed for resource in h.resources)and all(not any(raw)for raw in h.buffers)
    assert value.state==consume(inputs())and value.actor.serial_digest==SERIAL
    assert h.calls[-1].endswith('/'+NAME+'?format=name%7Ctype&with_meta=true')


@pytest.mark.parametrize('fault',['none','name_digest','serial_digest','schema_digest','defaults_digest'])
def test_preflight_m4_join_refuses_another_name_device_or_default_context(tmp_path,monkeypatch,synthetic_key,fault):
    h=Harness(tmp_path,monkeypatch);preflight=h.reader.observe()
    context=dict(schema_digest=SCHEMA_DIGEST,serial_digest=SERIAL)
    plan=JwtManualCreatePlan(NAME,'a'*64,JwtManualPublicKey(public_pem(synthetic_key)),defaults(),**context)
    request=JwtManualCreateRequest(plan,defaults(),**context)
    try:
        if fault=='none':
            assert r.jwt_manual_create_current_from_preflight(request,preflight)==jwt_manual_create_current_digest(
                request,preflight.actor,preflight.source_digest,preflight.state.state_digest)
        else:
            foreign=replace(preflight,state=replace(preflight.state,**{fault:'f'*64}))
            with pytest.raises(r.JwtManualKeyPreflightReadError):r.jwt_manual_create_current_from_preflight(request,foreign)
        assert len(h.calls)==9
    finally:request.close()


@pytest.mark.parametrize('fault',['source-before','source-after-tls','ca-drift','media','encoding','timeout','count','close','interrupt','default-denial'])
def test_reader_failure_never_retries_or_exposes_private_details(tmp_path,monkeypatch,fault):
    h=Harness(tmp_path,monkeypatch);h.fail=fault
    if fault=='source-before':h.source=False
    if fault=='ca-drift':h.ca.write_bytes(b'DRIFTED_CA_BINDING')
    if fault=='default-denial':h.reader._source_guard=h.reader._source_guard_pin=None
    with pytest.raises(KeyboardInterrupt if fault=='interrupt'else r.JwtManualKeyPreflightReadError)as error:
        h.reader.observe()
    assert 'SYNTHETIC_PRIVATE_NOTE'not in str(error.value)and 'synthetic-bearer'not in str(error.value)
    assert len(h.calls)<=1 and all(resource.closed for resource in h.resources)
    assert all(not any(raw)for raw in h.buffers)
