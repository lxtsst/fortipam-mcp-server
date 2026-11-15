"""Exercise durable ownership, no-content decoding and fixed native recovery."""
from copy import deepcopy
import hashlib
import json
from urllib.parse import parse_qs, unquote

import httpx
import pytest

from fortipam_mcp.client_integrity_http_contract import CERTIFICATE_NAME, _native_metadata, compile_native_client_integrity_create_body, compile_native_client_integrity_hash_create_body
from fortipam_mcp.client_integrity_http_transport import (
    FortiPamNativeClientIntegrityHttpTransport, NativeClientIntegrityBinding,
    ClientIntegrityHttpTransportError, _digest,
    CONTRACT, HASH_CONTRACT, NativeHashClientIntegrityBinding,
    load_native_client_integrity_binding, load_native_hash_client_integrity_binding,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig

NAME = 'mcp-v4-client-integrity-rest-20261004-r2'
FOREIGN = 'unrelated-synthetic-software'
SERIAL = 'SYNTHETIC001'


class Appliance:
    def __init__(self):
        self.name = NAME
        self.executable_sha256 = None
        self.rows = {FOREIGN: {'name': FOREIGN, 'q_origin_key': FOREIGN,
            'pkg': [{'name': 'other', 'package-content': 'private-sentinel-never-decode'}]}}
        self.calls = []
        self.references = []
        self.lose_post = False
        self.inject_content = False
        self.ack_extra = False
        self.ack_wrong_serial = False
        self.ack_missing_path = False
        self.post_error = False
        self.absence_results = None
        self.inject_unknown = None
        self.omit_package = False
        self.certificate_selector = [{'name': CERTIFICATE_NAME, 'type': 'local-ca',
                                      'certificate': 'private-sentinel-never-decode'}]

    def cmdb(self, method, **extra):
        return {'version':'v7.0.0','build':29,'http_method':method,'http_status':200,
            'status':'success','path':'secret','name':'client-software','vdom':'root','serial':SERIAL,'action':'',**extra}

    def default(self):
        return self.cmdb('GET', action='default', results={'name':'','pkg':[]})

    def binding(self):
        witnesses = {k:hashlib.sha256(json.dumps(v,separators=(',',':')).encode()).hexdigest() for k,v in self.rows.items()}
        if self.executable_sha256 is not None:
            return NativeHashClientIntegrityBinding(self.name, _digest(witnesses), self.executable_sha256,
                hashlib.sha256(SERIAL.encode()).hexdigest(), 13)
        return NativeClientIntegrityBinding(NAME,_digest(witnesses),_digest({'name':CERTIFICATE_NAME,'type':'local-ca'}),
            hashlib.sha256(SERIAL.encode()).hexdigest(),13)

    def handle(self, request):
        self.calls.append(request)
        query = parse_qs(request.url.query.decode()); method=request.method
        if '/vpn.certificate/local/' in request.url.path:
            result={'version':'v7.0.0','build':29,'http_method':'GET','http_status':200,'status':'success',
                'results':[{'name':CERTIFICATE_NAME,'private-key':'private-sentinel-never-decode'}]}
        elif request.url.path.endswith('/available-certificates'):
            assert query == {'with_ca':['1'],'with_crl':['1'],'with_remote':['1']}
            result={'version':'v7.0.0','build':29,'http_method':'GET','status':'success',
                'path':'system','name':'available-certificates','results':self.certificate_selector}
        elif request.url.path.endswith('/object-urls'):
            result={'version':'v7.0.0','build':29,'http_method':'GET','status':'success','path':'web-ui',
                'name':'object-urls','results':{'by_type':{'13':{'path':'secret.client-software'}}}}
        elif request.url.path.endswith('/object/usage'):
            assert query == {'mkey':[self.name],'qtypes':['[13]']}
            result={'version':'v7.0.0','build':29,'http_method':'GET','status':'success','path':'system/object',
                'name':'usage','mkey':self.name,'results':{'currently_using':self.references}}
        elif method == 'POST':
            assert request.url.path.endswith('/client-software') and query=={'vdom':['root']}
            body=json.loads(request.content)
            expected = (compile_native_client_integrity_hash_create_body(
                self.default(), software_name=self.name, executable_sha256=self.executable_sha256,
            ) if self.executable_sha256 is not None else
                compile_native_client_integrity_create_body(self.default(), software_name=self.name))
            assert body == expected
            assert self.name not in self.rows
            package={**body['pkg'][0],'browser':'edge','q_origin_key':'x64','client-name':self.name,'description':'','file-size':0,
                'package-content':'private-sentinel-never-decode' if self.inject_content else '',
                'state':'absent','uuid':'11111111-1111-1111-1111-111111111111'}
            self.rows[self.name]={'name':self.name,'q_origin_key':self.name,'pkg':[package],**_native_metadata(13)}
            if self.omit_package:
                self.rows[self.name]['pkg'] = []
            if self.inject_unknown == 'row':
                self.rows[self.name]['unknown'] = 'private-sentinel-never-decode'
            elif self.inject_unknown == 'package':
                package['unknown'] = 'private-sentinel-never-decode'
            elif self.inject_unknown == 'metadata':
                self.rows[self.name]['q_type'] = 14
            if self.lose_post:
                raise httpx.ReadTimeout('private exception must not escape')
            result=self.cmdb('POST',mkey=self.name,old_revision='synthetic-before',revision='synthetic-after',revision_changed=True)
            if self.ack_extra:
                result['unknown']='private-sentinel-never-decode'
            if self.ack_wrong_serial:
                result['serial'] = 'OTHER-SYNTHETIC'
            if self.ack_missing_path:
                result.pop('path')
            if self.post_error:
                return httpx.Response(500,json=self.cmdb('POST',http_status=500,status='error',error=-651,
                    private_payload='private-sentinel-never-decode'))
        elif method == 'DELETE':
            assert unquote(request.url.path.rsplit('/',1)[-1])==self.name and request.content==b''
            del self.rows[self.name];result=self.cmdb('DELETE',mkey=self.name,old_revision='synthetic-before',revision='synthetic-after',revision_changed=True)
        elif query.get('action') == ['default']:
            result=self.default()
        elif request.url.path.endswith('/client-software'):
            result=self.cmdb('GET',results=list(self.rows.values()),matched_count=len(self.rows),
                size=len(self.rows),next_idx=len(self.rows)-1)
        else:
            assert unquote(request.url.path.rsplit('/',1)[-1])==self.name
            if self.name not in self.rows:
                result = self.cmdb('GET',http_status=404,status='error',error=-3)
                if self.absence_results is not None:
                    result['results'] = self.absence_results
                return httpx.Response(404,json=result)
            result=self.cmdb('GET',results=[self.rows[self.name]])
        return httpx.Response(200,json=result)


def adapter(tmp_path, device, *, binding=None, clock=None, create=True, recover=True, factory=None):
    tmp_path=tmp_path.resolve();tmp_path.chmod(0o700)
    key=tmp_path/'authorization.key'
    if not key.exists():
        key.write_bytes(b'k'*32);key.chmod(0o600)
    config=SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-token',5,None)
    return FortiPamNativeClientIntegrityHttpTransport(config,binding or device.binding(),tmp_path,key,
        create_enabled=create,recovery_enabled=recover,clock=clock or (lambda:100),
        client_factory=factory or (lambda **kw:httpx.Client(transport=httpx.MockTransport(device.handle),**kw)))


def reserve(transport, *, recovery=False, expires=500):
    transport.reserve_intent('a'*64,'b'*64,expires_at=expires,recovery=recovery)


def test_create_and_owned_recovery_preserve_foreign_bytes_and_never_decode_content(tmp_path, monkeypatch):
    device=Appliance(); baseline=deepcopy(device.rows); binding=device.binding()
    original_loads=json.loads
    def guarded(value,*args,**kw):
        if isinstance(value,(bytes,bytearray,str)):
            assert ('private-sentinel-never-decode' not in value if isinstance(value,str)
                    else b'private-sentinel-never-decode' not in value)
        return original_loads(value,*args,**kw)
    monkeypatch.setattr(json,'loads',guarded)
    transport=adapter(tmp_path,device,binding=binding);reserve(transport)
    assert transport.execute()['software_present']
    reserve(transport,recovery=True)
    assert not transport.execute(recovery=True)['software_present']
    assert device.rows==baseline
    assert [r.method for r in device.calls if r.method!='GET']==['POST','DELETE']
    count=len(device.calls)
    fresh=adapter(tmp_path,device,binding=binding)
    for recovery in (False,True):
        with pytest.raises(ClientIntegrityHttpTransportError):fresh.execute(recovery=recovery)
    assert len(device.calls)==count
    for path in tmp_path.glob('*.json'):
        assert path.stat().st_mode&0o777==0o600
        assert NAME not in path.read_text() and 'private-sentinel' not in path.read_text()


@pytest.mark.parametrize('method', ['POST', 'DELETE'])
@pytest.mark.parametrize('updates', [
    {'old_revision': {}}, {'old_revision': None}, {'old_revision': 'x' * 256},
    {'old_revision': 'synthetic\nrevision'}, {'revision': False},
    {'revision_changed': False}, {'revision_changed': 1},
    {'unknown': 'private-sentinel-never-decode'},
])
def test_mutation_revision_metadata_does_not_admit_unknown_or_invalid_values(tmp_path, method, updates):
    device = Appliance(); transport = adapter(tmp_path, device)
    payload = device.cmdb(method, mkey=NAME, old_revision='synthetic-before',
                          revision='synthetic-after', revision_changed=True)
    payload.update(updates)
    with pytest.raises(ValueError):
        transport._acknowledgement(bytearray(json.dumps(payload).encode()), method)
    assert device.calls == []


def test_default_gate_and_unowned_recovery_refuse_before_network(tmp_path):
    device=Appliance();transport=adapter(tmp_path,device,create=False,recover=False)
    for recovery in (False,True):
        with pytest.raises(ClientIntegrityHttpTransportError):transport.execute(recovery=recovery)
    assert device.calls==[]
    transport=adapter(tmp_path,device)
    with pytest.raises(ClientIntegrityHttpTransportError):reserve(transport,recovery=True)
    assert device.calls==[]


@pytest.mark.parametrize('selector', [[], [{'name': CERTIFICATE_NAME, 'type': 'local-cer'}],
    [{'name': CERTIFICATE_NAME}], [{'name': CERTIFICATE_NAME, 'type': None}],
    [{'name': CERTIFICATE_NAME, 'type': 'local-ca'}] * 2])
def test_native_ca_selector_refuses_before_intent_or_dispatch(tmp_path, selector):
    device = Appliance(); device.certificate_selector = selector
    transport = adapter(tmp_path, device)
    with pytest.raises(ClientIntegrityHttpTransportError):
        reserve(transport)
    assert not (tmp_path / 'create.intent.json').exists()
    assert all(request.method == 'GET' for request in device.calls)


@pytest.mark.parametrize('failure',['lost','unknown-ack','wrong-serial','uploaded-content','empty-package','business-error','metadata-drift','missing-path'])
def test_uncertain_create_is_non_replayable_and_cannot_supply_recovery_ownership(tmp_path,failure):
    device=Appliance();binding=device.binding();transport=adapter(tmp_path,device,binding=binding)
    reserve(transport)
    device.lose_post=failure=='lost';device.ack_extra=failure=='unknown-ack';device.inject_content=failure=='uploaded-content'
    device.ack_wrong_serial = failure == 'wrong-serial'
    device.omit_package = failure == 'empty-package'
    device.post_error = failure == 'business-error'
    device.ack_missing_path = failure == 'missing-path'
    if failure == 'metadata-drift':
        device.inject_unknown = 'metadata'
    with pytest.raises(ClientIntegrityHttpTransportError,match='unavailable') as error:transport.execute()
    assert 'private' not in str(error.value) and NAME in device.rows
    assert (tmp_path/'create.claim.json').exists() and not (tmp_path/'create.verified.json').exists()
    if failure != 'lost':
        observation = transport._load('create.response.json','create','response_observed')
        assert observation['http_status'] == (500 if failure == 'business-error' else 200)
        assert observation['business_error_code'] == (-651 if failure == 'business-error' else None)
        assert observation['strict_acknowledgement_verified'] == (failure in ('uploaded-content','empty-package','metadata-drift'))
        assert observation['missing_fixed_members'] == (['path'] if failure == 'missing-path' else [])
        assert 'unknown' not in observation['known_root_members']
        assert 'private-sentinel' not in (tmp_path/'create.response.json').read_text()
    before=len(device.calls)
    fresh=adapter(tmp_path,device,binding=binding)
    for recovery in (False,True):
        with pytest.raises(ClientIntegrityHttpTransportError):fresh.execute(recovery=recovery)
    with pytest.raises(ClientIntegrityHttpTransportError):reserve(fresh,recovery=True)
    assert len(device.calls)==before


def test_prewrite_drift_and_new_reference_refuse_without_consuming_dispatch(tmp_path):
    device=Appliance();binding=device.binding();transport=adapter(tmp_path,device,binding=binding)
    reserve(transport);device.rows[FOREIGN]['extra']='drift'
    with pytest.raises(ClientIntegrityHttpTransportError):transport.execute()
    assert not (tmp_path/'create.claim.json').exists()
    del device.rows[FOREIGN]['extra'];assert transport.execute()['verified']
    device.references=[{'name':'new-synthetic-launcher-reference'}]
    with pytest.raises(ClientIntegrityHttpTransportError):reserve(transport,recovery=True)
    assert not (tmp_path/'recover.claim.json').exists()
    assert [r.method for r in device.calls if r.method!='GET']==['POST']


def test_expiry_inside_connection_factory_prevents_post_after_claim(tmp_path):
    device=Appliance();clock=[100];binding=device.binding()
    def factory(**kw):
        if (tmp_path/'create.claim.json').exists():clock[0]=500
        return httpx.Client(transport=httpx.MockTransport(device.handle),**kw)
    transport=adapter(tmp_path,device,binding=binding,clock=lambda:clock[0],factory=factory)
    reserve(transport,expires=500)
    with pytest.raises(ClientIntegrityHttpTransportError):transport.execute()
    assert (tmp_path/'create.claim.json').exists() and NAME not in device.rows
    assert all(r.method=='GET' for r in device.calls)


def test_tampered_creation_record_and_consumed_namespace_cannot_authorize_cleanup(tmp_path):
    device=Appliance();binding=device.binding();transport=adapter(tmp_path,device,binding=binding)
    reserve(transport);transport.execute()
    p=tmp_path/'create.verified.json';record=json.loads(p.read_bytes());record['configuration_digest']='0'*64
    p.write_text(json.dumps(record))
    before=len(device.calls)
    with pytest.raises(ClientIntegrityHttpTransportError):reserve(transport,recovery=True)
    assert len(device.calls)==before
    with pytest.raises(ClientIntegrityHttpTransportError):
        NativeClientIntegrityBinding('mcp-v4-client-integrity-mini-r1',binding.visible_collection_digest,
            binding.certificate_metadata_digest,binding.device_identity_digest,13)


def test_default_action_is_route_bound_and_arbitrary_read_paths_are_refused(tmp_path):
    device=Appliance();transport=adapter(tmp_path,device)
    original=device.default
    device.default=lambda: {**original(), 'action':'download'}
    with pytest.raises(ClientIntegrityHttpTransportError):reserve(transport)
    assert not (tmp_path/'create.intent.json').exists()
    count=len(device.calls)
    with pytest.raises(ValueError):transport._request('GET','/api/v2/cmdb/system/admin')
    assert len(device.calls)==count


def test_private_binding_loader_rejects_extra_fields_and_symlinks(tmp_path):
    tmp_path.chmod(0o700)
    binding = Appliance().binding()
    value = {'contract': CONTRACT, **{k: getattr(binding, k) for k in binding.__slots__}}
    path = tmp_path / 'binding.private.json'
    path.write_text(json.dumps(value)); path.chmod(0o600)
    assert load_native_client_integrity_binding(path) == binding
    for old_version in (1, 2):
        value['contract'] = 'fortipam_v4_client_integrity_native_700_transport_v' + str(old_version)
        path.write_text(json.dumps(value))
        with pytest.raises(ClientIntegrityHttpTransportError):
            load_native_client_integrity_binding(path)
    value['contract'] = CONTRACT
    value['unknown'] = 'private-sentinel-never-decode'
    path.write_text(json.dumps(value))
    with pytest.raises(ClientIntegrityHttpTransportError):
        load_native_client_integrity_binding(path)
    link = tmp_path / 'binding-link.json'; link.symlink_to(path)
    with pytest.raises(ClientIntegrityHttpTransportError):
        load_native_client_integrity_binding(link)


@pytest.mark.parametrize('result', [{'unexpected': 'private-sentinel-never-decode'},
                                  [{'name': NAME}], 'private-sentinel-never-decode'])
def test_nonempty_404_result_cannot_reserve_create_intent(tmp_path, result):
    device = Appliance(); device.absence_results = result
    transport = adapter(tmp_path, device)
    with pytest.raises(ClientIntegrityHttpTransportError):
        reserve(transport)
    assert not (tmp_path / 'create.intent.json').exists()
    assert all(request.method == 'GET' for request in device.calls)


@pytest.mark.parametrize('location', ['row', 'package'])
def test_unknown_own_fields_rejected_before_value_decode(tmp_path, monkeypatch, location):
    device = Appliance(); device.inject_unknown = location
    transport = adapter(tmp_path, device); reserve(transport)
    original_loads = json.loads
    decoded_sensitive_values = []
    def guarded(value, *args, **kwargs):
        if isinstance(value, (bytes, bytearray)) and b'private-sentinel-never-decode' in value:
            decoded_sensitive_values.append(True)
        return original_loads(value, *args, **kwargs)
    monkeypatch.setattr(json, 'loads', guarded)
    with pytest.raises(ClientIntegrityHttpTransportError):
        transport.execute()
    assert NAME in device.rows and (tmp_path / 'create.claim.json').exists()
    assert not (tmp_path / 'create.verified.json').exists()
    assert decoded_sensitive_values == []


@pytest.mark.parametrize('http_status,error', [(200, -3), (404, 0)])
def test_contradictory_business_error_cannot_reserve_intent(tmp_path, monkeypatch, http_status, error):
    device = Appliance(); original = device.cmdb
    def contradictory(method, **fields):
        result = original(method, **fields)
        if result['http_status'] == http_status:
            result['error'] = error
        return result
    monkeypatch.setattr(device, 'cmdb', contradictory)
    transport = adapter(tmp_path, device)
    with pytest.raises(ClientIntegrityHttpTransportError):
        reserve(transport)
    assert not (tmp_path / 'create.intent.json').exists()
    assert all(request.method == 'GET' for request in device.calls)


def hash_appliance():
    device = Appliance()
    device.name = 'mcp-v4-client-integrity-hash-20261006-r2'
    device.executable_sha256 = 'c' * 64
    return device


def test_hash_profile_preserves_foreign_content_and_isolates_records_and_certificate_reads(tmp_path, monkeypatch):
    device = hash_appliance()
    baseline = deepcopy(device.rows)
    binding = device.binding()
    original_loads = json.loads
    def guarded(value, *args, **kwargs):
        if isinstance(value, (bytes, bytearray, str)):
            assert ('private-sentinel-never-decode' not in value if isinstance(value, str)
                    else b'private-sentinel-never-decode' not in value)
        return original_loads(value, *args, **kwargs)
    monkeypatch.setattr(json, 'loads', guarded)
    transport = adapter(tmp_path, device, binding=binding)
    reserve(transport)
    assert transport.execute()['software_present']
    records = list(tmp_path.glob('*.json'))
    assert records and all(json.loads(path.read_bytes())['contract'] == HASH_CONTRACT for path in records)
    assert not any('certificate' in request.url.path for request in device.calls)
    for suffix in ('/api/v2/cmdb/vpn.certificate/local/Fortinet_CA_SSL?format=name',
                   '/api/v2/monitor/system/available-certificates?with_ca=1&with_crl=1&with_remote=1'):
        count = len(device.calls)
        with pytest.raises(ValueError):
            transport._request('GET', suffix)
        assert len(device.calls) == count
    # A certificate transport using the same key/state cannot consume hash intent.
    certificate_binding = NativeClientIntegrityBinding(NAME, binding.visible_collection_digest,
        'd' * 64, binding.device_identity_digest, binding.object_type)
    wrong = adapter(tmp_path, device, binding=certificate_binding)
    count = len(device.calls)
    with pytest.raises(ClientIntegrityHttpTransportError):
        wrong.execute()
    assert len(device.calls) == count
    reserve(transport, recovery=True)
    assert not transport.execute(recovery=True)['software_present']
    assert device.rows == baseline
    assert [r.method for r in device.calls if r.method != 'GET'] == ['POST', 'DELETE']
    fresh = adapter(tmp_path, device, binding=binding)
    count = len(device.calls)
    for recovery in (False, True):
        with pytest.raises(ClientIntegrityHttpTransportError):
            fresh.execute(recovery=recovery)
    assert len(device.calls) == count


def test_hash_profile_uncertain_create_remains_consumed_without_recovery_grant(tmp_path):
    device = hash_appliance()
    binding = device.binding()
    transport = adapter(tmp_path, device, binding=binding)
    reserve(transport)
    device.lose_post = True
    with pytest.raises(ClientIntegrityHttpTransportError):
        transport.execute()
    assert (tmp_path / 'create.claim.json').is_file()
    assert not (tmp_path / 'create.verified.json').exists()
    fresh = adapter(tmp_path, device, binding=binding)
    count = len(device.calls)
    with pytest.raises(ClientIntegrityHttpTransportError):
        fresh.execute()
    with pytest.raises(ClientIntegrityHttpTransportError):
        fresh.inspect(recovery=True)
    assert len(device.calls) == count
    assert [r.method for r in device.calls if r.method != 'GET'] == ['POST']


def test_hash_binding_is_default_closed_and_loaders_reject_profile_swaps(tmp_path):
    device = hash_appliance()
    binding = device.binding()
    transport = adapter(tmp_path, device, binding=binding, create=False, recover=False)
    for recovery in (False, True):
        with pytest.raises(ClientIntegrityHttpTransportError):
            transport.execute(recovery=recovery)
    assert not device.calls
    path = tmp_path / 'hash-binding.json'
    payload = {'contract': HASH_CONTRACT, **{key: getattr(binding, key) for key in binding.__slots__}}
    path.write_text(json.dumps(payload)); path.chmod(0o600)
    assert load_native_hash_client_integrity_binding(path) == binding
    with pytest.raises(ClientIntegrityHttpTransportError):
        load_native_client_integrity_binding(path)
    payload['contract'] = CONTRACT
    path.write_text(json.dumps(payload))
    with pytest.raises(ClientIntegrityHttpTransportError):
        load_native_hash_client_integrity_binding(path)
