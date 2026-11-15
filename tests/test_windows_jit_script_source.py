"""Five fixed reads and physical plan binding with synthetic Script responses."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp.windows_jit_script_contract import compile_windows_jit_script_pair
from fortipam_mcp.windows_jit_script_source import (WindowsJitScriptSource, SCHEMA_PATH, DEFAULT_PATH,
    COLLECTION_PATH, BASE_PATH, _default)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_saml_server_native_source import Socket
from test_system_email_m4_adapter import Clock
from v4_planning import canonical_digest

SERIAL = 'SYNTHETIC_SERIAL'
NONCE = '01234567'
PRIVATE = b'SYNTHETIC_SECRET_DO_NOT_DECODE'


def envelope(results, *, method='GET', status=200, **extra):
    return dict(http_method=method,http_status=status,status='success' if status == 200 else 'error',
        serial=SERIAL,version='v7.0.0',build=29,path='secret',name='script',vdom='root',results=results,**extra)


def schema():
    specs = {name:dict(type='string',size=35 if name == 'name' else 2047) for name in ('name','comments','script','expect-string')}
    for name,values in {'type':['powershell','ssh-script'],'expect-type':['failure','success'],'log-trigger':['any','failure']}.items():
        specs[name] = dict(type='option',options=values)
    native = {}
    for name,spec in specs.items():
        native[name] = {**spec,'default':PRIVATE.decode(),'help':PRIVATE.decode()}
        if spec['type'] == 'option': native[name]['options'] = [dict(name=value,help=PRIVATE.decode()) for value in spec['options']]
    return specs,native


class Peer:
    def __init__(self, present=0):
        self.clock = Clock(); self.time = 10.0; self.specs,native = schema(); self.pin = canonical_digest(self.specs)
        self.expected = compile_windows_jit_script_pair(_default(),nonce=NONCE)
        self.details = tuple(BASE_PATH+'/'+body['name']+'?with_meta=true&vdom=root' for body in self.expected)
        self.rows = [dict(name='synthetic-unrelated-script',script=PRIVATE.decode(),comments=PRIVATE.decode(),**{'expect-string':PRIVATE.decode()})]
        self.payloads = {SCHEMA_PATH:envelope(dict(children=native),action='schema'),
            DEFAULT_PATH:envelope(deepcopy(_default()['results']),action='default'),
            COLLECTION_PATH:envelope(self.rows,method='POST',size=1,matched_count=1,limit_reached=False)}
        for index,(path,body) in enumerate(zip(self.details,self.expected)):
            if index < present:
                row = {**body,'q_origin_key':body['name'],'q_mkey_type':'string','q_name':'script','q_path':'secret',
                    'q_ref':0,'q_type':1,'q_no_edit':False,'q_no_rename':False,'q_static':False,'q_global_entry':False}
                self.rows.append(row); self.payloads[path] = envelope(deepcopy(row),mkey=body['name'])
            else: self.payloads[path] = envelope(None,status=404,error=-3)
        self.counts(); self.calls = []; self.resources = []; self.buffers = []; self.fault = None
    def counts(self): self.payloads[COLLECTION_PATH].update(size=len(self.rows),matched_count=len(self.rows))
    def http_clock(self): return self.time
    def source(self, *, guarded=True):
        return WindowsJitScriptSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,None),
            nonce=NONCE,expected_serial=SERIAL,expected_schema_digest=self.pin,source_digest='a'*64,
            source_guard=(lambda:True) if guarded else None,connection_factory=self.factory,http_clock=self.http_clock,clock=self.clock)
    def factory(self, host, port, **kwargs):
        peer = self
        class Connection:
            def __init__(self): self.sock = Socket(); self.closed = False; self.path = None; peer.resources.append(self)
            def set_debuglevel(self, value): assert value == 0
            def connect(self): assert host == 'pam.example.test'
            def request(self, method, path, *, headers, body=None):
                assert headers['Authorization'] == 'Bearer synthetic-api-token'
                if path == COLLECTION_PATH:
                    assert method == 'POST' and body == b'{"json_filter":[]}' and headers['X-HTTP-Method-Override'] == 'GET'
                else: assert method == 'GET' and body is None and 'X-HTTP-Method-Override' not in headers
                peer.calls.append((method,path)); self.path = path
            def getresponse(self):
                payload = peer.payloads[self.path]; raw = json.dumps(payload).encode()
                return Response(raw,payload['http_status'])
            def close(self):
                self.closed = True
                if peer.fault == 'close': raise RuntimeError('SYNTHETIC_PRIVATE_CLOSE')
        class Response:
            def __init__(self, raw, status): self.raw,self.status,self.offset,self.closed = raw,status,0,False; peer.resources.append(self)
            def getheader(self, name, default=None):
                return {'content-type':'text/html' if peer.fault == 'html' else 'application/json',
                    'content-length':str(len(self.raw)+(1 if peer.fault == 'truncated' else 0))}.get(name.lower(),default)
            def isclosed(self): return self.offset >= len(self.raw)
            def readinto(self, view):
                if not peer.buffers or peer.buffers[-1] is not view.obj: peer.buffers.append(view.obj)
                count = min(len(view),len(self.raw)-self.offset,113)
                view[:count] = self.raw[self.offset:self.offset+count]; self.offset += count
                if peer.fault == 'deadline': peer.time += 1
                return count
            def close(self): self.closed = True
        return Connection()


@pytest.mark.parametrize('present', [0,1,2])
def test_exact_five_reads_keep_unrelated_script_and_schema_material_opaque(monkeypatch,present):
    peer = Peer(present); source = peer.source(); decode = json.loads; digest = hashlib.sha256
    def checked_decode(raw,*args,**kwargs):
        assert PRIVATE not in (raw.encode() if isinstance(raw,str) else raw)
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert PRIVATE not in raw
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    observed = source.read()
    assert observed.present == (present>0,present>1) and observed.script_count == 1+present
    assert peer.calls == [('GET',SCHEMA_PATH),('GET',DEFAULT_PATH),('POST',COLLECTION_PATH),*[('GET',path) for path in peer.details]]
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['field','type','option','size','pin','serial','version','build'])
def test_schema_or_device_mismatch_refuses_before_any_default_or_namespace_read(fault):
    peer = Peer(); source = peer.source(); root = peer.payloads[SCHEMA_PATH]; fields = root['results']['children']
    if fault == 'field': fields['password'] = dict(type='password-2')
    elif fault == 'type': fields['script']['type'] = 'password-2'
    elif fault == 'option': fields['type']['options'][0]['name'] = 'other'
    elif fault == 'size': fields['name']['size'] = 1
    elif fault == 'pin': fields['script']['size'] = 2046
    elif fault == 'build': root['build'] = True
    else: root[fault] = 'other'
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert peer.calls == [('GET',SCHEMA_PATH)] and source._latest is None
    assert all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['script','comments','singular-comment','extra'])
def test_default_drift_or_material_echo_is_refused_without_decoding_it(monkeypatch,fault):
    peer = Peer(); source = peer.source(); row = peer.payloads[DEFAULT_PATH]['results']; decode = json.loads
    if fault == 'singular-comment': row['comment'] = row.pop('comments')
    elif fault == 'extra': row['password'] = PRIVATE.decode()
    else: row[fault] = PRIVATE.decode()
    def checked(raw,*args,**kwargs):
        assert PRIVATE not in (raw.encode() if isinstance(raw,str) else raw)
        return decode(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked)
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert len(peer.calls) == 2 and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['counts','missing-counts','duplicate-name','truncated','wrong-method','foreign-detail',
    'detail-only','collection-only','script-drift','reference-drift','metadata-type','detail-echo'])
def test_name_view_and_fixed_details_must_agree_without_adopting_any_object(fault):
    peer = Peer(2); source = peer.source(); collection = peer.payloads[COLLECTION_PATH]; detail = peer.payloads[peer.details[0]]
    if fault == 'counts': collection['size'] += 1
    elif fault == 'missing-counts': del collection['matched_count']
    elif fault == 'duplicate-name': peer.rows.append(dict(peer.rows[0])); peer.counts()
    elif fault == 'truncated': collection['limit_reached'] = True
    elif fault == 'wrong-method': collection['http_method'] = 'GET'
    elif fault == 'foreign-detail': detail['mkey'] = 'other'
    elif fault == 'detail-only': del peer.rows[1]; peer.counts()
    elif fault == 'collection-only': peer.payloads[peer.details[0]] = envelope(None,status=404,error=-3)
    elif fault == 'script-drift': detail['results']['script'] = PRIVATE.decode()
    elif fault == 'reference-drift': detail['results']['q_ref'] = 1
    elif fault == 'metadata-type': detail['results']['q_ref'] = False
    else: detail['results']['password'] = PRIVATE.decode()
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert source._latest is None and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['html','truncated','close','deadline'])
def test_transport_and_cleanup_failures_clear_buffers_before_any_observation(fault):
    peer = Peer(); source = peer.source(); peer.fault = fault
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert source._latest is None and all(resource.closed for resource in peer.resources)
    assert all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['gate','closed','tls','binding','definition','epoch','monotonic'])
def test_source_authority_binding_and_clock_fail_closed(fault):
    peer = Peer(); source = peer.source(guarded=fault != 'gate')
    if fault in ('epoch','monotonic'):
        source.read()
        if fault == 'epoch': peer.clock.value = 999
        else: peer.time = 9
    elif fault == 'closed': source.close()
    elif fault == 'tls': source._tls.check_hostname = False
    elif fault == 'binding': source._nonce = '89abcdef'
    elif fault == 'definition': source._expected[0]['script'] = 'SYNTHETIC_CHANGED_COMMAND'
    count = len(peer.calls)
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert len(peer.calls) == count
    if fault in ('epoch','monotonic'):
        peer.clock.value = 1000; peer.time = 10
        with pytest.raises(ValueError,match='unavailable'): source.read()


def test_private_compile_rechecks_five_reads_and_keeps_physical_plan_origin_through_read_refresh():
    peer = Peer(); source = peer.source(); plan = source.prepare_plan(); source.read()
    bodies = source.compile_pair(plan)
    try:
        assert tuple(json.loads(body) for body in bodies) == peer.expected and len(peer.calls) == 15
    finally:
        for body in bodies: body[:] = b'\0'*len(body)
    public = source.preview(); text = json.dumps(public)
    assert public['candidate_names_absent_in_visible_view'] and not public['global_namespace_qualified']
    assert not public['product_actor_verified'] and not public['configuration_ready'] and not public['execution_authorized']
    assert all(value not in text for value in (NONCE,SERIAL,'synthetic-unrelated-script','$USER'))


@pytest.mark.parametrize('fault', ['cloned','foreign','expired','superseded','new-name','appeared'])
def test_equal_foreign_or_stale_plan_and_namespace_drift_never_compile_pair(fault):
    peer = Peer(); source = peer.source(); plan = source.prepare_plan()
    if fault == 'cloned': plan = replace(plan)
    elif fault == 'foreign': plan = peer.source().prepare_plan()
    elif fault == 'expired': peer.clock.value = 1010
    elif fault == 'superseded': source.prepare_plan()
    elif fault == 'new-name': peer.rows.append(dict(name='synthetic-new-name',script=PRIVATE.decode())); peer.counts()
    else:
        row = dict(peer.expected[0]); peer.rows.append(row); peer.counts(); peer.payloads[peer.details[0]] = envelope(row)
    with pytest.raises(ValueError,match='unavailable'): source.compile_pair(plan)


@pytest.mark.parametrize('present', [1,2])
def test_existing_matching_definition_does_not_supply_a_new_creation_plan(present):
    peer = Peer(present); source = peer.source()
    with pytest.raises(ValueError,match='unavailable'): source.prepare_plan()
    assert source._plan is None


def test_deadline_covers_all_five_reads_and_final_publication():
    peer = Peer(); source = peer.source(); fetch = source._fetch
    def delayed(*args):
        result = fetch(*args); peer.time += 1; return result
    source._fetch = delayed
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert source._latest is None and all(not any(raw) for raw in peer.buffers)
