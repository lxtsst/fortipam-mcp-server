"""Fixed User reads with synthetic schemas, profiles and HTTP resources only."""
import json

import pytest

from fortipam_mcp.fortitoken_user_contract import FortitokenUserPlan, _schema_types
from fortipam_mcp.fortitoken_user_source import FortitokenUserSource, SCHEMA_PATH
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_fortitoken_user_contract import fixture, binding, NAME, SERIAL, TOKEN
from test_saml_server_native_source import Peer as HttpPeer
from v4_planning import canonical_digest


class Peer(HttpPeer):
    def __init__(self, operation='assign'):
        super().__init__(); self.schema,self.user = fixture(operation)
        self.detail = '/api/v2/cmdb/system/admin/'+NAME+'?with_meta=true'
        self.schema_pin = canonical_digest(_schema_types(self.schema['results']['children']))
        self.payloads = {SCHEMA_PATH:self.schema,self.detail:dict(build=29,http_method='GET',http_status=200,
            name='admin',path='system',status='success',version='v7.0.0',vdom='root',serial=SERIAL,results=self.user)}
    def reader(self, *, guarded=True, **kwargs):
        return FortitokenUserSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,None),
            binding(),expected_serial=SERIAL,expected_schema_digest=self.schema_pin,source_digest='c'*64,
            source_guard=(lambda:True) if guarded else None,connection_factory=self.factory,
            http_clock=self.http_clock,clock=self.clock,**kwargs)


@pytest.mark.parametrize('operation', ['assign','revoke'])
def test_two_fixed_reads_and_private_compile_join_the_actual_codec_without_dispatch(operation, monkeypatch):
    peer = Peer(operation); peer.schema['results']['children']['comments']['default'] = 'NEVER_DECODE_SCHEMA_DEFAULT'
    original = json.loads
    def decode(raw,*args,**kwargs):
        if isinstance(raw,(bytes,bytearray,str)):
            text = raw if isinstance(raw,str) else raw.decode('ascii')
            assert 'NEVER_DECODE' not in text and TOKEN.decode('ascii') not in text
        return original(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',decode)
    reader = peer.reader(); observed = reader.read()
    assert observed.source_digest == 'c'*64 and observed.expires_at == 1010
    assert observed.state.token_present is (operation == 'revoke')
    plan = FortitokenUserPlan(observed.state,operation); material = bytearray(TOKEN)
    with memoryview(material).toreadonly() as token:
        body = reader.compile_body(plan,token_reference_digest='a'*64,token=token)
    try:
        assert original(body)['fortitoken'] == (TOKEN.decode('ascii') if operation == 'assign' else '')
        assert peer.calls == [SCHEMA_PATH,peer.detail]*2
        assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)
    finally:
        body[:] = b'\0'*len(body); material[:] = b'\0'*len(material)


@pytest.mark.parametrize('fault', ['serial','version','build','vdom','action','field','type','error'])
def test_foreign_or_changed_schema_refuses_before_the_detail_get(fault):
    peer = Peer()
    if fault == 'field': peer.schema['results']['children']['unexpected'] = {'type':'string'}
    elif fault == 'type': peer.schema['results']['children']['comments']['type'] = 'password-2'
    elif fault in ('build','error'): peer.schema[fault] = 30 if fault == 'build' else -3
    else: peer.schema[fault] = 'synthetic-other'
    with pytest.raises(ValueError,match='unavailable'): peer.reader().read()
    assert peer.calls == [SCHEMA_PATH] and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['html','truncated','close','deadline','oversize','not-found'])
def test_transport_failure_clears_buffers_and_closes_resources(fault):
    peer = Peer(); peer.fault = fault
    if fault == 'oversize': peer.schema['results']['oversize'] = 'x'*1048577
    elif fault == 'not-found': peer.schema['http_status'] = 404
    with pytest.raises(ValueError,match='unavailable'): peer.reader().read()
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['guard','closed','tls'])
def test_unready_source_never_connects(fault):
    peer = Peer(); reader = peer.reader(guarded=fault != 'guard')
    if fault == 'closed': reader.close()
    elif fault == 'tls': reader._tls.check_hostname = False
    with pytest.raises(ValueError,match='unavailable'): reader.read()
    assert peer.calls == []


@pytest.mark.parametrize('clock', ['epoch','monotonic'])
def test_clock_rollback_is_terminal(clock):
    peer = Peer(); reader = peer.reader(); reader.read()
    if clock == 'epoch': peer.clock.value = 999
    else: peer.time = 9
    with pytest.raises(ValueError,match='unavailable'): reader.read()
    peer.clock.value = 1000; peer.time = 10; calls = len(peer.calls)
    with pytest.raises(ValueError,match='unavailable'): reader.read()
    assert len(peer.calls) == calls


@pytest.mark.parametrize('fault', ['drift','wrong-token','foreign-state','expired','guard-loss'])
def test_private_compile_rechecks_origin_fresh_state_token_and_source_gate(fault):
    peer = Peer('revoke'); reader = peer.reader(); observed = reader.read(); plan = FortitokenUserPlan(observed.state,'revoke')
    if fault == 'drift': peer.user['comments'] = 'changed'
    elif fault == 'wrong-token': peer.user['fortitoken'] = 'SYNTHETIC_TOKEN_BETA'
    elif fault == 'foreign-state': plan = FortitokenUserPlan(peer.reader().read().state,'revoke')
    elif fault == 'expired': peer.clock.value = 1010
    else: reader._guard = lambda: False
    with memoryview(TOKEN) as token:
        with pytest.raises(ValueError,match='unavailable'): reader.compile_body(plan,token_reference_digest='a'*64,token=token)
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


def test_read_deadline_covers_both_gets_and_final_resource_cleanup():
    peer = Peer(); reader = peer.reader(); fetch = reader._fetch
    def delayed(path,deadline):
        raw = fetch(path,deadline); peer.time += 3
        return raw
    reader._fetch = delayed
    with pytest.raises(ValueError,match='unavailable'): reader.read()
    assert reader._latest is None and all(not any(raw) for raw in peer.buffers)


def test_post_compile_deadline_failure_clears_the_private_body(monkeypatch):
    from fortipam_mcp import fortitoken_user_source as native
    peer = Peer(); reader = peer.reader(); plan = FortitokenUserPlan(reader.read().state,'assign')
    compile_body = native.build_fortitoken_user_body; captured = []
    def delayed(*args,**kwargs):
        raw = compile_body(*args,**kwargs); captured.append(raw); peer.time += 5
        return raw
    monkeypatch.setattr(native,'build_fortitoken_user_body',delayed)
    with memoryview(TOKEN) as token:
        with pytest.raises(ValueError,match='unavailable'): reader.compile_body(plan,token_reference_digest='a'*64,token=token)
    assert captured and all(not any(raw) for raw in captured+peer.buffers)


def test_explicit_physical_plan_admission_survives_fresh_reads_but_not_drift_or_foreign_origin():
    peer = Peer(); reader = peer.reader(); plan = FortitokenUserPlan(reader.read().state,'assign')
    reader.bind_plan(plan); peer.clock.value = 1011; reader.read()
    with memoryview(TOKEN) as token: body = reader.compile_body(plan,token_reference_digest='a'*64,token=token)
    assert json.loads(body)['two-factor'] == 'fortitoken'; body[:] = b'\0'*len(body)
    peer.user['comments'] = 'changed'; reader.read()
    with memoryview(TOKEN) as token:
        with pytest.raises(ValueError,match='unavailable'): reader.compile_body(plan,token_reference_digest='a'*64,token=token)
    foreign = FortitokenUserPlan(peer.reader().read().state,'assign')
    with pytest.raises(ValueError,match='unavailable'): reader.bind_plan(foreign)
    assert all(not any(raw) for raw in peer.buffers)
