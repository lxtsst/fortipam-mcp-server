"""Fixed projections, opaque credential rejection and bounded source lifetimes."""
from copy import deepcopy
import json

import pytest

from fortipam_mcp import scim_client_native_source as native
from fortipam_mcp.scim_client_native_source import (ScimNativeSource, ScimTrustObservation, scim_trust_binding,
    SCHEMA_PATH, CURRENT_PATH, GLOBAL_PATH, INTERFACES_PATH, SAML_PATH)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_scim_client_contract import values, OLD, NEW
from test_scim_client_m4_adapter import SCOPE
from test_system_email_m4_adapter import Clock


def envelope(path, name, results, collection=False):
    result = dict(http_method='GET',http_status=200,status='success',serial='SYNTHETIC01',
        version='v7.0.0',build=29,path=path,name=name,results=results)
    if collection: result.update(size=len(results),matched_count=len(results),limit_reached=False)
    return result


def schema():
    return {'id':{'type':'integer','min-value':0,'max-value':4294967295},'name':{'type':'string','size':35},
        'status':{'type':'option','options':[{'name':'enable'},{'name':'disable'}]},
        'base-url':{'type':'string','size':127},'auth-method':{'type':'option','options':[{'name':'base'}]},
        'secret':{'type':'password','size':59,'default':'SYNTHETIC_C3_SENTINEL'},
        'client-identity-check':{'type':'option','options':[{'name':'enable'},{'name':'disable'}]},
        'certificate':{'type':'string','size':79},'token-certificate':{'type':'string','size':79}}


class Trust:
    def __init__(self, clock): self.clock = clock; self.fault = None; self.calls = []
    def observe(self, base_url, port, certificate_selector, *, timeout_seconds, service_enabled=True):
        assert 0 < timeout_seconds <= 5; self.calls.append((base_url,port,certificate_selector))
        now = self.clock(); result = ScimTrustObservation('a'*64,scim_trust_binding(base_url,port,certificate_selector),'b'*64,now,now+10,
            active_tls_verified=service_enabled)
        if self.fault == 'error': raise RuntimeError('SYNTHETIC_PRIVATE_TRUST')
        from dataclasses import replace
        if self.fault == 'source': result = replace(result,source_digest='f'*64)
        if self.fault == 'binding': result = replace(result,binding_digest='f'*64)
        if self.fault == 'stale': result = replace(result,observed_at=now-11,expires_at=now-1)
        if self.fault == 'mode': result = replace(result,active_tls_verified=not service_enabled)
        return result


class Socket:
    def settimeout(self, value): assert value > 0


class Peer:
    def __init__(self):
        self.clock = Clock(); self.http_time = 10.0; self.trust = Trust(self.clock)
        self.payloads = {SCHEMA_PATH:envelope('user','scim',{'children':schema()}),
            CURRENT_PATH:envelope('user','scim',[values()],True),
            GLOBAL_PATH:envelope('system','global',{'scim-https-port':9443,'scim-server-cert':'synthetic-cert','q_origin_key':'global'}),
            INTERFACES_PATH:envelope('system','interface',[{'name':'synthetic-if','allowaccess':'https scim'}],True),
            SAML_PATH:envelope('user','saml',[{'name':'synthetic-saml','scim-client':values()['name']}],True)}
        self.resources = []; self.buffers = []; self.calls = []; self.put_buffers = []; self.puts = 0
        self.material = 'synthetic-old-secret'; self.fault = None; self.decode = json.loads
        self.ack = dict(http_method='PUT',http_status=200,status='success',serial='SYNTHETIC01',version='v7.0.0',build=29,
            path='user',name='scim',mkey=values()['name'])
    def http_clock(self): return self.http_time
    def factory(self, host, port, **kwargs):
        peer = self
        class Connection:
            def __init__(self): self.sock = Socket(); self.closed = False; self.path = self.method = None; peer.resources.append(self)
            def set_debuglevel(self, value): assert value == 0
            def connect(self): assert host == 'pam.example.test'
            def request(self, method, path, *, body=None, headers):
                assert headers['Authorization'] == 'Bearer synthetic-api-token'
                peer.calls.append((method,path)); self.path, self.method = path, method
                if method == 'PUT':
                    peer.put_buffers.append(body); peer.puts += 1
                    decoded = peer.decode(body); peer.material = decoded.pop('secret')
                    peer.payloads[CURRENT_PATH]['results'][0].update(decoded)
                    if peer.fault == 'write-timeout': raise TimeoutError('SYNTHETIC_PRIVATE_WRITE')
                    if peer.fault == 'omitted-drift': peer.payloads[CURRENT_PATH]['results'][0]['token-certificate'] = 'synthetic-drift'
                    if peer.fault == 'wrong-material': peer.material = 'synthetic-wrong-secret'
                    if peer.fault == 'post-deadline': peer.http_time += 6.0
            def getresponse(self):
                data = peer.ack if self.path == native.DETAIL_PATH else peer.payloads[self.path]
                return Response(json.dumps(data).encode(),self.method == 'PUT')
            def close(self):
                self.closed = True
                if peer.fault == 'close' or peer.fault == 'write-close' and self.method == 'PUT': raise OSError('SYNTHETIC_PRIVATE_CLOSE')
        class Response:
            status = 200
            def __init__(self, data, write): self.data = data; self.write = write; self.offset = 0; self.closed = False; peer.resources.append(self)
            def getheader(self, key, default=None):
                truncated = peer.fault == 'truncated' or self.write and peer.fault == 'write-truncated'
                return {'content-type':'application/json','content-length':str(len(self.data)+(1 if truncated else 0))}.get(key.lower(),default)
            def isclosed(self): return self.offset >= len(self.data)
            def readinto(self, view):
                if not peer.buffers or peer.buffers[-1] is not view.obj: peer.buffers.append(view.obj)
                count = min(len(view),len(self.data)-self.offset,37)
                view[:count] = self.data[self.offset:self.offset+count]; self.offset += count
                if peer.fault == 'deadline': peer.http_time += 1.0
                return count
            def close(self): self.closed = True
        return Connection()
    def source(self, *, trust=True):
        return ScimNativeSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,None),
            expected_serial='SYNTHETIC01',source_digest=SCOPE.configuration_source_digest,trust_source_digest='a'*64,
            trust_reader=self.trust if trust else None,connection_factory=self.factory,http_clock=self.http_clock,clock=self.clock)


def test_fixed_metadata_join_excludes_credential_fields_and_clears_raw_buffers(monkeypatch):
    peer = Peer(); source = peer.source(); original = json.loads
    def decode(raw, *args, **kwargs):
        marker = b'SYNTHETIC_C3_SENTINEL' if isinstance(raw,(bytes,bytearray)) else 'SYNTHETIC_C3_SENTINEL'
        assert marker not in raw
        return original(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',decode)
    readback = source.read()
    assert readback.state._values() == values() and readback.source_digest == SCOPE.configuration_source_digest
    assert peer.calls == [('GET',path) for path in (SCHEMA_PATH,CURRENT_PATH,GLOBAL_PATH,INTERFACES_PATH,SAML_PATH)]
    assert 'secret' not in CURRENT_PATH and len(original(readback.context)) == 6
    assert all(resource.closed for resource in peer.resources) and all(not any(buffer) for buffer in peer.buffers)
    assert 'synthetic.invalid' not in repr(readback) and source._latest is readback


@pytest.mark.parametrize('path,field,value', [(CURRENT_PATH,'token-certificate','synthetic-changed-cert'),
    (GLOBAL_PATH,'scim-server-cert','synthetic-changed-cert'),(INTERFACES_PATH,'allowaccess','https ssh scim'),
    (SAML_PATH,'scim-client','synthetic-other')])
def test_full_projection_and_dependency_drift_changes_the_bound_state(path, field, value):
    peer = Peer(); source = peer.source(); first = source.read()
    result = peer.payloads[path]['results']; row = result[0] if isinstance(result,list) else result
    row[field] = value
    changed = source.read()
    assert changed.digest != first.digest


@pytest.mark.parametrize('fault', ['credential-returned','missing-field','duplicate-name','incomplete','count','schema-size',
    'schema-option','no-scim-interface','global-port','wrong-device','wrong-version','wrong-build','wrong-action','close','truncated','deadline'])
def test_unqualified_or_incomplete_sources_fail_without_publishing_values(fault):
    peer = Peer(); source = peer.source()
    current = peer.payloads[CURRENT_PATH]
    if fault == 'credential-returned': current['results'][0]['secret'] = 'SYNTHETIC_C3_SENTINEL'
    elif fault == 'missing-field': del current['results'][0]['token-certificate']
    elif fault == 'duplicate-name': current['results'].append(deepcopy(current['results'][0])); current.update(size=2,matched_count=2)
    elif fault == 'incomplete': current['limit_reached'] = True
    elif fault == 'count': current['matched_count'] = 2
    elif fault == 'schema-size': peer.payloads[SCHEMA_PATH]['results']['children']['secret']['size'] = 60
    elif fault == 'schema-option': peer.payloads[SCHEMA_PATH]['results']['children']['status']['options'] = [{'name':'disable'}]
    elif fault == 'no-scim-interface': peer.payloads[INTERFACES_PATH]['results'][0]['allowaccess'] = 'https ssh'
    elif fault == 'global-port': peer.payloads[GLOBAL_PATH]['results']['scim-https-port'] = True
    elif fault == 'wrong-device': current['serial'] = 'SYNTHETIC_OTHER'
    elif fault == 'wrong-version': current['version'] = 'v7.0.1'
    elif fault == 'wrong-build': current['build'] = 30
    elif fault == 'wrong-action': current['action'] = 'other'
    else: peer.fault = fault
    with pytest.raises(ValueError) as error: source.read()
    assert source._latest is None and 'SYNTHETIC_C3_SENTINEL' not in str(error.value)
    assert all(resource.closed for resource in peer.resources) and all(not any(buffer) for buffer in peer.buffers)


@pytest.mark.parametrize('fault', ['error','source','binding','stale','mode'])
def test_unproven_service_trust_never_becomes_a_configuration_readback(fault):
    peer = Peer(); peer.trust.fault = fault; source = peer.source()
    with pytest.raises(ValueError): source.read()
    assert source._latest is None and all(not any(buffer) for buffer in peer.buffers)


def test_disabled_readback_retains_configured_trust_but_never_claims_live_tls():
    peer = Peer(); source = peer.source(); active = source.read()
    assert source._last_trust.active_tls_verified is True
    peer.payloads[CURRENT_PATH]['results'][0]['status'] = 'disable'
    disabled = source.read()
    assert disabled.state._values()['status'] == 'disable'
    assert source._last_trust.active_tls_verified is False
    assert json.loads(active.context)['trust_digest'] == json.loads(disabled.context)['trust_digest']
    assert active.digest != disabled.digest
    peer.trust.fault = 'mode'
    with pytest.raises(ValueError): source.read()


def test_unbound_trust_and_closed_or_weakened_tls_source_deny_before_http():
    peer = Peer()
    with pytest.raises(ValueError): peer.source(trust=False).read()
    assert peer.calls == []
    source = peer.source(); source._context.check_hostname = False
    with pytest.raises(ValueError): source.read()
    assert peer.calls == []
    source = peer.source(); source.close()
    with pytest.raises(ValueError): source.read()
    assert peer.calls == []


def test_clock_rollback_stays_closed_and_outer_send_budget_caps_all_guard_reads():
    peer = Peer(); source = peer.source(); source.read()
    peer.http_time = 9.0
    with pytest.raises(ValueError): source.read()
    peer.http_time = 11.0
    with pytest.raises(ValueError): source.read()
    peer = Peer(); source = peer.source(); peer.fault = 'deadline'
    with source._bounded_by(11.0):
        with pytest.raises(ValueError): source.read()
    assert len(peer.calls) == 1 and all(not any(buffer) for buffer in peer.buffers)
