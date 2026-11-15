"""Two verified-owned objects can gain only one reversible software reference."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from urllib.parse import parse_qs

import httpx
import pytest

from fortipam_mcp.putty_integrity_association_http_transport import (
    CONTRACT, PuttyIntegrityAssociationBinding, PuttyIntegrityAssociationHttpTransport,
    PuttyIntegrityAssociationTransportError, load_putty_integrity_association_binding,
)
from fortipam_mcp.launcher_clone_http_transport import FortiPamLauncherCloneHttpTransport
from fortipam_mcp.client_integrity_http_transport import FortiPamNativeClientIntegrityHttpTransport
from test_client_integrity_http_transport import Appliance, adapter as software_adapter, reserve, SERIAL
from test_putty_launcher_windows_http_transport import WindowsAppliance
from test_putty_launcher_windows_http_contract import APPLICATION
from test_putty_launcher_clone_http_transport import adapter as launcher_adapter, DESTINATION


class JoinedAppliance:
    def __init__(self):
        self.launcher = WindowsAppliance(); self.launcher.serial = SERIAL
        self.software = Appliance(); self.software.name = 'mcp-v4-client-integrity-hash-20261006-r2'
        self.software.executable_sha256 = APPLICATION.executable_sha256
        self.puts = []; self.lose_put = False; self.ack_extra = {}; self.omit_child = False

    def handle(self, request):
        if request.method == 'PUT':
            self.puts.append(request)
            assert request.url.path == '/api/v2/cmdb/secret/launcher/'+DESTINATION
            assert parse_qs(request.url.query.decode()) == {'vdom':['root']}
            body = json.loads(request.content)
            assert body['$originalName'] == DESTINATION
            reference = body['os_app'][0]['client-software']
            assert reference in {'',self.software.name}
            expected = deepcopy(self.launcher.rows[DESTINATION]); expected['os_app'][0]['client-software'] = reference
            submitted = {k:deepcopy(expected[k]) for k in ('name','type','is-file-launcher','elevation','session-close-log','launch-timeout','os_app')}
            del submitted['os_app'][0]['q_origin_key']; submitted['$originalName'] = DESTINATION
            assert body == submitted
            self.launcher.rows[DESTINATION] = expected
            self.software.rows[self.software.name]['q_ref'] = int(bool(reference))
            if self.omit_child: self.launcher.rows[DESTINATION]['os_app'] = []
            if self.lose_put: raise httpx.ReadTimeout('private-sentinel')
            return httpx.Response(200,json={'version':'v7.0.0','build':29,'http_method':'PUT','http_status':200,
                'path':'secret','name':'launcher','vdom':'root','status':'OK','serial':SERIAL,
                'mkey':DESTINATION,'action':'','error':0,'old_revision':'synthetic-old',
                'revision_changed':True,**self.ack_extra})
        is_launcher = '/secret/launcher' in request.url.path or (
            request.url.path.endswith('/object/usage') and parse_qs(request.url.query.decode()).get('mkey') == [DESTINATION])
        if is_launcher: return self.launcher.handle(request)
        response = self.software.handle(request)
        if request.method == 'POST': self.software.rows[self.software.name]['q_ref'] = 0
        return response


def prepared(tmp_path):
    device = JoinedAppliance(); factory = lambda **kw:httpx.Client(transport=httpx.MockTransport(device.handle),**kw)
    launcher_state = tmp_path/'launcher'; launcher_state.mkdir(mode=0o700)
    software_state = tmp_path/'software'; software_state.mkdir(mode=0o700)
    state = tmp_path/'association'; state.mkdir(mode=0o700)
    launcher_binding = replace(device.launcher.binding(),device_identity_digest=hashlib.sha256(SERIAL.encode()).hexdigest())
    launcher = launcher_adapter(launcher_state,device.launcher,launcher_binding,clone_enabled=True)
    launcher._factory = factory
    launcher.execute()
    software_binding = device.software.binding()
    software = software_adapter(software_state,device.software,binding=software_binding,factory=factory)
    reserve(software); software.execute()
    launcher = FortiPamLauncherCloneHttpTransport(launcher._config,launcher_binding,launcher_state,client_factory=factory)
    software = FortiPamNativeClientIntegrityHttpTransport(software._config,software_binding,software_state,
        software_state/'authorization.key',client_factory=factory,clock=lambda:100)
    row = deepcopy(device.launcher.rows[DESTINATION]); row['os_app'][0]['client-software'] = device.software.name
    binding = PuttyIntegrityAssociationBinding(launcher_binding.digest,software_binding.digest,
        hashlib.sha256(json.dumps(row,sort_keys=True,separators=(',',':')).encode()).hexdigest())
    key = state/'authorization.key'; key.write_bytes(b'a'*32); key.chmod(0o600)
    def adapter(**gates):
        return PuttyIntegrityAssociationHttpTransport(launcher,software,binding,state,key,
            clock=lambda:100,client_factory=factory,**gates)
    return device,launcher,software,binding,state,key,adapter


def execute(transport, *, recovery=False):
    transport.reserve_intent('a'*64,'b'*64,expires_at=500,recovery=recovery)
    return transport.execute(recovery=recovery)


def test_owned_fixed_association_and_restore_preserve_both_objects_and_cannot_replay(tmp_path):
    device,launcher,software,binding,state,key,adapter = prepared(tmp_path)
    baseline = deepcopy((device.launcher.rows,device.software.rows))
    t = adapter(association_enabled=True,restore_enabled=True)
    assert t.inspect()['owned_hash_software_verified']
    assert execute(t)['software_reference_present'] is True
    assert device.software.rows[device.software.name]['q_ref'] == 1
    assert execute(t,recovery=True)['software_reference_present'] is False
    assert (device.launcher.rows,device.software.rows) == baseline and len(device.puts) == 2
    for recovery in (False,True):
        with pytest.raises(PuttyIntegrityAssociationTransportError):
            adapter(association_enabled=True,restore_enabled=True).execute(recovery=recovery)
    for path in state.glob('*.json'):
        value = json.loads(path.read_bytes()); assert value['contract'] == CONTRACT and 'mac' in value
        assert DESTINATION not in path.read_text() and APPLICATION.executable_path not in path.read_text()
    assert len(device.puts) == 2


@pytest.mark.parametrize('failure',['lost_response','unknown_ack','missing_child'])
def test_uncertain_association_remains_consumed_without_restore_or_replay(tmp_path,failure):
    device,launcher,software,binding,state,key,adapter = prepared(tmp_path)
    if failure == 'lost_response': device.lose_put = True
    elif failure == 'unknown_ack': device.ack_extra = {'unknown':'private-sentinel'}
    else: device.omit_child = True
    t = adapter(association_enabled=True,restore_enabled=True)
    with pytest.raises(PuttyIntegrityAssociationTransportError) as error: execute(t)
    assert 'private-sentinel' not in str(error.value)
    assert (state/'associate.claim.json').exists() and not (state/'associate.verified.json').exists()
    for recovery in (False,True):
        with pytest.raises(PuttyIntegrityAssociationTransportError):
            adapter(association_enabled=True,restore_enabled=True).execute(recovery=recovery)
    assert len(device.puts) == 1


def test_post_claim_drift_consumes_without_dispatch(tmp_path,monkeypatch):
    device,launcher,software,binding,state,key,adapter = prepared(tmp_path)
    t = adapter(association_enabled=True); t.reserve_intent('a'*64,'b'*64,expires_at=500,recovery=False)
    original = t._snapshot; calls = 0
    def snapshot(**kwargs):
        nonlocal calls; calls += 1
        if calls == 2: device.launcher.rows[DESTINATION]['launch-timeout'] += 1
        return original(**kwargs)
    monkeypatch.setattr(t,'_snapshot',snapshot)
    with pytest.raises(PuttyIntegrityAssociationTransportError): t.execute()
    assert (state/'associate.claim.json').exists() and not device.puts


@pytest.mark.parametrize('failure',['partial_launcher','unverified_software','software_hash','launcher_used','software_used'])
def test_absence_of_ownership_or_exact_eligible_state_refuses_before_intent(tmp_path,failure):
    device,launcher,software,binding,state,key,adapter = prepared(tmp_path)
    if failure == 'partial_launcher': device.launcher.rows[DESTINATION]['os_app'] = []
    elif failure == 'unverified_software': (software._state/'create.verified.json').unlink()
    elif failure == 'software_hash': device.software.rows[device.software.name]['pkg'][0]['hash'] = 'b'*64
    elif failure == 'launcher_used': device.launcher.references = [{'private':'sentinel'}]
    else: device.software.rows[device.software.name]['q_ref'] = 1
    with pytest.raises(PuttyIntegrityAssociationTransportError):
        adapter(association_enabled=True).reserve_intent('a'*64,'b'*64,expires_at=500,recovery=False)
    assert not device.puts and not (state/'associate.intent.json').exists()


def test_key_state_binding_domain_and_signed_record_tampering_are_refused(tmp_path):
    device,launcher,software,binding,state,key,adapter = prepared(tmp_path)
    path = state/'binding.private.json'; path.write_text(json.dumps({'contract':CONTRACT,
        **{k:getattr(binding,k) for k in binding.__slots__}})); path.chmod(0o600)
    assert load_putty_integrity_association_binding(path) == binding
    value = json.loads(path.read_bytes()); value['contract'] = 'old-copy-domain'; path.write_text(json.dumps(value))
    with pytest.raises(PuttyIntegrityAssociationTransportError): load_putty_integrity_association_binding(path)
    key.write_bytes(software._key)
    with pytest.raises(PuttyIntegrityAssociationTransportError): adapter()
    key.write_bytes(b'a'*32)
    t = adapter(association_enabled=True); t.reserve_intent('a'*64,'b'*64,expires_at=500,recovery=False)
    path = state/'associate.intent.json'; value = json.loads(path.read_bytes()); value['expires_at'] += 1
    path.write_text(json.dumps(value))
    with pytest.raises(PuttyIntegrityAssociationTransportError): t.execute()
    assert not device.puts and not (state/'associate.claim.json').exists()


def test_closed_gate_and_expired_intent_do_not_dispatch(tmp_path):
    device,launcher,software,binding,state,key,adapter = prepared(tmp_path)
    t = adapter(); t.reserve_intent('a'*64,'b'*64,expires_at=500,recovery=False)
    with pytest.raises(PuttyIntegrityAssociationTransportError): t.execute()
    t = adapter(association_enabled=True); t._clock = lambda:500
    with pytest.raises(PuttyIntegrityAssociationTransportError): t.execute()
    assert not device.puts and not (state/'associate.claim.json').exists()
