"""Fixed dependency projections and real metadata parsing over synthetic peers."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from fortipam_mcp.saml_server_dependency_source import SamlDependencySource, GLOBAL_PATH, CERTIFICATES_PATH
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_saml_idp_metadata_probe import Peer as MetadataPeer, certificates
from test_saml_server_native_source import Peer as ApiPeer, envelope


PROXY_PATH = '/api/v2/cmdb/firewall/access-proxy/synthetic-proxy?format=name%7Cvip%7Cclient-cert%7Capi-gateway%7Capi-gateway6'


def dependency_payloads(record, signing_pin, references=7):
    certificate_path = '/api/v2/cmdb/vpn.certificate/remote/'+record['idp-cert']+'?format=name'
    def result(value, path, name):
        return {**envelope(value), 'path':path, 'name':name, 'vdom':'root'}
    return {
        GLOBAL_PATH:result({'saml-authentication':'enable'},'system','global'),
        PROXY_PATH:result(dict(name='synthetic-proxy',vip='synthetic-vip',**{'client-cert':'disable',
            'api-gateway':[dict(id=1,service='samlsp',**{'url-map':'/','saml-server':record['name']})],
            'api-gateway6':[]}), 'firewall','access-proxy'),
        certificate_path:result({'name':record['idp-cert']},'vpn.certificate','remote'),
        CERTIFICATES_PATH:result([dict(name=record['idp-cert'],type='remote-cer',fingerprint=signing_pin,
            valid_from=0,valid_to=10000,q_ref=references)],'system','available-certificates'),
    }


class Peer(ApiPeer):
    def __init__(self, certificates):
        super().__init__()
        self.metadata = MetadataPeer(certificates); self.metadata.clock = self.clock
        self.probe = self.metadata.probe()
        self.payloads.update(dependency_payloads(self.original,certificates[0][1]))
        self.certificate_path = '/api/v2/cmdb/vpn.certificate/remote/'+self.original['idp-cert']+'?format=name'
    @property
    def certificate(self): return self.payloads[CERTIFICATES_PATH]['results'][0]
    def reader(self, *, guarded=True, **kwargs):
        return SamlDependencySource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,None),
            self.original,expected_serial='SYNTHETIC01',proxy_name='synthetic-proxy',source_digest='2'*64,
            metadata_source_digest='a'*64,metadata_probe=self.probe,source_guard=(lambda:True) if guarded else None,
            connection_factory=self.factory,http_clock=self.http_clock,clock=self.clock,**kwargs)
    def observe(self, reader=None):
        return (reader or self.reader()).observe(self.probe._binding.record_digest,timeout_seconds=5)


def test_four_fixed_reads_bind_device_proxy_and_certificate_without_inventing_environment_proof(certificates):
    peer = Peer(certificates); reader = peer.reader(); first = peer.observe(reader)
    assert peer.calls == [GLOBAL_PATH,PROXY_PATH,peer.certificate_path,CERTIFICATES_PATH]
    assert peer.metadata.calls == ['/idp/metadata']
    assert first.complete and first.certificate_reference_count == 7
    assert not first.runtime_isolation_verified and not first.independent_recovery_ready
    assert first.idp_certificate_sha256 == certificates[0][1] and first.expires_at == 1010
    assert all(resource.closed for resource in peer.resources+peer.metadata.resources)
    assert all(not any(raw) for raw in peer.buffers+peer.metadata.buffers)
    peer.payloads[GLOBAL_PATH]['results']['saml-authentication'] = 'disable'
    peer.payloads[PROXY_PATH]['results']['api-gateway'] = []
    peer.certificate['q_ref'] = 0
    other = peer.observe(reader)
    assert other.dependencies_digest != first.dependencies_digest
    assert other.complete and not other.runtime_isolation_verified and not other.independent_recovery_ready
    reader.close()
    with pytest.raises(ValueError,match='unavailable'): peer.observe(reader)
    assert peer.probe.observe(peer.probe._binding.record_digest,timeout_seconds=5)  # The metadata probe is borrowed.


def test_reference_count_is_separate_and_unselected_monitor_material_is_never_decoded_or_hashed(certificates, monkeypatch):
    peer = Peer(certificates); reader = peer.reader(); first = peer.observe(reader)
    peer.certificate['q_ref'] = 8
    peer.certificate['unselected-field'] = 'SYNTHETIC_UNSELECTED_MATERIAL'
    peer.payloads[CERTIFICATES_PATH]['results'].append(dict(name='synthetic-unrelated',type='local-cer',
        certificate='SYNTHETIC_UNSELECTED_MATERIAL'))
    original = json.loads
    def decode(raw,*args,**kwargs):
        sentinel = b'SYNTHETIC_UNSELECTED_MATERIAL' if isinstance(raw,(bytes,bytearray)) else 'SYNTHETIC_UNSELECTED_MATERIAL'
        assert sentinel not in raw
        return original(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',decode)
    other = peer.observe(reader)
    assert other.dependencies_digest == first.dependencies_digest and other.certificate_reference_count == 8


@pytest.mark.parametrize('field,value', [('error',-3),('error',False),('limit_reached',True),
    ('limit_reached','false'),('size',2),('matched_count',0),('size',True)])
def test_monitor_error_or_explicitly_incomplete_collection_is_not_complete_evidence(certificates, field, value):
    peer = Peer(certificates); peer.payloads[CERTIFICATES_PATH][field] = value
    with pytest.raises(ValueError,match='unavailable'): peer.observe()
    assert peer.metadata.calls == [] and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['metadata-source','metadata-record','unsafe-proxy','unsafe-certificate','zero-port'])
def test_constructor_requires_exact_sources_and_safe_fixed_selectors(certificates, fault):
    peer = Peer(certificates); record = dict(peer.original)
    config = SecretMetadataHttpTransportConfig('https://pam.example.test'+(':0' if fault == 'zero-port' else ''),
        'synthetic-api-token',5,None)
    if fault == 'metadata-record': record['user-name'] = 'synthetic-other'
    elif fault == 'unsafe-certificate': record['idp-cert'] = '../synthetic-other'
    with pytest.raises(ValueError,match='unavailable'):
        SamlDependencySource(config,record,expected_serial='SYNTHETIC01',
            proxy_name='../synthetic-other' if fault == 'unsafe-proxy' else 'synthetic-proxy',
            source_digest='2'*64,metadata_source_digest='f'*64 if fault == 'metadata-source' else 'a'*64,
            metadata_probe=peer.probe)
    assert peer.calls == [] and peer.metadata.calls == []


@pytest.mark.parametrize('field', ['serial','version','build','path','name','vdom','http_method','http_status','status'])
def test_foreign_device_version_or_route_is_rejected_before_metadata(certificates, field):
    peer = Peer(certificates)
    peer.payloads[GLOBAL_PATH][field] = 30 if field in ('build','http_status') else 'synthetic-other'
    with pytest.raises(ValueError,match='unavailable'): peer.observe()
    assert peer.metadata.calls == [] and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['global-field','global-state','proxy-field','proxy-name','client-cert','gateway-field',
    'gateway-id','gateway-duplicate','gateway-origin','gateway-url','certificate-name','missing-certificate',
    'duplicate-certificate','certificate-type','pin','valid-from','valid-to','references','reference-bool'])
def test_incomplete_unsafe_or_disagreeing_dependencies_never_publish(certificates, monkeypatch, fault):
    peer = Peer(certificates); proxy = peer.payloads[PROXY_PATH]['results']; gateway = proxy['api-gateway'][0]
    if fault == 'global-field': peer.payloads[GLOBAL_PATH]['results']['password'] = 'SYNTHETIC_UNEXPECTED_MATERIAL'
    elif fault == 'global-state': peer.payloads[GLOBAL_PATH]['results']['saml-authentication'] = 'unknown'
    elif fault == 'proxy-field': proxy['password'] = 'SYNTHETIC_UNEXPECTED_MATERIAL'
    elif fault == 'proxy-name': proxy['name'] = 'synthetic-other'
    elif fault == 'client-cert': proxy['client-cert'] = 'unknown'
    elif fault == 'gateway-field': gateway['password'] = 'SYNTHETIC_UNEXPECTED_MATERIAL'
    elif fault == 'gateway-id': gateway['id'] = True
    elif fault == 'gateway-duplicate': proxy['api-gateway'].append(deepcopy(gateway))
    elif fault == 'gateway-origin': gateway['q_origin_key'] = 2
    elif fault == 'gateway-url': gateway['url-map'] = 'https://user:password@synthetic-other.invalid/'
    elif fault == 'certificate-name': peer.payloads[peer.certificate_path]['results']['name'] = 'synthetic-other'
    elif fault == 'missing-certificate': peer.payloads[CERTIFICATES_PATH]['results'] = []
    elif fault == 'duplicate-certificate': peer.payloads[CERTIFICATES_PATH]['results'].append(deepcopy(peer.certificate))
    elif fault == 'certificate-type': peer.certificate['type'] = 'local-cer'
    elif fault == 'pin': peer.certificate['fingerprint'] = 'f'*64
    elif fault == 'valid-from': peer.certificate['valid_from'] = 1
    elif fault == 'valid-to': peer.certificate['valid_to'] = 9999
    elif fault == 'references': peer.certificate['q_ref'] = -1
    elif fault == 'reference-bool': peer.certificate['q_ref'] = True
    original = json.loads
    def decode(raw,*args,**kwargs):
        sentinel = b'SYNTHETIC_UNEXPECTED_MATERIAL' if isinstance(raw,(bytes,bytearray)) else 'SYNTHETIC_UNEXPECTED_MATERIAL'
        assert sentinel not in raw
        return original(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',decode)
    with pytest.raises(ValueError,match='unavailable'): peer.observe()
    assert all(resource.closed for resource in peer.resources+peer.metadata.resources)
    assert all(not any(raw) for raw in peer.buffers+peer.metadata.buffers)


@pytest.mark.parametrize('fault', ['duplicate-json','html','truncated','close','deadline','oversize'])
def test_transport_errors_clear_buffers_and_never_fetch_metadata(certificates, fault):
    peer = Peer(certificates); peer.fault = fault
    if fault == 'duplicate-json':
        # The shared peer repeats the envelope table member named "saml".
        peer.payloads[GLOBAL_PATH]['name'] = 'saml'
    with pytest.raises(ValueError,match='unavailable'): peer.observe()
    assert peer.metadata.calls == [] and all(resource.closed for resource in peer.resources)
    assert all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['guard','closed','tls','probe-disabled','probe-closed','record','timeout'])
def test_unready_sources_refuse_before_any_management_request(certificates, fault):
    peer = Peer(certificates); reader = peer.reader(guarded=fault != 'guard')
    if fault == 'closed': reader.close()
    elif fault == 'tls': reader._tls.check_hostname = False
    elif fault == 'probe-disabled': peer.probe._enabled = False
    elif fault == 'probe-closed': peer.probe.close()
    with pytest.raises(ValueError,match='unavailable'):
        reader.observe('f'*64 if fault == 'record' else peer.probe._binding.record_digest,
            timeout_seconds=0 if fault == 'timeout' else 5)
    assert peer.calls == [] and peer.metadata.calls == []


@pytest.mark.parametrize('clock', ['epoch','monotonic'])
def test_clock_rollback_permanently_closes_dependency_source(certificates, clock):
    peer = Peer(certificates); reader = peer.reader(); peer.observe(reader)
    if clock == 'epoch': peer.clock.value = 999
    else: peer.time = 9
    with pytest.raises(ValueError,match='unavailable'): peer.observe(reader)
    peer.clock.value = 1000; peer.time = 10
    calls = len(peer.calls)
    with pytest.raises(ValueError,match='unavailable'): peer.observe(reader)
    assert len(peer.calls) == calls


def test_metadata_delay_consumes_the_same_total_dependency_deadline(certificates):
    peer = Peer(certificates); reader = peer.reader(); observe = peer.probe.observe
    def delayed(*args,**kwargs):
        value = observe(*args,**kwargs); peer.time += 5
        return value
    peer.probe.observe = delayed
    with pytest.raises(ValueError,match='unavailable'): peer.observe(reader)
    assert peer.metadata.calls == ['/idp/metadata'] and all(not any(raw) for raw in peer.buffers)


def test_fixed_native_source_can_report_unqualified_dependencies_but_cannot_mint_execution(certificates, tmp_path):
    from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
    from fortipam_mcp.saml_server_local_m4 import saml_execution_digests
    from test_m4_execution_store import _ExternalM4Checkpoint
    from test_saml_server_local_m4 import SCOPE

    peer = Peer(certificates); peer.dependencies = peer.reader(); observation = peer.source().read()
    assert observation.dependencies.complete
    assert not observation.summary()['runtime_isolation_reported']
    assert not observation.summary()['independent_recovery_reported']
    key = tmp_path/'execution.key'; key.write_bytes(b'x'*32); key.chmod(0o600)
    store = PersistentM4ExecutionStateStore(tmp_path/'execution.db',key,
        monotonic_checkpoint=_ExternalM4Checkpoint('synthetic-saml'),checkpoint_store_ref='synthetic-saml')
    from v4_planning import M4AdapterDenied
    with pytest.raises(M4AdapterDenied): saml_execution_digests(observation,SCOPE,store)
    assert store.claim_count == 0


@pytest.mark.parametrize('drift', [None,'global','proxy','certificate'])
def test_final_send_guard_rechecks_fixed_dependencies_and_never_promotes_synthetic_environment(certificates, tmp_path, drift):
    from test_saml_server_local_m4 import make, removal
    from v4_planning import M4AdapterDenied

    peer = Peer(certificates); reader = peer.reader()
    class SyntheticEnvironment:
        # Only this test supplies isolation/recovery evidence. The production
        # reader always returns both flags false, including after successful GETs.
        @property
        def references(self): return peer.certificate['q_ref']
        @references.setter
        def references(self, value): peer.certificate['q_ref'] = value
        def observe(self, *args, **kwargs):
            return replace(reader.observe(*args,**kwargs),runtime_isolation_verified=True,independent_recovery_ready=True)
    peer.dependencies = SyntheticEnvironment()
    value = make(tmp_path,peer=peer)
    def change():
        if drift == 'global': peer.payloads[GLOBAL_PATH]['results']['saml-authentication'] = 'disable'
        elif drift == 'proxy': peer.payloads[PROXY_PATH]['results']['client-cert'] = 'enable'
        elif drift == 'certificate': peer.certificate['fingerprint'] = 'f'*64
    value.backend.on_send = change
    result = value.kernel.execute(value.plan,value.authorization)
    assert (result.outcome == 'succeeded') is (drift is None)
    reads = len(peer.calls)
    assert value.kernel.execute(value.plan,value.authorization).idempotent_replay
    assert len(peer.calls) == reads
    if drift is None:
        value.backend.on_send = None
        kernel,plan,authorization = removal(value)
        assert kernel.execute(plan,authorization).outcome == 'succeeded'
        assert value.backend.sends == value.store.claim_count == 2
        assert not peer.observe(reader).runtime_isolation_verified
    else:
        assert value.backend.sends == 0
        with pytest.raises(M4AdapterDenied): removal(value)
    assert all(resource.closed for resource in peer.resources+peer.metadata.resources)
    assert all(not any(raw) for raw in peer.buffers+peer.metadata.buffers)
