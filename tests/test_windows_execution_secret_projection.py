"""Real private creation chain with fixed HTTP and synthetic namespace peers."""
from dataclasses import replace
import json

import httpx
import pytest

from fortipam_mcp import windows_execution_secret_projection as p
from fortipam_mcp import windows_execution_secret_contract as c
from fortipam_mcp import windows_execution_secret_http_transport as h
from fortipam_mcp import secret_bulk_import_metadata as m
from fortipam_mcp.dlp_api_actor_guard import DlpApiActorGuardBinding
from fortipam_mcp.secret_bulk_import_namespace_reader import ImportSecretNamespaceObservation
from fortipam_mcp.secret_bulk_import_namespace_source import ImportSecretNamespaceSourceReader, ImportSecretNamespaceSourceObservation
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig
from fortipam_mcp.windows_execution_secret_ack import WindowsExecutionSecretAckCustody
from fortipam_mcp.windows_execution_secret_authority import WindowsExecutionSecretLabAuthority
from fortipam_mcp.windows_execution_secret_material import windows_execution_secret_material_runtime
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from test_windows_execution_secret_preflight import setup as owned_setup
from test_windows_execution_secret_material import components
from test_windows_execution_secret_contract import source
from test_windows_execution_secret_http_transport import Connection
from test_web_secret_create_ack import AckResponse
from v4_planning import M4Outcome


def setup(tmp_path, monkeypatch):
    owned = owned_setup(tmp_path, monkeypatch, privilege_metadata=False)
    profile, config, harness = owned['profile'], owned['creator']._config, owned['harness']
    defaults = replace(source(), serial_digest=profile.serial_digest)
    native = dict(created=False, fault=None, namespace_reads=0, post_reads=0, http=[], hook=lambda:None)
    namespace_instances = []
    def namespace_read(instance):
        instance._require_pins()
        assert not instance._used
        instance._used = True
        native['namespace_reads'] += 1
        namespace_instances.append(instance)
        if native['fault'] == 'namespace-unavailable': raise ValueError('Synthetic source refusal.')
        names = ['Visible A', 'Visible B'] + ([profile.secret_name] if native['created'] else [])
        if native['fault'] in ('collision', 'duplicate'): names.append(profile.secret_name)
        if native['fault'] == 'case-collision': names.append(profile.secret_name.lower())
        rows = tuple(m.ImportMetadataSecret(43 if name == profile.secret_name else index, name, 'owner')
            for index, name in enumerate(names, 1))
        if native['fault'] == 'foreign-id' and native['created']:
            rows = tuple(replace(row, identifier=44) if row.name == profile.secret_name else row for row in rows)
        view = m.NativeImportMetadataCollection('database', rows, len(rows), len(rows), 'revision', profile.serial_digest)
        ns = ImportSecretNamespaceObservation(tuple(names), view, instance._now(), instance._now()+30)
        observed = ImportSecretNamespaceSourceObservation(view, ns, instance._source, 'a'*64, 'b'*64,
            instance._ssh_source, profile.serial_digest, instance._now(), instance._now()+30)
        instance._current = observed
        return observed
    def namespace_check(instance, observation):
        instance._require_pins()
        assert observation is instance._current and observation.source_context_digest == instance._source
        assert observation.observed_at <= instance._now() < observation.expires_at
    monkeypatch.setattr(ImportSecretNamespaceSourceReader, 'read_once', namespace_read)
    monkeypatch.setattr(ImportSecretNamespaceSourceReader, 'check_current', namespace_check)
    known_hosts = tmp_path/'known_hosts'
    known_hosts.write_bytes(b'Synthetic fixed SSH public host pin')
    known_hosts.chmod(0o600)
    ns_proto = ImportSecretNamespaceSourceReader(config,
        TargetSshTransportConfig('ssh.synthetic.invalid', 22, 'test-owner', 'synthetic-password', known_hosts, 30),
        DlpApiActorGuardBinding('synthetic-owner', 'super_admin', 'SYNTHETIC', 'e'*64), clock=lambda:harness.now)
    projection = p.WindowsExecutionSecretProjection(owned['reader'], ns_proto, defaults)
    def metadata():
        row = {**c._proposed_metadata(profile, c.REQUEST_UUID), 'id':43, 'q_ref':0, 'q_static':False,
            'uuid':'00000000-0000-4000-8000-000000000001', 'target-info':{'priv_acct':0},
            'field':[{'name':'Password', 'value':'synthetic-never-decode'}]}
        return dict(version='v7.0.0', build=29, http_method='GET', http_status=200, status='OK',
            path='secret', name='database', vdom='root', serial='SYNTHETIC', mkey=43, results=row)
    def handle(request):
        harness.requests.append(request)
        path = request.url.path
        if '/secret/database/' in path:
            assert request.method == 'GET' and path.endswith('/43')
            assert 'field' not in request.url.params['format'].split('|')
            native['post_reads'] += 1
            value = metadata()
            if native['fault'] == 'post-folder': value['results']['folder'] = 99
            if native['fault'] == 'post-uuid': value['results']['uuid'] = '00000000-0000-4000-8000-000000000002'
            if native['fault'] == 'post-privilege': value['results']['target-info']['priv_acct'] = 43
            response = httpx.Response(403 if native['fault']=='post-http' else 200,
                headers={'content-type':'application/json'}, stream=httpx.ByteStream(json.dumps(value).encode()))
        else:
            if path.endswith('/web-ui/state'): index=0
            elif '/system/api-user/' in path: index=1
            elif '/system/accprofile/' in path: index=2
            elif path.endswith('/secret/template'): index=3
            else:
                assert path.endswith('/secret/target')
                index=4
            response = httpx.Response(200, headers={'content-type':'application/json'},
                stream=httpx.ByteStream(json.dumps(harness.values[index]).encode()))
        native['hook']()
        return response
    harness.handle = handle
    owned.update(projection=projection, ns_proto=ns_proto, namespace_instances=namespace_instances,
        native=native, defaults=defaults, metadata=metadata)
    return owned


def bind(cmp, tmp_path, monkeypatch):
    root = tmp_path/'secret-runtime'
    root.mkdir(mode=0o700)
    material = components(root)
    current = cmp['projection'].preview_current()
    for name, key in (('authority.key', b'a'*32), ('custody.key', b'w'*32)):
        path=root/name; path.write_bytes(key); path.chmod(0o600)
    identity = dict(requester_digest=cmp['reader']._requester, transport_digest='b'*64)
    authority = WindowsExecutionSecretLabAuthority(profile=cmp['profile'], defaults=cmp['defaults'],
        material_binding=material['bound'].material_binding, execution_store=material['execution'],
        material_store=material['material'], authority_key_file=root/'authority.key', witness_key_file=root/'custody.key',
        source_context_digest=cmp['projection'].source_context_digest, environment_ref='owner-lab-development',
        scope_ref='one-private-windows-fixture', audience_ref='fixed-test-client',
        check_source=cmp['projection'].check_source, execution_enabled=True, clock=lambda:1000, **identity)
    preview = authority.preview(current_digest=current, **identity)
    issued = authority.issue(preview, **identity)
    state=root/'custody'; state.mkdir(mode=0o700)
    custody = WindowsExecutionSecretAckCustody(state, root/'custody.key', config=cmp['creator']._config,
        profile=cmp['profile'], defaults=cmp['defaults'], plan=issued.plan, authorization=issued.authorization,
        request=issued.lease_request, execution_store=material['execution'], material_store=material['material'], clock=lambda:1000)
    cmp['projection'].bind_original_creation(custody)
    def factory(*args, **kwargs):
        post = not cmp['native']['created']
        value = dict(version='v7.0.0', build=29, http_method='POST', http_status=200, status='success',
            path='secret', name='database', vdom='root', serial='SYNTHETIC', mkey=43, error=0) if post else cmp['metadata']()
        connection = Connection(AckResponse(bytearray(json.dumps(value).encode())))
        send = connection.request
        def request(method, path, **options):
            send(method, path, **options)
            cmp['native']['http'].append(method)
            if method == 'POST':
                cmp['native']['created'] = True
                cmp['target'].created['q_ref'] = 1
                if cmp['native']['fault'] == 'target-extra-reference': cmp['target'].created['q_ref'] = 2
                if cmp['native']['fault'] == 'target-config': cmp['target'].created['description'] = 'changed'
        connection.request = request
        return connection
    transport = h.WindowsExecutionSecretHttpTransport(cmp['creator']._config, custody, execution_enabled=True,
        source_guard=cmp['projection'].require_create_ready, connection_factory=factory, http_clock=lambda:0)
    runtime = windows_execution_secret_material_runtime(**{**material['kwargs'], 'profile':cmp['profile'],
        'defaults':cmp['defaults'], 'plan':issued.plan, 'authorization':issued.authorization,
        'request':issued.lease_request, 'transport':transport})
    protected = ProtectedSecretCreateM4Runtime(authority, authority, material['execution'], runtime, cmp['projection'],
        authenticated_requester_digest=issued.plan.requester_digest, clock=lambda:1000)
    cmp.update(authority=authority, issued=issued, custody=custody, material=material, transport=transport, protected=protected)
    return protected


def execute(cmp):
    return cmp['protected'].execute_bound(cmp['issued'].authorization.authorization_ref)


def test_full_original_create_has_fresh_absence_and_independent_metadata_postcondition(tmp_path, monkeypatch):
    cmp=setup(tmp_path, monkeypatch)
    bind(cmp, tmp_path, monkeypatch)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    assert cmp['native']['namespace_reads']==3 and cmp['native']['post_reads']==1
    assert cmp['native']['http']==['POST','GET']
    assert cmp['custody'].inspect_original_creation().original_outcome=='succeeded'
    assert cmp['material']['loader'].loads==cmp['material']['execution'].claim_count==cmp['material']['material'].claim_count==1
    assert all(instance._closed for instance in cmp['namespace_instances'][:-1])
    counts=cmp['native']['namespace_reads'], cmp['native']['post_reads'], len(cmp['harness'].requests)
    assert execute(cmp).idempotent_replay
    assert counts==(cmp['native']['namespace_reads'], cmp['native']['post_reads'], len(cmp['harness'].requests))


@pytest.mark.parametrize('fault',['collision','case-collision','namespace-unavailable'])
def test_hidden_ambiguous_or_unavailable_namespace_refuses_before_any_material_binding(tmp_path, monkeypatch, fault):
    cmp=setup(tmp_path, monkeypatch)
    cmp['native']['fault']=fault
    with pytest.raises(p.WindowsExecutionProjectionError): cmp['projection'].preview_current()
    assert not cmp['native']['http'] and not cmp['projection'].check_source()


@pytest.mark.parametrize('fault',['collision','case-collision','namespace-unavailable'])
def test_m4_fresh_namespace_drift_consumes_no_c3_material_or_http_dispatch(tmp_path, monkeypatch, fault):
    cmp=setup(tmp_path, monkeypatch)
    bind(cmp, tmp_path, monkeypatch)
    cmp['native']['fault']=fault
    assert execute(cmp).outcome is not M4Outcome.SUCCEEDED
    assert cmp['material']['loader'].loads==cmp['material']['material'].claim_count==0
    assert cmp['material']['execution'].claim_count==1 and not cmp['native']['http']


@pytest.mark.parametrize('fault',['duplicate','foreign-id','post-folder','post-uuid','post-privilege','post-http',
    'target-extra-reference','target-config'])
def test_postcondition_drift_retains_original_ack_as_unknown_without_replay(tmp_path, monkeypatch, fault):
    cmp=setup(tmp_path, monkeypatch)
    bind(cmp, tmp_path, monkeypatch)
    def after_send():
        if cmp['native']['created']: cmp['native']['fault']=fault
    cmp['native']['hook']=after_send
    if fault in ('target-extra-reference','target-config'): cmp['native']['fault']=fault
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    original=cmp['custody'].inspect_original_creation()
    assert original.native_secret_id==43 and original.native_uuid is not None
    assert original.original_outcome=='reconciliation_required'
    assert cmp['native']['http']==['POST','GET'] and cmp['material']['loader'].loads==1
    with pytest.raises(Exception): execute(cmp)
    assert cmp['native']['http']==['POST','GET']


def test_sending_without_the_pinned_projection_source_guard_never_loads_material(tmp_path, monkeypatch):
    cmp=setup(tmp_path, monkeypatch)
    bind(cmp, tmp_path, monkeypatch)
    cmp['transport']._source_guard=None
    assert execute(cmp).outcome is not M4Outcome.SUCCEEDED
    assert not cmp['native']['http'] and cmp['material']['loader'].loads==cmp['material']['material'].claim_count==0


def test_local_source_drift_after_preview_cannot_issue_or_acquire_material(tmp_path, monkeypatch):
    cmp=setup(tmp_path, monkeypatch)
    bind(cmp, tmp_path, monkeypatch)
    (tmp_path/'known_hosts').write_bytes(b'Changed synthetic host pin')
    with pytest.raises(Exception): execute(cmp)
    assert not cmp['native']['http'] and cmp['material']['execution'].claim_count==0
