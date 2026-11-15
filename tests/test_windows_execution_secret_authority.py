"""Real lab HMAC authority joined to persistent M4/C3 and synthetic product IO."""
from dataclasses import replace
import ssl

import pytest

from fortipam_mcp import windows_execution_secret_authority as a
from fortipam_mcp import windows_execution_secret_http_transport as h
from fortipam_mcp.windows_execution_secret_ack import WindowsExecutionSecretAckCustody
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from fortipam_mcp.windows_execution_secret_material import windows_execution_secret_material_runtime
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_windows_execution_secret_material import components
from test_windows_execution_secret_contract import SERIAL,postcondition,raw
from test_windows_execution_secret_http_transport import Connection
from test_web_secret_create_ack import AckResponse,_envelope
from test_secret_create_m4_runtime import _Reader
from v4_planning import M4AuthorizationDenied,M4Outcome


def setup(tmp_path,*,enabled=True):
    cmp=components(tmp_path)
    for name,key in (('authority.key',b'a'*32),('custody.key',b'w'*32)):
        path=tmp_path/name;path.write_bytes(key);path.chmod(0o600)
    source=[True]
    values=cmp['kwargs']
    identity=dict(requester_digest=values['plan'].requester_digest,transport_digest='b'*64)
    kwargs=dict(profile=values['profile'],defaults=values['defaults'],material_binding=values['material_binding'],
        execution_store=cmp['execution'],material_store=cmp['material'],authority_key_file=tmp_path/'authority.key',
        witness_key_file=tmp_path/'custody.key',source_context_digest='c'*64,
        environment_ref='owner-lab-development',scope_ref='one-private-windows-fixture',audience_ref='fixed-test-client',
        check_source=lambda:source[0],execution_enabled=enabled,clock=lambda:cmp['now'][0],**identity)
    authority=a.WindowsExecutionSecretLabAuthority(**kwargs)
    cmp.update(authority=authority,authority_kwargs=kwargs,source=source,identity=identity)
    return cmp


def issue(cmp):
    preview=cmp['authority'].preview(current_digest=a.windows_execution_secret_state_digest(cmp['kwargs']['profile'],exists=False),**cmp['identity'])
    return preview,cmp['authority'].issue(preview,**cmp['identity'])


def bind(cmp,tmp_path,monkeypatch,issued):
    directory=tmp_path/'custody';directory.mkdir(mode=0o700)
    config=SecretMetadataHttpTransportConfig('https://lab.example.test','synthetic-api-token',15,None)
    values={**cmp['kwargs'],'plan':issued.plan,'authorization':issued.authorization,'request':issued.lease_request}
    custody=WindowsExecutionSecretAckCustody(directory,tmp_path/'custody.key',config=config,
        **{key:values[key] for key in ('profile','defaults','plan','authorization','request','execution_store','material_store','clock')})
    connections=[Connection(AckResponse(raw(_envelope(serial=SERIAL,identifier=43)))),Connection(AckResponse(raw(postcondition())))]
    created=[]
    def factory(*args,**kwargs):
        connection=connections[len(created)];created.append(connection);return connection
    monkeypatch.setattr(h,'_ssl_context',lambda config:ssl.create_default_context())
    transport=h.WindowsExecutionSecretHttpTransport(config,custody,execution_enabled=True,source_guard=lambda:True,connection_factory=factory,http_clock=lambda:0)
    runtime=windows_execution_secret_material_runtime(**{**values,'transport':transport})
    reader=_Reader(post=issued.plan.expected_state_digest,onboarding_binding_digest=cmp['kwargs']['profile'].parameters_digest)
    reader.read_current=lambda plan:plan.expected_current_digest
    protected=ProtectedSecretCreateM4Runtime(cmp['authority'],cmp['authority'],cmp['execution'],runtime,reader,
        authenticated_requester_digest=issued.plan.requester_digest,clock=lambda:cmp['now'][0])
    return protected,custody,created


def test_real_signed_creation_authority_replaces_synthetic_verifier_in_the_full_private_chain(tmp_path,monkeypatch):
    cmp=setup(tmp_path)
    preview,issued=issue(cmp)
    assert issued.plan.parameters_digest==preview.parameters_digest
    assert issued.authorization.requester_digest!=issued.authorization.approver_digest
    protected,custody,created=bind(cmp,tmp_path,monkeypatch,issued)
    result=protected.execute_bound(issued.authorization.authorization_ref)
    assert result.outcome is M4Outcome.SUCCEEDED and len(created)==2
    assert custody.inspect_original_creation().original_outcome=='succeeded'
    assert cmp['loader'].loads==cmp['execution'].claim_count==cmp['material'].claim_count==1
    assert protected.execute_bound(issued.authorization.authorization_ref).idempotent_replay
    assert len(created)==2 and cmp['loader'].loads==1
    with pytest.raises(M4AuthorizationDenied):cmp['authority'].issue(preview,**cmp['identity'])
    rebuilt=a.WindowsExecutionSecretLabAuthority(**cmp['authority_kwargs'])
    with pytest.raises(M4AuthorizationDenied):rebuilt.preview(current_digest=preview.current_digest,**cmp['identity'])


def test_manual_verification_without_the_original_m4_claim_cannot_consume_authorization(tmp_path,monkeypatch):
    cmp=setup(tmp_path);_,issued=issue(cmp)
    with pytest.raises(M4AuthorizationDenied):cmp['authority'].verify(issued.plan,issued.authorization,now_epoch=1000)
    assert cmp['execution'].claim_count==0 and not cmp['authority']._verified
    protected,_,_=bind(cmp,tmp_path,monkeypatch,issued)
    assert protected.execute_bound(issued.authorization.authorization_ref).outcome is M4Outcome.SUCCEEDED


@pytest.mark.parametrize('fault',['closed','requester','transport','present','source','clock'])
def test_missing_lab_scope_or_wrong_cpe_identity_cannot_issue(tmp_path,fault):
    cmp=setup(tmp_path,enabled=fault!='closed')
    identity=dict(cmp['identity'])
    current=a.windows_execution_secret_state_digest(cmp['kwargs']['profile'],exists=fault=='present')
    if fault=='requester':identity['requester_digest']='f'*64
    if fault=='transport':identity['transport_digest']='f'*64
    if fault=='source':cmp['source'][0]=False
    if fault=='clock':cmp['now'][0]=True
    with pytest.raises(M4AuthorizationDenied):cmp['authority'].preview(current_digest=current,**identity)
    assert cmp['loader'].loads==cmp['execution'].claim_count==cmp['material'].claim_count==0


@pytest.mark.parametrize('fault',['expiry','source','profile','namespace','key','source-callback'])
def test_source_binding_drift_or_expiry_blocks_before_material_and_http(tmp_path,monkeypatch,fault):
    cmp=setup(tmp_path);_,issued=issue(cmp)
    protected,_,created=bind(cmp,tmp_path,monkeypatch,issued)
    if fault=='expiry':cmp['now'][0]=1060
    if fault=='source':cmp['source'][0]=False
    if fault=='profile':cmp['authority']._profile=replace(cmp['kwargs']['profile'],private_nonce='f'*64)
    if fault=='namespace':cmp['authority']._binding['scope_ref']='different-scope'
    if fault=='key':(tmp_path/'authority.key').write_bytes(b'z'*32)
    if fault=='source-callback':cmp['authority']._source=lambda:True
    with pytest.raises(M4AuthorizationDenied):protected.execute_bound(issued.authorization.authorization_ref)
    assert cmp['loader'].loads==len(created)==cmp['material'].claim_count==0


def test_unsigned_or_altered_preview_cannot_become_a_lab_grant(tmp_path):
    cmp=setup(tmp_path)
    preview=cmp['authority'].preview(current_digest=a.windows_execution_secret_state_digest(cmp['kwargs']['profile'],exists=False),**cmp['identity'])
    altered=replace(preview,parameters_digest='f'*64)
    with pytest.raises(M4AuthorizationDenied):cmp['authority'].issue(altered,**cmp['identity'])
    assert cmp['loader'].loads==0


def test_authority_key_cannot_reuse_creation_material_or_witness_keys(tmp_path):
    cmp=setup(tmp_path)
    (tmp_path/'authority.key').write_bytes(b'w'*32)
    with pytest.raises(M4AuthorizationDenied):a.WindowsExecutionSecretLabAuthority(**cmp['authority_kwargs'])
