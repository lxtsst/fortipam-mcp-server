"""Native wire omission stays bound to complete expected state and durable inputs."""
import json

import pytest

from fortipam_mcp import target_creation_http_transport as t
from fortipam_mcp import target_preservation_contract as c
from fortipam_mcp.target_creation_serializer import compile_request
from fortipam_mcp.target_creation_inputs import TargetCreationInputStore, TargetCreationInputsError
from fortipam_mcp.target_contract import DEFAULT_TEMPLATE
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_target_preservation_contract import row, capture
from test_target_creation_http_transport import Peer, create


def material(rpc='enable'):
    value = row()
    value.update({'class':'Other','template':DEFAULT_TEMPLATE,'access':'customized',
        'web-proxy-status':'disable','service-addrs':[],'hostkey':[],
        'group-permission':[], 'user-permission':[{'id':1,'user-name':[{'name':'synthetic-owner'}],
                                                  'permission':'owner'}],
        'sql-log':{'log-all':'disable','log-rpc-parameters':rpc,'max-log-entry-sz':16,'monitor-db':[]}})
    proposal = capture(value)
    body = {name:value[name] for name in c.TARGET_STATE_FIELDS-t.e._GENERATED}
    body['$originalName'] = proposal.name
    return value, proposal, bytearray(json.dumps(body).encode())


@pytest.mark.parametrize('rpc', ['enable','disable'])
def test_compiler_omits_wire_only_and_binds_full_expected_state(rpc):
    value, proposal, raw = material(rpc)
    original = bytearray(raw)
    wire = compile_request(proposal, raw)
    assert not any(raw)
    decoded = json.loads(wire)
    assert 'web-proxy' not in decoded
    assert 'log-rpc-parameters' not in decoded['sql-log']
    assert decoded['user-permission'] == value['user-permission'] and decoded['group-permission'] == []
    assert decoded['class'] == 'Other'
    digest = t._verify_request(wire, proposal, original)
    assert len(digest) == 64 and not any(original)
    other_value, other_proposal, other_raw = material('disable' if rpc=='enable' else 'enable')
    other_wire = compile_request(other_proposal, bytearray(other_raw))
    assert wire == other_wire
    assert digest != t._verify_request(other_wire, other_proposal, other_raw)


@pytest.mark.parametrize('fault', ['class','group','owner','web','service','hostkey','sql','state','wire'])
def test_compiler_denies_unsupported_or_mismatched_input_and_wipes(fault):
    value, proposal, raw = material()
    body = json.loads(raw)
    if fault == 'class': body['class'] = ''
    if fault == 'group': body['group-permission'] = [{'id':1,'group-name':[{'name':'everyone'}],'permission':'create-secret'}]
    if fault == 'owner': body['user-permission'][0]['permission'] = 'create-secret'
    if fault == 'web': body['web-proxy-status'] = 'enable'
    if fault == 'service': body['service-addrs'] = [{'service-addr':'192.0.2.10:22'}]
    if fault == 'hostkey': body['hostkey'] = [{'fingerprint':'synthetic'}]
    if fault == 'sql': body['sql-log'].pop('log-rpc-parameters')
    if fault == 'state': body['description'] = 'changed'
    if fault != 'state': proposal = capture(dict(value, **{k:v for k,v in body.items() if k!='$originalName'}))
    raw = bytearray(json.dumps(body).encode())
    with pytest.raises(ValueError):
        if fault == 'wire':
            wire = compile_request(proposal, bytearray(raw));wire.append(32)
            t._verify_request(wire, proposal, raw)
        else: compile_request(proposal, raw)
    assert not any(raw)


@pytest.mark.parametrize('drift', [False, True])
def test_durable_compiled_inputs_create_full_readback_or_fail_without_seal(tmp_path, drift):
    expected, proposal, raw = material()
    wire = compile_request(proposal, bytearray(raw))
    inputs_dir = tmp_path/'inputs';inputs_dir.mkdir(mode=0o700)
    state = tmp_path/'state';state.mkdir(mode=0o700)
    inputs = TargetCreationInputStore(inputs_dir)
    digest = inputs.provision(proposal, wire, expected_material=raw)
    assert not any(raw) and not any(wire)
    assert (inputs_dir/'expected-fields.bin').stat().st_mode & 0o777 == 0o600
    peer = Peer(); factory = peer.factory
    def connection(*args, **kwargs):
        conn = factory(*args, **kwargs);send=conn.request
        def request(method, *args):
            send(method, *args)
            if method=='POST':
                peer.created['web-proxy']=expected['web-proxy']
                peer.created['sql-log']=dict(expected['sql-log'])
                if drift: peer.created['sql-log']['log-rpc-parameters']='disable'
        conn.request=request
        return conn
    config=SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',5,None)
    creator=inputs.open_creator(config,input_digest=digest,state_directory=state,
        execution_enabled=True,clock=lambda:100,connection_factory=connection)
    if drift:
        with pytest.raises(t.TargetCreationTransportError): create(creator)
        assert not (state/'create.verified.json').exists()
        assert (state/'create.ack.json').exists()
    else:
        evidence=create(creator)
        assert dict(evidence.created.field_digests)['sql-log']==dict(proposal.field_digests)['sql-log']
        reopened=inputs.open_creator(config,input_digest=digest,state_directory=state)
        assert reopened.load_creation_evidence()==evidence
        assert not reopened._enabled and not reopened._recovery_enabled
        reopened.close()
    assert peer.calls==['GET','POST','GET']
    assert all(obj.closed for obj in peer.connections+peer.responses)


def test_expected_material_tamper_denies_before_network(tmp_path):
    _, proposal, raw = material()
    wire=compile_request(proposal,bytearray(raw));inputs_dir=tmp_path/'inputs';inputs_dir.mkdir(mode=0o700)
    state=tmp_path/'state';state.mkdir(mode=0o700)
    inputs=TargetCreationInputStore(inputs_dir);digest=inputs.provision(proposal,wire,expected_material=raw)
    path=inputs_dir/'expected-fields.bin';path.write_bytes(path.read_bytes().replace(b'enable',b'disable'))
    with pytest.raises(TargetCreationInputsError):
        inputs.open_creator(SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',5,None),
            input_digest=digest,state_directory=state,connection_factory=lambda *a,**kw:pytest.fail('network'))
