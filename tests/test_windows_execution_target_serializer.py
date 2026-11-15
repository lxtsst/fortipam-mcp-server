"""Fixed Windows Target wire shares native omissions without widening Unix."""
import json

import pytest

from fortipam_mcp import target_creation_serializer as s
from fortipam_mcp import target_creation_http_transport as t
from fortipam_mcp import target_preservation_contract as c
from test_target_creation_serializer import material
from test_target_preservation_contract import response, DIGEST
from fortipam_mcp.target_creation_inputs import TargetCreationInputStore
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig

NAME='MCPV4WinTarget20261021R1'


def windows(**changes):
    value,_,_=material()
    value.update(name=NAME,template='Windows Machine',domain='',url='',q_origin_key=NAME,
        **{'winrm-https':'disable','dynamic-gateway':'disable','gateway':'','gateway-cn':'',
           'user-base':'','user-naming-attribute':'sAMAccountName','kdc-address':'','sql-server-log-status':'disable'})
    value.update(changes)
    value['q_origin_key']=value['name']
    payload=json.loads(response(value));payload['mkey']=value['name']
    proposal=c.capture_target_state(bytearray(json.dumps(payload).encode()),expected_name=value['name'],expected_serial_digest=DIGEST)
    body={key:value[key] for key in c.TARGET_STATE_FIELDS-t.e._GENERATED}
    body['$originalName']=proposal.name
    return value,proposal,bytearray(json.dumps(body).encode())


def test_fixed_windows_compiler_is_separate_and_keeps_complete_expected_fields():
    value,proposal,raw=windows()
    expected=bytearray(raw)
    body=s.compile_windows_execution_target_request(proposal,raw)
    assert not any(raw)
    wire=json.loads(body)
    assert wire['template']=='Windows Machine' and wire['class']=='Other'
    assert wire['winrm-https']=='disable' and wire['user-permission']==value['user-permission']
    assert 'web-proxy' not in wire and 'log-rpc-parameters' not in wire['sql-log']
    assert len(t._verify_request(body,proposal,expected))==64 and not any(expected)
    _,_,raw=windows()
    with pytest.raises(ValueError):s.compile_request(proposal,raw)
    assert not any(raw)


@pytest.mark.parametrize('fault', [None, 'row_origin', 'bool_origin', 'name_origin', 'extra'])
def test_windows_acl_metadata_stays_in_expected_state_but_not_native_wire(fault):
    acl = [{'id':1, 'user-name':[{'name':'synthetic-owner', 'q_origin_key':'synthetic-owner'}],
        'permission':'owner', 'q_origin_key':1}]
    if fault == 'row_origin': acl[0]['q_origin_key'] = 2
    if fault == 'bool_origin': acl[0]['q_origin_key'] = True
    if fault == 'name_origin': acl[0]['user-name'][0]['q_origin_key'] = 'different-owner'
    if fault == 'extra': acl[0]['extra'] = 'unexpected'
    _, proposal, raw = windows(**{'user-permission':acl})
    if fault:
        with pytest.raises(ValueError): s.compile_windows_execution_target_request(proposal, raw)
    else:
        expected = bytearray(raw)
        body = s.compile_windows_execution_target_request(proposal, raw)
        _, original, clean = windows()
        assert json.loads(body) == json.loads(s.compile_windows_execution_target_request(original, clean))
        assert dict(proposal.field_digests)['user-permission'] != dict(original.field_digests)['user-permission']
        assert len(t._verify_request(body, proposal, expected)) == 64 and not any(expected)
    assert not any(raw)


@pytest.mark.parametrize('changes',[{'name':'shared-existing-target'},{'domain':'example.test'},
    {'url':'https://example.test'},{'winrm-https':'enable'},{'dynamic-gateway':'enable'},
    {'gateway':'shared-gateway'},{'user-base':'directory-base'},{'user-naming-attribute':''},{'kdc-address':'192.0.2.20'},
    {'sql-server-log-status':'enable'},{'access':'everyone'},
    {'group-permission':[{'group-name':[{'name':'everyone'}],'permission':'owner'}]}])
def test_unqualified_or_broader_windows_target_profiles_refuse_and_erase(changes):
    _,proposal,raw=windows(**changes)
    with pytest.raises(ValueError):s.compile_windows_execution_target_request(proposal,raw)
    assert not any(raw)


def test_existing_durable_inputs_reload_windows_wire_with_distinct_serialization_context(tmp_path):
    _,proposal,expected=windows()
    body=s.compile_windows_execution_target_request(proposal,bytearray(expected))
    serialization=t._verify_request(body,proposal,bytearray(expected))
    root=tmp_path/'inputs';root.mkdir(mode=0o700)
    state=tmp_path/'state';state.mkdir(mode=0o700)
    store=TargetCreationInputStore(root)
    digest=store.provision(proposal,body,expected_material=expected)
    assert not any(body) and not any(expected)
    creator=store.open_creator(SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',5,None),
        input_digest=digest,state_directory=state,connection_factory=lambda *args,**kwargs:pytest.fail('network'))
    assert creator._proposal==proposal and not creator._enabled and not creator._recovery_enabled
    assert json.loads((root/'inputs.verified.json').read_bytes())['serialization_digest']==serialization
    creator.close()
