"""A fixed mapped SSH prerequisite preserves complete native ACL metadata."""
import json
import pytest
from fortipam_mcp.target_creation_serializer import compile_job_mapped_target_request
from fortipam_mcp import target_preservation_contract as c
from test_target_creation_serializer import material
from test_target_preservation_contract import response,DIGEST


def test_fixed_mapped_target_binds_complete_owner_and_omits_only_native_wire_fields():
    value,_,_=material()
    value['name']='mcp-v4-target-job-mapped-20261031-r1';value['q_origin_key']=value['name'];value['domain']=''
    owner=value['user-permission'][0];owner['q_origin_key']=owner['id']
    owner['user-name'][0]['q_origin_key']=owner['user-name'][0]['name']
    payload=json.loads(response(value));payload['mkey']=value['name']
    proposal=c.capture_target_state(bytearray(json.dumps(payload).encode()),expected_name=value['name'],expected_serial_digest=DIGEST)
    body={k:value[k] for k in c.TARGET_STATE_FIELDS-{'uuid'}}
    from fortipam_mcp.target_creation_evidence import _GENERATED
    body={k:v for k,v in body.items() if k not in _GENERATED};body['$originalName']=value['name']
    raw=bytearray(json.dumps(body).encode())
    result=json.loads(compile_job_mapped_target_request(proposal,raw))
    assert not any(raw) and 'q_origin_key' not in result['user-permission'][0]
    assert 'q_origin_key' in value['user-permission'][0] and result['template']==value['template']
    value['name']='mcp-v4-target-other-20261031-r1';value['q_origin_key']=value['name'];payload=json.loads(response(value));payload['mkey']=value['name']
    proposal=c.capture_target_state(bytearray(json.dumps(payload).encode()),expected_name=value['name'],expected_serial_digest=DIGEST)
    raw=bytearray(json.dumps(body).encode())
    with pytest.raises(ValueError):compile_job_mapped_target_request(proposal,raw)
    assert not any(raw)
