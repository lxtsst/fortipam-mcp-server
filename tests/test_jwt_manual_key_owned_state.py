"""Complete owned-row checks and material-free original-state preservation."""
import copy
import json

import pytest

from fortipam_mcp import jwt_manual_key_owned_state as c
from fortipam_mcp.jwt_manual_key_contract import JwtManualCreatePlan, JwtManualPublicKey
from fortipam_mcp.jwt_manual_key_request_contract import JwtManualCreateRequest
from test_jwt_manual_key_preflight import NAME, SERIAL, SCHEMA_DIGEST, inputs, packet, raw, consume
from test_jwt_manual_key_contract import defaults, public_pem, synthetic_key


def request(key):
    context=dict(schema_digest=SCHEMA_DIGEST,serial_digest=SERIAL)
    plan=JwtManualCreatePlan(NAME,'a'*64,JwtManualPublicKey(public_pem(key)),defaults(),**context)
    return JwtManualCreateRequest(plan,defaults(),**context)


def owned_row(value):
    with value.borrow_body()as body:row=json.loads(body.tobytes())
    row.update({'oidc-discovery-url':'','last-check-time':'synthetic-never','last-update-time':'synthetic-never',
        'q_global_entry':False,'q_mkey_type':'string','q_name':'jwt-key','q_no_edit':False,'q_no_rename':False,
        'q_origin_key':NAME,'q_path':'secret','q_ref':0,'q_static':False,'q_type':0})
    return row


def state_inputs(value):
    row=owned_row(value)
    keys=packet('jwt-key',[dict(name=NAME,type='manually')],size=1,matched_count=1,next_idx=0)
    return [packet('jwt-key',[row],mkey=NAME),keys,inputs()[3],packet('jwt-key',[copy.deepcopy(row)],mkey=NAME)]


def observe(values,value,baseline,*,expected=None):
    buffers=[raw(row)for row in values]
    try:
        return c.consume_jwt_manual_key_owned_state(*buffers,request=value,baseline=baseline,witness_key=b'w'*32,
            expected_full_row_hmac=expected)
    finally:assert all(not raw for raw in buffers)


def test_initial_complete_state_and_closed_request_preservation_use_the_same_original_hmac(synthetic_key):
    value=request(synthetic_key);baseline=consume(inputs());values=state_inputs(value)
    first=observe(values,value,baseline)
    assert first.postcondition_digest==c.expected_jwt_manual_key_created_state(value,baseline)
    assert first.request_digest==value.digest and first.api_users_digest==baseline.api_users_digest
    value.close()
    assert observe(values,value,baseline,expected=first.full_row_hmac)==first
    changed=copy.deepcopy(values)
    for index in(0,3):changed[index]['results'][0]['last-update-time']='changed'
    with pytest.raises(c.JwtManualKeyOwnedStateError):observe(changed,value,baseline,expected=first.full_row_hmac)


@pytest.mark.parametrize('fault',['missing-field','extra-field','nested-extra','wrong-key','q-ref','static','no-edit','rename',
    'boolean-ref','wrong-origin','remote-mode','remote-url','claims','row-drift','key-namespace','new-jwt-user','users-drift'])
def test_unqualified_full_state_cannot_become_a_pristine_receipt(synthetic_key,fault):
    value=request(synthetic_key);baseline=consume(inputs());values=state_inputs(value)
    for index in(0,3):
        row=values[index]['results'][0]
        if fault=='missing-field':del row['q_ref']
        if fault=='extra-field':row['private-unknown']='PRIVATE_UNCLASSIFIED'
        if fault=='nested-extra':row['key'][0]['password']='PRIVATE_UNCLASSIFIED'
        if fault=='wrong-key':row['key'][0]['key-name']='not-a-public-key'
        if fault=='q-ref':row['q_ref']=1
        if fault=='boolean-ref':row['q_ref']=False
        if fault=='static':row['q_static']=True
        if fault=='no-edit':row['q_no_edit']=True
        if fault=='rename':row['q_no_rename']=True
        if fault=='wrong-origin':row['q_origin_key']='mcp-v4-jwt-other'
        if fault=='remote-mode':row['type']='jwks'
        if fault=='remote-url':row['jwks-url']='https://synthetic.invalid/'
        if fault=='claims':row['claim']=[{'claim-name':'synthetic-issuer'}]
    if fault=='row-drift':values[3]['results'][0]['last-check-time']='changed'
    if fault=='key-namespace':values[1]['results'][0]['name']='mcp-v4-jwt-other'
    if fault=='new-jwt-user':values[2]['results'][0]['type']='jwt'
    if fault=='users-drift':values[2]['results'][0]['name']='synthetic-other'
    try:
        with pytest.raises(c.JwtManualKeyOwnedStateError):observe(values,value,baseline)
    finally:value.close()


def test_unknown_nested_values_are_refused_before_whole_value_decoding(synthetic_key,monkeypatch):
    value=request(synthetic_key);baseline=consume(inputs());values=state_inputs(value)
    values[0]['results'][0]['key'][0]['password']='PRIVATE_UNCLASSIFIED'
    loads=json.loads
    def classified_only(data,*args,**kwargs):
        assert b'PRIVATE_UNCLASSIFIED'not in bytes(data)if not isinstance(data,str)else'PRIVATE_UNCLASSIFIED'not in data
        return loads(data,*args,**kwargs)
    monkeypatch.setattr(c.json,'loads',classified_only)
    try:
        with pytest.raises(c.JwtManualKeyOwnedStateError):observe(values,value,baseline)
    finally:value.close()
