"""Fixed JWT request binding, byte ownership and candidate ACK denial cases."""
import copy
import hashlib
import json
import pickle

import pytest

from fortipam_mcp import jwt_manual_key_request_contract as r
from fortipam_mcp.jwt_manual_key_contract import JwtManualCreatePlan, JwtManualPublicKey, JwtManualKeyContractError
from test_jwt_manual_key_contract import defaults, public_pem, synthetic_key
from v4_planning.material_provider import MaterialAccessDenied

SERIAL = 'SYNTHETIC-JWT'
CONTEXT = dict(schema_digest='a'*64, serial_digest=hashlib.sha256(SERIAL.encode()).hexdigest())


def request(key, *, nonce='c'*64):
    plan=JwtManualCreatePlan('mcp-v4-jwt-synthetic',nonce,JwtManualPublicKey(public_pem(key)),defaults(),**CONTEXT)
    return r.JwtManualCreateRequest(plan,defaults(),**CONTEXT)


def response(**changes):
    value=dict(version='v7.0.0',build=29,serial=SERIAL,http_method='POST',http_status=200,
        status='success',path='secret',name='jwt-key',vdom='root',mkey='mcp-v4-jwt-synthetic',error=0)
    value.update(changes)
    return bytearray(json.dumps(value,separators=(',',':')).encode())


def test_native_query_is_bound_to_the_complete_body_and_source_context(synthetic_key):
    first,second=request(synthetic_key),request(synthetic_key,nonce='d'*64)
    try:
        with first.borrow_body()as body:
            assert body.readonly and type(body.obj)is bytearray
            assert first.method=='POST' and first.path=='/api/v2/cmdb/secret/jwt-key' and first.query=='with_meta=true'
            value=json.loads(body.tobytes())
            assert value['name']=='mcp-v4-jwt-synthetic'and len(value)==7
            assert 'q_origin_key'not in value and value['key'][0]['key-name']==public_pem(synthetic_key).decode()
            assert first.body_digest==hashlib.sha256(body).hexdigest()
        assert first.body_digest==second.body_digest and first.digest!=second.digest
        assert first.plan_digest!=second.plan_digest
    finally:
        first.close();second.close()


@pytest.mark.parametrize('fault',['body','subject','query-digest','defaults-digest'])
def test_tampering_refuses_borrow_and_erases_underlying_buffer(synthetic_key,fault):
    value=request(synthetic_key)
    raw=value._body
    if fault=='body':raw[0]=32
    if fault=='subject':object.__setattr__(value,'_name','mcp-v4-jwt-other')
    if fault=='query-digest':object.__setattr__(value,'digest','f'*64)
    if fault=='defaults-digest':object.__setattr__(value,'defaults_digest','f'*64)
    with pytest.raises(JwtManualKeyContractError):value.borrow_body()
    assert value._closed and not any(raw)


def test_close_clears_outstanding_views_without_granting_a_second_body(synthetic_key):
    value=request(synthetic_key)
    view=value.borrow_body()
    value.close()
    assert not any(view)
    view.release()
    value.close()
    with pytest.raises(JwtManualKeyContractError):value.borrow_body()


def test_request_and_ack_are_opaque_noncopyable_and_immutable(synthetic_key):
    value=request(synthetic_key)
    ack=r.consume_jwt_manual_create_ack(response(),value,http_status=200)
    try:
        for item in (value,ack):
            assert 'mcp-v4-jwt-synthetic'not in repr(item)and 'PUBLIC KEY'not in repr(item)
            for operation in (copy.copy,copy.deepcopy,pickle.dumps):
                with pytest.raises(MaterialAccessDenied):operation(item)
        with pytest.raises(JwtManualKeyContractError):value.query='other'
    finally:value.close()


def test_candidate_ack_binds_request_without_decoding_unselected_response_content(synthetic_key,monkeypatch):
    from fortipam_mcp import secret_bulk_import_metadata as parser
    value=request(synthetic_key)
    raw=response(results={'private-note':'SYNTHETIC_UNSELECTED_CONTENT'})
    digest=hashlib.sha256(raw).hexdigest()
    scalar=parser._scalar
    def selected_only(data,span):
        assert b'SYNTHETIC_UNSELECTED_CONTENT'not in data[slice(*span)]
        return scalar(data,span)
    monkeypatch.setattr(parser,'_scalar',selected_only)
    try:
        ack=r.consume_jwt_manual_create_ack(raw,value,http_status=200)
        assert not raw and ack.request_digest==value.digest and ack.response_digest==digest
    finally:value.close()


@pytest.mark.parametrize('changes',[{'http_method':'GET'},{'http_status':True},{'http_status':500},
    {'status':'error'},{'status':'OK'},{'build':True},{'build':30},{'version':'v7.0.1'},
    {'path':'system'},{'name':'api-user'},{'vdom':'other'},{'serial':'OTHER'},
    {'mkey':'mcp-v4-jwt-other'},{'mkey':1},{'error':False},{'error':-3},{'schema_errors':None},{'action':'refresh'}])
def test_foreign_or_unqualified_response_is_erased_and_never_an_ack(synthetic_key,changes):
    value=request(synthetic_key)
    raw=response(**changes)
    try:
        with pytest.raises(JwtManualKeyContractError):r.consume_jwt_manual_create_ack(raw,value,http_status=200)
        assert not raw
    finally:value.close()


@pytest.mark.parametrize('fault',['http','boolean-http','duplicate','trailing','oversize','closed-request'])
def test_transport_or_framing_uncertainty_does_not_produce_an_ack(synthetic_key,fault):
    value=request(synthetic_key)
    raw=response()
    status=403 if fault=='http'else True if fault=='boolean-http'else 200
    if fault=='duplicate':raw=raw.replace(b'"status":"success"',b'"status":"success","status":"success"')
    if fault=='trailing':raw.extend(b'false')
    if fault=='oversize':raw=bytearray(b' '*(524288+1))
    if fault=='closed-request':value.close()
    try:
        with pytest.raises(JwtManualKeyContractError):r.consume_jwt_manual_create_ack(raw,value,http_status=status)
        assert not raw
    finally:value.close()


def test_interruption_erases_response_without_relabeling_it_as_success(synthetic_key,monkeypatch):
    from fortipam_mcp import secret_bulk_import_metadata as parser
    value=request(synthetic_key)
    raw=response()
    def interrupted(*args):raise KeyboardInterrupt
    monkeypatch.setattr(parser,'_scalar',interrupted)
    try:
        with pytest.raises(KeyboardInterrupt):r.consume_jwt_manual_create_ack(raw,value,http_status=200)
        assert not raw
    finally:value.close()
