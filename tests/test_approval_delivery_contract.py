"""Synthetic private approval settings only; no mailbox, secret or product access."""
import copy
import json
import pickle

import pytest

from fortipam_mcp.approval_delivery_contract import (
    prepare_empty_disabled_approval_delivery,approval_delivery_request_boundary,
)
import fortipam_mcp.approval_delivery_contract as module
from v4_planning.material_provider import MaterialAccessDenied


def state(protocol='imaps'):
    return {'approval-email-protocol':protocol,'email-pulling-server':'imap.example.test',
        'server':'example.test','port':993,'server-cert':'SYNTHETIC_CERT','email-folder':'INBOX',
        'ssl-min-version':'tls-1.2','check-interval':2,'tenant-id':'SYNTHETIC_TENANT',
        'app-id':'SYNTHETIC_APP','user-id':'SYNTHETIC_USER'}


def prepare(values,**flags):
    return prepare_empty_disabled_approval_delivery(values,**dict(
        username_empty=True,credential_empty=True,client_secret_empty=True,**flags))


@pytest.mark.parametrize('protocol',['imaps','ms-graph'])
def test_disable_has_exact_nested_sdk_fields_preserves_nonmaterial_and_clears_both_servers(protocol):
    values=state(protocol);original=dict(values);draft=prepare(values)
    body=json.loads(draft._encode());assert set(body)=={'approval-email-setting'}
    data=body['approval-email-setting'];assert len(data)==14 and 'enabled' not in data
    assert data['server']==data['email-pulling-server']==''
    assert data['username']==data['credential']==data['client-secret']==''
    assert all(data[key]==value for key,value in values.items() if key not in ('server','email-pulling-server'))
    assert values==original
    assert 'example.test' not in repr(draft) and 'SYNTHETIC_TENANT' not in str(draft)
    for operation in (copy.copy,copy.deepcopy,pickle.dumps):
        with pytest.raises(MaterialAccessDenied): operation(draft)


def test_original_server_change_is_bound_even_when_the_disabled_request_is_identical():
    values=state();first=prepare(values);values['server']='other.example.test';second=prepare(values)
    assert first.request_digest==second.request_digest
    assert first.input_nonmaterial_digest!=second.input_nonmaterial_digest
    values['email-folder']='OTHER';third=prepare(values)
    assert third.request_digest!=second.request_digest and third.input_nonmaterial_digest!=second.input_nonmaterial_digest


@pytest.mark.parametrize('field',['username_empty','credential_empty','client_secret_empty'])
@pytest.mark.parametrize('value',[False,1,None])
def test_empty_slot_facts_are_explicit_booleans(field,value):
    flags=dict(username_empty=True,credential_empty=True,client_secret_empty=True);flags[field]=value
    with pytest.raises(ValueError): prepare_empty_disabled_approval_delivery(state(),**flags)


@pytest.mark.parametrize('field,value',[
    ('username','SYNTHETIC_C3_CANARY'),('credential','SYNTHETIC_C3_CANARY'),
    ('client-secret','SYNTHETIC_C3_CANARY'),('enabled',True),('port',True),('port',0),
    ('port',65536),('check-interval',0),('check-interval',1441),('check-interval',False),
    ('approval-email-protocol','smtp'),('ssl-min-version','none'),('server-cert',{'name':'SYNTHETIC_CERT'}),
    ('email-folder','SYNTHETIC\nCANARY'),('server',float('nan')),
])
def test_material_extra_fields_or_unqualified_types_never_compile(field,value):
    values=state();values[field]=value
    with pytest.raises(ValueError) as error: prepare(values)
    assert 'SYNTHETIC' not in str(error.value) and 'example.test' not in str(error.value)


def test_missing_field_or_missing_emptiness_facts_never_compile():
    values=state();del values['user-id']
    with pytest.raises(ValueError): prepare(values)
    with pytest.raises(ValueError): prepare_empty_disabled_approval_delivery(state())


def test_public_boundary_is_value_free_and_does_not_promote_qualification():
    body=json.dumps(approval_delivery_request_boundary())
    assert 'SYNTHETIC' not in body and 'example.test' not in body
    for key in ('native_schema_or_ack_verified','singleton_partial_put_merge_qualified',
            'complete_baseline_or_material_preservation_verified','execution_authorized',
            'http_transport_registered','mcp_tool_registered','device_contacted'):
        assert approval_delivery_request_boundary()[key] is False


@pytest.mark.parametrize('field,limit',[
    ('email-pulling-server',255),('server',255),('server-cert',79),('email-folder',79),
    ('tenant-id',79),('app-id',79),('user-id',79),
])
def test_captured_child_schema_string_limits_are_enforced_even_for_cleared_server_fields(field,limit):
    values=state();values[field]='X'*limit
    prepare(values)
    values[field]+='X'
    with pytest.raises(ValueError): prepare(values)


def test_schema_metadata_binding_changes_private_digests_without_changing_wire(monkeypatch):
    first=prepare(state())
    assert first.schema_metadata_digest==module.SCHEMA_METADATA_SHA256
    monkeypatch.setattr(module,'SCHEMA_METADATA_SHA256','0'*64)
    second=prepare(state())
    assert first._encode()==second._encode()
    assert first.schema_metadata_digest!=second.schema_metadata_digest
    assert first.request_digest!=second.request_digest
    assert first.input_nonmaterial_digest!=second.input_nonmaterial_digest


@pytest.mark.parametrize('marker',['%0%','%1%'])
def test_native_empty_certificate_marker_normalizes_wire_but_preserves_original_input_binding(marker):
    values=state();values['server-cert']=marker;marked=prepare(values)
    values['server-cert']='';empty=prepare(values)
    assert marked._encode()==empty._encode()
    assert marked.request_digest==empty.request_digest
    assert marked.input_nonmaterial_digest!=empty.input_nonmaterial_digest
