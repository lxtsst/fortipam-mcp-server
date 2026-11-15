"""Synthetic schemas containing unknown/default canaries, never real product data."""
import json

import pytest

import fortipam_mcp.approval_delivery_schema as module
from fortipam_mcp.approval_delivery_contract import _FIELDS

CANARY='UNSELECTED_SYNTHETIC_SCHEMA_CANARY'


def schema():
    fields={name:dict(type='string',default=CANARY,help=CANARY) for name in _FIELDS}
    fields['credential']['type']=fields['client-secret']['type']='password-2'
    fields['port'].update(type='integer',**{'min-value':1,'max-value':65535})
    fields['check-interval'].update(type='integer',**{'min-value':1,'max-value':1440})
    fields['approval-email-protocol'].update(type='option',options=[dict(name=x,help=CANARY) for x in ('imaps','ms-graph')])
    fields['ssl-min-version'].update(type='option',options=[dict(name=x) for x in ('tls-1.1','tls-1.2','tls-1.3')])
    return dict(version='v7.0.0',build=29,http_method='GET',http_status=200,path='secret',name='setting',
        action='schema',status='success',serial=CANARY,revision=CANARY,
        results=dict(children={'approval-email-setting':dict(type='table',children=fields),CANARY:dict(default=CANARY)}))


def encoded(value): return bytearray(json.dumps(value,separators=(',',':')).encode())


def test_only_compiled_metadata_survives_without_json_decoding_or_defaults(tmp_path,monkeypatch):
    raw=encoded(schema())
    monkeypatch.setattr(json,'loads',lambda *_args,**_kwargs:pytest.fail('Raw schema must never reach a JSON decoder.'))
    result=module.consume_approval_delivery_schema(raw)
    assert not any(raw) and CANARY not in repr(result)
    assert result['selected_field_count']==14 and result['unclassified_child_count']==0
    fields=result['fields']
    assert fields['credential']['protected_slot'] is True and fields['credential']['type']=='password-2'
    assert fields['port']['max-value']==65535
    assert fields['approval-email-protocol']['recognized_options']==['imaps','ms-graph']
    assert result['configuration_or_material_read'] is False
    assert result['full_action_contract_qualified'] is False


def test_defaults_private_envelope_and_unrelated_schema_cannot_change_projection():
    first=schema();second=schema();second['serial']='OTHER_CANARY';second['revision']='OTHER_CANARY'
    for descriptor in second['results']['children']['approval-email-setting']['children'].values():
        descriptor['default']={'deep':['OTHER_CANARY']};descriptor['help']='OTHER_CANARY'
    second['results']['children'][CANARY]['default']='OTHER_CANARY'
    assert module.consume_approval_delivery_schema(encoded(first))==module.consume_approval_delivery_schema(encoded(second))


def test_unknown_type_option_and_child_values_are_counted_without_decoding():
    value=schema();fields=value['results']['children']['approval-email-setting']['children']
    fields['user-id']['type']=CANARY
    fields['approval-email-protocol']['options'].append(dict(name=CANARY,default=CANARY))
    fields[CANARY]=dict(type=CANARY,default=CANARY)
    result=module.consume_approval_delivery_schema(encoded(value))
    assert result['unclassified_child_count']==1 and CANARY not in repr(result)
    assert result['fields']['user-id']['type'] is None
    assert result['fields']['approval-email-protocol']['unclassified_option_count']==1


@pytest.mark.parametrize('field,value',[('action',''),('build',True),('http_status',201),('path','system'),
    ('name','email-server'),('version','v1.9.1'),('status',CANARY)])
def test_wrong_or_configuration_envelope_refuses_and_clears(field,value):
    data=schema();data[field]=value;raw=encoded(data)
    with pytest.raises(ValueError) as error: module.consume_approval_delivery_schema(raw)
    assert not any(raw) and CANARY not in str(error.value)


@pytest.mark.parametrize('constraint',[True,1.5,CANARY,2**64])
def test_unqualified_constraint_values_refuse_before_decoding(constraint):
    value=schema();value['results']['children']['approval-email-setting']['children']['port']['max-value']=constraint
    raw=encoded(value)
    with pytest.raises(ValueError): module.consume_approval_delivery_schema(raw)
    assert not any(raw)


def test_missing_feature_or_extra_field_reports_incompleteness_without_guessing():
    value=schema();del value['results']['children']['approval-email-setting']
    result=module.consume_approval_delivery_schema(encoded(value))
    assert result['approval_setting_present'] is False and result['selected_field_count']==0
    value=schema();del value['results']['children']['approval-email-setting']['children']['client-secret']
    assert module.consume_approval_delivery_schema(encoded(value))['selected_field_count']==13


@pytest.mark.parametrize('failure',[KeyboardInterrupt,SystemExit])
def test_control_interrupt_clears_schema_and_propagates(monkeypatch,failure):
    raw=encoded(schema())
    def interrupted(*_args,**_kwargs): raise failure()
    monkeypatch.setattr(module,'_members',interrupted)
    with pytest.raises(failure): module.consume_approval_delivery_schema(raw)
    assert not any(raw)


def test_duplicate_selected_fields_and_trailing_payload_refuse():
    raw=encoded(schema());raw[1:1]=b'"build":29,'
    with pytest.raises(ValueError): module.consume_approval_delivery_schema(raw)
    assert not any(raw)
    raw=encoded(schema());raw.extend(b' '+CANARY.encode())
    with pytest.raises(ValueError): module.consume_approval_delivery_schema(raw)
    assert not any(raw)
