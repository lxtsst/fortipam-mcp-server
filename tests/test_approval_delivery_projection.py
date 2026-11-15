"""Only synthetic current-response fixtures; no product or current-value GET."""
import copy
import json
import pickle

import pytest

import fortipam_mcp.approval_delivery_projection as module
from test_approval_delivery_contract import state,prepare
from v4_planning.material_provider import MaterialAccessDenied

CANARY='UNSELECTED_SYNTHETIC_CURRENT_CANARY'
SERIAL='SYNTHETIC01'


def response(protocol='imaps'):
    values=state(protocol)
    return dict(version='v7.0.0',build=29,http_method='GET',http_status=200,path='secret',name='setting',
        serial=SERIAL,status='success',revision=CANARY,results={
            'approval-email-setting':{**values,'username':'','credential':'','client-secret':''},
            'unselected-setting':dict(password=CANARY,private_identity=CANARY)})


def encoded(value): return bytearray(json.dumps(value,separators=(',',':')).encode())


@pytest.mark.parametrize('protocol',['imaps','ms-graph'])
def test_selected_wire_empty_projection_matches_codec_but_does_not_certify_material(protocol,monkeypatch):
    raw=encoded(response(protocol));decode=json.loads;seen=[]
    def safe(value,*args,**kwargs):
        assert CANARY not in str(value);seen.append(True);return decode(value,*args,**kwargs)
    monkeypatch.setattr(json,'loads',safe)
    result=module.project_wire_empty_approval_delivery(raw,expected_serial=SERIAL)
    assert result._draft._encode()==prepare(state(protocol))._encode()
    assert not any(raw) and seen
    summary=result.summary()
    assert summary['ui_enabled_inference'] is True and summary['wire_empty_protected_slot_count']==3
    assert summary['material_empty_state_proved'] is False
    assert summary['native_masking_or_material_continuity_qualified'] is False
    assert CANARY not in repr(summary) and 'example.test' not in repr(summary) and SERIAL not in repr(summary)
    for operation in (copy.copy,copy.deepcopy,pickle.dumps):
        with pytest.raises(MaterialAccessDenied): operation(result)


@pytest.mark.parametrize('field',['username','credential','client-secret'])
@pytest.mark.parametrize('value',[CANARY,None,'********'])
def test_nonempty_null_or_masked_material_refuses_before_any_current_decode(monkeypatch,field,value):
    data=response();data['results']['approval-email-setting'][field]=value;raw=encoded(data)
    monkeypatch.setattr(json,'loads',lambda *_args,**_kwargs:pytest.fail('Protected slots must be checked before decoding.'))
    with pytest.raises(ValueError) as error: module.project_wire_empty_approval_delivery(raw,expected_serial=SERIAL)
    assert not any(raw) and CANARY not in str(error.value)


@pytest.mark.parametrize('change',['missing-material','extra-field','nested-nonmaterial','overlong','boolean-port'])
def test_unknown_or_incomplete_subtree_never_produces_a_draft(change):
    data=response();setting=data['results']['approval-email-setting']
    if change=='missing-material': del setting['credential']
    elif change=='extra-field': setting[CANARY]=dict(secret=CANARY)
    elif change=='nested-nonmaterial': setting['email-folder']=dict(secret=CANARY)
    elif change=='overlong': setting['email-folder']='X'*80
    else: setting['port']=True
    raw=encoded(data)
    with pytest.raises(ValueError) as error: module.project_wire_empty_approval_delivery(raw,expected_serial=SERIAL)
    assert not any(raw) and CANARY not in str(error.value)


@pytest.mark.parametrize('field,value',[('action','schema'),('serial','SYNTHETIC02'),('build',True),
    ('path','system'),('name','email-server'),('status',CANARY),('error',-3)])
def test_wrong_envelope_or_schema_response_is_not_current_state(field,value):
    data=response();data[field]=value;raw=encoded(data)
    with pytest.raises(ValueError) as error: module.project_wire_empty_approval_delivery(raw,expected_serial=SERIAL)
    assert not any(raw) and CANARY not in str(error.value)


def test_unrelated_settings_and_revision_cannot_change_selected_digests():
    first=response();second=response();second['revision']='DIFFERENT'
    second['results']['unselected-setting']=dict(password='DIFFERENT',other=['DIFFERENT'])
    one=module.project_wire_empty_approval_delivery(encoded(first),expected_serial=SERIAL)
    two=module.project_wire_empty_approval_delivery(encoded(second),expected_serial=SERIAL)
    assert one._draft.input_nonmaterial_digest==two._draft.input_nonmaterial_digest
    assert one._draft.request_digest==two._draft.request_digest
    assert one.summary()['whole_setting_baseline_verified'] is False


@pytest.mark.parametrize('protocol',['imaps','ms-graph'])
@pytest.mark.parametrize('server_present',[False,True])
@pytest.mark.parametrize('pulling_present',[False,True])
def test_ui_enabled_inference_uses_only_the_native_protocol_server_rule(protocol,server_present,pulling_present):
    data=response(protocol);setting=data['results']['approval-email-setting']
    setting['server']='example.test' if server_present else ''
    setting['email-pulling-server']='imap.example.test' if pulling_present else ''
    result=module.project_wire_empty_approval_delivery(encoded(data),expected_serial=SERIAL)
    expected=server_present if protocol=='ms-graph' else server_present or pulling_present
    assert result.summary()['ui_enabled_inference'] is expected


@pytest.mark.parametrize('marker',['%0%','%1%'])
def test_wire_empty_projection_normalizes_scalar_certificate_markers_and_keeps_input_binding(marker):
    data=response();data['results']['approval-email-setting']['server-cert']=marker
    marked=module.project_wire_empty_approval_delivery(encoded(data),expected_serial=SERIAL)
    data['results']['approval-email-setting']['server-cert']=''
    empty=module.project_wire_empty_approval_delivery(encoded(data),expected_serial=SERIAL)
    assert marked._draft.request_digest==empty._draft.request_digest
    assert marked._draft.input_nonmaterial_digest!=empty._draft.input_nonmaterial_digest


@pytest.mark.parametrize('failure',[KeyboardInterrupt,SystemExit])
def test_control_interrupt_during_selected_decode_clears_input(monkeypatch,failure):
    raw=encoded(response())
    def interrupted(*_args,**_kwargs): raise failure()
    monkeypatch.setattr(module.metadata,'_scalar',interrupted)
    with pytest.raises(failure): module.project_wire_empty_approval_delivery(raw,expected_serial=SERIAL)
    assert not any(raw)
