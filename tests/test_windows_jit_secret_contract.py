"""Full supplied nonmaterial states and seven-field drafts, with synthetic C3."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp.secret_checkout_association_contract import CONTROLS, IDLE_FIELD
from fortipam_mcp.windows_jit_secret_contract import (WindowsJitSecretBinding, WindowsJitSecretPlan,
    project_windows_jit_secret)

SERIAL = 'SYNTHETIC_SERIAL'
SECRET = 'SYNTHETIC_MATERIAL_NEVER_DECODE_OR_HASH'


def binding(): return WindowsJitSecretBinding(17,9,'11111111-2222-4333-8444-555555555555',41,'01234567')


def fixture():
    bound = binding()
    row = {**bound.identity,'checkout':'disable','checkout-script':'','checkin-script':'','checkout-duration':60,
        'checkout-duration-renew':'disable','checkout-renew-times':3,'checkin-pwd-change':'disable',IDLE_FIELD:10,
        'associated-secret':41,'target-privilege-account':'disable','auto-association':'disable','proxy':'enable','recording':'enable',
        'field':[dict(id=1,name='Username',value=SECRET),dict(id=2,name='Password',value=SECRET),dict(id=3,name='Host',value=SECRET)],
        'totp-setting':{'status':'disable','shared-key':None,'digits':6},'target-info':{'priv_acct':0,'address':'synthetic-address'},
        'description':'','unrelated-option':'preserve-exactly','nested-extra':{'counter':3,'opaque':SECRET},
        'permissions':dict(checkout_status='none',passwd_change='allowed',other='preserve-exactly'),
        'q_ref':0,'q_static':False,'q_origin_key':17,'q_no_edit':False}
    def descriptor(value):
        if type(value) is str or value is None: return {'type':'string'}
        if type(value) is int: return {'type':'integer'}
        if type(value) is dict: return {'children':{name:descriptor(member) for name,member in value.items()}}
        if type(value) is list: return {'children':{name:descriptor(member) for name,member in value[0].items()}}
        raise ValueError
    fields = {name:descriptor(value) for name,value in row.items() if not name.startswith('q_')}
    fields['nested-extra']['children']['opaque'] = {'type':'password-2'}
    schema = dict(build=29,http_method='GET',http_status=200,name='database',path='secret',status='success',version='v7.0.0',
        serial=SERIAL,action='schema',results={'children':fields})
    return schema,row


def envelope(row):
    return dict(build=29,http_method='GET',http_status=200,name='database',path='secret',status='OK',version='v7.0.0',
        vdom='root',serial=SERIAL,mkey=17,results=row)


def project(schema,row, *, wrapper=None):
    raw = bytearray(json.dumps(wrapper if wrapper is not None else envelope(row)).encode())
    try: return project_windows_jit_secret(raw,schema,binding(),expected_serial=SERIAL)
    finally: assert not any(raw)


def test_all_credential_slots_totp_and_declared_nested_material_are_erased_before_decode_or_hash(monkeypatch):
    schema,row = fixture(); row['totp-setting']['shared-key'] = SECRET; decode = json.loads; digest = hashlib.sha256
    def checked_decode(raw,*args,**kwargs):
        assert SECRET.encode() not in (raw.encode() if isinstance(raw,str) else raw)
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert SECRET.encode() not in raw
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    state = project(schema,row); assert state.digest and SECRET.encode() not in state._encoded
    record = decode(state._encoded)
    assert all('value' not in slot for slot in record['field']) and 'shared-key' not in record['totp-setting']
    assert 'opaque' not in record['nested-extra'] and record['nested-extra']['counter'] == 3
    assert 'SYNTHETIC' not in repr(state) and '01234567' not in repr(state.binding)


def test_exact_seven_field_apply_and_restore_preserve_complete_supplied_nonmaterial_baseline():
    schema,row = fixture(); original = project(schema,row); plan = WindowsJitSecretPlan(original)
    patch = plan.compile_metadata_patch(original)
    assert set(patch) == CONTROLS and patch['checkout'] == 'enable' and patch['checkout-duration'] == 5
    assert patch['checkout-duration-renew'] == patch['checkin-pwd-change'] == 'disable'
    assert patch['checkout-renew-times'] == 3 and 'field' not in patch and 'target' not in patch
    applied_row = {**row,**patch,'permissions':{**row['permissions'],'checkout_status':'required','passwd_change':'forbidden'}}
    applied = project(schema,applied_row)
    assert applied.digest == plan.expected().digest
    reverse = plan.compile_metadata_patch(applied,restore=True)
    assert set(reverse) == CONTROLS and reverse == {name:row[name] for name in CONTROLS}
    assert project(schema,{**applied_row,**reverse,'permissions':row['permissions']}).digest == original.digest
    assert applied_row['associated-secret'] == 41 and applied_row[IDLE_FIELD] == 10


def test_credential_changes_are_not_nonmaterial_continuity_or_preservation_evidence():
    schema,row = fixture(); original = project(schema,row)
    for slot in row['field']: slot['value'] = 'SYNTHETIC_CHANGED_MATERIAL'
    row['totp-setting']['shared-key'] = 'SYNTHETIC_CHANGED_KEY'
    assert project(schema,row).digest == original.digest
    public = WindowsJitSecretPlan(original).preview()
    assert not public['material_preservation_qualified'] and not public['execution_authorized']
    assert not public['native_partial_put_qualified'] and public['metadata_patch_only']


@pytest.mark.parametrize('field,value', [('name','other'),('id',True),('folder',10),('template','Windows Domain Account'),
    ('target','other'),('uuid','22222222-2222-4333-8444-555555555555'),('q_ref',1),('q_ref',False),('q_static',True),
    ('q_no_edit',True),('q_origin_key','other'),('associated-secret',17),('associated-secret',True),
    ('target-privilege-account','enable'),('auto-association','enable'),('proxy','disable'),('recording','disable'),
    ('checkout-duration',True),('checkout-duration',2),('checkout-duration',1441),('checkout-renew-times',0),
    ('checkout-renew-times',6),('checkout-duration-renew','enable'),('checkin-pwd-change','enable'),(IDLE_FIELD,31)])
def test_unsafe_foreign_or_unqualified_profile_refuses(field,value):
    schema,row = fixture(); row[field] = value
    with pytest.raises(ValueError,match='unavailable'): project(schema,row)


@pytest.mark.parametrize('fault', ['missing-field','unknown-field','material-identity','missing-value','missing-totp',
    'material-object','duplicate-slot','slot-id','totp-enabled','privileged-target','schema-version','serial','row-version','error'])
def test_schema_complete_slot_framing_and_source_envelope_fail_closed(fault):
    schema,row = fixture(); wrapper = None
    if fault == 'missing-field': del row['unrelated-option']
    elif fault == 'unknown-field': row['undeclared'] = 'SYNTHETIC_UNCLASSIFIED'
    elif fault == 'material-identity': schema['results']['children']['template']['type'] = 'password-2'
    elif fault == 'missing-value': del row['field'][0]['value']
    elif fault == 'missing-totp': del row['totp-setting']['shared-key']
    elif fault == 'material-object': row['field'][1]['value'] = {'value':SECRET}
    elif fault == 'duplicate-slot': row['field'][1]['name'] = 'Username'
    elif fault == 'slot-id': row['field'][1]['id'] = True
    elif fault == 'totp-enabled': row['totp-setting']['status'] = 'enable'
    elif fault == 'privileged-target': row['target-info']['priv_acct'] = 99
    elif fault == 'schema-version': schema['build'] = True
    else:
        wrapper = envelope(row)
        if fault == 'serial': wrapper['serial'] = 'OTHER'
        elif fault == 'row-version': wrapper['version'] = 'v1.9.1'
        else: wrapper['error'] = -3
    with pytest.raises(ValueError,match='unavailable'): project(schema,row,wrapper=wrapper)


@pytest.mark.parametrize('field,value', [('unrelated-option','changed'),('description','changed'),(IDLE_FIELD,9),
    ('checkout-duration',61),('checkout-renew-times',4)])
def test_complete_nonmaterial_drift_rejects_apply_and_restore(field,value):
    schema,row = fixture(); original = project(schema,row); plan = WindowsJitSecretPlan(original)
    changed = {**row,field:value}
    with pytest.raises(ValueError,match='unavailable'): plan.compile_metadata_patch(project(schema,changed))
    applied = {**row,**plan.compile_metadata_patch(original),field:value,
        'permissions':{**row['permissions'],'checkout_status':'required','passwd_change':'forbidden'}}
    with pytest.raises(ValueError,match='unavailable'): plan.compile_metadata_patch(project(schema,applied),restore=True)


def test_readback_keeps_all_nested_nonmaterial_fields_and_rejects_binding_or_schema_drift():
    schema,row = fixture(); original = project(schema,row); plan = WindowsJitSecretPlan(original)
    row['nested-extra']['counter'] = 4
    with pytest.raises(ValueError,match='unavailable'): plan.compile_metadata_patch(project(schema,row))
    foreign = replace(original,binding=replace(binding(),folder_id=10))
    with pytest.raises(ValueError,match='unavailable'): plan.compile_metadata_patch(foreign)
    schema['results']['children']['description']['type'] = 'var-string'
    with pytest.raises(ValueError,match='unavailable'): plan.compile_metadata_patch(project(schema,row))


def test_matching_unowned_applied_configuration_cannot_be_adopted_as_a_new_plan():
    schema,row = fixture(); plan = WindowsJitSecretPlan(project(schema,row))
    applied = project(schema,{**row,**plan.compile_metadata_patch(plan.baseline),
        'permissions':{**row['permissions'],'checkout_status':'required','passwd_change':'forbidden'}})
    with pytest.raises(ValueError,match='unavailable'): WindowsJitSecretPlan(applied)


def test_preview_exposes_only_configuration_intent_and_real_effect_gaps():
    schema,row = fixture(); public = WindowsJitSecretPlan(project(schema,row)).preview(); text = json.dumps(public)
    for value in (binding().secret_uuid,binding().nonce,binding().identity['target'],SECRET,'$USER'): assert value not in text
    assert not public['configuration_ready'] and not public['execution_authorized']
    assert not public['associated_admin_qualified'] and not public['original_subject_custody_verified']
    assert not public['complete_activity_scope_verified'] and not public['independent_recovery_verified']
    assert not public['Security Changes']['checkout_duration_bounds_os_logon_privilege']


@pytest.mark.parametrize('checkout,status,password', [('disable','required','allowed'),('disable','none','forbidden'),
    ('enable','none','allowed'),('enable','required','allowed'),('enable','checked-out','forbidden')])
def test_checkout_derived_permissions_require_exact_native_inversion(checkout,status,password):
    schema,row = fixture(); row['checkout'] = checkout
    row['permissions'].update(checkout_status=status,passwd_change=password)
    with pytest.raises(ValueError,match='unavailable'): project(schema,row)


def test_only_two_derived_permission_changes_are_expected_and_none_are_sent():
    schema,row = fixture(); plan = WindowsJitSecretPlan(project(schema,row))
    patch = plan.compile_metadata_patch(plan.baseline)
    assert 'permissions' not in patch
    applied = json.loads(plan.expected()._encoded)
    assert applied['permissions'] == dict(checkout_status='required',passwd_change='forbidden',other='preserve-exactly')
    changed = deepcopy(row); changed.update(patch); changed['permissions'] = {**applied['permissions'],'other':'changed'}
    with pytest.raises(ValueError,match='unavailable'): plan.compile_metadata_patch(project(schema,changed),restore=True)
    del schema['results']['children']['permissions']
    with pytest.raises(ValueError,match='unavailable'): project(schema,row)
