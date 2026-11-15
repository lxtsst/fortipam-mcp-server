"""Synthetic MFA selectors only; no device, notification or real enrollment."""
from copy import copy, deepcopy
import json
import pickle

import pytest

from fortipam_mcp.fortitoken_user_contract import (FortitokenUserBinding, FortitokenUserContractError,
    FortitokenUserPlan, project_fortitoken_user, build_fortitoken_user_body)
from fortipam_mcp.local_user_reset_fixture_create import _FIELDS
from test_local_user_reset_fixture_create import _defaults
from test_local_user_reset_projection import _body
from v4_planning.material_provider import MaterialAccessDenied

NAME = 'mcp-v4-user-ftk-01234567'
SERIAL = 'SYNTHETIC_SERIAL'
TOKEN = b'SYNTHETIC_TOKEN_ALPHA'


def binding(): return FortitokenUserBinding(NAME,7,'a'*64,'b'*64)


def fixture(operation='assign'):
    schema,row = _defaults(); schema['serial'] = SERIAL
    row.update(id=7,name=NAME,status='disable',accprofile='pam_standard_user',**{'guest-lang':'en',
        'two-factor':'disable' if operation == 'assign' else 'fortitoken',
        'two-factor-authentication':'fortitoken', 'two-factor-notification':'email',
        'fortitoken':'' if operation == 'assign' else TOKEN.decode('ascii')})
    schema['results']['children']['two-factor-authentication'] = {'type':'option'}
    row.update(q_ref=0,q_origin_key=NAME,q_static=False,q_global_entry=False,q_mkey_type='string',
        q_name='admin',q_no_edit=False,q_no_rename=False,q_path='system',q_type=1)
    row['webauthn'].update({'user-handle':'','credential-id':'','public-key':'','transports':'','algorithm':0})
    return schema,row


def project(schema,row,**overrides):
    raw = _body(row,serial=SERIAL,vdom='root',**overrides)
    value = project_fortitoken_user(raw,schema,binding(),expected_serial=SERIAL)
    assert not any(raw)
    return value


def encode(plan,schema,row,**kwargs):
    raw = _body(row,serial=SERIAL,vdom='root'); material = bytearray(TOKEN)
    try:
        with memoryview(material).toreadonly() as token:
            return build_fortitoken_user_body(plan,raw,schema,expected_serial=SERIAL,
                token_reference_digest=kwargs.pop('token_reference_digest','a'*64),token=kwargs.pop('token',token),**kwargs)
    finally:
        assert not any(raw); material[:] = b'\0'*len(material)


@pytest.mark.parametrize('operation', ['assign','revoke'])
def test_native_existing_user_body_preserves_submitted_configuration_and_omits_password_and_activation(operation):
    schema,row = fixture(operation); state = project(schema,row); plan = FortitokenUserPlan(state,operation)
    body = encode(plan,schema,row)
    try:
        value = json.loads(body)
        assert set(value) == (_FIELDS | {'webauthn','$originalName'} |
            ({'two-factor-authentication'} if operation == 'assign' else set()))
        assert value['id'] == 7 and value['$originalName'] == NAME and value['status'] == 'disable'
        assert value['fortitoken'] == (TOKEN.decode('ascii') if operation == 'assign' else '')
        assert value['two-factor'] == ('fortitoken' if operation == 'assign' else 'disable')
        for name in _FIELDS-{'two-factor','fortitoken'}: assert value[name] == row[name]
        assert value['webauthn'] == {'status':'disable'}
        assert not {'password','history0','shared-key','is-send-activation-code','force-saml-login'} & value.keys()
        preview = plan.preview()
        assert preview['Security Changes']['mfa_requirement_removed'] is (operation == 'revoke')
        for key in ('complete_postcondition_qualified','token_ownership_verified','role_entitlement_verified',
            'independent_recovery_verified','native_backend_qualified','configuration_write_authorized',
            'activation_delivery_verified','mfa_login_verified'): assert preview[key] is False
        assert NAME not in json.dumps(preview) and 'a'*64 not in json.dumps(preview)
    finally: body[:] = b'\0'*len(body)


def test_token_password_history_and_nested_material_are_not_decoded_or_in_state_hash(monkeypatch):
    schema,row = fixture('revoke'); original = json.loads
    row.update(password='NEVER_DECODE_PASSWORD',history0='NEVER_DECODE_HISTORY',**{'shared-key':'NEVER_DECODE_SHARED'})
    row['webauthn']['synthetic-material'] = 'NEVER_DECODE_NESTED'
    def decode(raw,*args,**kwargs):
        if isinstance(raw,(bytes,bytearray,str)):
            text = raw if isinstance(raw,str) else raw.decode('ascii')
            assert 'NEVER_DECODE' not in text and TOKEN.decode('ascii') not in text
        return original(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',decode)
    state = project(schema,row); plan = FortitokenUserPlan(state,'revoke')
    row['fortitoken'] = 'SYNTHETIC_TOKEN_BETA'
    assert project(schema,row).digest == state.digest
    with pytest.raises(FortitokenUserContractError): encode(plan,schema,row)
    row['fortitoken'] = TOKEN.decode('ascii')
    body = encode(plan,schema,row)
    assert original(body)['fortitoken'] == ''
    body[:] = b'\0'*len(body)
    assert TOKEN not in state._encoded and 'NEVER_DECODE' not in state._encoded.decode('ascii')


@pytest.mark.parametrize('field,value', [('status','enable'),('accprofile','super_admin'),('id',True),('name','admin'),
    ('q_ref',1),('q_ref',False),('q_type',2),('q_no_edit',True),('q_static',True),('q_global_entry',True),
    ('q_origin_key','other'),('remote-auth','enable'),('wildcard','enable'),('guest-auth','enable'),
    ('cert-auth','enable'),('force-saml-login','enable'),('remote-server','other'),('schedule','other'),
    ('sponsor-group','other'),('auto-created-user','yes'),('vdom',[{'name':'root'}]),('two-factor','email'),
    ('two-factor','fortitoken-cloud')])
def test_active_privileged_external_referenced_or_unqualified_user_is_rejected(field, value):
    schema,row = fixture(); row[field] = value; raw = _body(row,serial=SERIAL,vdom='root')
    with pytest.raises(FortitokenUserContractError): project_fortitoken_user(raw,schema,binding(),expected_serial=SERIAL)
    assert not any(raw)


@pytest.mark.parametrize('fault', ['missing-field','unknown-field','material-descriptor','missing-token',
    'foreign-schema','foreign-serial','foreign-version','webauthn','root-error','root-extra','duplicate-json'])
def test_incomplete_foreign_or_unclassified_source_is_cleared_and_refused(fault):
    schema,row = fixture(); overrides = {}
    if fault == 'missing-field': row.pop('comments')
    elif fault == 'unknown-field': row['synthetic-unknown'] = 'NEVER_DECODE_UNKNOWN'
    elif fault == 'material-descriptor': schema['results']['children']['comments']['type'] = 'password-2'
    elif fault == 'missing-token': row.pop('fortitoken')
    elif fault == 'foreign-schema': schema['serial'] = 'OTHER'
    elif fault == 'foreign-serial': overrides['serial'] = 'OTHER'
    elif fault == 'foreign-version': overrides['build'] = 30
    elif fault == 'webauthn': row['webauthn']['status'] = 'enable'
    elif fault == 'root-error': overrides['error'] = -3
    elif fault == 'root-extra': overrides['unknown'] = 'NEVER_DECODE_UNKNOWN'
    raw = _body(row,**{'serial':SERIAL,'vdom':'root',**overrides})
    if fault == 'duplicate-json': raw = raw.replace(b'"id":7',b'"id":7,"id":7')
    with pytest.raises(FortitokenUserContractError): project_fortitoken_user(raw,schema,binding(),expected_serial=SERIAL)
    assert not any(raw)


@pytest.mark.parametrize('field,value', [('comments','changed'),('email-to','changed'),('two-factor-notification','sms'),
    ('trusthost1','192.0.2.1 255.255.255.255'),('gui-custom-conf','enable')])
def test_complete_nonmaterial_drift_blocks_body_compilation(field,value):
    schema,row = fixture(); plan = FortitokenUserPlan(project(schema,row),'assign'); row[field] = value
    with pytest.raises(FortitokenUserContractError): encode(plan,schema,row)


def test_wrong_material_reference_and_token_views_do_not_compile():
    schema,row = fixture(); plan = FortitokenUserPlan(project(schema,row),'assign')
    with pytest.raises(FortitokenUserContractError): encode(plan,schema,row,token_reference_digest='c'*64)
    for value in (b'NOT_A_VIEW',memoryview(b''),memoryview(b'X\nY'),memoryview(b'X'*129)):
        with pytest.raises(FortitokenUserContractError): encode(plan,schema,row,token=value)


@pytest.mark.parametrize('operation', ['assign','revoke'])
def test_inconsistent_or_already_applied_transition_is_not_a_new_plan(operation):
    schema,row = fixture(operation); state = project(schema,row)
    with pytest.raises(ValueError): FortitokenUserPlan(state,'revoke' if operation == 'assign' else 'assign')


def test_private_objects_are_opaque_and_schema_default_material_does_not_enter_hash():
    schema,row = fixture(); first = project(schema,row)
    schema['results']['children']['comments']['default'] = 'NEVER_HASH_DEFAULT_MATERIAL'
    assert project(schema,row).digest == first.digest
    for value in (binding(),first,FortitokenUserPlan(first,'assign')):
        assert NAME not in repr(value) and TOKEN.decode('ascii') not in repr(value)
        for transform in (copy,deepcopy,pickle.dumps):
            with pytest.raises(MaterialAccessDenied): transform(value)


def test_partial_private_encoding_failure_clears_owned_body_and_source_without_consuming_callers_lease(monkeypatch):
    from fortipam_mcp import fortitoken_user_contract as native
    schema,row = fixture(); plan = FortitokenUserPlan(project(schema,row),'assign')
    captured = []
    def interrupted(body, token):
        body.extend(token); captured.append(body._storage)
        raise RuntimeError('SYNTHETIC_PRIVATE_ENCODING_FAILURE')
    monkeypatch.setattr(native,'_append_material',interrupted)
    raw = _body(row,serial=SERIAL,vdom='root'); material = bytearray(TOKEN)
    try:
        with memoryview(material).toreadonly() as token:
            with pytest.raises(FortitokenUserContractError):
                build_fortitoken_user_body(plan,raw,schema,expected_serial=SERIAL,token_reference_digest='a'*64,token=token)
        assert not any(raw) and captured and all(not any(value) for value in captured)
        assert material == TOKEN
    finally: material[:] = b'\0'*len(material)
