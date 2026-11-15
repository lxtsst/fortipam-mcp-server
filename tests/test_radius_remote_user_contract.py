"""Disabled direct-RADIUS User source draft; no runtime, material or network."""
from __future__ import annotations

import json
import pickle
from typing import Any

import pytest

from fortipam_mcp.radius_remote_user_contract import RadiusRemoteUserBinding, RadiusRemoteUserError, prepare_radius_remote_user_create
from test_radius_server_pair_contract import binding as pair_binding
from test_local_user_reset_fixture_create import _defaults
from test_local_user_reset_projection import _body

SERIAL='SYNTHETIC_SERIAL'

def binding() -> RadiusRemoteUserBinding:
    return RadiusRemoteUserBinding('mcp-v4-radius-user-01234567',pair_binding(),'c'*64)

def fixture() -> tuple[dict[str,Any],dict[str,Any]]:
    schema,row=_defaults();schema['serial']=SERIAL
    return schema,row

def prepare(schema: Any,row: Any,b: Any=None,**kwargs: Any) -> Any:
    raw=_body(row,action='default',serial=SERIAL)
    try:return prepare_radius_remote_user_create(raw,schema,binding()if b is None else b,expected_serial=kwargs.get('serial',SERIAL))
    finally:assert not raw

def test_direct_radius_body_is_disabled_standard_nonwildcard_and_opaque(monkeypatch: pytest.MonkeyPatch) -> None:
    schema,row=fixture();row['password']='NEVER_DECODE_DEFAULT_PASSWORD';row['history0']='NEVER_DECODE_HISTORY';row['shared-key']='NEVER_DECODE_SHARED'
    row['guest-lang']='GB2312'
    loads=json.loads
    def decode(value: Any,*a: Any,**k: Any) -> Any:
        if isinstance(value,(bytes,bytearray,str)):assert 'NEVER_DECODE'not in str(value)
        return loads(value,*a,**k)
    monkeypatch.setattr(json,'loads',decode)
    draft=prepare(schema,row);body=loads(draft._wire)
    assert body['name']==draft.binding.username and body['remote-server']==draft.binding.radius.name
    assert body['remote-auth']=='enable'and body['remote-group']==''and body['status']=='disable'
    assert body['accprofile']=='pam_standard_user'and body['wildcard']=='disable'and body['password']==''
    assert body['guest-lang']=='en'
    assert body['vdom']==[]and body['webauthn']=={'status':'disable'}and body['two-factor']=='disable'
    assert not any(k.startswith('history')or k in('shared-key','type','role','remote-option')for k in body)
    assert draft.binding.username not in repr(draft)and draft.binding.radius.name not in repr(draft)
    with pytest.raises(Exception):pickle.dumps(draft)

@pytest.mark.parametrize('field,value',[('id',True),('id',1),('name','existing'),('remote-auth','enable'),('remote-server','foreign'),
    ('remote-group','foreign'),('wildcard','enable'),('two-factor','email'),('guest-auth','enable'),('cert-auth','enable'),
    ('sponsor-group','foreign'),('schedule','foreign'),('email-to','foreign'),('auto-created-user','yes'),('force-saml-login','enable')])
def test_existing_identity_or_relation_defaults_are_not_new_user_input(field: str,value: Any) -> None:
    schema,row=fixture();row[field]=value
    with pytest.raises(RadiusRemoteUserError):prepare(schema,row)

@pytest.mark.parametrize('fault',['schema_serial','default_serial','schema_version','missing_field','material_descriptor','webauthn','password_type','scope'])
def test_foreign_incomplete_or_protected_source_fails_closed(fault: str) -> None:
    schema,row=fixture()
    if fault=='schema_serial':schema['serial']='FOREIGN'
    elif fault=='default_serial':
        raw=_body(row,action='default',serial='FOREIGN')
        with pytest.raises(RadiusRemoteUserError):prepare_radius_remote_user_create(raw,schema,binding(),expected_serial=SERIAL)
        assert not raw
        return
    elif fault=='schema_version':schema['build']=30
    elif fault=='missing_field':row.pop('remote-server')
    elif fault=='material_descriptor':schema['results']['children']['comments']['type']='password-2'
    elif fault=='webauthn':row['webauthn']['status']='enable'
    elif fault=='password_type':row['password']=7
    else:
        raw=_body(row,action='default',serial=SERIAL,vdom=[])
        with pytest.raises(RadiusRemoteUserError):prepare_radius_remote_user_create(raw,schema,binding(),expected_serial=SERIAL)
        assert not raw
        return
    with pytest.raises(RadiusRemoteUserError):prepare(schema,row)

@pytest.mark.parametrize('field,value',[('username','admin'),('username','mcp-v4-radius-user-01234567\n'),('private_nonce','invalid'),('radius','arbitrary-name')])
def test_private_binding_cannot_select_an_unbound_server_or_username(field: str,value: Any) -> None:
    args={'username':'mcp-v4-radius-user-01234567','radius':pair_binding(),'private_nonce':'c'*64};args[field]=value
    with pytest.raises(RadiusRemoteUserError):RadiusRemoteUserBinding(**args)


def test_source_digest_excludes_default_material_but_binds_selected_defaults() -> None:
    schema,row=fixture();one=prepare(schema,row)
    row['password']='different-synthetic-password';row['history0']='different-synthetic-history'
    two=prepare(schema,row);assert one.source_defaults_digest==two.source_defaults_digest and one.request_digest==two.request_digest
    row['comments']='changed-synthetic-comment';three=prepare(schema,row)
    assert three.source_defaults_digest!=one.source_defaults_digest and three.request_digest!=one.request_digest


@pytest.mark.parametrize('fault',[None,'status','server','group','profile','reference','id','missing','foreign','rebound_serial','opaque','metadata','forced_saml','schema_drift','vdom_bound','vdom_plain','vdom_foreign','vdom_multiple'])
def test_complete_disabled_remote_user_readback_and_excluded_material(fault: str | None,monkeypatch: pytest.MonkeyPatch) -> None:
    from fortipam_mcp.radius_remote_user_contract import qualify_radius_remote_user_detail
    schema,defaults=fixture();draft=prepare(schema,defaults);row={**defaults,**json.loads(draft._wire),'id':19,'q_ref':0}
    from fortipam_mcp.local_user_reset_projection import _WEBAUTHN_EXTRA_FIELDS
    row['webauthn']={**defaults['webauthn'],**{k:0 if v['type']=='integer'else ''for k,v in _WEBAUTHN_EXTRA_FIELDS.items()}}
    row['password']='NEVER_DECODE_STORED_PASSWORD';row['history0']='NEVER_DECODE_HISTORY'
    if fault=='rebound_serial':schema['serial']='FOREIGN'
    elif fault=='schema_drift':schema['results']['children']['comments']['type']='option'
    elif fault in('vdom_bound','vdom_plain','vdom_foreign','vdom_multiple'):
        scope=draft._response_vdom if fault!='vdom_foreign'else 'foreign'
        row['vdom']=[{'name':scope,'q_origin_key':scope}]
        if fault=='vdom_plain':row['vdom'][0].pop('q_origin_key')
        if fault=='vdom_multiple':row['vdom']*=2
    elif fault=='forced_saml':row['force-saml-login']='enable'
    elif fault=='status':row['status']='enable'
    elif fault=='server':row['remote-server']='foreign'
    elif fault=='group':row['remote-group']='foreign'
    elif fault=='profile':row['accprofile']='super_admin'
    elif fault=='reference':row['q_ref']=1
    elif fault=='id':row['id']=True
    elif fault=='missing':row.pop('force-saml-login')
    elif fault=='opaque':row['webauthn']['synthetic-material']='NEVER_DECODE_NESTED'
    elif fault=='metadata':row['q_no_edit']='NEVER_DECODE_METADATA'
    loads=json.loads
    def decode(value: Any,*a: Any,**k: Any) -> Any:
        if isinstance(value,(bytes,bytearray,str)):assert 'NEVER_DECODE'not in str(value)
        return loads(value,*a,**k)
    monkeypatch.setattr(json,'loads',decode)
    raw=_body(row,mkey=draft.binding.username,serial='FOREIGN'if fault in('foreign','rebound_serial')else SERIAL)
    if fault in(None,'opaque','vdom_bound'):
        state=qualify_radius_remote_user_detail(raw,schema,draft,expected_serial=SERIAL)
        assert state.assigned_id==19 and state.reported_reference_count==0 and len(state.nonmaterial_state_digest)==64
    else:
        with pytest.raises(RadiusRemoteUserError):qualify_radius_remote_user_detail(raw,schema,draft,expected_serial='FOREIGN'if fault=='rebound_serial'else SERIAL)
    assert not raw


@pytest.mark.parametrize('references', [0, 1, 2**31 - 1, -1, True, 2**31])
def test_readonly_reference_projection_does_not_relax_creation_or_removal(references: Any) -> None:
    from fortipam_mcp.radius_remote_user_contract import project_radius_remote_user_detail, qualify_radius_remote_user_detail
    from fortipam_mcp.local_user_reset_projection import _WEBAUTHN_EXTRA_FIELDS
    schema,defaults=fixture();draft=prepare(schema,defaults)
    row={**defaults,**json.loads(draft._wire),'id':19,'q_ref':references,
        'password':'NEVER_DECODE_STORED_PASSWORD','history0':'NEVER_DECODE_HISTORY'}
    row['webauthn']={**defaults['webauthn'],**{k:0 if v['type']=='integer'else ''for k,v in _WEBAUTHN_EXTRA_FIELDS.items()}}
    def content() -> bytearray:return _body(row,mkey=draft.binding.username,serial=SERIAL)
    raw=content()
    if type(references)is int and 0<=references<=2**31-1:
        observed=project_radius_remote_user_detail(raw,schema,draft,expected_serial=SERIAL)
        assert observed.reported_reference_count==references
    else:
        with pytest.raises(RadiusRemoteUserError):project_radius_remote_user_detail(raw,schema,draft,expected_serial=SERIAL)
    assert not raw
    raw=content()
    if type(references)is int and references==0:
        assert qualify_radius_remote_user_detail(raw,schema,draft,expected_serial=SERIAL).reported_reference_count==0
    else:
        with pytest.raises(RadiusRemoteUserError):qualify_radius_remote_user_detail(raw,schema,draft,expected_serial=SERIAL)
    assert not raw


@pytest.mark.parametrize('cursor', [0, 15, 16, True])
def test_name_absence_uses_build29_complete_collection_last_row_cursor(cursor: int) -> None:
    from fortipam_mcp.radius_remote_user_contract import qualify_radius_remote_user_absence
    rows = [{'name': f'synthetic-unrelated-user-{index}'} for index in range(16)]
    values = dict(build=29, version='v7.0.0', serial=SERIAL, path='system', name='admin',
        vdom='synthetic-scope', http_method='GET', http_status=200, status='success',
        results=rows, matched_count=16, size=16, next_idx=cursor)
    raw = bytearray(json.dumps(values).encode())
    if type(cursor) is int and cursor == 15:
        qualify_radius_remote_user_absence(raw, binding(), expected_serial=SERIAL,
            expected_vdom='synthetic-scope', http_status=200, collection=True)
    else:
        with pytest.raises(RadiusRemoteUserError):
            qualify_radius_remote_user_absence(raw, binding(), expected_serial=SERIAL,
                expected_vdom='synthetic-scope', http_status=200, collection=True)
    assert not raw


@pytest.mark.parametrize('fault', [None, 'serial', 'scope', 'method', 'status', 'http', 'mkey',
    'missing_mkey', 'results', 'revision', 'unchanged', 'unknown', 'trailing', 'duplicate'])
def test_mutation_ack_has_exact_identity_and_never_adopts_arbitrary_results(fault: str | None) -> None:
    from fortipam_mcp.radius_remote_user_contract import qualify_radius_remote_user_ack
    values = dict(build=29, version='v7.0.0', serial=SERIAL, path='system', name='admin',
        vdom='synthetic-scope', http_method='POST', http_status=200, status='success', mkey=binding().username)
    changes = {'serial': ('serial', 'FOREIGN'), 'scope': ('vdom', 'foreign'), 'method': ('http_method', 'PUT'),
        'status': ('status', 'error'), 'http': ('http_status', True), 'mkey': ('mkey', 'foreign'),
        'results': ('results', {'password': 'NEVER_DECODE_ACK_MATERIAL'}),
        'revision': ('revision', {'token': 'NEVER_DECODE_ACK_MATERIAL'}),
        'unchanged': ('revision_changed', False), 'unknown': ('password', 'NEVER_DECODE_ACK_MATERIAL')}
    if fault in changes:
        field, value = changes[fault]; values[field] = value
    elif fault == 'missing_mkey':
        values.pop('mkey')
    raw = bytearray(json.dumps(values).encode())
    if fault == 'trailing': raw.extend(b'{}')
    if fault == 'duplicate': raw[-1:] = b',"status":"success"}'
    if fault is None:
        assert len(qualify_radius_remote_user_ack(raw, binding(), expected_serial=SERIAL,
            expected_vdom='synthetic-scope', method='POST', http_status=200)) == 64
    else:
        with pytest.raises(RadiusRemoteUserError):
            qualify_radius_remote_user_ack(raw, binding(), expected_serial=SERIAL,
                expected_vdom='synthetic-scope', method='POST', http_status=200)
    assert not raw


@pytest.mark.parametrize('fault', [None, 'present', 'nested', 'material', 'truncated', 'page', 'count', 'empty_body'])
def test_name_only_absence_rejects_partial_or_unrestricted_collection(fault: str | None) -> None:
    from fortipam_mcp.radius_remote_user_contract import qualify_radius_remote_user_absence
    row = {'name': 'synthetic-unrelated-user'}
    values = dict(build=29, version='v7.0.0', serial=SERIAL, path='system', name='admin',
        vdom='synthetic-scope', http_method='GET', http_status=200, status='success', results=[row])
    if fault == 'present': row['name'] = binding().username
    elif fault == 'nested': row['name'] = {'token': 'NEVER_DECODE_COLLECTION_MATERIAL'}
    elif fault == 'material': row['password'] = 'NEVER_DECODE_COLLECTION_MATERIAL'
    elif fault == 'truncated': values['limit_reached'] = True
    elif fault == 'page': values['next_idx'] = 1
    elif fault == 'count': values['matched_count'] = 0
    elif fault == 'empty_body': values = {}
    raw = bytearray(json.dumps(values).encode())
    if fault is None:
        qualify_radius_remote_user_absence(raw, binding(), expected_serial=SERIAL,
            expected_vdom='synthetic-scope', http_status=200, collection=True)
    else:
        with pytest.raises(RadiusRemoteUserError):
            qualify_radius_remote_user_absence(raw, binding(), expected_serial=SERIAL,
                expected_vdom='synthetic-scope', http_status=200, collection=True)
    assert not raw
