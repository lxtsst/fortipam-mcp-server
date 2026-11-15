"""Explicit actor/mode/profile projection and fixed bodies with synthetic data."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp.glass_break_contract import (GlassBreakBinding,GlassBreakIncident,GlassBreakPlan,
    glass_break_profile_schema_digest,project_glass_break_state)

ACTOR='synthetic-owner'
SERIAL='SYNTHETIC_DEVICE'
PRIVATE='SYNTHETIC_UNCLASSIFIED_MATERIAL_NEVER_DECODE_OR_HASH'
REASON='Synthetic isolated recovery drill'


def fixture():
    schema={'name':dict(type='string',size=64),'glass-breaking':dict(type='option',size=7,
        options=[dict(name='enable'),dict(name='disable')]),'sysgrp':dict(type='option',options=['none','read','read-write']),
        'secretgrp':dict(type='option',options=['none','read','read-write']),
        'permissions':dict(children={'audit':dict(type='option',options=['none','read','read-write']),
            'description':dict(type='string',size=64)})}
    raw=dict(http_method='GET',http_status=200,path='web-ui',name='state',action='',status='success',serial=SERIAL,
        version='v7.0.0',build=29,results={'admin':{'name':ACTOR,'login_name':ACTOR,'sponsored_group_name':'','guest_admin':False,
            'promoted_admin':False,'profile':{'name':'synthetic-role','glass-breaking':'enable','sysgrp':'read-write','secretgrp':'read-write',
                'permissions':dict(audit='read',description='synthetic-role-description')},'session_token':PRIVATE},'unrelated':dict(password=PRIVATE)})
    binding=GlassBreakBinding('1'*64,ACTOR,hashlib.sha256(SERIAL.encode()).hexdigest(),glass_break_profile_schema_digest(schema))
    return schema,raw,binding


def project(schema,body,binding):
    raw=bytearray(json.dumps(body).encode())
    try: return project_glass_break_state(raw,binding,schema)
    finally: assert not any(raw)


def plan():
    schema,raw,binding=fixture()
    return GlassBreakPlan(project(schema,raw,binding),GlassBreakIncident('2'*64,REASON))


def test_full_classified_profile_and_explicit_flags_never_decode_or_hash_unrelated_material(monkeypatch):
    schema,body,binding=fixture(); decode,digest=json.loads,hashlib.sha256
    for spec in schema.values(): spec.update(default=PRIVATE,help=PRIVATE)
    def checked_decode(raw,*args,**kwargs):
        assert PRIVATE.encode() not in (raw.encode() if isinstance(raw,str) else raw)
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert PRIVATE.encode() not in raw
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    state=project(schema,body,binding)
    assert state.eligible and state.promoted is False
    assert all(marker not in repr(state)+repr(binding) for marker in (ACTOR,SERIAL,PRIVATE,'synthetic-role-description'))


@pytest.mark.parametrize('flag',[None,'false',0,1,[],{},'missing'])
def test_mode_requires_explicit_native_boolean_not_ui_fallback(flag):
    schema,body,binding=fixture()
    if flag=='missing': del body['results']['admin']['promoted_admin']
    else: body['results']['admin']['promoted_admin']=flag
    with pytest.raises(ValueError,match='unavailable'): project(schema,body,binding)


@pytest.mark.parametrize('fault',['disabled','missing','wrong-type','wrong-value','role-name-implies-eligibility'])
def test_exact_role_predicate_is_required_without_super_admin_inference(fault):
    schema,body,binding=fixture(); role=body['results']['admin']['profile']
    if fault in ('disabled','role-name-implies-eligibility'): role['glass-breaking']='disable'
    elif fault=='missing': del role['glass-breaking']
    elif fault=='wrong-type': role['glass-breaking']=True
    else: role['glass-breaking']='ENABLE'
    if fault=='role-name-implies-eligibility': role['name']='super_admin'
    if fault in ('disabled','role-name-implies-eligibility'):
        state=project(schema,body,binding); assert not state.eligible
        with pytest.raises(ValueError): GlassBreakPlan(state,GlassBreakIncident('2'*64,REASON))
    else:
        with pytest.raises(ValueError,match='unavailable'): project(schema,body,binding)


@pytest.mark.parametrize('fault',['actor','login','guest','sponsor','serial','missing-serial','build','bool-build','version','method','route','status'])
def test_identity_context_and_version_envelope_are_exact(fault):
    schema,body,binding=fixture(); actor=body['results']['admin']
    if fault=='actor': actor['name']='foreign'
    elif fault=='login': actor['login_name']='foreign'
    elif fault=='guest': actor['guest_admin']=True
    elif fault=='sponsor': actor['sponsored_group_name']='foreign'
    elif fault=='serial': body['serial']='foreign'
    elif fault=='missing-serial': del body['serial']
    elif fault=='build': body['build']=30
    elif fault=='bool-build': body['build']=True
    elif fault=='version': body['version']='v7.0.1'
    elif fault=='method': body['http_method']='POST'
    elif fault=='route': body['name']='foreign'
    else: body['status']='error'
    with pytest.raises(ValueError,match='unavailable'): project(schema,body,binding)


@pytest.mark.parametrize('fault',['pin','material-schema','missing-field','extra-field','nested-scalar','nested-extra'])
def test_schema_classification_precedes_current_decode_and_unknown_values_are_not_hashed(monkeypatch,fault):
    schema,body,binding=fixture(); role=body['results']['admin']['profile']; decode,digest=json.loads,hashlib.sha256
    if fault=='pin': schema['name']['size']=63
    elif fault=='material-schema': schema['access-token']=dict(type='password-2',default=PRIVATE)
    elif fault=='missing-field': del role['sysgrp']
    elif fault=='extra-field': role['unclassified']=PRIVATE
    elif fault=='nested-scalar': role['name']=dict(password=PRIVATE)
    else: role['permissions']['unclassified']=PRIVATE
    def checked_decode(raw,*args,**kwargs):
        assert PRIVATE.encode() not in (raw.encode() if isinstance(raw,str) else raw)
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert PRIVATE.encode() not in raw
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    with pytest.raises(ValueError,match='unavailable'): project(schema,body,binding)


def test_fixed_native_bodies_require_original_off_baseline_and_complete_profile_continuity():
    change=plan(); body=change.compile(change.baseline)
    try: assert json.loads(body)==dict(comments=REASON)
    finally: body[:]=b'\0'*len(body)
    inverse=change.compile(change.expected(),deactivate=True)
    try: assert inverse==b'{}'
    finally: inverse[:]=b'\0'*len(inverse)
    assert change.expected().profile_digest==change.baseline.profile_digest
    for current,deactivate in ((change.baseline,True),(change.expected(),False),(replace(change.expected(),profile_digest='f'*64),True),
            (replace(change.baseline,binding_digest='f'*64),False)):
        with pytest.raises(ValueError,match='unavailable'): change.compile(current,deactivate=deactivate)
    with pytest.raises(ValueError): GlassBreakPlan(change.expected(),change.incident)


def test_unrelated_permission_changes_affect_the_full_profile_digest_even_if_mode_and_eligibility_match():
    schema,body,binding=fixture(); before=project(schema,body,binding)
    body['results']['admin']['profile']['permissions']['audit']='read-write'
    after=project(schema,body,binding)
    assert after.eligible==before.eligible and after.promoted==before.promoted and after.profile_digest!=before.profile_digest
    with pytest.raises(ValueError): GlassBreakPlan(before,GlassBreakIncident('2'*64,REASON)).compile(after)


@pytest.mark.parametrize('reason',['','   ','\n','synthetic\x00reason','é','x'*257])
def test_reason_is_private_bounded_local_text_not_an_inferred_native_limit(reason):
    with pytest.raises(ValueError): GlassBreakIncident('2'*64,reason)


def test_preview_explains_global_reach_and_qualified_gaps_without_incident_or_actor_values():
    change=plan(); public=change.preview(); text=json.dumps(public)
    assert public['Security Changes']['normal_access_controls_bypassed']
    assert public['Security Changes']['all_folders_secrets_requests_and_launches_affected']
    assert public['Security Changes']['cleartext_access_becomes_possible']
    assert public['Security Changes']['logout_does_not_prove_deactivation'] and public['Security Changes']['no_native_automatic_expiry_established']
    assert public['Expected State']['original_activation_receipt_required_for_deactivation']
    assert not any(public[key] for key in ('activation_ready','execution_authorized','access_elevated','native_subject_or_session_scope_verified',
        'native_ack_qualified','isolated_drill_verified','independent_observer_verified','reason_retention_verified',
        'audit_recording_verified','notification_scope_verified','independent_deactivation_verified'))
    assert all(marker not in text+repr(change)+repr(change.incident) for marker in (ACTOR,SERIAL,REASON,PRIVATE,'synthetic-role'))
