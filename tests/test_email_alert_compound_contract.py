"""Full supplied compound states, fixed topology and private ordered drafts."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from fortipam_mcp.email_alert_compound_contract import (SLOTS,STEPS,_NAMES,_TABLES,EmailAlertCompoundPlan,
    EmailAlertCompoundState,email_alert_frame_schema_digest,project_email_alert_frame)
from fortipam_mcp.email_alert_general_contract import EmailAlertMailScope
from test_email_alert_general_contract import fixture as general_fixture,project as general_project,SERIAL,SENDER,RECIPIENT


def descriptor(value):
    if type(value) is str: return dict(type='string',size=255)
    if type(value) is int: return dict(type='integer')
    if isinstance(value,dict): return dict(children={k:descriptor(v) for k,v in value.items()})
    if isinstance(value,list): return dict(children={k:descriptor(v) for k,v in (value[0] if value else dict(id=0)).items()})
    raise ValueError


def frame(kind,slot,row,*,schema=None,wrapper=None,pin=None):
    path,table = _TABLES[kind]
    if schema is None:
        fields = {key:descriptor(value) for key,value in row.items() if not key.startswith('q_')}
        schema = dict(build=29,http_method='GET',http_status=200,name=table,path=path,status='success',
            version='v7.0.0',serial=SERIAL,action='schema',results={'children':fields})
    if wrapper is None:
        wrapper = dict(build=29,http_method='GET',http_status=200,name=table,path=path,status='success',
            version='v7.0.0',serial=SERIAL,vdom='root',results=row)
    raw = bytearray(json.dumps(wrapper).encode())
    try:
        pin = pin or email_alert_frame_schema_digest(schema,kind,expected_serial=SERIAL)
        return project_email_alert_frame(raw,schema,kind,slot,expected_serial=SERIAL,expected_schema_digest=pin)
    finally: assert not any(raw)


def fixture():
    schema,general = general_fixture(); actions=[];stitches=[];triggers=[]
    for slot in SLOTS:
        action,stitch,trigger = _NAMES[slot]
        actions.append(frame('action',slot,dict(name=action,**{'action-type':'email','email-from':f'old.{slot}@owned.example.test',
            'email-to':[dict(name=f'old.{slot}.to@owned.example.test')],'email-subject':'Original '+slot},unrelated=3)))
        stitches.append(frame('stitch',slot,dict(name=stitch,status='disable',trigger=trigger,
            actions=[dict(id=1,action=action,required='enable')],description='Original '+slot,unrelated=3)))
        triggers.append(frame('trigger',slot,dict(name=trigger,**{'trigger-type':'event-based',
            'event-type':'license-near-expiry' if slot == 'license' else 'event-log',
            'logid':[] if slot == 'license' else [dict(id=44557 if slot == 'glass' else 37912)]},unrelated=3)))
    settings = frame('settings',None,{'cert-setting':{'alert-status':'disable','warning-days-before-expiry':7,
        'email-to':[dict(name='old.cert@owned.example.test')],'unrelated':3},
        'reverse-service-setting':dict(status='enable',port=8443),'unrelated-global':'keep','q_origin_key':''})
    return EmailAlertCompoundState(general_project(schema,general),tuple(actions),tuple(stitches),tuple(triggers),settings)


def plan(): return EmailAlertCompoundPlan(fixture(),EmailAlertMailScope('1'*64,SENDER,RECIPIENT))


def mutated(original,**values):
    row = json.loads(original._encoded); row.update(values)
    return replace(original,_encoded=json.dumps(row,sort_keys=True,separators=(',',':')).encode())


def test_eight_ordered_native_drafts_and_inverse_keep_per_object_originals_and_trigger_graph():
    change = plan(); assert change.changed_steps == STEPS
    for index,step in enumerate(STEPS):
        current = change.expected(index); body = change.compile(step,current)
        try: wire = json.loads(body)
        finally: body[:] = b'\0'*len(body)
        if step.endswith('_action'):
            assert set(wire) == {'name','action-type','email-from','email-to','email-subject','$originalName'}
            assert wire['email-from'] == SENDER and wire['email-to'] == [dict(name=RECIPIENT)]
            assert wire['email-subject'] == 'Original '+SLOTS[index-1] and wire['name'] == wire['$originalName']
        elif step.endswith('_stitch'):
            assert set(wire) == {'name','status','trigger','actions','description','$originalName'} and wire['status'] == 'enable'
        elif step == 'certificate':
            assert set(wire) == {'cert-setting','reverse-service-setting'} and wire['reverse-service-setting'] == {}
            assert wire['cert-setting']['warning-days-before-expiry'] == 3 and wire['cert-setting']['unrelated'] == 3
        for before,after in zip(change.baseline.triggers,change.expected(index+1).triggers): assert before.digest == after.digest
    for index in reversed(range(len(STEPS))):
        body = change.compile(STEPS[index],change.expected(index+1),restore=True)
        try:
            wire = json.loads(body)
            if STEPS[index].endswith('_action'):
                assert wire['email-from'] == f'old.{SLOTS[index-1]}@owned.example.test'
        finally: body[:] = b'\0'*len(body)
    assert change.expected(0).digest == change.baseline.digest
    assert json.loads(change.expected().settings._encoded)['reverse-service-setting'] == dict(status='enable',port=8443)


@pytest.mark.parametrize('fault',['missing','order','aggregate-name','http-action','extra-action','wrong-trigger','native-floating-default','event-id','serial'])
def test_only_complete_existing_fixed_graph_is_eligible_no_ui_fallbacks_or_default_repair(fault):
    original = fixture(); actions=list(original.actions);stitches=list(original.stitches);triggers=list(original.triggers)
    if fault == 'missing': actions.pop()
    elif fault == 'order': actions.reverse()
    elif fault == 'aggregate-name': actions[0] = mutated(actions[0],name='Critical Alert')
    elif fault == 'http-action': actions[0] = mutated(actions[0],**{'action-type':'webhook'})
    elif fault == 'extra-action':
        row=json.loads(stitches[0]._encoded); stitches[0]=mutated(stitches[0],actions=[*row['actions'],dict(id=2,action='foreign',required='enable')])
    elif fault in ('wrong-trigger','native-floating-default'):
        stitches[2]=mutated(stitches[2],trigger='foreign' if fault == 'wrong-trigger' else _NAMES['glass'][2])
    elif fault == 'event-id': triggers[2]=mutated(triggers[2],logid=[dict(id=44557)])
    else: actions[0]=replace(actions[0],serial_digest='f'*64)
    with pytest.raises(ValueError): replace(original,actions=tuple(actions),stitches=tuple(stitches),triggers=tuple(triggers))


@pytest.mark.parametrize('area',['action','stitch','trigger','certificate','reverse-service','general'])
def test_any_compound_drift_or_wrong_prefix_prevents_a_draft(area):
    change = plan(); current=change.expected(1)
    if area in ('action','stitch','trigger'):
        attribute=area+'s' if area != 'stitch' else 'stitches'; items=list(getattr(current,attribute))
        items[0]=mutated(items[0],unrelated=4); current=replace(current,**{attribute:tuple(items)})
    elif area == 'certificate':
        row=json.loads(current.settings._encoded); row['cert-setting']['unrelated']=4
        current=replace(current,settings=mutated(current.settings,**{'cert-setting':row['cert-setting']}))
    elif area == 'reverse-service': current=replace(current,settings=mutated(current.settings,**{'reverse-service-setting':dict(status='disable',port=8443)}))
    else:
        row=json.loads(current.general._encoded);row['unrelated-integer']=4
        current=replace(current,general=replace(current.general,_encoded=json.dumps(row).encode()))
    with pytest.raises(ValueError,match='unavailable'): change.compile('glass_action',current)
    with pytest.raises(ValueError,match='unavailable'): change.compile('license_action',change.expected(1))


def test_full_master_truth_is_derived_from_recipients_not_certificate_status_or_critical_sender():
    original=fixture(); general=json.loads(original.general._encoded);general.update(username='',**{'email-to':[]})
    actions=tuple(mutated(a,**{'email-to':[]}) for a in original.actions)
    root=json.loads(original.settings._encoded);cert={**root['cert-setting'],'alert-status':'enable','email-to':[]}
    disabled=replace(original,general=replace(original.general,_encoded=json.dumps(general).encode()),actions=actions,
        settings=mutated(original.settings,**{'cert-setting':cert}))
    assert not disabled.master_enabled()
    assert replace(disabled,actions=(mutated(actions[0],**{'email-to':[dict(name=RECIPIENT)]}),*actions[1:])).master_enabled()


def test_equal_steps_are_skipped_without_a_write_or_inverse_entitlement():
    change=plan(); already=change.expected(); copied=EmailAlertCompoundPlan(already,change.mail_scope)
    assert copied.changed_steps == ()
    for step in STEPS:
        with pytest.raises(ValueError,match='unavailable'): copied.compile(step,already)
        with pytest.raises(ValueError,match='unavailable'): copied.compile(step,already,restore=True)


def test_preview_contains_no_mail_identity_or_false_native_merge_delivery_authority():
    change=plan(); public=change.preview(); text=json.dumps(public)
    assert public['Proposed Changes']['ordered_write_steps'] == 8
    assert public['Security Changes']['certificate_serialization_contains_empty_reverse_service_block']
    assert SENDER not in text and RECIPIENT not in text and 'old.glass' not in text and 'Glassbreaking Email' not in text
    for flag in ('configuration_ready','execution_authorized','native_put_qualified','recipient_scope_authorized',
        'critical_graph_native_qualified','certificate_merge_qualified','reverse_service_preservation_qualified',
        'device_model_qualified','delivery_verified','independent_recovery_verified'): assert public[flag] is False


def test_known_action_stitch_icon_metadata_is_preserved_and_never_sent():
    change=plan(); actions=tuple(mutated(a,q_class='synthetic-icon') for a in change.baseline.actions)
    stitches=tuple(mutated(s,q_class='synthetic-icon') for s in change.baseline.stitches)
    change=replace(change,baseline=replace(change.baseline,actions=actions,stitches=stitches))
    body=change.compile('glass_action',change.expected(1))
    try: assert 'q_class' not in json.loads(body)
    finally: body[:]=b'\0'*len(body)
    assert json.loads(change.expected().actions[0]._encoded)['q_class'] == 'synthetic-icon'


@pytest.mark.parametrize('fault',['identity','method','schema-pin','missing','extra','material','nested-scalar','bool-integer'])
def test_private_frame_boundary_refuses_unclassified_or_foreign_data_and_always_clears_input(monkeypatch,fault):
    kind,slot='action','glass'; name=_NAMES[slot][0]
    row=dict(name=name,**{'action-type':'email','email-from':'old@owned.example.test','email-to':[dict(name=RECIPIENT)],'email-subject':'Original'})
    fields={key:descriptor(value) for key,value in row.items()}
    schema=dict(build=29,http_method='GET',http_status=200,name='automation-action',path='system',status='success',
        version='v7.0.0',serial=SERIAL,action='schema',results={'children':fields})
    pin=email_alert_frame_schema_digest(schema,kind,expected_serial=SERIAL)
    wrapper=dict(build=29,http_method='GET',http_status=200,name='automation-action',path='system',status='success',
        version='v7.0.0',serial=SERIAL,vdom='root',mkey=name,results=row)
    if fault=='identity': wrapper['mkey']='Critical Alert'
    elif fault=='method': wrapper['http_method']='POST'
    elif fault=='schema-pin': pin='f'*64
    elif fault=='missing': del row['email-subject']
    elif fault=='extra': row['opaque']='SYNTHETIC_PRIVATE_MATERIAL'
    elif fault=='material':
        fields['password']=dict(type='password-2');row['password']='SYNTHETIC_PRIVATE_MATERIAL'
        monkeypatch.setattr(json,'loads',lambda *args,**kwargs:pytest.fail('Material was decoded'))
    elif fault=='nested-scalar': row['email-subject']=dict(opaque='SYNTHETIC_PRIVATE_MATERIAL')
    else:
        fields['counter']=dict(type='integer');row['counter']=True
        pin=email_alert_frame_schema_digest(schema,kind,expected_serial=SERIAL)
    raw=bytearray(json.dumps(wrapper).encode())
    with pytest.raises(ValueError,match='unavailable'):
        project_email_alert_frame(raw,schema,kind,slot,expected_serial=SERIAL,expected_schema_digest=pin)
    assert not any(raw)
