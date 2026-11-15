"""Private general-alert drafts with synthetic identities and supplied full schema."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp.email_alert_general_contract import (FIELDS, EmailAlertMailScope, EmailAlertGeneralPlan,
    email_alert_general_schema_digest, project_email_alert_general)

SERIAL = 'SYNTHETIC_SERIAL'
SENDER = 'synthetic.sender@owned.example.test'
RECIPIENT = 'synthetic.recipient@owned.example.test'
PRIVATE = 'SYNTHETIC_DEFAULT_NEVER_DECODE_OR_HASH'


def fixture():
    row = dict(username='old.sender@owned.example.test',**{'email-to':[dict(name='old.recipient@owned.example.test')],
        'filter-mode':'threshold','email-interval':17,'antivirus-logs':'enable','configuration-changes-logs':'disable',
        'HA-logs':'enable','severity':'warning','FDS-license-expiring-days':15},
        **{'unrelated-integer':3,'unrelated-nested':{'option':'keep'},'q_origin_key':'','q_static':False})
    fields = {name:dict(type='option',options=[dict(name=v,help=PRIVATE) for v in ('enable','disable')])
        for name in ('antivirus-logs','configuration-changes-logs','HA-logs')}
    fields.update(username=dict(type='string',size=63),**{'email-to':dict(children={'name':dict(type='string',size=63)}),
        'filter-mode':dict(type='option',options=[dict(name='category'),dict(name='threshold')]),
        'email-interval':dict(type='integer',**{'min-value':1,'max-value':99999}),
        'severity':dict(type='option',options=[dict(name='alert'),dict(name='warning')]),
        'FDS-license-expiring-days':dict(type='integer',**{'min-value':0,'max-value':365}),
        'unrelated-integer':dict(type='integer'),'unrelated-nested':dict(children={'option':dict(type='string')})})
    schema = dict(build=29,http_method='GET',http_status=200,name='setting',path='alertemail',status='success',
        version='v7.0.0',serial=SERIAL,action='schema',results={'children':fields})
    for descriptor in fields.values(): descriptor.update(default=PRIVATE,help=PRIVATE)
    return schema,row


def envelope(row):
    return dict(build=29,http_method='GET',http_status=200,name='setting',path='alertemail',status='success',
        version='v7.0.0',serial=SERIAL,vdom='root',results=row)


def project(schema,row,*,wrapper=None,pin=None):
    pin = pin or email_alert_general_schema_digest(schema,expected_serial=SERIAL)
    raw = bytearray(json.dumps(envelope(row) if wrapper is None else wrapper).encode())
    try: return project_email_alert_general(raw,schema,expected_serial=SERIAL,expected_schema_digest=pin)
    finally: assert not any(raw)


def plan():
    schema,row = fixture()
    return schema,row,EmailAlertGeneralPlan(project(schema,row),EmailAlertMailScope('1'*64,SENDER,RECIPIENT))


def test_native_nine_field_draft_and_inverse_keep_fds_severity_and_unrelated_state():
    schema,row,change = plan(); body = change.compile(change.baseline)
    try: wire = json.loads(body)
    finally: body[:] = b'\0'*len(body)
    assert set(wire) == FIELDS and wire['username'] == SENDER and wire['email-to'] == [dict(name=RECIPIENT)]
    assert wire['email-interval'] == 5 and wire['filter-mode'] == 'category'
    assert wire['configuration-changes-logs'] == 'enable' and wire['antivirus-logs'] == wire['HA-logs'] == 'disable'
    assert wire['FDS-license-expiring-days'] == 15 and wire['severity'] == 'warning'
    expected = project(schema,{**row,**wire}); assert expected.digest == change.expected().digest
    reverse = change.compile(expected,restore=True)
    try: assert json.loads(reverse) == {name:row[name] for name in FIELDS}
    finally: reverse[:] = b'\0'*len(reverse)
    assert json.loads(expected._encoded)['unrelated-nested'] == row['unrelated-nested']


def test_schema_defaults_and_help_are_never_part_of_record_decode_or_digest(monkeypatch):
    schema,row = fixture(); decode,digest = json.loads,hashlib.sha256
    def checked_decode(raw,*args,**kwargs):
        assert PRIVATE.encode() not in (raw.encode() if isinstance(raw,str) else raw)
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert PRIVATE.encode() not in raw
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    original = project(schema,row); change = EmailAlertGeneralPlan(original,EmailAlertMailScope('1'*64,SENDER,RECIPIENT))
    assert change.digest and change.expected().digest


@pytest.mark.parametrize('nested',[False,True])
def test_rejected_material_schema_erases_owned_input_before_a_whole_record_decoder(monkeypatch,nested):
    schema,row = fixture(); pin = email_alert_general_schema_digest(schema,expected_serial=SERIAL)
    if nested:
        schema['results']['children']['unrelated-nested']['children']['option']['type'] = 'password-2'
        row['unrelated-nested']['option'] = PRIVATE
    else:
        schema['results']['children']['material'] = dict(type='password-2'); row['material'] = PRIVATE
    raw = bytearray(json.dumps(envelope(row)).encode())
    monkeypatch.setattr(json,'loads',lambda *args,**kwargs:pytest.fail('A rejected material record was decoded'))
    with pytest.raises(ValueError,match='unavailable'):
        project_email_alert_general(raw,schema,expected_serial=SERIAL,expected_schema_digest=pin)
    assert not any(raw)


@pytest.mark.parametrize('field,value',[('unrelated-integer',4),('severity','alert'),('email-interval',18),
    ('FDS-license-expiring-days',14),('username','changed@owned.example.test'),('q_static',True)])
def test_complete_supplied_state_drift_rejects_forward_and_inverse(field,value):
    schema,row,change = plan()
    with pytest.raises(ValueError,match='unavailable'): change.compile(project(schema,{**row,field:value}))
    expected = json.loads(change.expected()._encoded); expected[field] = value
    if field == 'email-interval': expected[field] = 6
    with pytest.raises(ValueError,match='unavailable'): change.compile(project(schema,expected),restore=True)


@pytest.mark.parametrize('fault',['missing','extra','material','nested-material','wrong-type','pin','scalar-object',
    'option','bounds','duplicate-recipient','recipient-metadata','version','serial','error','master-switch'])
def test_incomplete_unknown_material_or_unqualified_shape_fails_closed_and_clears_input(fault):
    schema,row = fixture(); wrapper = None; pin = None
    if fault == 'missing': del row['unrelated-integer']
    elif fault == 'extra': row['unclassified'] = PRIVATE
    elif fault == 'material': schema['results']['children']['opaque'] = dict(type='password-2'); row['opaque'] = PRIVATE
    elif fault == 'nested-material': schema['results']['children']['unrelated-nested']['children']['option']['type'] = 'password-2'
    elif fault == 'wrong-type': row['email-interval'] = True
    elif fault == 'pin': pin = 'f'*64
    elif fault == 'scalar-object': row['unrelated-integer'] = dict(value=PRIVATE)
    elif fault == 'option': row['severity'] = 'unqualified'
    elif fault == 'bounds': row['FDS-license-expiring-days'] = 366
    elif fault == 'duplicate-recipient': row['email-to'].append(dict(row['email-to'][0]))
    elif fault == 'recipient-metadata': row['email-to'][0]['unknown'] = PRIVATE
    elif fault == 'master-switch': row['emailAlertOn'] = True
    else:
        wrapper = envelope(row)
        if fault == 'version': wrapper['build'] = True
        elif fault == 'serial': wrapper['serial'] = 'FOREIGN'
        else: wrapper['error'] = -1
    with pytest.raises(ValueError,match='unavailable'): project(schema,row,wrapper=wrapper,pin=pin)


def test_native_type_pin_and_schema_limits_apply_to_the_proposed_mail_identity():
    schema,row = fixture(); schema['results']['children']['username']['size'] = 32
    original = project(schema,row); change = EmailAlertGeneralPlan(original,EmailAlertMailScope('1'*64,SENDER,RECIPIENT))
    with pytest.raises(ValueError): change.compile(original)
    schema,row = fixture(); original = project(schema,row)
    schema['results']['children']['email-interval']['max-value'] = 50
    assert project(schema,row).digest != original.digest


@pytest.mark.parametrize('sender,recipient',[('bad','a@owned.example.test'),('a@owned.example.test','bad'),
    ('a\r\nb@owned.example.test','a@owned.example.test'),('a@owned.example.test','a..b@owned.example.test')])
def test_mail_scope_is_private_bounded_configuration_not_an_arbitrary_header(sender,recipient):
    with pytest.raises(ValueError): EmailAlertMailScope('1'*64,sender,recipient)


def test_matching_configuration_cannot_mint_inverse_ownership_or_noop_write():
    schema,row,change = plan(); applied = change.expected()
    unowned = EmailAlertGeneralPlan(applied,change.mail_scope)
    with pytest.raises(ValueError,match='unavailable'): unowned.compile(applied)
    with pytest.raises(ValueError,match='unavailable'): unowned.compile(applied,restore=True)
    assert replace(change,mail_scope=replace(change.mail_scope,binding_digest='2'*64)).digest != change.digest


def test_existing_long_smtp_debug_capture_identity_is_not_a_qualified_general_recipient():
    from fortipam_mcp.system_email_delivery_contract import SystemEmailDeliveryBinding
    binding = SystemEmailDeliveryBinding('a'*48,'b'*64,'c'*64,'d'*64)
    assert len(binding._recipient()) == 73
    with pytest.raises(ValueError): EmailAlertMailScope('1'*64,SENDER,binding._recipient())


def test_preview_never_exposes_mail_identity_or_claims_compound_delivery_authority():
    schema,row,change = plan(); public = change.preview(); text = json.dumps(public)
    assert all(address not in text for address in (SENDER,RECIPIENT,row['username'],row['email-to'][0]['name']))
    assert SENDER not in repr(change) and RECIPIENT not in repr(change.mail_scope)
    assert public['Proposed Changes']['scope'] == 'general_only' and public['Security Changes']['external_email_possible']
    for key in ('configuration_ready','execution_authorized','native_put_qualified','global_master_state_verified',
        'critical_automation_preserved','certificate_settings_preserved','mail_service_qualified','recipient_scope_authorized',
        'delivery_verified','independent_recovery_verified'): assert public[key] is False
