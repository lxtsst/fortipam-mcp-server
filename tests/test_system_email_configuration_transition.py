"""Fixed SMTP proposal and complete readback boundaries with synthetic peers."""
import json

import pytest

from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.system_email_configuration_transition import prepare_system_email_transition
from fortipam_mcp.system_email_native_source import SystemEmailNativeSource
from test_system_email_native_source import Peer


def proposed():
    values={k:v for k,v in Peer().body['results'].items()if k not in ('username','password')}
    values['server']='capture.example.test'
    return values


def transition():
    return prepare_system_email_transition(Peer().source().read_empty_auth_payload(),proposed())


def test_expected_state_and_original_state_have_distinct_readback_requirements():
    plan=transition();peer=Peer();peer.body['results']['server']='capture.example.test'
    current=peer.source().read_empty_auth_payload()
    plan.verify_applied(current)
    with pytest.raises(ValueError):plan.verify_restored(current)
    original=Peer().source().read_empty_auth_payload()
    plan.verify_restored(original)
    with pytest.raises(ValueError):plan.verify_applied(original)
    assert 'redacted'in repr(plan)
    summary=plan.summary()
    assert summary['configuration_write_authorized']is False
    assert summary['smtp_send_authorized']is False
    assert summary['independent_restoration_authorized']is False
    assert 'capture.example.test'not in json.dumps(summary)


@pytest.mark.parametrize('field,value',[
    ('interface','synthetic-interface'),('interface-select-method','specify'),
    ('ssl-min-proto-version','tls1-3'),
])
def test_proposal_cannot_change_fields_omitted_from_native_sdk(field,value):
    values=proposed();values[field]=value
    with pytest.raises(ValueError):
        prepare_system_email_transition(Peer().source().read_empty_auth_payload(),values)


@pytest.mark.parametrize('phase',['applied','restored'])
@pytest.mark.parametrize('field,value',[
    ('interface','synthetic-interface'),('interface-select-method','specify'),
    ('ssl-min-proto-version','tls1-3'),('reply-to','other@example.test'),('port',587),
])
def test_complete_readback_refuses_unintended_configuration_drift(phase,field,value):
    plan=transition();peer=Peer()
    if phase=='applied':peer.body['results']['server']='capture.example.test'
    peer.body['results'][field]=value
    observed=peer.source().read_empty_auth_payload()
    with pytest.raises(ValueError):getattr(plan,'verify_'+phase)(observed)


@pytest.mark.parametrize('phase',['applied','restored'])
def test_matching_configuration_on_another_device_cannot_satisfy_readback(phase):
    plan=transition();peer=Peer();peer.body['serial']=peer.schema['serial']='SYNTHETIC02'
    if phase=='applied':peer.body['results']['server']='capture.example.test'
    source=SystemEmailNativeSource(SecretMetadataHttpTransportConfig(
        'https://pam.example.test','synthetic-token',5,None),
        expected_serial='SYNTHETIC02',connection_factory=peer.factory)
    with pytest.raises(ValueError):getattr(plan,'verify_'+phase)(source.read_empty_auth_payload())


@pytest.mark.parametrize('phase',['applied','restored'])
def test_same_values_under_changed_schema_cannot_satisfy_readback(phase):
    plan=transition();peer=Peer();peer.schema['results']['children']['port']['max-value']=65000
    if phase=='applied':peer.body['results']['server']='capture.example.test'
    with pytest.raises(ValueError):getattr(plan,'verify_'+phase)(peer.source().read_empty_auth_payload())


def test_unbound_caller_data_cannot_replace_the_source_read():
    with pytest.raises(ValueError):prepare_system_email_transition({},proposed())
    with pytest.raises(ValueError):transition().verify_applied({})


@pytest.mark.parametrize('fault',['port-bound','server-length','security-option','type-option'])
def test_proposal_uses_source_specific_schema_limits(fault):
    peer=Peer();fields=peer.schema['results']['children'];values=proposed()
    if fault=='port-bound':
        fields['port']['max-value']=500;values['port']=587
    elif fault=='server-length':fields['server']['size']=18
    elif fault=='security-option':
        fields['security']['options']=[{'name':'smtps'}];values['security']='starttls'
    elif fault=='type-option':
        fields['type']['options']=[{'name':'custom'}];values['type']='default'
    original=peer.source().read_empty_auth_payload()
    with pytest.raises(ValueError):prepare_system_email_transition(original,values)


def test_later_mutation_of_peer_schema_cannot_relax_bound_constraints():
    peer=Peer();peer.schema['results']['children']['port']['max-value']=500
    original=peer.source().read_empty_auth_payload()
    peer.schema['results']['children']['port']['max-value']=65535
    values=proposed();values['port']=587
    with pytest.raises(ValueError):prepare_system_email_transition(original,values)


def test_preview_exposes_actual_field_changes_without_values_or_authority():
    preview=transition().preview()
    assert preview['Proposed Changes']['changed_fields']==['server']
    assert preview['Proposed Changes']['sdk_omitted_fields_unchanged']is True
    assert preview['configuration_write_authorized']is False
    assert preview['smtp_send_authorized']is False
    assert 'capture.example.test'not in json.dumps(preview)
    assert 'smtp.example.test'not in json.dumps(preview)


def test_unchanged_proposal_preview_does_not_invent_a_change():
    peer=Peer();original=peer.source().read_empty_auth_payload()
    values={k:v for k,v in peer.body['results'].items()if k not in ('username','password')}
    plan=prepare_system_email_transition(original,values)
    assert plan.preview()['Proposed Changes']['changed_fields']==[]
    plan.verify_applied(original);plan.verify_restored(original)
