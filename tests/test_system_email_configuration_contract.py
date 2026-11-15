"""Pinned SDK payload preserves current metadata without accepting credentials."""
import json

import pytest

from fortipam_mcp.system_email_configuration_contract import prepare_empty_auth_system_email
from test_system_email_native_source import Peer


def state():return {k:v for k,v in Peer().body['results'].items()if k not in ('username','password')}


def prepare(value):return prepare_empty_auth_system_email(value,username_empty=True,password_empty=True)


def test_sdk_roundtrip_emits_exact_twelve_fields_and_keeps_unforwarded_state_separate():
    values=state();draft=prepare(values);body=draft._encode();decoded=json.loads(body)
    assert list(decoded)==['type','sender','reply-to','server','port','source-ip','source-ip6','authenticate',
        'validate-server','username','password','security']
    assert decoded['username']==decoded['password']=='' and decoded['type']=='custom'
    assert all(decoded[k]==v for k,v in values.items()if k in decoded)
    assert not {'interface','interface-select-method','ssl-min-proto-version'}&set(decoded)
    assert 'smtp.example.test'not in repr(draft) and 'redacted'in repr(draft)
    values['port']=587;changed=prepare(values)
    assert changed.request_digest!=draft.request_digest and changed.unforwarded_state_digest==draft.unforwarded_state_digest
    values=state();values['ssl-min-proto-version']='tls1-3';hidden=prepare(values)
    assert hidden.request_digest==draft.request_digest and hidden.unforwarded_state_digest!=draft.unforwarded_state_digest
    body[:]=b'\x00'*len(body);assert draft._encode()!=body


@pytest.mark.parametrize('fault',['no-flags','nonempty-username','nonempty-password','auth-enabled','credential-input',
    'recipient-input','ui-boolean-type','missing-native-field','wrong-port','invalid-source-family'])
def test_unproven_auth_or_other_scope_cannot_produce_request(fault):
    values=state();flags=dict(username_empty=True,password_empty=True)
    if fault=='no-flags':flags={}
    elif fault=='nonempty-username':flags['username_empty']=False
    elif fault=='nonempty-password':flags['password_empty']=False
    elif fault=='auth-enabled':values['authenticate']='enable'
    elif fault=='credential-input':values['password']='SYNTHETIC_C3_SENTINEL'
    elif fault=='recipient-input':values['email-to']='recipient@example.test'
    elif fault=='ui-boolean-type':values['type']=True
    elif fault=='missing-native-field':del values['interface']
    elif fault=='wrong-port':values['port']=True
    elif fault=='invalid-source-family':values['source-ip6']='192.0.2.1'
    with pytest.raises(ValueError)as error:prepare_empty_auth_system_email(values,**flags)
    assert 'SYNTHETIC_C3_SENTINEL'not in str(error.value)


def test_source_bound_payload_uses_complete_native_read_and_closes_before_return():
    peer=Peer();source=peer.source();joined=source.read_empty_auth_payload()
    body=json.loads(joined.draft._encode())
    assert len(body)==12 and joined.observation.schema_field_count==15
    assert body['server']==peer.body['results']['server']
    assert body['type']=='custom'and body['username']==body['password']==''
    assert len(peer.calls)==2 and all(resource.closed for resource in peer.resources)
    assert all(not any(buffer)for buffer in peer.buffers)
    summary=joined.summary()
    assert summary['configuration_write_authorized']is False
    assert summary['backend_type_conversion_qualified']is False
    assert summary['credential_safe_rollback_qualified']is False
    assert 'smtp.example.test'not in json.dumps(summary)and 'redacted'in repr(joined)
    source.close()
    with pytest.raises(ValueError):source.read_empty_auth_payload()
    assert len(peer.calls)==2


@pytest.mark.parametrize('field',['interface','interface-select-method','ssl-min-proto-version'])
def test_source_bound_payload_binds_every_omitted_field_without_forwarding_it(field):
    first=Peer().source().read_empty_auth_payload()
    peer=Peer();peer.body['results'][field]={'interface':'synthetic-interface',
        'interface-select-method':'specify','ssl-min-proto-version':'tls1-3'}[field]
    changed=peer.source().read_empty_auth_payload()
    assert changed.observation.nonmaterial_digest!=first.observation.nonmaterial_digest
    assert changed.draft.unforwarded_state_digest!=first.draft.unforwarded_state_digest
    assert changed.draft.request_digest==first.draft.request_digest


@pytest.mark.parametrize('fault',['username','password','authenticate'])
def test_source_bound_payload_refuses_nonempty_or_enabled_auth_without_decoding_it(monkeypatch,fault):
    peer=Peer();peer.body['results'][fault]='enable'if fault=='authenticate'else'SYNTHETIC_C3_SENTINEL'
    decode=json.loads
    def safe(raw,*args,**kwargs):
        if isinstance(raw,(bytes,bytearray,str)):assert 'SYNTHETIC_C3_SENTINEL'not in str(raw)
        return decode(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',safe)
    with pytest.raises(ValueError)as error:peer.source().read_empty_auth_payload()
    assert 'SYNTHETIC_C3_SENTINEL'not in str(error.value)
    assert len(peer.calls)==2 and all(resource.closed for resource in peer.resources)
    assert all(not any(buffer)for buffer in peer.buffers)


def test_source_bound_payload_never_publishes_after_cleanup_failure():
    peer=Peer();peer.close_failure=True
    with pytest.raises(ValueError):peer.source().read_empty_auth_payload()
    assert len(peer.calls)==1 and all(resource.closed for resource in peer.resources)
    assert all(not any(buffer)for buffer in peer.buffers)


def test_source_bound_payload_keeps_source_device_separate_from_configuration():
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from fortipam_mcp.system_email_native_source import SystemEmailNativeSource

    first=Peer().source().read_empty_auth_payload();peer=Peer()
    peer.body['serial']=peer.schema['serial']='SYNTHETIC02'
    source=SystemEmailNativeSource(SecretMetadataHttpTransportConfig(
        'https://pam.example.test','synthetic-token',5,None),
        expected_serial='SYNTHETIC02',connection_factory=peer.factory)
    changed=source.read_empty_auth_payload()
    assert changed.source_serial_digest!=first.source_serial_digest
    assert changed.observation.nonmaterial_digest==first.observation.nonmaterial_digest
    assert changed.draft.request_digest==first.draft.request_digest
