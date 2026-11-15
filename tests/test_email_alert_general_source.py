"""Two fixed general-alert reads and physical C4 draft with synthetic peer data."""
from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp.email_alert_general_contract import EmailAlertMailScope,email_alert_general_schema_digest
from fortipam_mcp.email_alert_general_source import EmailAlertGeneralSource,SCHEMA_PATH,CURRENT_PATH
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_email_alert_general_contract import fixture,envelope,SERIAL,SENDER,RECIPIENT,PRIVATE
from test_windows_jit_script_source import Peer


def candidate(*,guarded=True):
    peer = Peer(); schema,row = fixture(); peer.payloads[SCHEMA_PATH] = schema; peer.payloads[CURRENT_PATH] = envelope(row)
    source = EmailAlertGeneralSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,None),
        EmailAlertMailScope('1'*64,SENDER,RECIPIENT),expected_serial=SERIAL,
        expected_schema_digest=email_alert_general_schema_digest(schema,expected_serial=SERIAL),source_digest='a'*64,
        source_guard=(lambda:True) if guarded else None,connection_factory=peer.factory,http_clock=peer.http_clock,clock=peer.clock)
    return peer,source,schema,row


def test_exact_two_reads_exclude_schema_defaults_from_decoder_and_digest(monkeypatch):
    peer,source,schema,row = candidate(); decode,digest = json.loads,hashlib.sha256
    def checked_decode(raw,*args,**kwargs):
        assert PRIVATE.encode() not in (raw.encode() if isinstance(raw,str) else raw)
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert PRIVATE.encode() not in raw
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    observed = source.read()
    assert observed.source_digest == 'a'*64 and peer.calls == [('GET',SCHEMA_PATH),('GET',CURRENT_PATH)]
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


def test_connection_close_header_may_detach_the_connection_socket_before_body_read():
    peer,source,schema,row = candidate(); factory = source._factory
    def detached(*args,**kwargs):
        connection = factory(*args,**kwargs); receive = connection.getresponse
        def response():
            result = receive(); connection.sock = None; return result
        connection.getresponse = response; return connection
    source._factory = detached
    assert source.read().state.digest and len(peer.calls) == 2
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


def test_private_encoding_requires_original_fresh_plan_and_two_fresh_reads():
    peer,source,schema,row = candidate(); plan = source.prepare_plan(); source.read()
    body = source.compile(plan)
    try: assert json.loads(body)['email-to'] == [dict(name=RECIPIENT)]
    finally: body[:] = b'\0'*len(body)
    assert len(peer.calls) == 6
    with pytest.raises(ValueError,match='unavailable'): source.compile(replace(plan))
    row['unrelated-integer'] = 4
    with pytest.raises(ValueError,match='unavailable'): source.compile(plan)


@pytest.mark.parametrize('fault',['schema-pin','schema-identity','material-schema','gate','closed','tls','source','clock','epoch'])
def test_guard_binding_schema_and_clock_fail_before_an_unqualified_read_or_body(fault):
    peer,source,schema,row = candidate(guarded=fault != 'gate')
    if fault == 'schema-pin': schema['results']['children']['username']['size'] = 62
    elif fault == 'schema-identity': schema['serial'] = 'foreign'
    elif fault == 'material-schema': schema['results']['children']['hidden-password'] = dict(type='password-2',default=PRIVATE)
    elif fault == 'closed': source.close()
    elif fault == 'tls': source._tls.check_hostname = False
    elif fault == 'source': source._source = 'f'*64
    elif fault in ('clock','epoch'):
        source.read(); peer.calls.clear()
        if fault == 'clock': peer.time -= 1
        else: peer.clock.value -= 1
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert peer.calls == ([('GET',SCHEMA_PATH)] if fault.startswith('schema-') or fault == 'material-schema' else [])
    assert all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault',['html','truncated','close','deadline','state-drift','expired','foreign','superseded'])
def test_transport_cleanup_drift_or_stale_plan_never_publishes_a_body(fault):
    peer,source,schema,row = candidate(); plan = source.prepare_plan()
    if fault in ('html','truncated','close','deadline'): peer.fault = fault
    elif fault == 'state-drift': row['unrelated-integer'] = 4
    elif fault == 'expired': peer.clock.value = 1010
    elif fault == 'foreign': plan = candidate()[1].prepare_plan()
    else: source.prepare_plan()
    with pytest.raises(ValueError,match='unavailable'): source.compile(plan)
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


def test_two_reads_parse_encoding_and_cleanup_share_one_compile_deadline():
    peer,source,schema,row = candidate(); plan = source.prepare_plan(); factory = source._factory
    def delayed(*args,**kwargs):
        connection = factory(*args,**kwargs); connect = connection.connect
        def connected(): connect(); peer.time += 2.6
        connection.connect = connected; return connection
    source._factory = delayed
    with pytest.raises(ValueError,match='unavailable'): source.compile(plan)
    assert len(peer.calls) == 3 and all(not any(raw) for raw in peer.buffers)


def test_preview_is_general_only_and_contains_no_mail_identity_or_write_authority():
    peer,source,schema,row = candidate(); public = source.preview(); text = json.dumps(public)
    assert public['source_configuration_observed_locally'] and public['schema_pin_matched_locally']
    assert not public['configuration_written'] and not public['mail_contacted'] and not public['product_actor_verified']
    assert not public['native_complete_schema_qualified'] and not public['global_master_state_verified']
    assert all(marker not in text for marker in (SENDER,RECIPIENT,row['username'],SERIAL,PRIVATE))
