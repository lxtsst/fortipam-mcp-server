"""Fixed test mailbox encoding and minimized capture comparisons, with no I/O."""
from dataclasses import replace
import json

import pytest

from fortipam_mcp.system_email_delivery_contract import (
    SystemEmailCaptureObservation,SystemEmailDeliveryBinding,TEST_MESSAGE_PATH,
    verify_system_email_capture,
)


def binding():return SystemEmailDeliveryBinding('a'*48,'b'*64,'c'*64,'d'*64)


def observations(value):
    before=SystemEmailCaptureObservation(value.capture_scope_digest,value.recipient_digest,'e'*64,0,True)
    return before,replace(before,matched_messages=1)


def test_fixed_native_request_accepts_no_arbitrary_mailbox_or_message_body():
    value=binding();body=json.loads(value._encode())
    assert TEST_MESSAGE_PATH=='/api/v2/monitor/system/debug/email'
    assert body=={'email':'mcp-smtp-'+'a'*48+'@capture.invalid'}
    with pytest.raises(TypeError):SystemEmailDeliveryBinding('a'*48,'b'*64,'c'*64,'d'*64,recipient='other@example.test')
    assert 'capture.invalid'not in json.dumps(value.summary())
    assert value.summary()['test_send_authorized']is False
    assert 'redacted'in repr(value)


@pytest.mark.parametrize('fault',['nonce','scope','serial','configuration'])
def test_foreign_or_malformed_binding_is_refused_without_values(fault):
    fields=dict(nonce='a'*48,capture_scope_digest='b'*64,source_serial_digest='c'*64,configuration_digest='d'*64)
    fields[{'nonce':'nonce','scope':'capture_scope_digest','serial':'source_serial_digest',
        'configuration':'configuration_digest'}[fault]]='SYNTHETIC_PRIVATE_MARKER'
    with pytest.raises(ValueError)as error:SystemEmailDeliveryBinding(**fields)
    assert 'SYNTHETIC_PRIVATE_MARKER'not in str(error.value)


def test_complete_selected_capture_is_not_native_send_or_provenance_qualification():
    value=binding();before,after=observations(value)
    result=verify_system_email_capture(value,before,after)
    assert result['matching_capture_observed']is True and result['matched_messages']==1
    assert result['source_provenance_qualified']is False
    assert result['native_ack_qualified']is False and result['native_delivery_qualified']is False
    assert result['test_send_authorized']is False and result['raw_message_content_returned']is False
    assert value.recipient_digest not in json.dumps(result)


@pytest.mark.parametrize('fault',['existing','empty','duplicate','before-incomplete','after-incomplete',
    'scope','recipient','window'])
def test_wrong_incomplete_or_duplicate_capture_never_becomes_delivery(fault):
    value=binding();before,after=observations(value)
    if fault=='existing':before=replace(before,matched_messages=1)
    elif fault=='empty':after=replace(after,matched_messages=0)
    elif fault=='duplicate':after=replace(after,matched_messages=2)
    elif fault=='before-incomplete':before=replace(before,complete=False)
    elif fault=='after-incomplete':after=replace(after,complete=False)
    elif fault=='scope':after=replace(after,capture_scope_digest='f'*64)
    elif fault=='recipient':after=replace(after,recipient_digest='f'*64)
    elif fault=='window':after=replace(after,window_digest='f'*64)
    with pytest.raises(ValueError):verify_system_email_capture(value,before,after)


@pytest.mark.parametrize('changes',[{'matched_messages':True},{'matched_messages':-1},
    {'complete':1},{'window_digest':'invalid'}])
def test_capture_types_are_exact(changes):
    before,_=observations(binding())
    with pytest.raises(ValueError):replace(before,**changes)


@pytest.mark.parametrize('field,value',[('nonce','f'*48),('capture_scope_digest','f'*64),
    ('source_serial_digest','f'*64),('configuration_digest','f'*64)])
def test_each_scope_component_binds_the_delivery_parameters(field,value):
    original=binding();changed=replace(original,**{field:value})
    assert changed.parameters_digest!=original.parameters_digest
