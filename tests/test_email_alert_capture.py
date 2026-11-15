"""Short fixed alert mailbox; shared bounded parser never supplies delivery authority."""
from dataclasses import replace
import json
import smtplib

import pytest

from fortipam_mcp.email_alert_capture import EmailAlertCaptureBinding,LoopbackEmailAlertSmtpCapture
from fortipam_mcp.email_alert_general_contract import EmailAlertGeneralPlan
from fortipam_mcp.system_email_capture_evidence import SystemEmailCaptureEvidenceReader
from fortipam_mcp.system_email_delivery_contract import SystemEmailDeliveryBinding
from fortipam_mcp.system_email_smtp_capture import LoopbackSystemEmailSmtpCapture,SystemEmailSmtpCaptureError,_SmtpCaptureSession
from test_email_alert_general_contract import fixture,project


def binding(): return EmailAlertCaptureBinding('a'*32,'b'*64,'c'*64,'d'*64)


def test_short_binding_fits_the_native_general_profile_without_accepting_arbitrary_addresses():
    value = binding(); assert len(value._recipient()) == 58
    schema,row = fixture(); plan = EmailAlertGeneralPlan(project(schema,row),value.mail_scope())
    body = plan.compile(plan.baseline)
    try: assert json.loads(body)['email-to'] == [dict(name=value._recipient())]
    finally: body[:] = b'\0'*len(body)
    assert value._recipient() not in json.dumps(value.summary()) and value.nonce not in repr(value)
    for key in ('recipient_authority_verified','sender_quiescence_verified','native_delivery_verified',
        'alert_trigger_verified','execution_authorized'): assert value.summary()[key] is False


@pytest.mark.parametrize('nonce',['a'*48,'a'*31,'A'*32,'not-an-address'])
def test_short_scope_has_its_own_fixed_nonce_grammar(nonce):
    with pytest.raises(ValueError): replace(binding(),nonce=nonce)


def test_legacy_and_alert_capture_bindings_are_not_interchangeable():
    short = binding(); legacy = SystemEmailDeliveryBinding('a'*48,'b'*64,'c'*64,'d'*64)
    with pytest.raises(SystemEmailSmtpCaptureError): LoopbackSystemEmailSmtpCapture(short,window_digest='e'*64)
    with pytest.raises(SystemEmailSmtpCaptureError): LoopbackEmailAlertSmtpCapture(legacy,window_digest='e'*64)
    receiver = LoopbackEmailAlertSmtpCapture(short,window_digest='e'*64)
    with pytest.raises(ValueError): SystemEmailCaptureEvidenceReader(receiver,sender_source_digest='f'*64)
    with pytest.raises(SystemEmailSmtpCaptureError): receiver.observe(replace(short))
    assert len(legacy._recipient()) == 73 and short.parameters_digest != legacy.parameters_digest
    receiver.close()


def test_short_capture_reuses_the_discarding_parser_without_an_empty_receiver_inference():
    value = binding(); replies = []; counts = dict(pending=0,messages=0)
    def begin(): counts['pending'] += 1
    def end(accepted,incomplete): counts['pending'] -= 1; counts['messages'] += int(accepted)
    session = _SmtpCaptureSession(value._recipient().encode(),replies.append,begin,end)
    wire = (b'EHLO synthetic.invalid\r\nMAIL FROM:<>\r\nRCPT TO:<' + value._recipient().encode()
        + b'>\r\nDATA\r\nSubject: Synthetic\r\n\r\nSYNTHETIC_PRIVATE_ALERT_BODY\r\n.\r\nQUIT\r\n')
    for octet in wire:
        with memoryview(bytes([octet])) as view: session.feed(view)
    session.close()
    assert counts == dict(pending=0,messages=1) and not session._command
    assert all(b'SYNTHETIC_PRIVATE_ALERT_BODY' not in v for v in vars(session).values() if isinstance(v,(bytes,bytearray)))
    assert not binding().summary()['native_delivery_verified']


def test_real_loopback_short_capture_accepts_only_its_mailbox_and_keeps_legacy_separate():
    value = binding(); capture = LoopbackEmailAlertSmtpCapture(value,window_digest='e'*64)
    with capture:
        assert capture._listener.getsockname()[0] == '127.0.0.1'
        with smtplib.SMTP('127.0.0.1',capture._port,timeout=3,local_hostname='synthetic.invalid') as client:
            with pytest.raises(smtplib.SMTPRecipientsRefused):
                client.sendmail('sender@synthetic.invalid','mcp-smtp-'+'a'*48+'@capture.invalid',b'Refused')
            client.sendmail('sender@synthetic.invalid',value._recipient(),b'Subject: Synthetic\r\n\r\nSYNTHETIC_PRIVATE_ALERT_BODY\r\n')
        observed = capture.observe(value)
        assert observed.matched_messages == 1 and observed.complete
    assert not capture.observe(value).complete and not value.summary()['alert_trigger_verified']
