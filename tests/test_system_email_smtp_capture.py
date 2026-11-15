"""Selected SMTP transactions, discarded DATA and independent sender evidence."""
from dataclasses import replace
import smtplib
import socket

import pytest

from fortipam_mcp.system_email_capture_evidence import (
    SystemEmailCaptureEvidenceReader, SystemEmailSenderObservation,
)
from fortipam_mcp.system_email_delivery_contract import SystemEmailDeliveryBinding
from fortipam_mcp.system_email_smtp_capture import (
    LoopbackSystemEmailSmtpCapture, LoopbackSystemEmailSmtpReservation,
    SystemEmailSmtpCaptureError, _SmtpCaptureSession, _SmtpProtocolError,
)
from test_system_email_m4_adapter import Clock


def binding():
    return SystemEmailDeliveryBinding('a'*48, 'b'*64, '1'*64, '2'*64)


class Transactions:
    def __init__(self):
        self.pending = self.messages = self.ends = 0; self.incomplete = False; self.replies = []
    def begin(self): self.pending += 1
    def end(self, accepted, incomplete):
        self.ends += 1; self.pending -= 1; self.messages += int(accepted)
        self.incomplete |= incomplete
    def session(self):
        return _SmtpCaptureSession(binding()._recipient().encode(), self.replies.append, self.begin, self.end)


def envelope():
    return (b'EHLO synthetic.invalid\r\nMAIL FROM:<sender@example.invalid>\r\nRCPT TO:<'
        + binding()._recipient().encode() + b'>\r\nDATA\r\n')


def feed(session, raw):
    with memoryview(raw) as part: session.feed(part)


@pytest.mark.parametrize('chunk_size', [1, 7, 1024])
def test_complete_crlf_dot_frame_is_counted_without_retaining_data(chunk_size):
    transactions = Transactions(); session = transactions.session()
    wire = envelope() + b'Subject: Synthetic\r\n\r\nSYNTHETIC_PRIVATE_BODY\r\n..\r\n.\r\nQUIT\r\n'
    for offset in range(0, len(wire), chunk_size): feed(session, wire[offset:offset+chunk_size])
    session.close()
    assert transactions.messages == 1 and transactions.pending == 0 and transactions.ends == 1
    assert not transactions.incomplete and transactions.replies[-1].startswith(b'221')
    assert session._command == bytearray()
    assert all(b'SYNTHETIC_PRIVATE_BODY' not in value for value in vars(session).values() if isinstance(value, (bytes, bytearray)))


def test_dot_transparency_and_commands_in_data_do_not_end_or_control_the_session():
    transactions = Transactions(); session = transactions.session()
    feed(session, envelope() + b'..\r\nQUIT\r\nRSET\r\n')
    assert transactions.messages == 0 and transactions.pending == 1
    feed(session, b'.\r\n')
    assert transactions.messages == 1 and transactions.pending == 0
    session.close()


@pytest.mark.parametrize('wire', [
    b'body\n.\n', b'body\rX\r\n.\r\n', b'x'*999+b'\r\n.\r\n',
    (b'x'*998+b'\r\n')*66+b'.\r\n',
])
def test_invalid_or_oversized_selected_data_cannot_create_complete_capture(wire):
    transactions = Transactions(); session = transactions.session(); feed(session, envelope())
    with pytest.raises(_SmtpProtocolError): feed(session, wire)
    session.close(); session.close()
    assert transactions.messages == 0 and transactions.incomplete
    assert transactions.pending == 0 and transactions.ends == 1 and not session._command


def test_transparency_dot_does_not_reduce_the_supported_line_length():
    transactions = Transactions(); session = transactions.session()
    feed(session, envelope() + b'..' + b'x'*997 + b'\r\n.\r\n')
    assert transactions.messages == 1
    session.close()


def test_unfinished_selected_data_is_incomplete_and_is_not_counted():
    transactions = Transactions(); session = transactions.session()
    feed(session, envelope() + b'partial private body')
    session.close(); session.close()
    assert transactions.messages == 0 and transactions.incomplete
    assert transactions.pending == 0 and transactions.ends == 1


def test_reset_discards_selected_envelope_and_duplicate_messages_are_counted():
    transactions = Transactions(); session = transactions.session()
    feed(session, envelope().removesuffix(b'DATA\r\n') + b'RSET\r\n')
    assert transactions.pending == 0 and not transactions.incomplete
    for _ in range(2): feed(session, envelope() + b'.\r\n')
    session.close()
    assert transactions.messages == 2 and transactions.pending == 0


def test_other_mailboxes_and_unsupported_auth_are_not_a_relay_or_credential_decoder():
    transactions = Transactions(); session = transactions.session()
    feed(session, b'EHLO synthetic\r\nAUTH SYNTHETIC_PRIVATE_VALUE\r\nMAIL FROM:<>\r\nRCPT TO:<other@invalid>\r\nDATA\r\n')
    assert any(reply.startswith(b'550') for reply in transactions.replies)
    assert any(reply.startswith(b'502') for reply in transactions.replies)
    assert transactions.messages == transactions.pending == 0
    assert not session._command
    session.close()


def test_command_line_bound_and_crlf_are_enforced():
    for wire in (b'NOOP\n', b'NOOP '+b'x'*508+b'\r\n'):
        transactions = Transactions(); session = transactions.session()
        with pytest.raises(_SmtpProtocolError): feed(session, wire)
        session.close()
        assert not session._command and transactions.messages == 0


def test_failed_end_callback_is_never_called_again_by_cleanup():
    transactions = Transactions()
    def end(accepted, incomplete):
        transactions.end(accepted, incomplete)
        raise RuntimeError('Synthetic observer failure')
    session = _SmtpCaptureSession(binding()._recipient().encode(), transactions.replies.append, transactions.begin, end)
    with pytest.raises(RuntimeError): feed(session, envelope()+b'.\r\n')
    session.close()
    assert transactions.ends == 1 and transactions.pending == 0


class Sender:
    """Synthetic synchronous sender scope; not a FortiPAM queue source."""
    def __init__(self, clock): self.clock = clock; self.pending = 0; self.complete = True; self.fault = 'none'
    def observe(self, value):
        if self.fault == 'next-second': self.clock.value += 1
        if self.fault == 'backwards': self.clock.value -= 1
        now = self.clock()
        observed = SystemEmailSenderObservation('d'*64, value.parameters_digest, 'e'*64,
            self.pending, self.complete, now, now+10)
        if self.fault in ('source_digest', 'binding_digest', 'window_digest'):
            observed = replace(observed, **{self.fault: 'f'*64})
        if self.fault == 'stale': observed = replace(observed, observed_at=now-20, expires_at=now-10)
        if self.fault == 'future': observed = replace(observed, observed_at=now+1, expires_at=now+11)
        return observed


def test_default_evidence_reader_never_infers_sender_quiescence_from_empty_receiver():
    value = binding(); receiver = LoopbackSystemEmailSmtpCapture(value, window_digest='e'*64)
    reader = SystemEmailCaptureEvidenceReader(receiver, sender_source_digest='d'*64, clock=Clock())
    with pytest.raises(ValueError): reader.observe(value)
    assert receiver.observe(value).matched_messages == 0


@pytest.mark.parametrize('fault', ['source_digest', 'binding_digest', 'window_digest', 'stale', 'future'])
def test_sender_source_window_and_freshness_are_independently_checked(fault):
    value = binding(); clock = Clock(); sender = Sender(clock); sender.fault = fault
    receiver = LoopbackSystemEmailSmtpCapture(value, window_digest='e'*64)
    reader = SystemEmailCaptureEvidenceReader(receiver, sender_source_digest='d'*64, sender=sender, clock=clock)
    with pytest.raises(ValueError): reader.observe(value)


def test_fresh_sender_time_may_advance_during_observation_without_becoming_future():
    value = binding(); clock = Clock(); sender = Sender(clock); sender.fault = 'next-second'
    receiver = LoopbackSystemEmailSmtpCapture(value, window_digest='e'*64)
    reader = SystemEmailCaptureEvidenceReader(receiver, sender_source_digest='d'*64, sender=sender, clock=clock)
    observed = reader.observe(value)
    assert observed.observed_at == clock() and observed.expires_at == clock()+9
    assert observed.capture.complete is False and observed.quiescence_complete is True


def test_foreign_binding_and_backwards_clock_cannot_refresh_evidence():
    value = binding(); clock = Clock(); sender = Sender(clock)
    receiver = LoopbackSystemEmailSmtpCapture(value, window_digest='e'*64)
    reader = SystemEmailCaptureEvidenceReader(receiver, sender_source_digest='d'*64, sender=sender, clock=clock)
    with pytest.raises(ValueError): reader.observe(replace(value))
    sender.fault = 'backwards'
    with pytest.raises(ValueError): reader.observe(value)
    clock.value = 1000; sender.fault = 'none'
    with pytest.raises(ValueError): reader.observe(value)


def test_arbitrary_socket_cannot_be_adopted_as_a_reserved_receiver():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as handle:
        with pytest.raises(SystemEmailSmtpCaptureError):
            LoopbackSystemEmailSmtpCapture(binding(), window_digest='e'*64, _reservation=handle)
        assert handle.fileno() >= 0


def test_real_loopback_reservation_transfers_once_and_preserves_the_consumer():
    value = binding(); reservation = LoopbackSystemEmailSmtpReservation()
    capture = LoopbackSystemEmailSmtpCapture(value, window_digest='e'*64, _reservation=reservation)
    try:
        reservation.close()  # The capture now owns the socket, not this wrapper.
        with pytest.raises(SystemEmailSmtpCaptureError):
            LoopbackSystemEmailSmtpCapture(value, window_digest='e'*64, _reservation=reservation)
        with capture:
            assert capture._port == reservation.port
            with smtplib.SMTP('127.0.0.1', capture._port, timeout=3, local_hostname='sender.invalid') as client:
                client.sendmail('sender@example.invalid', value._recipient(), b'Subject: Synthetic\r\n\r\nBody\r\n')
            assert capture.observe(value).matched_messages == 1
    finally:
        capture.close(); reservation.close()


def test_real_loopback_smtp_counts_only_fixed_mailbox_and_discards_content():
    value = binding(); capture = LoopbackSystemEmailSmtpCapture(value, window_digest='e'*64)
    with capture:
        assert capture._listener.getsockname()[0] == '127.0.0.1'
        assert capture.observe(value).complete
        with smtplib.SMTP('127.0.0.1', capture._port, timeout=3, local_hostname='sender.invalid') as client:
            client.sendmail('sender@example.invalid', value._recipient(), b'Subject: Synthetic\r\n\r\nSYNTHETIC_PRIVATE_BODY\r\n')
            observed = capture.observe(value)
            assert observed.matched_messages == 1 and observed.complete
            with pytest.raises(smtplib.SMTPRecipientsRefused):
                client.sendmail('sender@example.invalid', 'other@invalid', b'Not accepted')
            client.sendmail('sender@example.invalid', value._recipient(), b'Subject: duplicate\r\n\r\n..\r\n')
            assert capture.observe(value).matched_messages == 2
        port = capture._port
        with pytest.raises(SystemEmailSmtpCaptureError): capture.start()
        assert capture._port == port and capture.observe(value).complete
    assert capture.observe(value).matched_messages == 2 and not capture.observe(value).complete
    assert not capture._thread.is_alive() and not capture._clients
    with pytest.raises(SystemEmailSmtpCaptureError): capture.start()


def test_real_loopback_shutdown_cannot_promote_partial_data():
    value = binding(); capture = LoopbackSystemEmailSmtpCapture(value, window_digest='e'*64).start()
    client = smtplib.SMTP('127.0.0.1', capture._port, timeout=3, local_hostname='sender.invalid')
    try:
        client.ehlo(); client.mail('sender@example.invalid'); client.rcpt(value._recipient())
        assert client.docmd('DATA')[0] == 354
        client.sock.sendall(b'Unfinished synthetic body')
        assert not capture.observe(value).complete
        capture.close()
        assert capture.observe(value).matched_messages == 0 and not capture.observe(value).complete
        assert capture._pending == 0 and not capture._clients
    finally:
        client.close(); capture.close()


def test_real_loopback_expired_window_cannot_be_reopened():
    value = binding(); clock = Clock()
    capture = LoopbackSystemEmailSmtpCapture(value, window_digest='e'*64, lifetime_seconds=1, clock=clock).start()
    try:
        assert capture.observe(value).complete
        clock.value += 2
        assert not capture.observe(value).complete
        with pytest.raises(SystemEmailSmtpCaptureError): capture.start()
    finally:
        capture.close()
