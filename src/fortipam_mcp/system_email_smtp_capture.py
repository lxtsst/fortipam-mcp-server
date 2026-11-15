"""Explicit loopback-only SMTP capture fixture; no relay, inbox or mail content.

This limited plaintext fixture discards DATA octets and records only accepted
fixed-mailbox transactions. It does not implement a production SMTP server,
sender queue inspection, native ACK qualification or runtime Tool registration.
Framing/line bounds follow RFC5321 sections4.1.1.4 and4.5.3.1.4/6.
"""
from __future__ import annotations

from collections.abc import Callable
import math
import secrets
import socket
from threading import RLock, Thread, current_thread
import time
from types import TracebackType
from typing import Protocol, Self

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .secret_metadata_http_transport import _zeroize_mutable
from .system_email_delivery_contract import SystemEmailCaptureObservation, SystemEmailDeliveryBinding

CONTRACT = "fortipam-system-email-loopback-smtp-capture/v1"
_ERROR = "The private loopback system-email capture is unavailable."
_MAX_DATA_BYTES = 65536


class SystemEmailSmtpCaptureError(RuntimeError):
    """Fixed failure without socket, envelope or content information."""


class _SmtpProtocolError(ValueError):
    pass


class LoopbackSystemEmailSmtpReservation(_OpaqueC3Object):
    """Own one fresh bound, unlistened loopback socket and transfer it once."""
    def __init__(self) -> None:
        handle = None
        try:
            handle = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            handle.bind(('127.0.0.1', 0))
            self._socket: socket.socket | None = handle
            self._port: int = handle.getsockname()[1]
            self._lock = RLock()
        except Exception:
            if handle is not None:
                handle.close()
            raise SystemEmailSmtpCaptureError(_ERROR) from None

    @property
    def port(self) -> int:
        return self._port

    def _consume(self) -> socket.socket:
        with self._lock:
            if self._socket is None:
                raise SystemEmailSmtpCaptureError(_ERROR)
            handle, self._socket = self._socket, None
            return handle

    def close(self) -> None:
        with self._lock:
            handle, self._socket = self._socket, None
        if handle is not None:
            handle.close()


class _SmtpCaptureSession(_OpaqueC3Object):
    """Bounded command buffer; DATA retains only framing counters and flags."""
    def __init__(self, recipient: bytes, reply: Callable[[bytes], None],
                 begin: Callable[[], None], end: Callable[[bool, bool], None]) -> None:
        self._recipient = b'<' + recipient + b'>'
        self._reply, self._begin, self._end = reply, begin, end
        self._command = bytearray()
        self._greeted = self._mail = self._selected = self._data = self._closed = False
        self._data_bytes = self._line_bytes = 0
        self._line_dot = self._previous_cr = False

    def _reset(self, *, incomplete: bool = False) -> None:
        selected = self._selected
        self._mail = self._selected = self._data = False
        self._data_bytes = self._line_bytes = 0
        self._line_dot = self._previous_cr = False
        if selected:
            self._end(False, incomplete)

    def _reject(self, response: bytes) -> None:
        self._reply(response)
        raise _SmtpProtocolError(_ERROR)

    def _command_line(self, command: memoryview) -> None:
        if any(value < 32 or value > 126 for value in command):
            self._reply(b'500 Invalid command\r\n')
            return
        verb = bytes(command[:4]).upper()
        if verb in (b'EHLO', b'HELO') and len(command) > 5 and command[4] == 32:
            self._reset(); self._greeted = True
            self._reply(b'250 capture.invalid\r\n')
        elif verb == b'QUIT' and len(command) == 4:
            self._reset(); self._closed = True
            self._reply(b'221 Closing\r\n')
        elif verb == b'RSET' and len(command) == 4:
            self._reset(); self._reply(b'250 Reset\r\n')
        elif verb == b'NOOP' and (len(command) == 4 or command[4] == 32):
            self._reply(b'250 OK\r\n')
        elif verb == b'MAIL' and bytes(command[:10]).upper() == b'MAIL FROM:':
            if not self._greeted or self._mail:
                self._reply(b'503 Bad sequence\r\n')
            elif (len(command) < 12 or command[10] != 60 or command[-1] != 62
                    or any(value in (60, 62) for value in command[11:-1])):
                self._reply(b'501 Unsupported envelope\r\n')
            else:
                self._mail = True; self._reply(b'250 Sender accepted\r\n')
        elif verb == b'RCPT' and bytes(command[:8]).upper() == b'RCPT TO:':
            if not self._mail or self._selected:
                self._reply(b'503 Bad sequence\r\n')
            elif command[8:] != self._recipient:
                self._reply(b'550 Fixed mailbox only\r\n')
            else:
                self._begin(); self._selected = True
                self._reply(b'250 Recipient accepted\r\n')
        elif verb == b'DATA' and len(command) == 4:
            if not self._selected:
                self._reply(b'503 Bad sequence\r\n')
            else:
                self._data = True; self._reply(b'354 End with dot\r\n')
        else:
            self._reply(b'502 Unsupported command\r\n')

    def _data_octet(self, value: int) -> None:
        self._data_bytes += 1; self._line_bytes += 1
        if self._line_bytes == 1:
            self._line_dot = value == 46
        if self._data_bytes > _MAX_DATA_BYTES + 3 or self._line_bytes > 1000 + int(self._line_dot):
            self._reject(b'552 Capture limit exceeded\r\n')
        if value == 10:
            if not self._previous_cr:
                self._reject(b'500 CRLF required\r\n')
            if self._line_dot and self._line_bytes == 3:
                self._selected = False
                self._reset()
                self._end(True, False)
                self._reply(b'250 Captured\r\n')
                return
            self._line_bytes = 0; self._line_dot = self._previous_cr = False
        else:
            if self._previous_cr:
                self._reject(b'500 CRLF required\r\n')
            self._previous_cr = value == 13

    def feed(self, incoming: memoryview) -> None:
        for value in incoming:
            if self._closed:
                break
            if self._data:
                self._data_octet(value)
            else:
                self._command.append(value)
                if len(self._command) > 512:
                    self._reject(b'500 Command limit exceeded\r\n')
                if value == 10:
                    try:
                        if len(self._command) < 2 or self._command[-2] != 13:
                            self._reject(b'500 CRLF required\r\n')
                        with memoryview(self._command)[:-2] as command:
                            self._command_line(command)
                    finally:
                        _zeroize_mutable(self._command)

    def close(self) -> None:
        self._closed = True
        self._reset(incomplete=True)
        _zeroize_mutable(self._command)


class _SmtpCaptureBinding(Protocol):
    @property
    def capture_scope_digest(self) -> str: ...
    @property
    def recipient_digest(self) -> str: ...
    @property
    def parameters_digest(self) -> str: ...
    def _recipient(self) -> str: ...


class _LoopbackSmtpCapture(_OpaqueC3Object):
    """Private bounded receiver core; public wrappers own exact binding types."""
    def __init__(self, binding: _SmtpCaptureBinding, *, contract: str, window_digest: str,
                 lifetime_seconds: int = 120, clock: Callable[[], float] = time.monotonic,
                 _reservation: LoopbackSystemEmailSmtpReservation | None = None) -> None:
        listener = None
        try:
            if (type(lifetime_seconds) is not int
                    or not 1 <= lifetime_seconds <= 300 or not callable(clock)):
                raise ValueError
            require_digest(window_digest, 'window_digest')
            if _reservation is not None and type(_reservation) is not LoopbackSystemEmailSmtpReservation:
                raise ValueError
            self._binding, self._window = binding, window_digest
            self._source_digest = canonical_digest({'contract': contract, 'binding': binding.parameters_digest,
                'window': window_digest, 'instance': secrets.token_hex(32)})
            self._clock, self._lifetime = clock, lifetime_seconds
            self._last_now = -1.0
            self._expires_at = 0.0
            self._started = self._ended = self._failed = False
            self._messages = self._pending = 0
            # The reservation allocates only a fresh, unlistened socket. This
            # transfer avoids nonportable SO_ACCEPTCONN introspection or adoption
            # of an arbitrary existing listener/client.
            listener = _reservation._consume() if _reservation is not None else None
            self._listener = listener
            self._thread: Thread | None = None
            self._clients: dict[socket.socket, Thread] = {}
            self._port: int | None = _reservation.port if _reservation is not None else None
            self._lock = RLock()
        except Exception:
            if listener is not None:
                listener.close()
            raise SystemEmailSmtpCaptureError(_ERROR) from None

    @property
    def source_digest(self) -> str:
        return self._source_digest

    @property
    def window_digest(self) -> str:
        return self._window

    def _now(self) -> float:
        now = self._clock()
        if (type(now) not in (int, float) or not math.isfinite(now) or now < 0 or now < self._last_now):
            self._failed = True
            raise ValueError
        self._last_now = float(now)
        return float(now)

    def _running(self) -> bool:
        return self._started and not self._ended and not self._failed and self._now() < self._expires_at

    def _begin(self) -> None:
        with self._lock:
            if not self._running():
                raise _SmtpProtocolError(_ERROR)
            self._pending += 1

    def _end(self, accepted: bool, incomplete: bool) -> None:
        with self._lock:
            self._pending -= 1
            self._failed = self._failed or incomplete
            if accepted:
                if not self._running():
                    self._failed = True
                    raise _SmtpProtocolError(_ERROR)
                else:
                    self._messages += 1

    def observe(self, binding: _SmtpCaptureBinding) -> SystemEmailCaptureObservation:
        try:
            with self._lock:
                if binding is not self._binding:
                    raise ValueError
                return SystemEmailCaptureObservation(binding.capture_scope_digest, binding.recipient_digest,
                    self.window_digest, self._messages, self._running() and self._pending == 0)
        except Exception:
            raise SystemEmailSmtpCaptureError(_ERROR) from None

    def start(self) -> Self:
        with self._lock:
            if self._started or self._ended:
                raise SystemEmailSmtpCaptureError(_ERROR)
            self._started = True
            listener = self._listener
        try:
            with self._lock:
                self._expires_at = self._now() + self._lifetime
                if listener is None:
                    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    listener.bind(('127.0.0.1', 0))
                listener.listen(4); listener.settimeout(0.2)
                self._listener, self._port = listener, listener.getsockname()[1]
                self._thread = Thread(target=self._serve, args=(listener,), daemon=True)
                self._thread.start()
            return self
        except Exception:
            if listener is not None:
                listener.close()
            with self._lock:
                self._failed = self._ended = True
            raise SystemEmailSmtpCaptureError(_ERROR) from None

    def _serve(self, listener: socket.socket) -> None:
        try:
            while True:
                with self._lock:
                    if not self._running():
                        break
                try:
                    client, _ = listener.accept()
                except TimeoutError:
                    continue
                with self._lock:
                    if not self._running() or len(self._clients) >= 4:
                        self._failed = True; client.close()
                        continue
                    thread = Thread(target=self._receive, args=(client,), daemon=True)
                    self._clients[client] = thread
                    thread.start()
        except Exception:
            with self._lock:
                if not self._ended:
                    self._failed = True
        finally:
            listener.close()
            with self._lock:
                self._ended = True

    def _receive(self, client: socket.socket) -> None:
        session = _SmtpCaptureSession(self._binding._recipient().encode('ascii'), client.sendall, self._begin, self._end)
        raw = bytearray(1024)
        try:
            with self._lock:
                deadline = min(self._expires_at, self._now() + 10)
            client.settimeout(10); client.sendall(b'220 capture.invalid\r\n')
            while not session._closed:
                with self._lock:
                    if not self._running():
                        break
                    remaining = deadline - self._now()
                if remaining <= 0:
                    break
                # Closing a socket from another thread did not reliably wake
                # recv_into on the current host. Poll the same transaction's
                # stop/deadline state instead of extending the close budget.
                client.settimeout(min(0.2, remaining))
                try:
                    count = client.recv_into(raw)
                except TimeoutError:
                    continue
                if count == 0:
                    break
                try:
                    with memoryview(raw)[:count] as incoming:
                        session.feed(incoming)
                finally:
                    raw[:] = b'\x00' * len(raw)
        except (OSError, _SmtpProtocolError):
            pass
        except Exception:
            with self._lock:
                self._failed = True
        finally:
            session.close(); _zeroize_mutable(raw); client.close()
            with self._lock:
                self._clients.pop(client, None)

    def close(self) -> None:
        with self._lock:
            self._ended = True
            listener, self._listener = self._listener, None
            clients = list(self._clients.items())
            thread = self._thread
        if listener is not None:
            listener.close()
        for client, _ in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # A peer may already have closed this accepted socket.
            client.close()
        for worker in [thread, *(worker for _, worker in clients)]:
            if worker is not None and worker is not current_thread():
                worker.join(timeout=1)
                if worker.is_alive():
                    with self._lock:
                        self._failed = True
                    raise SystemEmailSmtpCaptureError(_ERROR)

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, kind: type[BaseException] | None, value: BaseException | None,
                 traceback: TracebackType | None) -> None:
        self.close()


class LoopbackSystemEmailSmtpCapture(_LoopbackSmtpCapture):
    """Exact legacy debug-test receiver; no short/foreign binding admission."""
    def __init__(self, binding: SystemEmailDeliveryBinding, *, window_digest: str,
                 lifetime_seconds: int = 120, clock: Callable[[],float] = time.monotonic,
                 _reservation: LoopbackSystemEmailSmtpReservation | None = None) -> None:
        if type(binding) is not SystemEmailDeliveryBinding: raise SystemEmailSmtpCaptureError(_ERROR)
        super().__init__(binding,contract=CONTRACT,window_digest=window_digest,
            lifetime_seconds=lifetime_seconds,clock=clock,_reservation=_reservation)
