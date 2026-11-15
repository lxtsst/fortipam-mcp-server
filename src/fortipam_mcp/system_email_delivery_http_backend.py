"""Default-closed fixed test-mail POST with separately bound local evidence.

Neither the candidate monitor ACK nor injected receiver/sender observations
qualify native delivery. No startup, credentials loader or evidence producer is
installed here. A mailbox count is never used to infer sender queue quiescence.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import http.client
from threading import RLock
import time
from typing import Any, Protocol, runtime_checkable

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .system_email_configuration_http_backend import SystemEmailConfigurationHttpBackend
from .system_email_delivery_contract import SystemEmailCaptureObservation, SystemEmailDeliveryBinding
from .system_email_delivery_m4_adapter import SystemEmailDeliveryInspection
from .system_email_http_exchange import _SystemEmailHttpExchange, SystemEmailOriginalHttpAck
from .system_email_m4_adapter import SystemEmailBackendReceipt, system_email_execution_digests, system_email_state_digest

_ERROR = "The private system-email delivery HTTP backend is unavailable."


class SystemEmailDeliveryHttpError(RuntimeError):
    """Fixed refusal without receiver, response, mailbox or configuration data."""


@dataclass(frozen=True, slots=True, repr=False)
class SystemEmailDeliverySourceObservation(_OpaqueC3Object):
    """Minimized receiver and sender source data; no provenance is inferred."""
    capture_source_digest: str
    sender_source_digest: str
    binding_digest: str
    capture: SystemEmailCaptureObservation
    sender_in_flight: int
    quiescence_complete: bool
    observed_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value in (self.capture_source_digest, self.sender_source_digest, self.binding_digest):
            require_digest(value, "source_digest")
        if (type(self.capture) is not SystemEmailCaptureObservation
                or type(self.sender_in_flight) is not int or self.sender_in_flight < 0
                or type(self.quiescence_complete) is not bool
                or type(self.observed_at) is not int or type(self.expires_at) is not int
                or not 0 <= self.observed_at < self.expires_at <= self.observed_at + 10):
            raise ValueError(_ERROR)


@runtime_checkable
class SystemEmailDeliveryEvidenceReader(Protocol):
    def observe(self, binding: SystemEmailDeliveryBinding) -> SystemEmailDeliverySourceObservation: ...


class SystemEmailDeliveryHttpBackend(_OpaqueC3Object):
    def __init__(self, configuration: SystemEmailConfigurationHttpBackend, binding: SystemEmailDeliveryBinding,
                 evidence: SystemEmailDeliveryEvidenceReader, *, capture_source_digest: str,
                 sender_source_digest: str, window_digest: str,
                 execution_enabled: Callable[[], bool] | None = None,
                 source_guard: Callable[[], bool] | None = None,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
                 http_clock: Callable[[], float] = time.monotonic,
                 clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(configuration) is not SystemEmailConfigurationHttpBackend
                    or type(binding) is not SystemEmailDeliveryBinding
                    or not isinstance(evidence, SystemEmailDeliveryEvidenceReader) or not callable(clock)):
                raise ValueError
            for value in (capture_source_digest, sender_source_digest, window_digest):
                require_digest(value, "source_digest")
            if (capture_source_digest == sender_source_digest
                    or binding.source_serial_digest != configuration._transition.original.source_serial_digest
                    or binding.configuration_digest != system_email_execution_digests(
                        configuration._transition, binding.parameters_digest)[1]):
                raise ValueError
            self._configuration, self._binding, self._evidence = configuration, binding, evidence
            self._capture_source, self._sender_source, self._window = capture_source_digest, sender_source_digest, window_digest
            self._clock, self._last_now, self._closed = clock, -1, False
            self._http = _SystemEmailHttpExchange(configuration._source, execution_enabled=execution_enabled,
                source_guard=source_guard, connection_factory=connection_factory, http_clock=http_clock)
            self._attempted = False
            self._ack: SystemEmailOriginalHttpAck | None = None
            self._lock = RLock()
        except Exception:
            raise SystemEmailDeliveryHttpError(_ERROR) from None

    def _now(self) -> int:
        now = self._clock()
        if self._closed or type(now) is not int or now < 0 or now < self._last_now:
            self._closed = True
            raise ValueError
        self._last_now = now
        return now

    def _bound(self, binding: SystemEmailDeliveryBinding) -> None:
        self._now()
        if binding is not self._binding:
            raise ValueError
        self._configuration._http._available()

    def inspect(self, binding: SystemEmailDeliveryBinding) -> SystemEmailDeliveryInspection:
        try:
            with self._lock:
                self._bound(binding)
                configuration = self._configuration.inspect()
                self._configuration._transition.verify_applied(configuration)
                if system_email_state_digest(configuration) != binding.configuration_digest:
                    raise ValueError
                evidence = self._evidence.observe(binding)
                now = self._now()
                if (type(evidence) is not SystemEmailDeliverySourceObservation
                        or evidence.capture_source_digest != self._capture_source
                        or evidence.sender_source_digest != self._sender_source
                        or evidence.binding_digest != binding.parameters_digest
                        or not evidence.observed_at <= now < evidence.expires_at
                        or evidence.capture.capture_scope_digest != binding.capture_scope_digest
                        or evidence.capture.recipient_digest != binding.recipient_digest
                        or evidence.capture.window_digest != self._window):
                    raise ValueError
                return SystemEmailDeliveryInspection(configuration, evidence.capture,
                    evidence.sender_in_flight, evidence.quiescence_complete)
        except Exception:
            raise SystemEmailDeliveryHttpError(_ERROR) from None

    def send_test(self, binding: SystemEmailDeliveryBinding, *, before_send: Callable[[], int],
                  timeout_seconds: int) -> SystemEmailBackendReceipt:
        try:
            with self._lock:
                self._bound(binding)
                self._http._available(write=True)
                ack = self._configuration._acks.get("update")
                if (self._attempted or not callable(before_send) or type(timeout_seconds) is not int
                        or timeout_seconds <= 0 or ack is None or "restore" in self._configuration._acks
                        or ack.source_serial_digest != binding.source_serial_digest
                        or ack.request_digest != self._configuration._transition.proposed.request_digest):
                    raise ValueError
                self._attempted = True
                self._ack = self._http.exchange("test-delivery", binding._encode(), binding.request_digest,
                    before_send, timeout_seconds)
                return SystemEmailBackendReceipt(self._ack.source_serial_digest, self._ack.request_digest)
        except Exception:
            raise SystemEmailDeliveryHttpError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._http.close()
