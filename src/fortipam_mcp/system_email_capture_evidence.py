"""Join an owned SMTP receiver to a separately supplied sender-state source.

No product sender-queue producer is provided. An empty/idle receiver cannot
replace that source, and this composition supplies no native qualification.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import time
from typing import Protocol, runtime_checkable

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .system_email_delivery_contract import SystemEmailDeliveryBinding
from .system_email_delivery_http_backend import SystemEmailDeliverySourceObservation
from .system_email_smtp_capture import LoopbackSystemEmailSmtpCapture

_ERROR = "The private system-email capture evidence is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class SystemEmailSenderObservation(_OpaqueC3Object):
    source_digest: str
    binding_digest: str
    window_digest: str
    in_flight: int
    complete: bool
    observed_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value in (self.source_digest, self.binding_digest, self.window_digest):
            require_digest(value, 'source_digest')
        if (type(self.in_flight) is not int or self.in_flight < 0 or type(self.complete) is not bool
                or type(self.observed_at) is not int or type(self.expires_at) is not int
                or not 0 <= self.observed_at < self.expires_at <= self.observed_at + 10):
            raise ValueError(_ERROR)


@runtime_checkable
class SystemEmailSenderEvidenceReader(Protocol):
    def observe(self, binding: SystemEmailDeliveryBinding) -> SystemEmailSenderObservation: ...


class SystemEmailCaptureEvidenceReader(_OpaqueC3Object):
    def __init__(self, receiver: LoopbackSystemEmailSmtpCapture, *, sender_source_digest: str,
                 sender: SystemEmailSenderEvidenceReader | None = None,
                 clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            require_digest(sender_source_digest, 'sender_source_digest')
            if (type(receiver) is not LoopbackSystemEmailSmtpCapture or not callable(clock)
                    or sender is not None and not isinstance(sender, SystemEmailSenderEvidenceReader)
                    or sender_source_digest == receiver.source_digest):
                raise ValueError
            self._receiver, self._sender, self._source = receiver, sender, sender_source_digest
            self._clock, self._last_now = clock, -1
            self._failed_clock = False
        except Exception:
            raise ValueError(_ERROR) from None

    def _now(self) -> int:
        try:
            now = self._clock()
            if self._failed_clock or type(now) is not int or now < 0 or now < self._last_now:
                raise ValueError
            self._last_now = now
            return now
        except Exception:
            self._failed_clock = True
            raise ValueError(_ERROR) from None

    def observe(self, binding: SystemEmailDeliveryBinding) -> SystemEmailDeliverySourceObservation:
        try:
            if binding is not self._receiver._binding or self._sender is None:
                raise ValueError
            start = self._now()
            sender = self._sender.observe(binding)
            if (type(sender) is not SystemEmailSenderObservation or sender.source_digest != self._source
                    or sender.binding_digest != binding.parameters_digest
                    or sender.window_digest != self._receiver.window_digest):
                raise ValueError
            capture = self._receiver.observe(binding)
            now = self._now()
            expires = min(sender.expires_at, start + 10)
            if not start <= now < expires or sender.observed_at > now:
                raise ValueError
            return SystemEmailDeliverySourceObservation(self._receiver.source_digest, sender.source_digest,
                binding.parameters_digest, capture, sender.in_flight, sender.complete, sender.observed_at, expires)
        except Exception:
            raise ValueError(_ERROR) from None
