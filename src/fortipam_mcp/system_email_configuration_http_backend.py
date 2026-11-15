"""Default-closed build29 singleton HTTP backend candidate.

The PUT route/body are source-backed. The accepted CMDB acknowledgement shape
is a local candidate, not a producer-qualified system-email ACK. No environment
loader or normal startup binds this backend. A qualified host still needs
independent source, isolation and permission gates, M4 and full readback.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import http.client
from threading import RLock
import time
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from .secret_metadata_http_transport import _zeroize_mutable
from .system_email_http_exchange import (
    _SystemEmailHttpExchange, SystemEmailOriginalHttpAck as SystemEmailOriginalConfigurationAck,
)
from .system_email_configuration_contract import CONTRACT as PAYLOAD_CONTRACT, SystemEmailEmptyAuthDraft
from .system_email_configuration_transition import SystemEmailConfigurationTransition
from .system_email_m4_adapter import SystemEmailBackendReceipt
from .system_email_native_source import SystemEmailNativeSource, SystemEmailSourceBoundDraft

CONTRACT = "fortipam-build29-system-email-http-candidate/v1"
_ERROR = "The private system-email HTTP backend is unavailable."


class SystemEmailConfigurationHttpError(RuntimeError):
    """Fixed refusal without payload, response, endpoint or credentials."""


class SystemEmailConfigurationHttpBackend(_OpaqueC3Object):
    """Only the two pinned update/restore bodies, each attempted once per host.

    The M4 ledger owns durable no-replay and the caller's guard owns authority;
    the local attempt set is not an independent durable recovery provider.
    """

    def __init__(self, source: SystemEmailNativeSource, transition: SystemEmailConfigurationTransition, *,
                 execution_enabled: Callable[[], bool] | None = None,
                 source_guard: Callable[[], bool] | None = None,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
                 http_clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(source) is not SystemEmailNativeSource
                    or type(transition) is not SystemEmailConfigurationTransition
                    or not callable(connection_factory) or not callable(http_clock)
                    or any(value is not None and not callable(value) for value in (execution_enabled, source_guard))
                    or transition.original.source_serial_digest != hashlib.sha256(source._serial.encode()).hexdigest()
                    or transition.original.draft.request_digest == transition.proposed.request_digest):
                raise ValueError
            self._source, self._transition, self._config = source, transition, source._config
            self._http = _SystemEmailHttpExchange(source, execution_enabled=execution_enabled,
                source_guard=source_guard, connection_factory=connection_factory, http_clock=http_clock)
            self._attempted: set[str] = set()
            self._acks: dict[str, SystemEmailOriginalConfigurationAck] = {}
            self._lock = RLock()
        except Exception:
            raise SystemEmailConfigurationHttpError(_ERROR) from None

    def inspect(self) -> SystemEmailSourceBoundDraft:
        try:
            with self._lock:
                self._http._available()
                return self._source.read_empty_auth_payload()
        except Exception:
            raise SystemEmailConfigurationHttpError(_ERROR) from None

    def submit(self, draft: SystemEmailEmptyAuthDraft, *, before_send: Callable[[], int],
               timeout_seconds: int) -> SystemEmailBackendReceipt:
        try:
            with self._lock:
                self._http._available(write=True)
                if (type(draft) is not SystemEmailEmptyAuthDraft or not callable(before_send)
                        or type(timeout_seconds) is not int or timeout_seconds <= 0
                        or draft.request_digest in self._attempted):
                    raise ValueError
                if draft is self._transition.proposed:
                    phase = "update"
                elif draft is self._transition.original.draft and "update" in self._acks:
                    phase = "restore"
                else:
                    raise ValueError
                body = draft._encode()
                if not hmac.compare_digest(draft.request_digest,
                        hashlib.sha256(PAYLOAD_CONTRACT.encode() + b"\x00" + body).hexdigest()):
                    _zeroize_mutable(body)
                    raise ValueError
                # Failure before/after egress does not reopen this body's slot.
                self._attempted.add(draft.request_digest)
                ack = self._http.exchange("configuration", body, draft.request_digest, before_send, timeout_seconds)
                self._acks[phase] = ack
                return SystemEmailBackendReceipt(ack.source_serial_digest, ack.request_digest)
        except Exception:
            raise SystemEmailConfigurationHttpError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._http.close()
