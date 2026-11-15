"""Private local SMTP-test request and capture comparison, without mail I/O.

Pinned build29 Settings module2367 posts exactly {email: emailTo} to the fixed
monitor route. Only a generated test mailbox is encodable here. Capture DTOs
remain caller-owned private observations, not source provenance or native ACKs.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

CONTRACT="fortipam-build29-system-email-local-delivery/v1"
TEST_MESSAGE_PATH="/api/v2/monitor/system/debug/email"
NATIVE_SETTINGS_SHA256="af9f72445871576551f7b77a9bda6a1c137798f6eae0f944401094019d681eca"
_ERROR="The private system-email delivery contract is unavailable."
_NONCE=re.compile(r'[a-f0-9]{48}\Z')


@dataclass(frozen=True,slots=True,repr=False)
class SystemEmailDeliveryBinding(_OpaqueC3Object):
    """Fixed capture/device/configuration binding; no arbitrary recipient input."""
    nonce: str
    capture_scope_digest: str
    source_serial_digest: str
    configuration_digest: str

    def __post_init__(self) -> None:
        try:
            if type(self.nonce) is not str or _NONCE.fullmatch(self.nonce)is None:raise ValueError
            for value in(self.capture_scope_digest,self.source_serial_digest,self.configuration_digest):
                require_digest(value,"binding_digest")
        except Exception:raise ValueError(_ERROR)from None

    def _recipient(self) -> str:
        return 'mcp-smtp-'+self.nonce+'@capture.invalid'

    @property
    def recipient_digest(self) -> str:
        return hashlib.sha256(self._recipient().encode()).hexdigest()

    @property
    def parameters_digest(self) -> str:
        return canonical_digest({"contract":CONTRACT,"capture":self.capture_scope_digest,
            "serial":self.source_serial_digest,"configuration":self.configuration_digest,
            "recipient":self.recipient_digest})

    @property
    def request_digest(self) -> str:
        return canonical_digest({"contract":CONTRACT,"method":"POST","path":TEST_MESSAGE_PATH,
            "body":hashlib.sha256(self._encode()).hexdigest()})

    def _encode(self) -> bytearray:
        return bytearray(json.dumps({"email":self._recipient()},separators=(',',':')).encode())

    def summary(self) -> dict[str,object]:
        return dict(contract=CONTRACT,fixed_native_test_request_shape=True,
            arbitrary_recipient_supported=False,test_send_authorized=False,
            native_ack_qualified=False,native_delivery_qualified=False,
            recipient_or_configuration_values_returned=False)


@dataclass(frozen=True,slots=True,repr=False)
class SystemEmailCaptureObservation(_OpaqueC3Object):
    """Minimized selected-mailbox capture; raw message content is unsupported."""
    capture_scope_digest: str
    recipient_digest: str
    window_digest: str
    matched_messages: int
    complete: bool

    def __post_init__(self) -> None:
        try:
            for value in(self.capture_scope_digest,self.recipient_digest,self.window_digest):
                require_digest(value,"capture_digest")
            if (type(self.matched_messages)is not int or not 0<=self.matched_messages<=2147483647
                    or type(self.complete)is not bool):raise ValueError
        except Exception:raise ValueError(_ERROR)from None


def verify_system_email_capture(binding: SystemEmailDeliveryBinding,
        before: SystemEmailCaptureObservation,after: SystemEmailCaptureObservation) -> dict[str,object]:
    """Compare complete zero-to-one capture; never infer a product-level send."""
    if (type(binding)is not SystemEmailDeliveryBinding
            or type(before)is not SystemEmailCaptureObservation
            or type(after)is not SystemEmailCaptureObservation
            or not before.complete or not after.complete
            or before.capture_scope_digest!=binding.capture_scope_digest
            or after.capture_scope_digest!=binding.capture_scope_digest
            or before.recipient_digest!=binding.recipient_digest
            or after.recipient_digest!=binding.recipient_digest
            or before.window_digest!=after.window_digest
            or before.matched_messages!=0 or after.matched_messages!=1):
        raise ValueError(_ERROR)
    return dict(contract=CONTRACT,matching_capture_observed=True,matched_messages=1,
        source_provenance_qualified=False,native_ack_qualified=False,
        native_delivery_qualified=False,test_send_authorized=False,
        raw_message_content_returned=False,recipient_values_returned=False)
