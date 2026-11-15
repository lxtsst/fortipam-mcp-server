"""Fixed short-address loopback capture for local alert configuration only.

The legacy SMTP debug binding remains distinct. DATA is discarded by the shared
bounded parser. A receiver transaction cannot prove an appliance notification,
sender quiescence, routing, recipient authority or a native alert trigger.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import re
import time

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from .email_alert_general_contract import EmailAlertMailScope
from .system_email_smtp_capture import _LoopbackSmtpCapture,LoopbackSystemEmailSmtpReservation,SystemEmailSmtpCaptureError

CONTRACT = 'fortipam-email-alert-fixed-capture-local/v1'
_ERROR = 'The private email-alert capture is unavailable.'


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertCaptureBinding(_OpaqueC3Object):
    nonce: str
    capture_scope_digest: str
    source_serial_digest: str
    configuration_digest: str

    def __post_init__(self) -> None:
        try:
            if type(self.nonce) is not str or re.fullmatch(r'[a-f0-9]{32}',self.nonce) is None: raise ValueError
            for value in (self.capture_scope_digest,self.source_serial_digest,self.configuration_digest): require_digest(value,'alert capture scope')
        except Exception: raise ValueError(_ERROR) from None

    def _recipient(self) -> str: return 'mcp-alert-'+self.nonce+'@capture.invalid'

    @property
    def recipient_digest(self) -> str: return hashlib.sha256(self._recipient().encode()).hexdigest()

    @property
    def parameters_digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,capture=self.capture_scope_digest,serial=self.source_serial_digest,
            configuration=self.configuration_digest,recipient=self.recipient_digest))

    def mail_scope(self) -> EmailAlertMailScope:
        return EmailAlertMailScope(self.parameters_digest,'mcp-alert-from@capture.invalid',self._recipient())

    def summary(self) -> dict[str,object]:
        return dict(contract=CONTRACT,short_fixed_recipient=True,recipient_fits_general_form=True,
            recipient_or_sender_values_returned=False,arbitrary_recipient_supported=False,recipient_authority_verified=False,
            sender_quiescence_verified=False,native_delivery_verified=False,alert_trigger_verified=False,execution_authorized=False)


class LoopbackEmailAlertSmtpCapture(_LoopbackSmtpCapture):
    def __init__(self, binding: EmailAlertCaptureBinding, *, window_digest: str,
            lifetime_seconds: int = 120, clock: Callable[[],float] = time.monotonic,
            _reservation: LoopbackSystemEmailSmtpReservation | None = None) -> None:
        if type(binding) is not EmailAlertCaptureBinding: raise SystemEmailSmtpCaptureError(_ERROR)
        binding.__post_init__()
        super().__init__(binding,contract=CONTRACT,window_digest=window_digest,lifetime_seconds=lifetime_seconds,
            clock=clock,_reservation=_reservation)
