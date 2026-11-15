"""Requester-bound fixed Windows Launcher/hash association and restoration."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import hmac
import re
import secrets
import threading
import time
from typing import Protocol

CONTRACT = "fortipam_v4_putty_integrity_association_700_workflow_v1"
_UNAVAILABLE = "The fixed Windows Client Integrity association workflow is unavailable."
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class PuttyIntegrityAssociationWorkflowError(RuntimeError):
    """Stable non-disclosing identity, freshness or state failure."""


class PuttyIntegrityAssociationTransport(Protocol):
    def inspect(self, *, recovery: bool = False) -> dict[str, bool]: ...
    def execute(self, *, recovery: bool = False) -> dict[str, bool]: ...
    def intent_consumed(self, *, recovery: bool) -> bool: ...
    def reserve_intent(self, requester_digest: str, authorization_digest: str, *,
                       expires_at: int, recovery: bool) -> None: ...


@dataclass(frozen=True, slots=True)
class _Intent:
    requester: str
    expires_at: int
    authorization: str | None = None


class PuttyIntegrityAssociationWorkflow:
    """A protected binding supplies all selectors and the complete baseline."""

    def __init__(self, transport: PuttyIntegrityAssociationTransport, *, recovery: bool = False,
                 clock: Callable[[], int] | None = None) -> None:
        if type(recovery) is not bool:
            raise PuttyIntegrityAssociationWorkflowError(_UNAVAILABLE)
        self._transport, self._recovery = transport, recovery
        self._contract = CONTRACT
        self._clock = clock or (lambda: int(time.time()))
        self._previews: dict[str, _Intent] = {}
        self._authorizations: dict[str, str] = {}
        self._lock = threading.RLock()

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int:
            raise ValueError
        return value

    def _inspect(self) -> None:
        if self._transport.intent_consumed(recovery=self._recovery):
            raise ValueError
        actual = self._transport.inspect(recovery=self._recovery)
        expected = {"owned_windows_launcher_verified":True,"owned_hash_software_verified":True,
                    "complete_expected_state_verified":True,"unrelated_visible_state_preserved":True,
                    "launcher_reported_usage_empty":True,"device_write_executed":False}
        if (type(actual) is not dict or actual != expected
                or any(type(v) is not bool for v in actual.values())):
            raise ValueError

    def _purge(self) -> None:
        now = self._now()
        for ref, record in tuple(self._previews.items()):
            if now >= record.expires_at:
                del self._previews[ref]
                if record.authorization is not None:
                    self._authorizations.pop(record.authorization, None)

    @staticmethod
    def _requester(requester: str) -> None:
        if not isinstance(requester, str) or not _DIGEST.fullmatch(requester):
            raise ValueError

    def _intent(self, ref: str, requester: str) -> _Intent:
        self._requester(requester)
        if not isinstance(ref, str) or not ref.isascii() or len(ref) > 128:
            raise ValueError
        self._purge()
        record = self._previews.get(ref)
        if record is None or not hmac.compare_digest(record.requester, requester):
            raise ValueError
        return record

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        try:
            self._requester(requester_digest)
            with self._lock:
                self._purge()
                if len(self._previews) >= 64:
                    raise ValueError
                self._inspect()
                ref = "putty-integrity-association-preview-" + secrets.token_urlsafe(24)
                record = _Intent(requester_digest, self._now() + 600)
                self._previews[ref] = record
            return {"contract": self._contract, "preview_ref": ref, "expires_at": record.expires_at,
                    "Current State": {"verified_owned_objects_required":True,
                                      "software_reference_present":self._recovery,
                                      "complete_expected_state_verified":True,
                                      "launcher_reported_usage_empty":True},
                    "Proposed Changes": {"operation":"restore_owned_windows_software_reference" if self._recovery
                                          else "associate_owned_windows_launcher_with_hash_software",
                                          "single_os_app_reference_changed":True,
                                          "executable_or_parameter_changes":False,"client_launched":False},
                    "Expected State": {"software_reference_present":not self._recovery,
                                       "complete_expected_state_verified":True,
                                       "unrelated_visible_state_preserved":True,"hash_enforcement_verified":False},
                    "device_write_executed": False}
        except Exception:
            raise PuttyIntegrityAssociationWorkflowError(_UNAVAILABLE) from None

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Bind unchanged intent; this record does not grant product authority."""
        try:
            with self._lock:
                record = self._intent(preview_ref, requester_digest)
                if record.authorization is not None:
                    raise ValueError
                self._inspect()
                self._intent(preview_ref, requester_digest)
                auth = "putty-integrity-association-authorized-" + secrets.token_urlsafe(24)
                self._previews[preview_ref] = replace(record, authorization=auth)
                self._authorizations[auth] = preview_ref
            return {"contract": self._contract, "authorization_ref": auth, "expires_at": record.expires_at,
                    "confirmation": "recorded", "execution": "authorized_once", "device_write_executed": False}
        except Exception:
            raise PuttyIntegrityAssociationWorkflowError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                if (not isinstance(authorization_ref, str) or not authorization_ref.isascii()
                        or len(authorization_ref) > 128):
                    raise ValueError
                ref = self._authorizations.get(authorization_ref)
                if ref is None:
                    raise ValueError
                record = self._intent(ref, requester_digest)
                if record.authorization != authorization_ref:
                    raise ValueError
                self._inspect()
                self._intent(ref, requester_digest)
                self._transport.reserve_intent(requester_digest, hashlib.sha256(authorization_ref.encode()).hexdigest(),
                                               expires_at=record.expires_at, recovery=self._recovery)
                del self._authorizations[authorization_ref]
                del self._previews[ref]
                try:
                    result = self._transport.execute(recovery=self._recovery)
                    verified = (type(result) is dict
                                and result == {"verified":True,"software_reference_present":not self._recovery,
                                               "complete_expected_state_verified":True,"unrelated_visible_state_preserved":True,
                                               "client_launched":False,"hash_enforcement_verified":False}
                                and all(type(value) is bool for value in result.values()))
                except Exception:
                    verified = False
            return {"contract": self._contract, "outcome": "succeeded" if verified else "reconciliation_required",
                    "verification": "verified" if verified else "unknown", "intent_consumed": True,
                    "recovery": self._recovery, "raw_response_returned": False,
                    "client_launched":False,"hash_enforcement_verified":False}
        except Exception:
            raise PuttyIntegrityAssociationWorkflowError(_UNAVAILABLE) from None
