"""Requester-bound native Client Software creation and owned recovery."""
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

CONTRACT = "fortipam_v4_client_integrity_native_700_workflow_v3"
HASH_CONTRACT = "fortipam_v4_client_integrity_native_hash_700_workflow_v1"
_UNAVAILABLE = "The native Client Integrity workflow is unavailable."
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class NativeClientIntegrityWorkflowError(RuntimeError):
    """Stable non-disclosing identity, freshness or state failure."""


class NativeClientIntegrityTransport(Protocol):
    @property
    def hash_profile(self) -> bool: ...

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


class NativeClientIntegrityWorkflow:
    """A protected binding supplies all selectors and the complete baseline."""

    def __init__(self, transport: NativeClientIntegrityTransport, *, recovery: bool = False,
                 clock: Callable[[], int] | None = None) -> None:
        if type(recovery) is not bool or type(transport.hash_profile) is not bool:
            raise NativeClientIntegrityWorkflowError(_UNAVAILABLE)
        self._transport, self._recovery = transport, recovery
        self._hash = transport.hash_profile
        self._contract = HASH_CONTRACT if self._hash else CONTRACT
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
        expected = {"fixed_native_profile_verified": True, "visible_collection_preserved": True,
                    "reported_usage_empty": self._recovery, "verified_creation_required": self._recovery,
                    "device_write_executed": False}
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
                ref = "client-integrity-native-preview-" + secrets.token_urlsafe(24)
                record = _Intent(requester_digest, self._now() + 600)
                self._previews[ref] = record
            return {"contract": self._contract, "preview_ref": ref, "expires_at": record.expires_at,
                    "Current State": {"bound_software_present": self._recovery,
                                      "visible_collection_preserved": True,
                                      "verified_creation_required": self._recovery,
                                      "reported_usage_empty": self._recovery},
                    "Proposed Changes": {"operation": "remove_verified_owned_native_software" if self._recovery
                                          else "create_fixed_native_client_integrity_precondition",
                                          "configuration_profile": ("native-x64-external-executable-sha256-700-v1" if self._hash
                                                                    else "native-x64-external-local-ca-700-v3"),
                                          "association_or_session_changes": False,
                                          "upload_or_download_dispatched": False},
                    "Expected State": {"bound_software_present": not self._recovery,
                                       "visible_collection_preserved": True,
                                       "complete_expected_state_verified": True,
                                       "signature_enforcement_verified": False,
                                       **({"hash_enforcement_verified": False} if self._hash else {})},
                    "device_write_executed": False}
        except Exception:
            raise NativeClientIntegrityWorkflowError(_UNAVAILABLE) from None

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Bind unchanged intent; this record does not grant product authority."""
        try:
            with self._lock:
                record = self._intent(preview_ref, requester_digest)
                if record.authorization is not None:
                    raise ValueError
                self._inspect()
                self._intent(preview_ref, requester_digest)
                auth = "client-integrity-native-authorized-" + secrets.token_urlsafe(24)
                self._previews[preview_ref] = replace(record, authorization=auth)
                self._authorizations[auth] = preview_ref
            return {"contract": self._contract, "authorization_ref": auth, "expires_at": record.expires_at,
                    "confirmation": "recorded", "execution": "authorized_once", "device_write_executed": False}
        except Exception:
            raise NativeClientIntegrityWorkflowError(_UNAVAILABLE) from None

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
                                and result == {"verified": True, "software_present": not self._recovery,
                                               "visible_collection_preserved": True, "upload_or_download_dispatched": False}
                                and all(type(value) is bool for value in result.values()))
                except Exception:
                    verified = False
            return {"contract": self._contract, "outcome": "succeeded" if verified else "reconciliation_required",
                    "verification": "verified" if verified else "unknown", "intent_consumed": True,
                    "recovery": self._recovery, "raw_response_returned": False,
                    "signature_enforcement_verified": False,
                    **({"hash_enforcement_verified": False} if self._hash else {})}
        except Exception:
            raise NativeClientIntegrityWorkflowError(_UNAVAILABLE) from None
