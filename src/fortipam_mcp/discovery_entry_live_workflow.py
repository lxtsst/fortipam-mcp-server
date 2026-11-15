"""One-shot C/P/E for a privately bound disabled Unix Discovery source."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import time
from typing import Callable

from .discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from .discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport


CONTRACT = "fortipam_v4_unix_discovery_create_700_candidate_v1"
_UNAVAILABLE = "FortiPAM V4 Unix Discovery creation is unavailable."
_TTL_SECONDS = 600


@dataclass(frozen=True, slots=True)
class _Preview:
    requester_digest: str
    reference_digest: str
    expires_at: int
    authorization_ref: str | None = None


class UnixDiscoveryCreateLiveWorkflow:
    """Keep transient intent references in memory and dispatch claims on disk."""

    def __init__(
        self,
        transport: FortiPamDiscoveryEntryCreateHttpTransport,
        request: DisabledUnixDiscoveryCreateInput,
        claim_path: Path,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if (type(transport) is not FortiPamDiscoveryEntryCreateHttpTransport
                or type(request) is not DisabledUnixDiscoveryCreateInput
                or not claim_path.is_absolute()):
            raise ValueError(_UNAVAILABLE)
        self._transport = transport
        self._request = request
        self._claim = claim_path
        self._clock = clock or (lambda: int(time.time()))
        self._previews: dict[str, _Preview] = {}
        self._authorized: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self._validate_requester(requester_digest)
        with self._lock:
            reference_digest = self._inspect_absent_and_references()
            ref = "unix-discovery-preview-" + secrets.token_urlsafe(24)
            record = _Preview(requester_digest, reference_digest,
                              self._clock() + _TTL_SECONDS)
            self._previews[ref] = record
        return {
            "contract": CONTRACT,
            "preview_ref": ref,
            "expires_at": record.expires_at,
            "Current State": {
                "bound_unix_secret_and_target_visible": True,
                "bound_source_absent": True,
            },
            "Proposed Changes": {
                "operation": "create_one_unix_account_discovery_source",
                "periodic_scanning": "disable",
                "auto_onboarding": "disable",
                "scan_or_import": False,
                "credential_change": False,
            },
            "Expected State": {
                "exact_source_detail_verified": True,
                "source_disabled_and_unscanned": True,
            },
            "device_write_executed": False,
        }

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._get_preview(preview_ref, requester_digest)
            if record.authorization_ref is not None or not hmac.compare_digest(
                record.reference_digest, self._inspect_absent_and_references(),
            ):
                raise RuntimeError(_UNAVAILABLE)
            self._get_preview(preview_ref, requester_digest)
            auth = "unix-discovery-authorized-" + secrets.token_urlsafe(24)
            self._previews[preview_ref] = _Preview(
                record.requester_digest, record.reference_digest,
                record.expires_at, auth,
            )
            self._authorized[auth] = preview_ref
        return {
            "contract": CONTRACT,
            "authorization_ref": auth,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            ref = self._authorized.get(authorization_ref)
            if ref is None:
                raise RuntimeError(_UNAVAILABLE)
            record = self._get_preview(ref, requester_digest)
            if (record.authorization_ref != authorization_ref
                    or not hmac.compare_digest(
                        record.reference_digest, self._inspect_absent_and_references(),
                    )):
                raise RuntimeError(_UNAVAILABLE)
            self._get_preview(ref, requester_digest)
            self._reserve_claim(record.reference_digest)
            del self._authorized[authorization_ref]
        try:
            def before_dispatch() -> None:
                self._get_preview(ref, requester_digest)

            result = self._transport.create_and_readback(
                self._request, before_dispatch=before_dispatch,
            )
            independent = self._transport.inspect_current(self._request)
            success = bool(result.verified and independent
                           and independent.create_readback_verified)
        except Exception:
            success = False
        return {
            "contract": CONTRACT,
            "outcome": "succeeded" if success else "reconciliation_required",
            "verification": "exact_disabled_unscanned_source" if success else "unknown",
            "one_shot_claim_consumed": True,
            "scan_or_import_dispatched": False,
            "credential_values_returned": False,
            "raw_api_response_returned": False,
        }

    def _inspect_absent_and_references(self) -> str:
        try:
            self._require_unconsumed()
            if self._transport.inspect_current(self._request) is not None:
                raise ValueError
            return self._transport.inspect_credential_reference(self._request)
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def _get_preview(self, ref: str, requester_digest: str) -> _Preview:
        self._validate_requester(requester_digest)
        record = self._previews.get(ref)
        if (record is None or self._clock() >= record.expires_at
                or not hmac.compare_digest(record.requester_digest, requester_digest)):
            raise RuntimeError(_UNAVAILABLE)
        return record

    @staticmethod
    def _validate_requester(value: str) -> None:
        if (not isinstance(value, str) or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)):
            raise RuntimeError(_UNAVAILABLE)

    def _require_unconsumed(self) -> None:
        info = self._claim.parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700 or self._claim.exists()):
            raise RuntimeError(_UNAVAILABLE)

    def _reserve_claim(self, reference_digest: str) -> None:
        self._require_unconsumed()
        try:
            fd = os.open(self._claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as output:
                json.dump({"contract": CONTRACT, "reference_digest": reference_digest,
                           "source_binding_digest": source_binding_digest(self._request),
                           "state": "post_attempt_reserved", "reserved_at": self._clock()},
                          output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
        except OSError:
            raise RuntimeError(_UNAVAILABLE) from None


def source_binding_digest(request: DisabledUnixDiscoveryCreateInput) -> str:
    """Bind the exact protected Source intent, without storing its fields."""
    return hashlib.sha256(json.dumps({"source_name": request.source_name,
                                     "discovery_secret_id": request.discovery_secret_id},
                                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()


__all__ = ["UnixDiscoveryCreateLiveWorkflow", "CONTRACT", "source_binding_digest"]
