"""One confirmation-gated FortiPAM IPv4 ``ipmask`` address create workflow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
import time
from typing import Protocol

from .address_http_transport import AddressInspection, AddressReadback


WORKFLOW_CONTRACT = "fortipam_v4_address_create_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Address action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class AddressLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded Address workflow."""


class AddressTransport(Protocol):
    """The exact preflight and create/readback contract used by this workflow."""

    def inspect(self, name: str) -> AddressInspection: ...

    def create_and_readback(self, name: str, cidr: str) -> AddressReadback: ...


@dataclass(frozen=True, slots=True)
class _AddressRequest:
    name: str
    cidr: str

    @classmethod
    def create(cls, name: str, cidr: str) -> "_AddressRequest":
        if not isinstance(name, str) or _NAME.fullmatch(name) is None:
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if not isinstance(cidr, str):
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        try:
            network = ipaddress.IPv4Network(cidr, strict=True)
        except ValueError as exc:
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if network.prefixlen < 8:
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(name=name, cidr=str(network))


@dataclass(frozen=True, slots=True)
class _AddressRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    request: _AddressRequest
    current_digest: str
    state: str
    expires_at: int


class AddressCreateLiveWorkflow:
    """Volatile one-confirmation workflow for a single IPv4 subnet address."""

    def __init__(
        self,
        transport: AddressTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _AddressRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        name: str,
        cidr: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read current state and return a minimized C/P/E preview."""

        request = _AddressRequest.create(name, cidr)
        _require_requester(requester_digest)
        inspection = self._inspect(request)
        if inspection.exists:
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _AddressRecord(
            preview_ref="address-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            request=request,
            current_digest=_inspection_digest(request, inspection),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm an unchanged preview and issue one execution reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(record.request)
            if not hmac.compare_digest(
                _inspection_digest(record.request, current), record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "address-authorized-" + secrets.token_urlsafe(24)
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": updated.preview_ref,
            "authorization_ref": authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": updated.expires_at,
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Execute exactly one confirmed create with pre-write and readback checks."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(record.request)
            if not hmac.compare_digest(
                _inspection_digest(record.request, current), record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(
                record.request.name,
                record.request.cidr,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if isinstance(readback, AddressReadback) and readback.verified
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, request: _AddressRequest) -> AddressInspection:
        try:
            inspection = self._transport.inspect(request.name)
        except Exception as exc:
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(inspection, AddressInspection):
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return inspection

    def _record_for_preview_locked(self, preview_ref: str) -> _AddressRecord:
        if not _valid_ref(preview_ref, "address-preview-"):
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _AddressRecord:
        if not _valid_ref(authorization_ref, "address-authorized-"):
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _AddressRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _AddressRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records[preview_ref] = replace(record, state=state)

    def _purge_expired_locked(self) -> None:
        now_epoch = self._clock()
        expired = [
            ref
            for ref, record in self._records.items()
            if record.expires_at <= now_epoch and record.state != "completed"
        ]
        for preview_ref in expired:
            record = self._records.pop(preview_ref)
            if record.authorization_ref is not None:
                self._authorization_index.pop(record.authorization_ref, None)

    @staticmethod
    def _preview_projection(record: _AddressRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_address_name": record.request.name,
                "requested_ipv4_cidr": record.request.cidr,
                "address_exists": False,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "create_ipv4_ipmask_address_via_api",
                "address_name": record.request.name,
                "ipv4_cidr": record.request.cidr,
                "address_type": "ipmask",
                "request_body": "fixed_name_type_ipmask_subnet_only",
            },
            "Expected State": {
                "address_exists": True,
                "address_name_matches": True,
                "address_type_matches": True,
                "ipv4_cidr_matches": True,
                "readback_transport": "rest_api",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _AddressRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_address_create_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_address_delete_action_required",
            "address_name_returned": False,
            "cidr_returned": False,
            "raw_api_response_returned": False,
        }


def _inspection_digest(request: _AddressRequest, inspection: AddressInspection) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "name": request.name,
                "cidr": request.cidr,
                "exists": inspection.exists,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _require_requester(value: str) -> None:
    if not isinstance(value, str) or len(value) < 16:
        raise AddressLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and len(value) <= 160
        and all(character.isalnum() or character in "-_" for character in value[len(prefix) :])
    )


def _now() -> int:
    return int(time.time())


__all__ = [
    "AddressCreateLiveWorkflow",
    "AddressLiveWorkflowError",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
