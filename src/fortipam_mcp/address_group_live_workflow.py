"""Confirmation-gated FortiPAM single-member Address Group creation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from typing import Protocol

from .address_group_ssh_transport import AddressGroupInspection, AddressGroupReadback
from .address_http_transport import AddressInspection


WORKFLOW_CONTRACT = "fortipam_v4_address_group_create_cli_fallback_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Address Group action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class AddressGroupLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded Address Group workflow."""


class AddressGroupCliTransport(Protocol):
    """Pinned CLI contract used for Group preflight/write/readback."""

    def inspect(self, group_name: str) -> AddressGroupInspection: ...

    def create_and_readback(
        self,
        group_name: str,
        member_name: str,
    ) -> AddressGroupReadback: ...


class AddressMemberTransport(Protocol):
    """Fixed API read contract used only to validate the member category."""

    def inspect(self, name: str) -> AddressInspection: ...


@dataclass(frozen=True, slots=True)
class _AddressGroupRequest:
    group_name: str
    member_name: str

    @classmethod
    def create(cls, group_name: str, member_name: str) -> "_AddressGroupRequest":
        if (
            not isinstance(group_name, str)
            or not isinstance(member_name, str)
            or _NAME.fullmatch(group_name) is None
            or _NAME.fullmatch(member_name) is None
            or group_name == member_name
        ):
            raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(group_name=group_name, member_name=member_name)


@dataclass(frozen=True, slots=True)
class _CurrentState:
    group_exists: bool
    member_exists: bool
    member_is_ipv4_ipmask: bool


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    request: _AddressGroupRequest
    current_digest: str
    state: str
    expires_at: int


class AddressGroupCreateLiveWorkflow:
    """Volatile one-confirmation workflow for exactly one CLI-created Group."""

    def __init__(
        self,
        group_transport: AddressGroupCliTransport,
        member_transport: AddressMemberTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._group_transport = group_transport
        self._member_transport = member_transport
        self._clock = clock or _now
        self._records: dict[str, _Record] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        group_name: str,
        member_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        request = _AddressGroupRequest.create(group_name, member_name)
        _require_requester(requester_digest)
        current = self._inspect(request)
        if current.group_exists or not (
            current.member_exists and current.member_is_ipv4_ipmask
        ):
            raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _Record(
            preview_ref="address-group-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            request=request,
            current_digest=_current_digest(request, current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(record.request)
            if not hmac.compare_digest(
                _current_digest(record.request, current), record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "address-group-authorized-" + secrets.token_urlsafe(24)
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
        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(record.request)
            if not hmac.compare_digest(
                _current_digest(record.request, current), record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._group_transport.create_and_readback(
                record.request.group_name,
                record.request.member_name,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if isinstance(readback, AddressGroupReadback) and readback.verified
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, request: _AddressGroupRequest) -> _CurrentState:
        try:
            group = self._group_transport.inspect(request.group_name)
            member = self._member_transport.inspect(request.member_name)
        except Exception as exc:
            raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(group, AddressGroupInspection) or not isinstance(
            member,
            AddressInspection,
        ):
            raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return _CurrentState(
            group_exists=group.exists,
            member_exists=member.exists,
            member_is_ipv4_ipmask=member.is_ipv4_ipmask,
        )

    def _record_for_preview_locked(self, preview_ref: str) -> _Record:
        if not _valid_ref(preview_ref, "address-group-preview-"):
            raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _Record:
        if not _valid_ref(authorization_ref, "address-group-authorized-"):
            raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _Record,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _Record, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _Record) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_address_group_name": record.request.group_name,
                "requested_member_address_name": record.request.member_name,
                "address_group_exists": False,
                "member_address_exists": True,
                "member_address_type": "ipv4_ipmask",
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "create_single_member_address_group_via_cli_fallback",
                "address_group_name": record.request.group_name,
                "member_address_name": record.request.member_name,
                "member_count": 1,
                "rest_write_attempted": False,
                "compiled_cli_sequence": "firewall_addrgrp_edit_set_member",
            },
            "Expected State": {
                "address_group_name_matches": True,
                "member_address_name_matches": True,
                "address_group_exists": True,
                "exactly_one_member_matches": True,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(self, record: _Record, *, idempotent_replay: bool) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_address_group_create_cli_fallback_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_address_group_delete_action_required",
            "address_group_name_returned": False,
            "member_address_name_returned": False,
            "raw_cli_returned": False,
        }


def _current_digest(request: _AddressGroupRequest, current: _CurrentState) -> str:
    payload = {
        "group_name": request.group_name,
        "member_name": request.member_name,
        "group_exists": current.group_exists,
        "member_exists": current.member_exists,
        "member_is_ipv4_ipmask": current.member_is_ipv4_ipmask,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise AddressGroupLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 160


def _now() -> int:
    return int(time.time())


__all__ = [
    "AddressGroupCreateLiveWorkflow",
    "AddressGroupLiveWorkflowError",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
