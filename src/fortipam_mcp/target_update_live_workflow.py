"""One live, confirmation-gated FortiPAM Target description-update workflow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hmac
import re
import secrets
import threading
import time
from typing import Protocol

from .target_contract import TargetUpdateInspection, TargetUpdateReadback


WORKFLOW_CONTRACT = "fortipam_v4_target_description_update_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Target description update is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class TargetDescriptionUpdateLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded Target update workflow."""


class TargetDescriptionUpdateTransport(Protocol):
    """The exact Target description preflight and update/readback contract."""

    def inspect_description_update(
        self,
        target_name: str,
        description: str,
    ) -> TargetUpdateInspection: ...

    def update_description_and_readback(
        self,
        target_name: str,
        description: str,
    ) -> TargetUpdateReadback: ...


@dataclass(frozen=True, slots=True)
class _TargetDescriptionRequest:
    name: str
    description: str

    @classmethod
    def create(cls, name: str, description: str) -> "_TargetDescriptionRequest":
        if not isinstance(name, str) or _NAME.fullmatch(name) is None:
            raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if (
            not isinstance(description, str)
            or not description
            or len(description) > 255
            or any(ord(character) < 32 or ord(character) == 127 for character in description)
        ):
            raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(name=name, description=description)


@dataclass(frozen=True, slots=True)
class _TargetDescriptionRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    name: str
    description: str
    current_digest: str
    state: str
    expires_at: int


class TargetDescriptionUpdateLiveWorkflow:
    """Volatile one-confirmation workflow for a Target description API update."""

    def __init__(
        self,
        transport: TargetDescriptionUpdateTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _TargetDescriptionRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        target_name: str,
        description: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read Current State and render a redacted C/P/E update preview."""

        request = _TargetDescriptionRequest.create(target_name, description)
        _require_requester(requester_digest)
        current = self._inspect(request)
        if not current.exists or current.description_matches:
            raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _TargetDescriptionRecord(
            preview_ref="target-update-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            name=request.name,
            description=request.description,
            current_digest=current.state_digest,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm one still-current preview and issue a one-time execution ref."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            if not self._state_is_unchanged(record):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "previewed")
            authorization_ref = "target-update-authorized-" + secrets.token_urlsafe(24)
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

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        """Perform one confirmed REST update and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            if not self._state_is_unchanged(record):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "authorized")
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.update_description_and_readback(
                record.name,
                record.description,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, TargetUpdateReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, request: _TargetDescriptionRequest) -> TargetUpdateInspection:
        try:
            result = self._transport.inspect_description_update(
                request.name,
                request.description,
            )
        except Exception as exc:
            raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, TargetUpdateInspection):
            raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _state_is_unchanged(self, record: _TargetDescriptionRecord) -> bool:
        current = self._inspect(_TargetDescriptionRequest(record.name, record.description))
        return (
            current.exists
            and not current.description_matches
            and hmac.compare_digest(current.state_digest, record.current_digest)
        )

    def _record_for_preview_locked(self, preview_ref: str) -> _TargetDescriptionRecord:
        if not _valid_ref(preview_ref, "target-update-preview-"):
            raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _TargetDescriptionRecord:
        if not _valid_ref(authorization_ref, "target-update-authorized-"):
            raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _TargetDescriptionRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _TargetDescriptionRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _TargetDescriptionRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_target_name": record.name,
                "target_exists": True,
                "requested_description_already_matches": False,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "update_target_description_via_api",
                "target_name": record.name,
                "requested_description": record.description,
            },
            "Expected State": {
                "target_exists": True,
                "target_name_matches": True,
                "description_matches_requested_value": True,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _TargetDescriptionRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_target_description_update_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "target_name_returned": False,
            "description_returned": False,
            "raw_api_response_returned": False,
        }


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise TargetDescriptionUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "TargetDescriptionUpdateLiveWorkflow",
    "TargetDescriptionUpdateLiveWorkflowError",
    "TargetDescriptionUpdateTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
