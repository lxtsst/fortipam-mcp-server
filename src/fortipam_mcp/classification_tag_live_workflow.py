"""One confirmation-gated FortiPAM Classification Tag create workflow."""

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

from .classification_tag_http_transport import (
    ClassificationTagInspection,
    ClassificationTagReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_classification_tag_create_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Classification Tag action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,63}\Z")


class ClassificationTagLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded Tag workflow."""


class ClassificationTagTransport(Protocol):
    """The exact preflight and create/readback contract used by this workflow."""

    def inspect(self, name: str) -> ClassificationTagInspection: ...

    def create_and_readback(self, name: str, description: str) -> ClassificationTagReadback: ...


@dataclass(frozen=True, slots=True)
class _ClassificationTagRequest:
    name: str
    description: str

    @classmethod
    def create(cls, name: str, description: str) -> "_ClassificationTagRequest":
        if (
            not isinstance(name, str)
            or _NAME.fullmatch(name) is None
            or not isinstance(description, str)
            or not description
            or len(description) > 255
            or any(ord(character) < 32 or ord(character) == 127 for character in description)
        ):
            raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(name=name, description=description)


@dataclass(frozen=True, slots=True)
class _ClassificationTagRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    request: _ClassificationTagRequest
    current_digest: str
    state: str
    expires_at: int


class ClassificationTagCreateLiveWorkflow:
    """Volatile one-confirmation workflow for a single Tag creation."""

    def __init__(
        self,
        transport: ClassificationTagTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _ClassificationTagRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        name: str,
        description: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read current state and return a minimized C/P/E preview."""

        request = _ClassificationTagRequest.create(name, description)
        _require_requester(requester_digest)
        inspection = self._inspect(request)
        if inspection.exists:
            raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _ClassificationTagRecord(
            preview_ref="classification-tag-preview-" + secrets.token_urlsafe(24),
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
                raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "classification-tag-authorized-" + secrets.token_urlsafe(24)
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
                raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(
                record.request.name,
                record.request.description,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if isinstance(readback, ClassificationTagReadback) and readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, request: _ClassificationTagRequest) -> ClassificationTagInspection:
        try:
            inspection = self._transport.inspect(request.name)
        except Exception as exc:
            raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(inspection, ClassificationTagInspection):
            raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return inspection

    def _record_for_preview_locked(self, preview_ref: str) -> _ClassificationTagRecord:
        if not _valid_ref(preview_ref, "classification-tag-preview-"):
            raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self, authorization_ref: str
    ) -> _ClassificationTagRecord:
        if not _valid_ref(authorization_ref, "classification-tag-authorized-"):
            raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _ClassificationTagRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _ClassificationTagRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _ClassificationTagRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_classification_tag_name": record.request.name,
                "requested_classification_tag_description": record.request.description,
                "classification_tag_exists": False,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "create_classification_tag_via_api",
                "classification_tag_name": record.request.name,
                "classification_tag_description": record.request.description,
                "request_body": "fixed_name_and_description_only",
            },
            "Expected State": {
                "classification_tag_exists": True,
                "classification_tag_name_matches": True,
                "description_matches": True,
                "readback_transport": "rest_api",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _ClassificationTagRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_classification_tag_create_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_tag_delete_action_required",
            "classification_tag_name_returned": False,
            "description_returned": False,
            "raw_api_response_returned": False,
        }


def _inspection_digest(
    request: _ClassificationTagRequest,
    inspection: ClassificationTagInspection,
) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "name": request.name,
                "description": request.description,
                "exists": inspection.exists,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _require_requester(value: str) -> None:
    if not isinstance(value, str) or len(value) < 16:
        raise ClassificationTagLiveWorkflowError(WORKFLOW_UNAVAILABLE)


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
    "ClassificationTagCreateLiveWorkflow",
    "ClassificationTagLiveWorkflowError",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
