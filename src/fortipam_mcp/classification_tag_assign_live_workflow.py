"""One confirmation-gated Target Classification Tag assignment workflow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hmac
import re
import secrets
import threading
import time
from typing import Protocol

from .classification_tag_assign_contract import (
    ClassificationTagAssignInspection,
    ClassificationTagAssignReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_classification_tag_assign_api_workflow_v1"
EXECUTION_CONTRACT = "fortipam_v4_classification_tag_assign_api_execution_v1"
ROLLBACK_WORKFLOW_CONTRACT = (
    "fortipam_v4_classification_tag_assign_rollback_api_workflow_v1"
)
ROLLBACK_EXECUTION_CONTRACT = (
    "fortipam_v4_classification_tag_assign_rollback_api_execution_v1"
)
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Classification Tag assignment is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_TARGET_PREFIX = "mcp-v4-target-"
_TAG_PREFIX = "mcp-v4-classification-tag-"


class ClassificationTagAssignLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded assignment workflow."""


class ClassificationTagAssignTransport(Protocol):
    """The exact Target/Tag preflight and class-only write contract."""

    def inspect_classification_tag_assignment(
        self,
        target_name: str,
        classification_tag_name: str,
    ) -> ClassificationTagAssignInspection: ...

    def assign_classification_tag_and_readback(
        self,
        target_name: str,
        classification_tag_name: str,
        *,
        target_non_class_state_digest: str,
        classification_tag_state_digest: str,
    ) -> ClassificationTagAssignReadback: ...

    def restore_default_classification_and_readback(
        self,
        target_name: str,
        classification_tag_name: str,
        *,
        target_non_class_state_digest: str,
        classification_tag_state_digest: str,
    ) -> ClassificationTagAssignReadback: ...


@dataclass(frozen=True, slots=True)
class _AssignmentRequest:
    target_name: str
    classification_tag_name: str

    @classmethod
    def create(
        cls,
        target_name: str,
        classification_tag_name: str,
    ) -> "_AssignmentRequest":
        if not _bounded_name(target_name, _TARGET_PREFIX) or not _bounded_name(
            classification_tag_name,
            _TAG_PREFIX,
        ):
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(target_name, classification_tag_name)


@dataclass(frozen=True, slots=True)
class _AssignmentRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    request: _AssignmentRequest
    current_digest: str
    target_non_class_state_digest: str
    classification_tag_state_digest: str
    state: str
    expires_at: int


class ClassificationTagAssignLiveWorkflow:
    """Volatile one-confirmation workflow for one class-only Target PUT."""

    def __init__(
        self,
        transport: ClassificationTagAssignTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _AssignmentRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        target_name: str,
        classification_tag_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read the exact baseline and render a minimized C/P/E preview."""

        request = _AssignmentRequest.create(target_name, classification_tag_name)
        _require_requester(requester_digest)
        current = self._inspect(request)
        if not _eligible(current):
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _AssignmentRecord(
            preview_ref="classification-tag-assign-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            request=request,
            current_digest=current.state_digest,
            target_non_class_state_digest=current.target_non_class_state_digest,
            classification_tag_state_digest=current.classification_tag_state_digest,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Re-read one exact preview and authorize one execution."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            if not self._state_is_unchanged(record):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "previewed")
            authorization_ref = (
                "classification-tag-assign-authorized-" + secrets.token_urlsafe(24)
            )
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
        """Execute once; uncertain results become non-retry reconciliation state."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            if not self._state_is_unchanged(record):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "authorized")
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.assign_classification_tag_and_readback(
                record.request.target_name,
                record.request.classification_tag_name,
                target_non_class_state_digest=record.target_non_class_state_digest,
                classification_tag_state_digest=record.classification_tag_state_digest,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                (
                    "completed"
                    if isinstance(readback, ClassificationTagAssignReadback)
                    and readback.verified
                    else "reconciliation_required"
                ),
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, request: _AssignmentRequest) -> ClassificationTagAssignInspection:
        try:
            result = self._transport.inspect_classification_tag_assignment(
                request.target_name,
                request.classification_tag_name,
            )
        except Exception as exc:
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, ClassificationTagAssignInspection):
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _state_is_unchanged(self, record: _AssignmentRecord) -> bool:
        current = self._inspect(record.request)
        return _eligible(current) and hmac.compare_digest(
            current.state_digest,
            record.current_digest,
        )

    def _record_for_preview_locked(self, preview_ref: str) -> _AssignmentRecord:
        if not _valid_ref(preview_ref, "classification-tag-assign-preview-"):
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _AssignmentRecord:
        if not _valid_ref(
            authorization_ref,
            "classification-tag-assign-authorized-",
        ):
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _AssignmentRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _AssignmentRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records[preview_ref] = replace(record, state=state)

    def _purge_expired_locked(self) -> None:
        expired = [
            preview_ref
            for preview_ref, record in self._records.items()
            if record.expires_at <= self._clock() and record.state != "completed"
        ]
        for preview_ref in expired:
            record = self._records.pop(preview_ref)
            if record.authorization_ref is not None:
                self._authorization_index.pop(record.authorization_ref, None)

    @staticmethod
    def _preview_projection(record: _AssignmentRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_target_name": record.request.target_name,
                "target_exists": True,
                "current_classification_tag_is_default": True,
                "requested_classification_tag_name": (
                    record.request.classification_tag_name
                ),
                "classification_tag_exists": True,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "assign_classification_tag_to_target_via_api",
                "target_name": record.request.target_name,
                "classification_tag_name": record.request.classification_tag_name,
                "request_body": "fixed_class_only",
            },
            "Expected State": {
                "target_exists": True,
                "classification_tag_exists": True,
                "target_class_matches": True,
                "target_non_class_state_preserved": True,
                "classification_tag_state_preserved": True,
                "readback_transport": "rest_api",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _AssignmentRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": EXECUTION_CONTRACT,
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_confirmed_target_classification_change_required",
            "target_name_returned": False,
            "classification_tag_name_returned": False,
            "target_payload_returned": False,
            "classification_tag_payload_returned": False,
            "raw_api_response_returned": False,
        }


class ClassificationTagAssignRollbackLiveWorkflow:
    """Restore one fixed accepted Target Classification to ``Other``."""

    def __init__(
        self,
        transport: ClassificationTagAssignTransport,
        *,
        target_name: str,
        classification_tag_name: str,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._request = _AssignmentRequest.create(target_name, classification_tag_name)
        self._clock = clock or _now
        self._records: dict[str, _AssignmentRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        """Read the exact assigned baseline and render a value-minimized rollback."""

        _require_requester(requester_digest)
        current = self._inspect()
        if not _rollback_eligible(current):
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _AssignmentRecord(
            preview_ref=(
                "classification-tag-assign-rollback-preview-"
                + secrets.token_urlsafe(24)
            ),
            authorization_ref=None,
            requester_digest=requester_digest,
            request=self._request,
            current_digest=current.state_digest,
            target_non_class_state_digest=current.target_non_class_state_digest,
            classification_tag_state_digest=current.classification_tag_state_digest,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Re-read the fixed assigned baseline and authorize one restoration."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            if not self._state_is_unchanged(record):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "previewed")
            authorization_ref = (
                "classification-tag-assign-rollback-authorized-"
                + secrets.token_urlsafe(24)
            )
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": ROLLBACK_WORKFLOW_CONTRACT,
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
        """Restore exactly ``class=Other``; uncertain writes are non-retryable."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            if not self._state_is_unchanged(record):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "authorized")
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.restore_default_classification_and_readback(
                record.request.target_name,
                record.request.classification_tag_name,
                target_non_class_state_digest=record.target_non_class_state_digest,
                classification_tag_state_digest=record.classification_tag_state_digest,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                (
                    "completed"
                    if isinstance(readback, ClassificationTagAssignReadback)
                    and readback.verified
                    else "reconciliation_required"
                ),
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> ClassificationTagAssignInspection:
        try:
            result = self._transport.inspect_classification_tag_assignment(
                self._request.target_name,
                self._request.classification_tag_name,
            )
        except Exception as exc:
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, ClassificationTagAssignInspection):
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _state_is_unchanged(self, record: _AssignmentRecord) -> bool:
        current = self._inspect()
        return _rollback_eligible(current) and hmac.compare_digest(
            current.state_digest,
            record.current_digest,
        )

    def _record_for_preview_locked(self, preview_ref: str) -> _AssignmentRecord:
        if not _valid_ref(preview_ref, "classification-tag-assign-rollback-preview-"):
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _AssignmentRecord:
        if not _valid_ref(
            authorization_ref,
            "classification-tag-assign-rollback-authorized-",
        ):
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _AssignmentRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _AssignmentRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records[preview_ref] = replace(record, state=state)

    def _purge_expired_locked(self) -> None:
        expired = [
            preview_ref
            for preview_ref, record in self._records.items()
            if record.expires_at <= self._clock() and record.state != "completed"
        ]
        for preview_ref in expired:
            record = self._records.pop(preview_ref)
            if record.authorization_ref is not None:
                self._authorization_index.pop(record.authorization_ref, None)

    @staticmethod
    def _preview_projection(record: _AssignmentRecord) -> dict[str, object]:
        return {
            "contract": ROLLBACK_WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "target_exists": True,
                "classification_tag_exists": True,
                "target_class_matches_protected_tag": True,
                "target_or_tag_reference_returned": False,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "restore_target_default_classification_via_api",
                "request_body": "fixed_class_only",
                "target_classification": "Other",
                "target_non_class_fields_changed": False,
                "classification_tag_changed": False,
                "secret_folder_ztna_or_session_changed": False,
            },
            "Expected State": {
                "pre_action_state_restored": True,
                "target_classification_is_default": True,
                "target_non_class_state_preserved": True,
                "classification_tag_state_preserved": True,
                "target_or_tag_reference_returned": False,
                "readback_transport": "rest_api",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _AssignmentRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": ROLLBACK_EXECUTION_CONTRACT,
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "pre_action_state_restored": succeeded,
            "target_classification_is_default": succeeded,
            "target_non_class_state_preserved": succeeded,
            "classification_tag_state_preserved": succeeded,
            "target_name_returned": False,
            "classification_tag_name_returned": False,
            "target_payload_returned": False,
            "classification_tag_payload_returned": False,
            "raw_api_response_returned": False,
        }


def _eligible(inspection: ClassificationTagAssignInspection) -> bool:
    return (
        inspection.target_exists
        and inspection.classification_tag_exists
        and inspection.current_class_is_other
    )


def _rollback_eligible(inspection: ClassificationTagAssignInspection) -> bool:
    return (
        inspection.target_exists
        and inspection.classification_tag_exists
        and inspection.current_class_matches_tag
    )


def _bounded_name(value: str, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and _NAME.fullmatch(value) is not None
    )


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ClassificationTagAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and value.isascii()
        and len(value) <= 160
    )


def _now() -> int:
    return int(time.time())


__all__ = [
    "ClassificationTagAssignLiveWorkflow",
    "ClassificationTagAssignRollbackLiveWorkflow",
    "ClassificationTagAssignLiveWorkflowError",
    "ClassificationTagAssignTransport",
    "EXECUTION_CONTRACT",
    "ROLLBACK_EXECUTION_CONTRACT",
    "ROLLBACK_WORKFLOW_CONTRACT",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
