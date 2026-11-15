"""One confirmation-gated recovery for the accepted laboratory Target."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Protocol

from .target_delete_http_transport import TargetDeleteInspection, TargetDeleteReadback


WORKFLOW_CONTRACT = "fortipam_v4_target_delete_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Target recovery is unavailable."
_TTL_SECONDS = 600


class TargetDeleteLiveWorkflowError(RuntimeError):
    """Stable non-disclosing fixed Target recovery failure."""


class TargetDeleteLiveWorkflowTransport(Protocol):
    def inspect_delete_target(self) -> TargetDeleteInspection: ...

    def delete_and_readback(
        self,
        expected_target_digest: str,
        expected_target_non_class_state_digest: str,
    ) -> TargetDeleteReadback: ...


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    target_digest: str
    target_non_class_state_digest: str
    state: str
    expires_at: int
    delete_authentication: str


class TargetDeleteLiveWorkflow:
    """Volatile one-confirmation flow for the exact unreferenced Target."""

    def __init__(
        self,
        transport: TargetDeleteLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _Record] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        _require_requester(requester_digest)
        current = self._inspect()
        if (
            not current.exists
            or not current.eligible_fixed_target
            or current.target_reference_count != 0
            or not current.target_class_is_other
            or not current.classification_tag_absent
            or not current.ssh_target_exists
        ):
            raise TargetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _Record(
            preview_ref="target-delete-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            current_digest=_inspection_digest(current),
            target_digest=current.target_digest,
            target_non_class_state_digest=current.target_non_class_state_digest,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
            delete_authentication=current.delete_authentication,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect()
            if not hmac.compare_digest(
                _inspection_digest(current),
                record.current_digest,
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TargetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "target-delete-authorized-" + secrets.token_urlsafe(24)
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
            current = self._inspect()
            if not hmac.compare_digest(
                _inspection_digest(current),
                record.current_digest,
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TargetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.delete_and_readback(
                record.target_digest,
                record.target_non_class_state_digest,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if isinstance(readback, TargetDeleteReadback) and readback.verified
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> TargetDeleteInspection:
        try:
            result = self._transport.inspect_delete_target()
        except Exception as exc:
            raise TargetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, TargetDeleteInspection):
            raise TargetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _Record:
        if not _valid_ref(preview_ref, "target-delete-preview-"):
            raise TargetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise TargetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _Record:
        if not _valid_ref(authorization_ref, "target-delete-authorized-"):
            raise TargetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise TargetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _Record,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise TargetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _Record, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise TargetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise TargetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
                "accepted_target_exists": True,
                "complete_api_record_digest_matches": True,
                "target_class_is_other": True,
                "accepted_classification_tag_absent": True,
                "target_reference_count": 0,
                "selectors_returned": False,
                "read_transports": ["rest_api", "ssh_cli"],
                **({"delete_authentication": "owner_session", "exact_owner_actor_and_relation_verified": True}
                   if record.delete_authentication == "owner_session" else {}),
            },
            "Proposed Changes": {
                "operation": "delete_exact_unreferenced_target_via_api",
                "target_count_affected": 1,
                "irreversible_after_execution": True,
                "classification_tag_secret_or_session_change": False,
            },
            "Expected State": {
                "target_absent": True,
                "accepted_classification_tag_absent": True,
                "target_reference_count": 0,
                "readback_transports": ["rest_api", "ssh_cli"],
            },
            "device_write_executed": False,
        }

    def _result(self, record: _Record, *, idempotent_replay: bool) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_target_delete_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_target_create_action_required",
            "target_name_or_configuration_returned": False,
            "classification_tag_name_returned": False,
            "raw_api_or_cli_response_returned": False,
        }


def _inspection_digest(inspection: TargetDeleteInspection) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "exists": inspection.exists,
                "eligible_fixed_target": inspection.eligible_fixed_target,
                "target_reference_count": inspection.target_reference_count,
                "target_class_is_other": inspection.target_class_is_other,
                "classification_tag_absent": inspection.classification_tag_absent,
                "ssh_target_exists": inspection.ssh_target_exists,
                "target_non_class_state_digest": (
                    inspection.target_non_class_state_digest
                ),
                "target_digest": inspection.target_digest,
                "delete_authentication": inspection.delete_authentication,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _require_requester(value: str) -> None:
    if not isinstance(value, str) or len(value) < 16:
        raise TargetDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and len(value) <= 160
        and all(
            character.isalnum() or character in "-_"
            for character in value[len(prefix) :]
        )
    )


def _now() -> int:
    return int(time.time())


__all__ = [
    "TargetDeleteLiveWorkflow",
    "TargetDeleteLiveWorkflowError",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
