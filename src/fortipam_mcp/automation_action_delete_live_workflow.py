"""One confirmation-gated recovery for the accepted unbound b44 Action."""

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

from .automation_action_delete_http_transport import (
    AutomationActionDeleteInspection,
    AutomationActionDeleteReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_automation_action_delete_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Automation Action recovery is unavailable."
_TTL_SECONDS = 600


class AutomationActionDeleteLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing fixed recovery failure."""


class AutomationActionDeleteLiveWorkflowTransport(Protocol):
    def inspect_delete_target(self) -> AutomationActionDeleteInspection: ...

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> AutomationActionDeleteReadback: ...


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    target_digest: str
    state: str
    expires_at: int


class AutomationActionDeleteLiveWorkflow:
    """Volatile one-confirmation flow for the exact unreferenced Action."""

    def __init__(
        self,
        transport: AutomationActionDeleteLiveWorkflowTransport,
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
            or not current.eligible_fixed_action
            or current.action_reference_count != 0
            or not current.accepted_trigger_absent
            or not current.accepted_stitch_absent
        ):
            raise AutomationActionDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _Record(
            preview_ref="automation-action-delete-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            current_digest=_inspection_digest(current),
            target_digest=current.target_digest,
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
            current = self._inspect()
            if not hmac.compare_digest(
                _inspection_digest(current), record.current_digest
            ):
                self._records[record.preview_ref] = replace(
                    record, state="invalidated"
                )
                raise AutomationActionDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = (
                "automation-action-delete-authorized-" + secrets.token_urlsafe(24)
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

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect()
            if not hmac.compare_digest(
                _inspection_digest(current), record.current_digest
            ):
                self._records[record.preview_ref] = replace(
                    record, state="invalidated"
                )
                raise AutomationActionDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.delete_and_readback(record.target_digest)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if isinstance(readback, AutomationActionDeleteReadback)
                and readback.verified
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> AutomationActionDeleteInspection:
        try:
            result = self._transport.inspect_delete_target()
        except Exception as exc:
            raise AutomationActionDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, AutomationActionDeleteInspection):
            raise AutomationActionDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _Record:
        if not _valid_ref(preview_ref, "automation-action-delete-preview-"):
            raise AutomationActionDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise AutomationActionDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _Record:
        if not _valid_ref(
            authorization_ref, "automation-action-delete-authorized-"
        ):
            raise AutomationActionDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise AutomationActionDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _Record,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise AutomationActionDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _Record, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise AutomationActionDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise AutomationActionDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
                "accepted_unbound_automation_action_exists": True,
                "exact_fixed_projection_observed": True,
                "complete_api_record_digest_matches": True,
                "accepted_trigger_absent": True,
                "accepted_stitch_absent": True,
                "action_reference_count": 0,
                "read_transports": ["rest_api", "ssh_cli"],
            },
            "Proposed Changes": {
                "operation": "delete_exact_unreferenced_automation_action_via_api",
                "action_count_affected": 1,
                "irreversible_after_execution": True,
                "automation_test_or_execution": False,
                "email_or_external_side_effect": False,
            },
            "Expected State": {
                "accepted_automation_action_absent": True,
                "automation_test_or_execution": False,
                "email_or_external_side_effect": False,
                "readback_transports": ["rest_api", "ssh_cli"],
            },
            "device_write_executed": False,
        }

    def _result(self, record: _Record, *, idempotent_replay: bool) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_automation_action_delete_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_automation_action_create_action_required",
            "irreversible_after_execution": True,
            "action_fields_returned": False,
            "automation_test_or_execution": False,
            "email_or_external_side_effect": False,
            "raw_api_or_cli_response_returned": False,
        }


def _inspection_digest(inspection: AutomationActionDeleteInspection) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "exists": inspection.exists,
                "eligible_fixed_action": inspection.eligible_fixed_action,
                "action_reference_count": inspection.action_reference_count,
                "target_digest": inspection.target_digest,
                "accepted_trigger_absent": inspection.accepted_trigger_absent,
                "accepted_stitch_absent": inspection.accepted_stitch_absent,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AutomationActionDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and 24 <= len(value.removeprefix(prefix)) <= 96
    )


def _now() -> int:
    return int(time.time())
