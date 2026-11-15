"""One live, confirmation-gated FortiPAM Automation Trigger create workflow."""

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

from .automation_trigger_ssh_transport import (
    AUTOMATION_TRIGGER_CONFIGURATION,
    AutomationTriggerInspection,
    AutomationTriggerReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_automation_trigger_create_cli_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Automation Trigger create action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"mcp-v4-automation-trigger-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z")


class AutomationTriggerLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded trigger workflow."""


class AutomationTriggerLiveWorkflowTransport(Protocol):
    """Exact trigger preflight and create/readback contract."""

    def inspect(self, trigger_name: str) -> AutomationTriggerInspection: ...

    def create_and_readback(self, trigger_name: str) -> AutomationTriggerReadback: ...


@dataclass(frozen=True, slots=True)
class _AutomationTriggerRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    trigger_name: str
    current_digest: str
    state: str
    expires_at: int


class AutomationTriggerCreateLiveWorkflow:
    """Volatile one-confirmation flow for one unbound Automation Trigger."""

    def __init__(
        self,
        transport: AutomationTriggerLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _AutomationTriggerRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, trigger_name: str, requester_digest: str) -> dict[str, object]:
        """Read current state and render C/P/E without a device write."""

        safe_name = _trigger_name(trigger_name)
        _require_requester(requester_digest)
        current = self._inspect(safe_name)
        if current.trigger_name_exists:
            raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _AutomationTriggerRecord(
            preview_ref="automation-trigger-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            trigger_name=safe_name,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm unchanged absence and issue one execution reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(record.trigger_name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "automation-trigger-authorized-" + secrets.token_urlsafe(24)
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
        """Create exactly the confirmed trigger and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(record.trigger_name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(record.trigger_name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, AutomationTriggerReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, trigger_name: str) -> AutomationTriggerInspection:
        try:
            result = self._transport.inspect(trigger_name)
        except Exception as exc:
            raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, AutomationTriggerInspection):
            raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _AutomationTriggerRecord:
        if not _valid_ref(preview_ref, "automation-trigger-preview-"):
            raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _AutomationTriggerRecord:
        if not _valid_ref(authorization_ref, "automation-trigger-authorized-"):
            raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _AutomationTriggerRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _AutomationTriggerRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(
        record: _AutomationTriggerRecord,
        current: AutomationTriggerInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_trigger_name": record.trigger_name,
                "trigger_name_exists": current.trigger_name_exists,
                "write_transport": "ssh_cli",
            },
            "Proposed Changes": {
                "operation": "create_automation_trigger_via_cli",
                "trigger_name": record.trigger_name,
                "configuration_profile": AUTOMATION_TRIGGER_CONFIGURATION,
                "event_type": "event-log",
                "automation_action_or_stitch_changes": False,
                "direct_automation_execution": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "trigger_name_matches": True,
                "trigger_name_exists": True,
                "event_log_type_enabled": True,
                "fixed_logid_present": True,
                "category_one_present": True,
                "logic_and_enabled": True,
                "msg_regex_field_present": True,
                "automation_action_or_stitch_changes": False,
                "direct_automation_execution": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _AutomationTriggerRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_automation_trigger_create_cli_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_automation_trigger_delete_action_required",
            "trigger_name_returned": False,
            "automation_action_or_stitch_changes": False,
            "direct_automation_execution": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: AutomationTriggerInspection) -> str:
    payload = json.dumps(
        {"trigger_name_exists": inspection.trigger_name_exists},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _trigger_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise AutomationTriggerLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "AutomationTriggerCreateLiveWorkflow",
    "AutomationTriggerLiveWorkflowError",
    "AutomationTriggerLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
