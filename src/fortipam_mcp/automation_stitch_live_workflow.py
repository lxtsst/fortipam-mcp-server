"""One confirmation-gated disabled FortiPAM Automation Stitch workflow."""

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

from .automation_stitch_ssh_transport import (
    AUTOMATION_STITCH_CONFIGURATION,
    AutomationStitchInspection,
    AutomationStitchReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_automation_stitch_create_cli_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Automation Stitch create action is unavailable."
_TTL_SECONDS = 600
_STITCH_NAME = re.compile(
    r"mcp-v4-automation-stitch-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z"
)
_TRIGGER_NAME = re.compile(
    r"mcp-v4-automation-trigger-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z"
)
_ACTION_NAME = re.compile(
    r"mcp-v4-automation-action-[A-Za-z0-9][A-Za-z0-9._-]{0,38}\Z"
)


class AutomationStitchLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded Stitch workflow."""


class AutomationStitchLiveWorkflowTransport(Protocol):
    """Exact preflight and disabled-Stitch create/readback contract."""

    def inspect(
        self,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
    ) -> AutomationStitchInspection: ...

    def create_and_readback(
        self,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
    ) -> AutomationStitchReadback: ...


@dataclass(frozen=True, slots=True)
class _AutomationStitchRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    stitch_name: str
    trigger_name: str
    action_name: str
    current_digest: str
    state: str
    expires_at: int


class AutomationStitchCreateLiveWorkflow:
    """Volatile one-confirmation flow for one disabled lab Stitch."""

    def __init__(
        self,
        transport: AutomationStitchLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _AutomationStitchRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read C/P/E inputs without creating or enabling a Stitch."""

        safe_stitch = _stitch_name(stitch_name)
        safe_trigger = _trigger_name(trigger_name)
        safe_action = _action_name(action_name)
        _require_requester(requester_digest)
        current = self._inspect(safe_stitch, safe_trigger, safe_action)
        if (
            current.stitch_name_exists
            or not current.trigger_name_exists
            or not current.action_name_exists
        ):
            raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _AutomationStitchRecord(
            preview_ref="automation-stitch-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            stitch_name=safe_stitch,
            trigger_name=safe_trigger,
            action_name=safe_action,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm the absent Stitch and both prerequisite objects are unchanged."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(
                record.stitch_name,
                record.trigger_name,
                record.action_name,
            )
            if (
                current.stitch_name_exists
                or not current.trigger_name_exists
                or not current.action_name_exists
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "automation-stitch-authorized-" + secrets.token_urlsafe(24)
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
        """Create only the confirmed disabled Stitch and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(
                record.stitch_name,
                record.trigger_name,
                record.action_name,
            )
            if (
                current.stitch_name_exists
                or not current.trigger_name_exists
                or not current.action_name_exists
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(
                record.stitch_name,
                record.trigger_name,
                record.action_name,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, AutomationStitchReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(
        self,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
    ) -> AutomationStitchInspection:
        try:
            result = self._transport.inspect(stitch_name, trigger_name, action_name)
        except Exception as exc:
            raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, AutomationStitchInspection):
            raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _AutomationStitchRecord:
        if not _valid_ref(preview_ref, "automation-stitch-preview-"):
            raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _AutomationStitchRecord:
        if not _valid_ref(authorization_ref, "automation-stitch-authorized-"):
            raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _AutomationStitchRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _AutomationStitchRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _AutomationStitchRecord,
        current: AutomationStitchInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_stitch_name": record.stitch_name,
                "requested_trigger_name": record.trigger_name,
                "requested_action_name": record.action_name,
                "stitch_name_exists": current.stitch_name_exists,
                "approved_trigger_exists": current.trigger_name_exists,
                "approved_action_exists": current.action_name_exists,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "create_disabled_automation_stitch_via_cli_fallback",
                "stitch_name": record.stitch_name,
                "trigger_name": record.trigger_name,
                "action_name": record.action_name,
                "configuration_profile": AUTOMATION_STITCH_CONFIGURATION,
                "stitch_status": "disable",
                "single_trigger_reference_created": True,
                "single_action_reference_created": True,
                "trigger_or_action_object_modified": False,
                "automation_test_or_execution": False,
                "email_or_external_side_effect": False,
                "destination_or_parallel_execution_change": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "stitch_name_matches": True,
                "stitch_name_exists": True,
                "status_disabled": True,
                "fixed_description_present": True,
                "trigger_reference_matches": True,
                "single_action_reference_matches": True,
                "action_delay_zero": True,
                "action_required_enabled": True,
                "trigger_or_action_object_modified": False,
                "automation_test_or_execution": False,
                "email_or_external_side_effect": False,
                "readback_transport": "ssh_cli_fallback",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _AutomationStitchRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_automation_stitch_create_cli_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_automation_stitch_delete_action_required",
            "stitch_name_returned": False,
            "trigger_name_returned": False,
            "action_name_returned": False,
            "stitch_status": "disable" if succeeded else "unknown",
            "trigger_or_action_object_modified": False,
            "automation_test_or_execution": False,
            "email_or_external_side_effect": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: AutomationStitchInspection) -> str:
    payload = json.dumps(
        {
            "action_name_exists": inspection.action_name_exists,
            "stitch_name_exists": inspection.stitch_name_exists,
            "trigger_name_exists": inspection.trigger_name_exists,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _stitch_name(value: str) -> str:
    if not isinstance(value, str) or _STITCH_NAME.fullmatch(value) is None:
        raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _trigger_name(value: str) -> str:
    if not isinstance(value, str) or _TRIGGER_NAME.fullmatch(value) is None:
        raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _action_name(value: str) -> str:
    if not isinstance(value, str) or _ACTION_NAME.fullmatch(value) is None:
        raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AutomationStitchLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return isinstance(value, str) and value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "AutomationStitchCreateLiveWorkflow",
    "AutomationStitchLiveWorkflowError",
    "AutomationStitchLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
