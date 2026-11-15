"""One confirmation-gated FortiPAM Secret Policy recording-enable workflow."""

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

from .recording_policy_http_transport import (
    RecordingPolicyInspection,
    RecordingPolicyReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_recording_policy_enable_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Recording Policy action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"mcp-v4-secret-policy-[A-Za-z0-9][A-Za-z0-9._-]{0,42}\Z")


class RecordingPolicyLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded recording workflow."""


class RecordingPolicyLiveWorkflowTransport(Protocol):
    """Exact Secret Policy recording inspection/update contract."""

    def inspect(self, policy_name: str) -> RecordingPolicyInspection: ...

    def enable_and_readback(self, policy_name: str) -> RecordingPolicyReadback: ...


@dataclass(frozen=True, slots=True)
class _RecordingPolicyRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    policy_name: str
    current_digest: str
    state: str
    expires_at: int


class RecordingPolicyEnableLiveWorkflow:
    """Enable recording only on a known laboratory Secret Policy baseline."""

    def __init__(
        self,
        transport: RecordingPolicyLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _RecordingPolicyRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self, *, policy_name: str, requester_digest: str
    ) -> dict[str, object]:
        """Read the current Policy posture and render C/P/E without a write."""

        safe_name = _policy_name(policy_name)
        _require_requester(requester_digest)
        current = self._inspect(safe_name)
        if not current.ready_to_enable:
            raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _RecordingPolicyRecord(
            preview_ref="recording-policy-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            policy_name=safe_name,
            current_digest=current.state_digest,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm the Policy recording baseline is still unchanged."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(record.policy_name)
            if not current.ready_to_enable or not hmac.compare_digest(
                current.state_digest, record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "recording-policy-authorized-" + secrets.token_urlsafe(24)
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
        self, authorization_ref: str, *, requester_digest: str
    ) -> dict[str, object]:
        """Perform exactly the confirmed recording enable and read it back."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(record.policy_name)
            if not current.ready_to_enable or not hmac.compare_digest(
                current.state_digest, record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.enable_and_readback(record.policy_name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if isinstance(readback, RecordingPolicyReadback) and readback.verified
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, policy_name: str) -> RecordingPolicyInspection:
        try:
            result = self._transport.inspect(policy_name)
        except Exception as exc:
            raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, RecordingPolicyInspection):
            raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _RecordingPolicyRecord:
        if not _valid_ref(preview_ref, "recording-policy-preview-"):
            raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self, authorization_ref: str
    ) -> _RecordingPolicyRecord:
        if not _valid_ref(authorization_ref, "recording-policy-authorized-"):
            raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _RecordingPolicyRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _RecordingPolicyRecord, requester_digest: str
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _RecordingPolicyRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "secret_policy_name": record.policy_name,
                "secret_policy_exists": True,
                "recording_enabled": False,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "enable_session_recording_on_existing_secret_policy_via_api",
                "secret_policy_name": record.policy_name,
                "recording": "enable",
                "other_policy_fields_modified": False,
                "folder_or_secret_association_changes": False,
            },
            "Expected State": {
                "secret_policy_name": record.policy_name,
                "secret_policy_exists": True,
                "recording_enabled": True,
                "other_policy_fields_modified": False,
                "folder_or_secret_association_changes": False,
                "readback_transport": "rest_api",
            },
            "device_write_executed": False,
        }

    def _result(
        self, record: _RecordingPolicyRecord, *, idempotent_replay: bool
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_recording_policy_enable_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_confirmed_secret_policy_reconciliation_required",
            "policy_name_returned": False,
            "raw_api_returned": False,
        }


def _policy_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RecordingPolicyLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "RecordingPolicyEnableLiveWorkflow",
    "RecordingPolicyLiveWorkflowError",
    "RecordingPolicyLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
