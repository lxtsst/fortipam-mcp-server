"""One live, confirmation-gated FortiPAM Approval Email Template update workflow."""

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

from .approval_email_template_ssh_transport import (
    APPROVAL_EMAIL_TEMPLATE_UPDATE_CONFIGURATION,
    ApprovalEmailTemplateReadback,
    ApprovalEmailTemplateUpdateReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_approval_email_template_update_cli_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Approval Email Template update action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(
    r"mcp-v4-approval-email-template-[A-Za-z0-9][A-Za-z0-9._-]{0,32}\Z"
)


class ApprovalEmailTemplateUpdateLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded template update."""


class ApprovalEmailTemplateUpdateLiveWorkflowTransport(Protocol):
    """Exact initial readback and fixed update/readback contract."""

    def readback(self, template_name: str) -> ApprovalEmailTemplateReadback: ...

    def update_and_readback(
        self,
        template_name: str,
    ) -> ApprovalEmailTemplateUpdateReadback: ...


@dataclass(frozen=True, slots=True)
class _ApprovalEmailTemplateUpdateRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    template_name: str
    current_digest: str
    state: str
    expires_at: int


class ApprovalEmailTemplateUpdateLiveWorkflow:
    """One-confirmation update of a known template baseline only."""

    def __init__(
        self,
        transport: ApprovalEmailTemplateUpdateLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _ApprovalEmailTemplateUpdateRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, template_name: str, requester_digest: str) -> dict[str, object]:
        """Read the known baseline and render C/P/E without a device write."""

        safe_name = _template_name(template_name)
        _require_requester(requester_digest)
        current = self._readback(safe_name)
        if not current.verified:
            raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _ApprovalEmailTemplateUpdateRecord(
            preview_ref="approval-email-template-update-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            template_name=safe_name,
            current_digest=_readback_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm the exact baseline remains unchanged."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._readback(record.template_name)
            if not current.verified or _readback_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = (
                "approval-email-template-update-authorized-" + secrets.token_urlsafe(24)
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
        """Apply fixed content revision and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._readback(record.template_name)
            if not current.verified or _readback_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.update_and_readback(record.template_name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, ApprovalEmailTemplateUpdateReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _readback(self, template_name: str) -> ApprovalEmailTemplateReadback:
        try:
            result = self._transport.readback(template_name)
        except Exception as exc:
            raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, ApprovalEmailTemplateReadback):
            raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(
        self,
        preview_ref: str,
    ) -> _ApprovalEmailTemplateUpdateRecord:
        if not _valid_ref(preview_ref, "approval-email-template-update-preview-"):
            raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _ApprovalEmailTemplateUpdateRecord:
        if not _valid_ref(authorization_ref, "approval-email-template-update-authorized-"):
            raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _ApprovalEmailTemplateUpdateRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _ApprovalEmailTemplateUpdateRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _ApprovalEmailTemplateUpdateRecord,
        current: ApprovalEmailTemplateReadback,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_template_name": record.template_name,
                "template_name_exists": current.template_name_exists,
                "known_create_baseline_verified": current.verified,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "update_approval_email_template_via_cli_fallback",
                "template_name": record.template_name,
                "configuration_profile": APPROVAL_EMAIL_TEMPLATE_UPDATE_CONFIGURATION,
                "subject_or_content_value_returned": False,
                "email_server_changes": False,
                "approval_profile_or_secret_association_changes": False,
                "email_delivery_or_approval_execution": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "template_name_matches": True,
                "template_name_exists": True,
                "updated_subject_present": True,
                "updated_content_present": True,
                "email_server_changes": False,
                "approval_profile_or_secret_association_changes": False,
                "email_delivery_or_approval_execution": False,
                "readback_transport": "ssh_cli_fallback",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _ApprovalEmailTemplateUpdateRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_approval_email_template_update_cli_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_approval_email_template_content_restore_action_required",
            "template_name_returned": False,
            "subject_or_content_value_returned": False,
            "email_server_changes": False,
            "approval_profile_or_secret_association_changes": False,
            "email_delivery_or_approval_execution": False,
            "raw_cli_returned": False,
        }


def _readback_digest(readback: ApprovalEmailTemplateReadback) -> str:
    payload = json.dumps(
        {
            "template_name_exists": readback.template_name_exists,
            "fixed_subject_present": readback.fixed_subject_present,
            "fixed_content_present": readback.fixed_content_present,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _template_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ApprovalEmailTemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "ApprovalEmailTemplateUpdateLiveWorkflow",
    "ApprovalEmailTemplateUpdateLiveWorkflowError",
    "ApprovalEmailTemplateUpdateLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
