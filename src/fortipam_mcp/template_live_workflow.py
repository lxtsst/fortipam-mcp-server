"""One confirmation-gated FortiPAM Web VNC Template create workflow."""

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

from .template_ssh_transport import (
    TEMPLATE_CONFIGURATION,
    TemplateInspection,
    TemplateReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_template_create_cli_fallback_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Template create action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"mcp-v4-template-[A-Za-z0-9][A-Za-z0-9._-]{0,46}\Z")


class TemplateLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded Template workflow."""


class TemplateLiveWorkflowTransport(Protocol):
    """Exact Template preflight and create/readback contract."""

    def inspect(self, template_name: str) -> TemplateInspection: ...

    def create_and_readback(self, template_name: str) -> TemplateReadback: ...


@dataclass(frozen=True, slots=True)
class _TemplateRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    template_name: str
    current_digest: str
    state: str
    expires_at: int


class TemplateCreateLiveWorkflow:
    """Volatile one-confirmation flow for one unattached Web VNC Template."""

    def __init__(
        self,
        transport: TemplateLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _TemplateRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, template_name: str, requester_digest: str) -> dict[str, object]:
        """Read current state and render C/P/E without a device write."""

        safe_name = _template_name(template_name)
        _require_requester(requester_digest)
        current = self._inspect(safe_name)
        if current.template_name_exists:
            raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _TemplateRecord(
            preview_ref="template-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            template_name=safe_name,
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
            current = self._inspect(record.template_name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "template-authorized-" + secrets.token_urlsafe(24)
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
        """Create exactly the confirmed Template and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(record.template_name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(record.template_name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, TemplateReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, template_name: str) -> TemplateInspection:
        try:
            result = self._transport.inspect(template_name)
        except Exception as exc:
            raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, TemplateInspection):
            raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _TemplateRecord:
        if not _valid_ref(preview_ref, "template-preview-"):
            raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _TemplateRecord:
        if not _valid_ref(authorization_ref, "template-authorized-"):
            raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _TemplateRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _TemplateRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _TemplateRecord,
        current: TemplateInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_template_name": record.template_name,
                "template_name_exists": current.template_name_exists,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "create_web_vnc_template_via_cli_fallback",
                "template_name": record.template_name,
                "configuration_profile": TEMPLATE_CONFIGURATION,
                "template_access": "everyone",
                "mandatory_fields": ["username", "password"],
                "launcher": "Web VNC",
                "launcher_port": 5900,
                "secret_or_target_association_changes": False,
                "secret_field_values_supplied": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "template_name_matches": True,
                "template_name_exists": True,
                "access_everyone": True,
                "username_field_present": True,
                "username_field_mandatory": True,
                "password_field_present": True,
                "password_field_mandatory": True,
                "web_vnc_launcher_present": True,
                "web_vnc_port_matches": True,
                "secret_or_target_association_changes": False,
                "secret_field_values_supplied": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _TemplateRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_template_create_cli_fallback_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_template_archive_action_required",
            "template_name_returned": False,
            "secret_or_target_association_changes": False,
            "secret_field_values_returned": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: TemplateInspection) -> str:
    payload = json.dumps(
        {"template_name_exists": inspection.template_name_exists},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _template_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise TemplateLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "TemplateCreateLiveWorkflow",
    "TemplateLiveWorkflowError",
    "TemplateLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
