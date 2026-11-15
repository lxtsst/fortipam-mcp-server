"""One confirmation-gated FortiPAM disposable Template archive workflow."""

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

from .template_archive_http_transport import TemplateArchiveDeleteReadback
from .template_ssh_transport import (
    TEMPLATE_ARCHIVE_CONFIGURATION,
    TemplateArchiveAbsenceReadback,
    TemplateArchivePreflightReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_template_archive_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Template archive action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"mcp-v4-template-archive-[A-Za-z0-9][A-Za-z0-9._-]{0,38}\Z")


class TemplateArchiveLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the irreversible Template action."""


class TemplateArchiveInspectionTransport(Protocol):
    """Fixed categorical Template and direct-reference inspection contract."""

    def archive_preflight_readback(
        self,
        template_name: str,
    ) -> TemplateArchivePreflightReadback: ...

    def archive_absence_readback(
        self,
        template_name: str,
    ) -> TemplateArchiveAbsenceReadback: ...


class TemplateArchiveDeleteTransport(Protocol):
    """Fixed REST DELETE contract for one special-purpose Template."""

    def delete_template(self, template_name: str) -> TemplateArchiveDeleteReadback: ...


@dataclass(frozen=True, slots=True)
class _TemplateArchiveRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    template_name: str
    current_digest: str
    state: str
    expires_at: int


class TemplateArchiveLiveWorkflow:
    """Delete only one exact, baseline-bound, directly unreferenced Template."""

    def __init__(
        self,
        inspection_transport: TemplateArchiveInspectionTransport,
        delete_transport: TemplateArchiveDeleteTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._inspection_transport = inspection_transport
        self._delete_transport = delete_transport
        self._clock = clock or _now
        self._records: dict[str, _TemplateArchiveRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, template_name: str, requester_digest: str) -> dict[str, object]:
        """Render a destructive C/P/E preview from fixed current state only."""

        safe_name = _template_name(template_name)
        _require_requester(requester_digest)
        current = self._preflight(safe_name)
        if not current.verified:
            raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _TemplateArchiveRecord(
            preview_ref="template-archive-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            template_name=safe_name,
            current_digest=_preflight_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Require the exact safe baseline again before granting one execution ref."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._preflight(record.template_name)
            if (
                not current.verified
                or not hmac.compare_digest(
                    _preflight_digest(current),
                    record.current_digest,
                )
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "template-archive-authorized-" + secrets.token_urlsafe(24)
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
        """Delete exactly the confirmed Template then prove categorical absence."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._preflight(record.template_name)
            if (
                not current.verified
                or not hmac.compare_digest(
                    _preflight_digest(current),
                    record.current_digest,
                )
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            deletion = self._delete_transport.delete_template(record.template_name)
            absence = self._absence(record.template_name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if isinstance(deletion, TemplateArchiveDeleteReadback)
                and deletion.deletion_accepted
                and absence.verified
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _preflight(self, template_name: str) -> TemplateArchivePreflightReadback:
        try:
            result = self._inspection_transport.archive_preflight_readback(template_name)
        except Exception as exc:
            raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, TemplateArchivePreflightReadback):
            raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _absence(self, template_name: str) -> TemplateArchiveAbsenceReadback:
        try:
            result = self._inspection_transport.archive_absence_readback(template_name)
        except Exception as exc:
            raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, TemplateArchiveAbsenceReadback):
            raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _TemplateArchiveRecord:
        if not _valid_ref(preview_ref, "template-archive-preview-"):
            raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _TemplateArchiveRecord:
        if not _valid_ref(authorization_ref, "template-archive-authorized-"):
            raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _TemplateArchiveRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _TemplateArchiveRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _TemplateArchiveRecord,
        current: TemplateArchivePreflightReadback,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_template_name": record.template_name,
                "template_exists": current.template_name_exists,
                "known_web_vnc_create_baseline_verified": current.verified,
                "secret_reference_absent": current.secret_references_absent,
                "target_reference_absent": current.target_references_absent,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "archive_by_deleting_unreferenced_v4_template_via_api",
                "template_name": record.template_name,
                "configuration_profile": TEMPLATE_ARCHIVE_CONFIGURATION,
                "irreversible_after_execution": True,
                "secret_or_target_association_changes": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "template_name_absent": True,
                "template_exists": False,
                "template_absence_verified_by_ssh_readback": True,
                "secret_reference_absent": True,
                "target_reference_absent": True,
                "other_template_configuration_modified": False,
                "secret_or_target_association_changes": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _TemplateArchiveRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_template_archive_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "manual_recreation_or_backup_restore_required",
            "irreversible_after_execution": True,
            "template_name_returned": False,
            "secret_or_target_association_changes": False,
            "raw_api_response_returned": False,
        }


def _template_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise TemplateArchiveLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and 24 <= len(value) <= 160
        and re.fullmatch(r"[A-Za-z0-9_-]+", value[len(prefix) :]) is not None
    )


def _preflight_digest(readback: TemplateArchivePreflightReadback) -> str:
    encoded = json.dumps(
        {
            "template_name_exists": readback.template_name_exists,
            "access_everyone": readback.access_everyone,
            "username_field_present": readback.username_field_present,
            "username_field_mandatory": readback.username_field_mandatory,
            "password_field_present": readback.password_field_present,
            "password_field_mandatory": readback.password_field_mandatory,
            "web_vnc_launcher_present": readback.web_vnc_launcher_present,
            "web_vnc_port_is_default": readback.web_vnc_port_is_default,
            "secret_references_absent": readback.secret_references_absent,
            "target_references_absent": readback.target_references_absent,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _now() -> int:
    return int(time.time())


__all__ = [
    "TemplateArchiveDeleteTransport",
    "TemplateArchiveInspectionTransport",
    "TemplateArchiveLiveWorkflow",
    "TemplateArchiveLiveWorkflowError",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
