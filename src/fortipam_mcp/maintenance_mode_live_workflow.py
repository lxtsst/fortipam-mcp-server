"""One confirmation-gated FortiPAM maintenance-mode enable workflow."""

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

from .maintenance_mode_ssh_transport import (
    MAINTENANCE_MODE_CONFIGURATION,
    MAINTENANCE_MODE_ROLLBACK_CONFIGURATION,
    MaintenanceModeInspection,
    MaintenanceModeReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_maintenance_mode_enable_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 maintenance mode action is unavailable."
_TTL_SECONDS = 600


class MaintenanceModeLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded maintenance workflow."""


class MaintenanceModeLiveWorkflowTransport(Protocol):
    """Fixed maintenance-mode inspection and enable/readback contract."""

    def inspect(self) -> MaintenanceModeInspection: ...

    def enable_and_readback(self) -> MaintenanceModeReadback: ...

    def disable_and_readback(self) -> MaintenanceModeReadback: ...


@dataclass(frozen=True, slots=True)
class _MaintenanceModeRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    state: str
    expires_at: int


class MaintenanceModeLiveWorkflow:
    """Volatile C/P/E flow for the one maintenance-mode enable transition."""

    def __init__(
        self,
        transport: MaintenanceModeLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _MaintenanceModeRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        """Read the exact disabled baseline and render C/P/E without a write."""

        _require_requester(requester_digest)
        current = self._inspect()
        if not current.exact_disabled_baseline:
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _MaintenanceModeRecord(
            preview_ref="maintenance-mode-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm unchanged baseline and issue one execution reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect()
            if (
                not current.exact_disabled_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "maintenance-mode-authorized-" + secrets.token_urlsafe(24)
            updated = replace(record, authorization_ref=authorization_ref, state="authorized")
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
        """Enable only confirmed maintenance mode and categorize CLI readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect()
            if (
                not current.exact_disabled_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.enable_and_readback()
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, MaintenanceModeReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> MaintenanceModeInspection:
        try:
            current = self._transport.inspect()
        except Exception as exc:
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(current, MaintenanceModeInspection):
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return current

    def _record_for_preview_locked(self, preview_ref: str) -> _MaintenanceModeRecord:
        if not _valid_ref(preview_ref, "maintenance-mode-preview-"):
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _MaintenanceModeRecord:
        if not _valid_ref(authorization_ref, "maintenance-mode-authorized-"):
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _MaintenanceModeRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _MaintenanceModeRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records[preview_ref] = replace(record, state=state)

    def _purge_expired_locked(self) -> None:
        now_epoch = self._clock()
        expired = [
            preview_ref
            for preview_ref, record in self._records.items()
            if record.expires_at <= now_epoch and record.state != "completed"
        ]
        for preview_ref in expired:
            record = self._records.pop(preview_ref)
            if record.authorization_ref is not None:
                self._authorization_index.pop(record.authorization_ref, None)

    @staticmethod
    def _preview_projection(
        record: _MaintenanceModeRecord,
        current: MaintenanceModeInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "maintenance_mode_status": current.status,
                "critical_process_effect_verified": False,
                "reboot_requested": False,
                "firmware_or_license_upload_requested": False,
                "configuration_restore_requested": False,
                "tpm_or_disk_encryption_changed": False,
                "write_transport": "strict_api_preflight_ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "enable_maintenance_mode_via_cli_fallback",
                "configuration_profile": MAINTENANCE_MODE_CONFIGURATION,
                "maintenance_mode_status": "enable",
                "critical_process_effect_tested": False,
                "reboot_requested": False,
                "firmware_or_license_upload_requested": False,
                "configuration_restore_requested": False,
                "tpm_or_disk_encryption_changed": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "maintenance_mode_status": "enable",
                "critical_process_effect_verified": False,
                "reboot_requested": False,
                "firmware_or_license_upload_requested": False,
                "configuration_restore_requested": False,
                "tpm_or_disk_encryption_changed": False,
                "readback_transport": "strict_api_after_ssh_cli_write",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _MaintenanceModeRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_maintenance_mode_enable_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_maintenance_mode_disable_action_required",
            "maintenance_mode_status": "enable" if succeeded else "unknown",
            "critical_process_effect_verified": False,
            "reboot_requested": False,
            "firmware_or_license_upload_requested": False,
            "configuration_restore_requested": False,
            "tpm_or_disk_encryption_changed": False,
            "raw_cli_returned": False,
        }


class MaintenanceModeRollbackLiveWorkflow:
    """One-confirmation restoration to the ordinary disabled mode."""

    def __init__(
        self,
        transport: MaintenanceModeLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _MaintenanceModeRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        _require_requester(requester_digest)
        current = self._inspect()
        if not current.exact_enabled_baseline:
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _MaintenanceModeRecord(
            preview_ref="maintenance-mode-rollback-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect()
            if (
                not current.exact_enabled_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = (
                "maintenance-mode-rollback-authorized-" + secrets.token_urlsafe(24)
            )
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": "fortipam_v4_maintenance_mode_rollback_workflow_v1",
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
            if (
                not current.exact_enabled_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.disable_and_readback()
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, MaintenanceModeReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified_disabled else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> MaintenanceModeInspection:
        try:
            current = self._transport.inspect()
        except Exception as exc:
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(current, MaintenanceModeInspection):
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return current

    def _record_for_preview_locked(self, preview_ref: str) -> _MaintenanceModeRecord:
        if not _valid_ref(preview_ref, "maintenance-mode-rollback-preview-"):
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _MaintenanceModeRecord:
        if not _valid_ref(
            authorization_ref,
            "maintenance-mode-rollback-authorized-",
        ):
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _MaintenanceModeRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _MaintenanceModeRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records[preview_ref] = replace(record, state=state)

    def _purge_expired_locked(self) -> None:
        now_epoch = self._clock()
        expired = [
            preview_ref
            for preview_ref, record in self._records.items()
            if record.expires_at <= now_epoch and record.state != "completed"
        ]
        for preview_ref in expired:
            record = self._records.pop(preview_ref)
            if record.authorization_ref is not None:
                self._authorization_index.pop(record.authorization_ref, None)

    @staticmethod
    def _preview_projection(
        record: _MaintenanceModeRecord,
        current: MaintenanceModeInspection,
    ) -> dict[str, object]:
        unchanged = {
            "critical_process_effect_verified": False,
            "reboot_requested": False,
            "firmware_or_license_upload_requested": False,
            "configuration_restore_requested": False,
            "tpm_or_disk_encryption_changed": False,
        }
        return {
            "contract": "fortipam_v4_maintenance_mode_rollback_workflow_v1",
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "maintenance_mode_status": current.status,
                **unchanged,
                "write_transport": "strict_api_preflight_ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "restore_ordinary_maintenance_mode_disabled_state_via_cli_fallback",
                "configuration_profile": MAINTENANCE_MODE_ROLLBACK_CONFIGURATION,
                "maintenance_mode_status": "disable",
                **unchanged,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "pre_action_state_restored": True,
                "maintenance_mode_status": "disable",
                **unchanged,
                "readback_transport": "strict_api_and_ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _MaintenanceModeRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_maintenance_mode_rollback_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "pre_action_state_restored": succeeded,
            "maintenance_mode_status": "disable" if succeeded else "unknown",
            "critical_process_effect_verified": False,
            "reboot_requested": False,
            "firmware_or_license_upload_requested": False,
            "configuration_restore_requested": False,
            "tpm_or_disk_encryption_changed": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: MaintenanceModeInspection) -> str:
    payload = json.dumps(
        {"status": inspection.status},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise MaintenanceModeLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "MaintenanceModeLiveWorkflow",
    "MaintenanceModeLiveWorkflowError",
    "MaintenanceModeLiveWorkflowTransport",
    "MaintenanceModeRollbackLiveWorkflow",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
