"""One live, confirmation-gated FortiPAM Dependency Updater create workflow."""

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

from .dependency_updater_ssh_transport import (
    DEPENDENCY_UPDATER_CONFIGURATION,
    DependencyUpdaterInspection,
    DependencyUpdaterReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_dependency_updater_create_cli_fallback_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Dependency Updater create action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"mcp-v4-dependency-updater-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z")
_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._$-]{0,63}\Z")


class DependencyUpdaterLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded Dependency Updater workflow."""


class DependencyUpdaterLiveWorkflowTransport(Protocol):
    """Exact Dependency Updater preflight and create/readback contract."""

    def inspect(self, updater_name: str) -> DependencyUpdaterInspection: ...

    def create_and_readback(
        self,
        updater_name: str,
        service_name: str,
    ) -> DependencyUpdaterReadback: ...


@dataclass(frozen=True, slots=True)
class _DependencyUpdaterRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    updater_name: str
    service_name: str
    current_digest: str
    state: str
    expires_at: int


class DependencyUpdaterCreateLiveWorkflow:
    """Volatile one-confirmation flow for one unattached Dependency Updater."""

    def __init__(
        self,
        transport: DependencyUpdaterLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _DependencyUpdaterRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        updater_name: str,
        service_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read current state and render C/P/E without a device write."""

        safe_updater_name = _updater_name(updater_name)
        safe_service_name = _service_name(service_name)
        _require_requester(requester_digest)
        current = self._inspect(safe_updater_name)
        if current.updater_name_exists:
            raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _DependencyUpdaterRecord(
            preview_ref="dependency-updater-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            updater_name=safe_updater_name,
            service_name=safe_service_name,
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
            current = self._inspect(record.updater_name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "dependency-updater-authorized-" + secrets.token_urlsafe(24)
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
        """Create exactly the confirmed updater and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(record.updater_name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(
                record.updater_name,
                record.service_name,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, DependencyUpdaterReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, updater_name: str) -> DependencyUpdaterInspection:
        try:
            result = self._transport.inspect(updater_name)
        except Exception as exc:
            raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, DependencyUpdaterInspection):
            raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _DependencyUpdaterRecord:
        if not _valid_ref(preview_ref, "dependency-updater-preview-"):
            raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _DependencyUpdaterRecord:
        if not _valid_ref(authorization_ref, "dependency-updater-authorized-"):
            raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _DependencyUpdaterRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _DependencyUpdaterRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _DependencyUpdaterRecord,
        current: DependencyUpdaterInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_updater_name": record.updater_name,
                "requested_service_name": record.service_name,
                "updater_name_exists": current.updater_name_exists,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "create_dependency_updater_via_cli_fallback",
                "updater_name": record.updater_name,
                "service_name": record.service_name,
                "configuration_profile": DEPENDENCY_UPDATER_CONFIGURATION,
                "updater_type": "win-service",
                "restart_after_updates": "disable",
                "secret_or_target_association_changes": False,
                "service_operation_executed": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "updater_name_matches": True,
                "updater_name_exists": True,
                "win_service_type_enabled": True,
                "restart_disabled": True,
                "service_name_matches": True,
                "secret_or_target_association_changes": False,
                "service_operation_executed": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _DependencyUpdaterRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_dependency_updater_create_cli_fallback_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_dependency_updater_delete_action_required",
            "updater_name_returned": False,
            "service_name_returned": False,
            "secret_or_target_association_changes": False,
            "service_operation_executed": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: DependencyUpdaterInspection) -> str:
    payload = json.dumps(
        {"updater_name_exists": inspection.updater_name_exists},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _updater_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _service_name(value: str) -> str:
    if not isinstance(value, str) or _SERVICE_NAME.fullmatch(value) is None:
        raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise DependencyUpdaterLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "DependencyUpdaterCreateLiveWorkflow",
    "DependencyUpdaterLiveWorkflowError",
    "DependencyUpdaterLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
