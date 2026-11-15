"""One confirmation-gated FortiPAM Access-level ZTNA user-control workflow."""

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

from .ztna_user_control_ssh_transport import (
    ZTNA_USER_CONTROL_CONFIGURATION,
    ZTNA_USER_CONTROL_ROLLBACK_CONFIGURATION,
    ZtnaUserControlInspection,
    ZtnaUserControlReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_ztna_user_control_access_level_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 ZTNA user-control action is unavailable."
_TTL_SECONDS = 600


class ZtnaUserControlLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded ZTNA workflow."""


class ZtnaUserControlLiveWorkflowTransport(Protocol):
    """Fixed private Access-level ZTNA inspection and enable/readback contract."""

    def inspect(self) -> ZtnaUserControlInspection: ...

    def enable_and_readback(self) -> ZtnaUserControlReadback: ...

    def disable_and_readback(self) -> ZtnaUserControlReadback: ...


@dataclass(frozen=True, slots=True)
class _ZtnaUserControlRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    state: str
    expires_at: int


class ZtnaUserControlLiveWorkflow:
    """Volatile C/P/E flow for one existing Access-level policy transition."""

    def __init__(
        self,
        transport: ZtnaUserControlLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _ZtnaUserControlRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        """Read the exact disabled baseline and render C/P/E without a write."""

        _require_requester(requester_digest)
        current = self._inspect()
        if not current.exact_disabled_access_level_baseline:
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _ZtnaUserControlRecord(
            preview_ref="ztna-user-control-preview-" + secrets.token_urlsafe(24),
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
                not current.exact_disabled_access_level_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "ztna-user-control-authorized-" + secrets.token_urlsafe(24)
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
        """Enable only the confirmed policy flag and categorize readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect()
            if (
                not current.exact_disabled_access_level_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.enable_and_readback()
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, ZtnaUserControlReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> ZtnaUserControlInspection:
        try:
            current = self._transport.inspect()
        except Exception as exc:
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(current, ZtnaUserControlInspection):
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return current

    def _record_for_preview_locked(self, preview_ref: str) -> _ZtnaUserControlRecord:
        if not _valid_ref(preview_ref, "ztna-user-control-preview-"):
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _ZtnaUserControlRecord:
        if not _valid_ref(authorization_ref, "ztna-user-control-authorized-"):
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _ZtnaUserControlRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _ZtnaUserControlRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _ZtnaUserControlRecord,
        current: ZtnaUserControlInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "client_certificate_mode": current.client_certificate_mode,
                "empty_certificate_action": current.empty_certificate_action,
                "policy_is_access_proxy": current.policy_is_access_proxy,
                "existing_ems_tag_configured": current.policy_ems_tag_matches,
                "ztna_status": current.ztna_status,
                "access_proxy_reference_returned": False,
                "policy_reference_returned": False,
                "ems_tag_reference_returned": False,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "enable_access_level_ztna_for_existing_ems_tag_via_cli_fallback",
                "configuration_profile": ZTNA_USER_CONTROL_CONFIGURATION,
                "ztna_status": "enable",
                "existing_ems_tag_preserved": True,
                "access_proxy_client_certificate_changed": False,
                "empty_certificate_action_changed": False,
                "access_proxy_binding_changed": False,
                "ems_connector_or_tag_sync_changed": False,
                "folder_or_secret_control_changed": False,
                "wad_debug_enabled": False,
                "session_or_secret_launch_executed": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "ztna_status": "enable",
                "existing_ems_tag_preserved": True,
                "managed_only_portal_login_required": True,
                "unmanaged_portal_access_allowed": False,
                "access_proxy_client_certificate_changed": False,
                "empty_certificate_action_changed": False,
                "folder_or_secret_control_changed": False,
                "session_or_secret_launch_effect_verified": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _ZtnaUserControlRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_ztna_user_control_access_level_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_ztna_user_control_disable_action_required",
            "ztna_scope": "access_level_only",
            "existing_ems_tag_preserved": True,
            "access_proxy_reference_returned": False,
            "policy_reference_returned": False,
            "ems_tag_reference_returned": False,
            "access_proxy_client_certificate_changed": False,
            "empty_certificate_action_changed": False,
            "folder_or_secret_control_changed": False,
            "wad_debug_enabled": False,
            "session_or_secret_launch_effect_verified": False,
            "raw_cli_returned": False,
        }


class ZtnaUserControlRollbackLiveWorkflow:
    """One-confirmation rollback to the exact disabled policy state."""

    def __init__(
        self,
        transport: ZtnaUserControlLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _ZtnaUserControlRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        """Read the exact enabled outcome and render a fixed disable rollback."""

        _require_requester(requester_digest)
        current = self._inspect()
        if not current.exact_enabled_access_level_baseline:
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _ZtnaUserControlRecord(
            preview_ref="ztna-user-control-rollback-preview-"
            + secrets.token_urlsafe(24),
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
        """Confirm the unchanged enabled state and issue one rollback reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect()
            if (
                not current.exact_enabled_access_level_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = (
                "ztna-user-control-rollback-authorized-" + secrets.token_urlsafe(24)
            )
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": "fortipam_v4_ztna_user_control_rollback_workflow_v1",
            "preview_ref": updated.preview_ref,
            "authorization_ref": authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": updated.expires_at,
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Restore ztna-status disable and categorize the exact readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect()
            if (
                not current.exact_enabled_access_level_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.disable_and_readback()
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, ZtnaUserControlReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified_disabled else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> ZtnaUserControlInspection:
        try:
            current = self._transport.inspect()
        except Exception as exc:
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(current, ZtnaUserControlInspection):
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return current

    def _record_for_preview_locked(self, preview_ref: str) -> _ZtnaUserControlRecord:
        if not _valid_ref(preview_ref, "ztna-user-control-rollback-preview-"):
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _ZtnaUserControlRecord:
        if not _valid_ref(
            authorization_ref,
            "ztna-user-control-rollback-authorized-",
        ):
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _ZtnaUserControlRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _ZtnaUserControlRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _ZtnaUserControlRecord,
        current: ZtnaUserControlInspection,
    ) -> dict[str, object]:
        return {
            "contract": "fortipam_v4_ztna_user_control_rollback_workflow_v1",
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "client_certificate_mode": current.client_certificate_mode,
                "empty_certificate_action": current.empty_certificate_action,
                "policy_is_access_proxy": current.policy_is_access_proxy,
                "existing_ems_tag_configured": current.policy_ems_tag_matches,
                "ztna_status": current.ztna_status,
                "access_proxy_reference_returned": False,
                "policy_reference_returned": False,
                "ems_tag_reference_returned": False,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "restore_access_level_ztna_pre_action_state_via_cli_fallback",
                "configuration_profile": ZTNA_USER_CONTROL_ROLLBACK_CONFIGURATION,
                "ztna_status": "disable",
                "existing_ems_tag_preserved": True,
                "access_proxy_client_certificate_changed": False,
                "empty_certificate_action_changed": False,
                "access_proxy_binding_changed": False,
                "ems_connector_or_tag_sync_changed": False,
                "folder_or_secret_control_changed": False,
                "wad_debug_enabled": False,
                "session_or_secret_launch_executed": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "pre_action_state_restored": True,
                "ztna_status": "disable",
                "existing_ems_tag_preserved": True,
                "access_level_tag_enforcement_enabled": False,
                "portal_login_effect_verified": False,
                "access_proxy_client_certificate_changed": False,
                "empty_certificate_action_changed": False,
                "folder_or_secret_control_changed": False,
                "session_or_secret_launch_effect_verified": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _ZtnaUserControlRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_ztna_user_control_rollback_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "pre_action_state_restored": succeeded,
            "ztna_scope": "access_level_only",
            "existing_ems_tag_preserved": True,
            "access_proxy_reference_returned": False,
            "policy_reference_returned": False,
            "ems_tag_reference_returned": False,
            "access_proxy_client_certificate_changed": False,
            "empty_certificate_action_changed": False,
            "folder_or_secret_control_changed": False,
            "wad_debug_enabled": False,
            "portal_login_effect_verified": False,
            "session_or_secret_launch_effect_verified": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: ZtnaUserControlInspection) -> str:
    payload = json.dumps(
        {
            "client_certificate_mode": inspection.client_certificate_mode,
            "empty_certificate_action": inspection.empty_certificate_action,
            "policy_is_access_proxy": inspection.policy_is_access_proxy,
            "policy_access_proxy_matches": inspection.policy_access_proxy_matches,
            "policy_ems_tag_matches": inspection.policy_ems_tag_matches,
            "ztna_status": inspection.ztna_status,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ZtnaUserControlLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
    "ZtnaUserControlLiveWorkflow",
    "ZtnaUserControlLiveWorkflowError",
    "ZtnaUserControlLiveWorkflowTransport",
    "ZtnaUserControlRollbackLiveWorkflow",
]
