"""One confirmation-gated ZTNA Access Proxy prerequisite workflow.

This local V4 package implements only the client-certificate prerequisite for
Secret-level ZTNA.  EMS tags, proxy policy tag enforcement, Folder/Secret
controls, sessions, and WAD debugging remain separate action contracts.
"""

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

from .ztna_access_proxy_client_certificate_ssh_transport import (
    ZTNA_ACCESS_PROXY_CONFIGURATION,
    ZTNA_MANAGED_ONLY,
    ZTNA_MIXED_ACCESS,
    ZtnaAccessProxyInspection,
    ZtnaAccessProxyReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_ztna_access_proxy_client_certificate_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 ZTNA Access Proxy action is unavailable."
_TTL_SECONDS = 600
_ACCESS_MODES = frozenset((ZTNA_MANAGED_ONLY, ZTNA_MIXED_ACCESS))


class ZtnaAccessProxyLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded ZTNA workflow."""


class ZtnaAccessProxyLiveWorkflowTransport(Protocol):
    """Fixed private Access Proxy inspection and update/readback contract."""

    def inspect(self) -> ZtnaAccessProxyInspection: ...

    def configure_and_readback(self, endpoint_access_mode: str) -> ZtnaAccessProxyReadback: ...

    def restore_disabled_block_and_readback(self) -> ZtnaAccessProxyReadback: ...


@dataclass(frozen=True, slots=True)
class _ZtnaAccessProxyRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    endpoint_access_mode: str
    current_digest: str
    state: str
    expires_at: int


class ZtnaAccessProxyClientCertificateLiveWorkflow:
    """Volatile one-confirmation flow for a fixed Secret-level prerequisite."""

    def __init__(
        self,
        transport: ZtnaAccessProxyLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _ZtnaAccessProxyRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        endpoint_access_mode: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read the exact safe baseline and render Current/Proposed/Expected."""

        mode = _access_mode(endpoint_access_mode)
        _require_requester(requester_digest)
        current = self._inspect()
        if not current.exact_disabled_block_baseline:
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _ZtnaAccessProxyRecord(
            preview_ref="ztna-access-proxy-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            endpoint_access_mode=mode,
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
                not current.exact_disabled_block_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "ztna-access-proxy-authorized-" + secrets.token_urlsafe(24)
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
        """Apply exactly the confirmed prerequisite and categorize readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect()
            if (
                not current.exact_disabled_block_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.configure_and_readback(record.endpoint_access_mode)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, ZtnaAccessProxyReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if readback.verified_for(record.endpoint_access_mode)
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> ZtnaAccessProxyInspection:
        try:
            result = self._transport.inspect()
        except Exception as exc:
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, ZtnaAccessProxyInspection):
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _ZtnaAccessProxyRecord:
        if not _valid_ref(preview_ref, "ztna-access-proxy-preview-"):
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _ZtnaAccessProxyRecord:
        if not _valid_ref(authorization_ref, "ztna-access-proxy-authorized-"):
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _ZtnaAccessProxyRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _ZtnaAccessProxyRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _ZtnaAccessProxyRecord,
        current: ZtnaAccessProxyInspection,
    ) -> dict[str, object]:
        managed_only = record.endpoint_access_mode == ZTNA_MANAGED_ONLY
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_endpoint_access_mode": record.endpoint_access_mode,
                "client_certificate_mode": current.client_certificate_mode,
                "empty_certificate_action": current.empty_certificate_action,
                "access_proxy_reference_returned": False,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "configure_ztna_access_proxy_client_certificate_prerequisite_via_cli_fallback",
                "configuration_profile": ZTNA_ACCESS_PROXY_CONFIGURATION,
                "endpoint_access_mode": record.endpoint_access_mode,
                "client_certificate_mode": "enable",
                "empty_certificate_action": "block" if managed_only else "accept",
                "access_level_proxy_policy_changed": False,
                "folder_or_secret_control_changed": False,
                "ems_connector_or_tag_changed": False,
                "wad_debug_enabled": False,
                "session_or_secret_launch_executed": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "endpoint_access_mode_matches": True,
                "client_certificate_mode": "enable",
                "empty_certificate_action": "block" if managed_only else "accept",
                "managed_only_portal_login_required": managed_only,
                "unmanaged_portal_access_allowed": not managed_only,
                "access_level_proxy_policy_changed": False,
                "folder_or_secret_control_changed": False,
                "ems_connector_or_tag_changed": False,
                "session_or_secret_launch_effect_verified": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _ZtnaAccessProxyRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_ztna_access_proxy_client_certificate_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_ztna_access_proxy_rollback_action_required",
            "endpoint_access_mode": record.endpoint_access_mode,
            "access_proxy_reference_returned": False,
            "access_level_proxy_policy_changed": False,
            "folder_or_secret_control_changed": False,
            "ems_connector_or_tag_changed": False,
            "wad_debug_enabled": False,
            "session_or_secret_launch_effect_verified": False,
            "raw_cli_returned": False,
        }


class ZtnaAccessProxyClientCertificateRollbackLiveWorkflow:
    """One-confirmation rollback to the exact accepted pre-action state."""

    def __init__(
        self,
        transport: ZtnaAccessProxyLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _ZtnaAccessProxyRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        """Read one enabled outcome and render an exact disable/block rollback."""

        _require_requester(requester_digest)
        current = self._inspect()
        source_mode = _rollback_source_mode(current)
        record = _ZtnaAccessProxyRecord(
            preview_ref="ztna-access-proxy-rollback-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            endpoint_access_mode=source_mode,
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
                _rollback_source_mode(current) != record.endpoint_access_mode
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = (
                "ztna-access-proxy-rollback-authorized-" + secrets.token_urlsafe(24)
            )
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": "fortipam_v4_ztna_access_proxy_client_certificate_rollback_workflow_v1",
            "preview_ref": updated.preview_ref,
            "authorization_ref": authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": updated.expires_at,
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Restore disable/block and categorize the exact readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect()
            if (
                _rollback_source_mode(current) != record.endpoint_access_mode
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.restore_disabled_block_and_readback()
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, ZtnaAccessProxyReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified_disabled_block else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> ZtnaAccessProxyInspection:
        try:
            result = self._transport.inspect()
        except Exception as exc:
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, ZtnaAccessProxyInspection):
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _ZtnaAccessProxyRecord:
        if not _valid_ref(preview_ref, "ztna-access-proxy-rollback-preview-"):
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _ZtnaAccessProxyRecord:
        if not _valid_ref(
            authorization_ref, "ztna-access-proxy-rollback-authorized-"
        ):
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _ZtnaAccessProxyRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _ZtnaAccessProxyRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _ZtnaAccessProxyRecord,
        current: ZtnaAccessProxyInspection,
    ) -> dict[str, object]:
        return {
            "contract": "fortipam_v4_ztna_access_proxy_client_certificate_rollback_workflow_v1",
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "endpoint_access_mode": record.endpoint_access_mode,
                "client_certificate_mode": current.client_certificate_mode,
                "empty_certificate_action": current.empty_certificate_action,
                "access_proxy_reference_returned": False,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "restore_ztna_access_proxy_client_certificate_pre_action_state_via_cli_fallback",
                "configuration_profile": "restore-pre-action-disabled-block-v1",
                "client_certificate_mode": "disable",
                "empty_certificate_action": "block",
                "access_level_proxy_policy_changed": False,
                "folder_or_secret_control_changed": False,
                "ems_connector_or_tag_changed": False,
                "wad_debug_enabled": False,
                "session_or_secret_launch_executed": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "pre_action_state_restored": True,
                "client_certificate_mode": "disable",
                "empty_certificate_action": "block",
                "access_level_proxy_policy_changed": False,
                "folder_or_secret_control_changed": False,
                "ems_connector_or_tag_changed": False,
                "session_or_secret_launch_effect_verified": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _ZtnaAccessProxyRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_ztna_access_proxy_client_certificate_rollback_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "source_endpoint_access_mode": record.endpoint_access_mode,
            "pre_action_state_restored": succeeded,
            "access_proxy_reference_returned": False,
            "access_level_proxy_policy_changed": False,
            "folder_or_secret_control_changed": False,
            "ems_connector_or_tag_changed": False,
            "wad_debug_enabled": False,
            "session_or_secret_launch_effect_verified": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: ZtnaAccessProxyInspection) -> str:
    payload = json.dumps(
        {
            "client_certificate_mode": inspection.client_certificate_mode,
            "empty_certificate_action": inspection.empty_certificate_action,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _rollback_source_mode(inspection: ZtnaAccessProxyInspection) -> str:
    if inspection.client_certificate_mode != "enable":
        raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    if inspection.empty_certificate_action == "block":
        return ZTNA_MANAGED_ONLY
    if inspection.empty_certificate_action == "accept":
        return ZTNA_MIXED_ACCESS
    raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _access_mode(value: str) -> str:
    if not isinstance(value, str) or value not in _ACCESS_MODES:
        raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ZtnaAccessProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
    "ZtnaAccessProxyClientCertificateLiveWorkflow",
    "ZtnaAccessProxyClientCertificateRollbackLiveWorkflow",
    "ZtnaAccessProxyLiveWorkflowError",
    "ZtnaAccessProxyLiveWorkflowTransport",
]
