"""One confirmation-gated FortiPAM Explicit Web Proxy enable workflow."""

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

from .interface_web_proxy_ssh_transport import (
    INTERFACE_WEB_PROXY_CONFIGURATION,
    INTERFACE_WEB_PROXY_ROLLBACK_CONFIGURATION,
    InterfaceWebProxyInspection,
    InterfaceWebProxyReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_interface_explicit_web_proxy_enable_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 interface Explicit Web Proxy action is unavailable."
_TTL_SECONDS = 600


class InterfaceWebProxyLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded interface workflow."""


class InterfaceWebProxyLiveWorkflowTransport(Protocol):
    """Fixed protected-interface inspection and enable/readback contract."""

    def inspect(self) -> InterfaceWebProxyInspection: ...

    def enable_and_readback(self) -> InterfaceWebProxyReadback: ...

    def disable_and_readback(self) -> InterfaceWebProxyReadback: ...


@dataclass(frozen=True, slots=True)
class _InterfaceWebProxyRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    state: str
    expires_at: int


class InterfaceWebProxyLiveWorkflow:
    """Volatile C/P/E flow for one existing-interface enable transition."""

    def __init__(
        self,
        transport: InterfaceWebProxyLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _InterfaceWebProxyRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        """Read the exact disabled baseline and render C/P/E without a write."""

        _require_requester(requester_digest)
        current = self._inspect()
        if not current.exact_disabled_baseline:
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _InterfaceWebProxyRecord(
            preview_ref="interface-web-proxy-preview-" + secrets.token_urlsafe(24),
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
                raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "interface-web-proxy-authorized-" + secrets.token_urlsafe(24)
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
        """Enable only the confirmed Explicit Web Proxy setting and read back."""

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
                raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.enable_and_readback()
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, InterfaceWebProxyReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> InterfaceWebProxyInspection:
        try:
            current = self._transport.inspect()
        except Exception as exc:
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(current, InterfaceWebProxyInspection):
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return current

    def _record_for_preview_locked(self, preview_ref: str) -> _InterfaceWebProxyRecord:
        if not _valid_ref(preview_ref, "interface-web-proxy-preview-"):
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _InterfaceWebProxyRecord:
        if not _valid_ref(authorization_ref, "interface-web-proxy-authorized-"):
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _InterfaceWebProxyRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _InterfaceWebProxyRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _InterfaceWebProxyRecord,
        current: InterfaceWebProxyInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "selected_interface_explicit_web_proxy": current.selected_interface_status,
                "enabled_explicit_web_proxy_interface_count": current.enabled_interface_count,
                "interface_reference_returned": False,
                "proxy_port_changed": False,
                "proxy_ca_changed": False,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "enable_explicit_web_proxy_on_one_existing_interface_via_cli_fallback",
                "configuration_profile": INTERFACE_WEB_PROXY_CONFIGURATION,
                "selected_interface_explicit_web_proxy": "enable",
                "other_interfaces_changed": False,
                "proxy_port_changed": False,
                "proxy_ca_changed": False,
                "vip_or_route_changed": False,
                "secret_or_target_changed": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "selected_interface_explicit_web_proxy": "enable",
                "enabled_explicit_web_proxy_interface_count": 1,
                "other_interfaces_changed": False,
                "proxy_port_changed": False,
                "proxy_ca_changed": False,
                "vip_or_route_changed": False,
                "web_proxy_reachability_verified": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _InterfaceWebProxyRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_interface_explicit_web_proxy_enable_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_interface_explicit_web_proxy_disable_action_required",
            "selected_interface_explicit_web_proxy": "enable" if succeeded else "unknown",
            "enabled_explicit_web_proxy_interface_count": 1 if succeeded else "unknown",
            "proxy_port_changed": False,
            "proxy_ca_changed": False,
            "vip_or_route_changed": False,
            "secret_or_target_changed": False,
            "web_proxy_reachability_verified": False,
            "raw_cli_returned": False,
        }


class InterfaceWebProxyRollbackLiveWorkflow:
    """One-confirmation restoration to the exact disabled interface state."""

    def __init__(
        self,
        transport: InterfaceWebProxyLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _InterfaceWebProxyRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        """Read the exact enabled state and render a fixed disable rollback."""

        _require_requester(requester_digest)
        current = self._inspect()
        if not current.exact_enabled_baseline:
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _InterfaceWebProxyRecord(
            preview_ref="interface-web-proxy-rollback-preview-"
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
                not current.exact_enabled_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = (
                "interface-web-proxy-rollback-authorized-"
                + secrets.token_urlsafe(24)
            )
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": "fortipam_v4_interface_explicit_web_proxy_rollback_workflow_v1",
            "preview_ref": updated.preview_ref,
            "authorization_ref": authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": updated.expires_at,
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Restore Explicit Web Proxy disable and categorize exact readback."""

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
                raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.disable_and_readback()
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, InterfaceWebProxyReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified_disabled else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> InterfaceWebProxyInspection:
        try:
            current = self._transport.inspect()
        except Exception as exc:
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(current, InterfaceWebProxyInspection):
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return current

    def _record_for_preview_locked(self, preview_ref: str) -> _InterfaceWebProxyRecord:
        if not _valid_ref(preview_ref, "interface-web-proxy-rollback-preview-"):
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _InterfaceWebProxyRecord:
        if not _valid_ref(
            authorization_ref,
            "interface-web-proxy-rollback-authorized-",
        ):
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _InterfaceWebProxyRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _InterfaceWebProxyRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _InterfaceWebProxyRecord,
        current: InterfaceWebProxyInspection,
    ) -> dict[str, object]:
        return {
            "contract": "fortipam_v4_interface_explicit_web_proxy_rollback_workflow_v1",
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "selected_interface_explicit_web_proxy": current.selected_interface_status,
                "enabled_explicit_web_proxy_interface_count": current.enabled_interface_count,
                "interface_reference_returned": False,
                "proxy_port_changed": False,
                "proxy_ca_changed": False,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "restore_interface_explicit_web_proxy_pre_action_state_via_cli_fallback",
                "configuration_profile": INTERFACE_WEB_PROXY_ROLLBACK_CONFIGURATION,
                "selected_interface_explicit_web_proxy": "disable",
                "other_interfaces_changed": False,
                "proxy_port_changed": False,
                "proxy_ca_changed": False,
                "vip_or_route_changed": False,
                "secret_or_target_changed": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "pre_action_state_restored": True,
                "selected_interface_explicit_web_proxy": "disable",
                "enabled_explicit_web_proxy_interface_count": 0,
                "other_interfaces_changed": False,
                "proxy_port_changed": False,
                "proxy_ca_changed": False,
                "vip_or_route_changed": False,
                "web_proxy_reachability_verified": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _InterfaceWebProxyRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_interface_explicit_web_proxy_rollback_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "pre_action_state_restored": succeeded,
            "selected_interface_explicit_web_proxy": "disable" if succeeded else "unknown",
            "enabled_explicit_web_proxy_interface_count": 0 if succeeded else "unknown",
            "proxy_port_changed": False,
            "proxy_ca_changed": False,
            "vip_or_route_changed": False,
            "secret_or_target_changed": False,
            "web_proxy_reachability_verified": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: InterfaceWebProxyInspection) -> str:
    payload = json.dumps(
        {
            "selected_interface_status": inspection.selected_interface_status,
            "enabled_interface_count": inspection.enabled_interface_count,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise InterfaceWebProxyLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "InterfaceWebProxyLiveWorkflow",
    "InterfaceWebProxyLiveWorkflowError",
    "InterfaceWebProxyLiveWorkflowTransport",
    "InterfaceWebProxyRollbackLiveWorkflow",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
