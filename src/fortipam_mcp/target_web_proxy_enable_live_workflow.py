"""One live, confirmation-gated FortiPAM Target Web Proxy enable workflow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hmac
import re
import secrets
import threading
import time
from typing import Protocol

from .target_contract import (
    TargetWebProxyEnableInspection,
    TargetWebProxyEnableReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_target_web_proxy_enable_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Target Web Proxy enable is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class TargetWebProxyEnableLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded Target update workflow."""


class TargetWebProxyEnableTransport(Protocol):
    """Exact Target Web Proxy preflight and update/readback contract."""

    def inspect_web_proxy_enable(
        self,
        target_name: str,
    ) -> TargetWebProxyEnableInspection: ...

    def enable_web_proxy_and_readback(
        self,
        target_name: str,
    ) -> TargetWebProxyEnableReadback: ...


@dataclass(frozen=True, slots=True)
class _TargetWebProxyEnableRequest:
    name: str

    @classmethod
    def create(cls, target_name: str) -> "_TargetWebProxyEnableRequest":
        if not isinstance(target_name, str) or _NAME.fullmatch(target_name) is None:
            raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(name=target_name)


@dataclass(frozen=True, slots=True)
class _TargetWebProxyEnableRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    name: str
    current_digest: str
    state: str
    expires_at: int


class TargetWebProxyEnableLiveWorkflow:
    """Volatile one-confirmation workflow for a Target Web Proxy API update."""

    def __init__(
        self,
        transport: TargetWebProxyEnableTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _TargetWebProxyEnableRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        target_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read Current State and render a value-minimized C/P/E preview."""

        request = _TargetWebProxyEnableRequest.create(target_name)
        _require_requester(requester_digest)
        current = self._inspect(request)
        if not current.exists or not current.web_proxy_disabled:
            raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _TargetWebProxyEnableRecord(
            preview_ref="target-web-proxy-enable-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            name=request.name,
            current_digest=current.state_digest,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm the unchanged disabled state and issue one execution ref."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            if not self._state_is_unchanged(record):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "previewed")
            authorization_ref = (
                "target-web-proxy-enable-authorized-" + secrets.token_urlsafe(24)
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

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        """Perform one confirmed API update and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            if not self._state_is_unchanged(record):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "authorized")
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.enable_web_proxy_and_readback(record.name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, TargetWebProxyEnableReadback):
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
        request: _TargetWebProxyEnableRequest,
    ) -> TargetWebProxyEnableInspection:
        try:
            result = self._transport.inspect_web_proxy_enable(request.name)
        except Exception as exc:
            raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, TargetWebProxyEnableInspection):
            raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _state_is_unchanged(self, record: _TargetWebProxyEnableRecord) -> bool:
        current = self._inspect(_TargetWebProxyEnableRequest(record.name))
        return (
            current.exists
            and current.web_proxy_disabled
            and hmac.compare_digest(current.state_digest, record.current_digest)
        )

    def _record_for_preview_locked(
        self,
        preview_ref: str,
    ) -> _TargetWebProxyEnableRecord:
        if not _valid_ref(preview_ref, "target-web-proxy-enable-preview-"):
            raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _TargetWebProxyEnableRecord:
        if not _valid_ref(authorization_ref, "target-web-proxy-enable-authorized-"):
            raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _TargetWebProxyEnableRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _TargetWebProxyEnableRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _TargetWebProxyEnableRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_target_name": record.name,
                "target_exists": True,
                "web_proxy_disabled": True,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "enable_target_web_proxy_via_api",
                "target_name": record.name,
                "web_proxy_status": "enable",
            },
            "Expected State": {
                "target_name_matches": True,
                "target_exists": True,
                "web_proxy_enabled": True,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _TargetWebProxyEnableRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_target_web_proxy_enable_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "target_name_returned": False,
            "raw_api_response_returned": False,
        }


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TargetWebProxyEnableLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return isinstance(value, str) and value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "TargetWebProxyEnableLiveWorkflow",
    "TargetWebProxyEnableLiveWorkflowError",
    "TargetWebProxyEnableTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
