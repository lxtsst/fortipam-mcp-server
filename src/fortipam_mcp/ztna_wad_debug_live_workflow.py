"""One-confirmation, self-cleaning FortiPAM ZTNA WAD debug workflow."""

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

from .ztna_wad_debug_ssh_transport import (
    ZTNA_WAD_DEBUG_CONFIGURATION,
    ZtnaWadDebugInspection,
    ZtnaWadDebugReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_ztna_wad_debug_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 ZTNA WAD debug diagnostic is unavailable."
_TTL_SECONDS = 600


class ZtnaWadDebugLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing WAD debug workflow failure."""


class ZtnaWadDebugLiveWorkflowTransport(Protocol):
    """Pinned debug preflight and self-cleaning capture boundary."""

    def inspect(self) -> ZtnaWadDebugInspection: ...

    def capture_and_cleanup(self) -> ZtnaWadDebugReadback: ...


@dataclass(frozen=True, slots=True)
class _WadDebugRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    state: str
    expires_at: int
    readback: ZtnaWadDebugReadback | None = None


class ZtnaWadDebugLiveWorkflow:
    """Run one global-debug window only when the initial state is safely known."""

    def __init__(
        self,
        transport: ZtnaWadDebugLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _WadDebugRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        _require_requester(requester_digest)
        current = self._inspect()
        if not current.debug_is_disabled:
            raise ZtnaWadDebugLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _WadDebugRecord(
            preview_ref="ztna-wad-debug-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect()
            if not current.debug_is_disabled or _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ZtnaWadDebugLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "ztna-wad-debug-authorized-" + secrets.token_urlsafe(24)
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
        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect()
            if not current.debug_is_disabled or _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ZtnaWadDebugLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.capture_and_cleanup()
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, ZtnaWadDebugReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            state = "completed" if readback.verified else "reconciliation_required"
            self._records[record.preview_ref] = replace(
                self._records[record.preview_ref], state=state, readback=readback
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> ZtnaWadDebugInspection:
        try:
            current = self._transport.inspect()
        except Exception as exc:
            raise ZtnaWadDebugLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(current, ZtnaWadDebugInspection):
            raise ZtnaWadDebugLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return current

    def _record_for_preview_locked(self, preview_ref: str) -> _WadDebugRecord:
        if not _valid_ref(preview_ref, "ztna-wad-debug-preview-"):
            raise ZtnaWadDebugLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise ZtnaWadDebugLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _WadDebugRecord:
        if not _valid_ref(authorization_ref, "ztna-wad-debug-authorized-"):
            raise ZtnaWadDebugLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ZtnaWadDebugLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _WadDebugRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ZtnaWadDebugLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _WadDebugRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ZtnaWadDebugLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise ZtnaWadDebugLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records[preview_ref] = replace(record, state=state)

    def _purge_expired_locked(self) -> None:
        now_epoch = self._clock()
        for preview_ref, record in tuple(self._records.items()):
            if record.expires_at <= now_epoch and record.state != "completed":
                self._records.pop(preview_ref, None)
                if record.authorization_ref is not None:
                    self._authorization_index.pop(record.authorization_ref, None)

    @staticmethod
    def _preview_projection(record: _WadDebugRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "global_debug_state": "disabled",
                "raw_cli_returned": False,
                "identity_tag_target_secret_or_session_data_returned": False,
                "persistent_configuration_changed": False,
            },
            "Proposed Changes": {
                "operation": "run_timeboxed_fixed_ztna_wad_debug_diagnostic",
                "configuration_profile": ZTNA_WAD_DEBUG_CONFIGURATION,
                "wad_debug_categories": "fixed_secret_gateway_svc_conn_only",
                "global_debug_enabled_temporarily": True,
                "automatic_cleanup_required": True,
                "caller_controlled_cli": False,
                "endpoint_or_tag_input_accepted": False,
                "persistent_configuration_changed": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "global_debug_state": "disabled_after_capture",
                "diagnostic_result": "categorical_device_context_tag_and_launch_evidence_only",
                "raw_cli_returned": False,
                "identity_tag_target_secret_or_session_data_returned": False,
                "persistent_configuration_changed": False,
            },
            "device_write_executed": False,
        }

    def _result(self, record: _WadDebugRecord, *, idempotent_replay: bool) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        readback = latest.readback if latest is not None else None
        succeeded = latest is not None and latest.state == "completed" and readback is not None
        return {
            "contract": "fortipam_v4_ztna_wad_debug_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "global_debug_cleanup_confirmed": (
                readback.cleanup_confirmed if readback is not None else False
            ),
            "device_context_state": (
                readback.device_context_state if readback is not None else "unknown"
            ),
            "device_tag_match_state": (
                readback.device_tag_match_state if readback is not None else "unknown"
            ),
            "launch_authorization_state": (
                readback.launch_authorization_state if readback is not None else "unknown"
            ),
            "compensation": "automatic_diagnose_debug_disable_cleanup; reconcile_manually_if_cleanup_unknown",
            "raw_cli_returned": False,
            "identity_tag_target_secret_or_session_data_returned": False,
            "persistent_configuration_changed": False,
            "device_write_executed": True,
        }


def _inspection_digest(inspection: ZtnaWadDebugInspection) -> str:
    return hashlib.sha256(
        json.dumps(
            {"debug_is_disabled": inspection.debug_is_disabled},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ZtnaWadDebugLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
    "ZtnaWadDebugLiveWorkflow",
    "ZtnaWadDebugLiveWorkflowError",
    "ZtnaWadDebugLiveWorkflowTransport",
]
