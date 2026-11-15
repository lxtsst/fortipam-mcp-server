"""One live, confirmation-gated FortiPAM Secret Policy update workflow."""

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

from .secret_policy_ssh_transport import (
    SECRET_POLICY_UPDATE_CONFIGURATION,
    SecretPolicyUpdateBaseline,
    SecretPolicyUpdateReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_secret_policy_update_cli_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Secret Policy update action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"mcp-v4-secret-policy-[A-Za-z0-9][A-Za-z0-9._-]{0,42}\Z")


class SecretPolicyUpdateLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded Policy update."""


class SecretPolicyUpdateLiveWorkflowTransport(Protocol):
    """Exact baseline/readback and one fixed update contract."""

    def read_update_baseline(self, policy_name: str) -> SecretPolicyUpdateBaseline: ...

    def update_clipboard_and_readback(
        self,
        policy_name: str,
    ) -> SecretPolicyUpdateReadback: ...


@dataclass(frozen=True, slots=True)
class _SecretPolicyUpdateRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    policy_name: str
    current_digest: str
    state: str
    expires_at: int


class SecretPolicyUpdateLiveWorkflow:
    """Update only one fixed field on the exact local-create Policy baseline."""

    def __init__(
        self,
        transport: SecretPolicyUpdateLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _SecretPolicyUpdateRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, policy_name: str, requester_digest: str) -> dict[str, object]:
        """Read the exact create baseline and render C/P/E without a write."""

        safe_name = _policy_name(policy_name)
        _require_requester(requester_digest)
        current = self._read_baseline(safe_name)
        if not current.verified:
            raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _SecretPolicyUpdateRecord(
            preview_ref="secret-policy-update-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            policy_name=safe_name,
            current_digest=_baseline_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm the exact Policy baseline remains unchanged."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._read_baseline(record.policy_name)
            if not current.verified or _baseline_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = (
                "secret-policy-update-authorized-" + secrets.token_urlsafe(24)
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
        """Disable only RDP clipboard blocking and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._read_baseline(record.policy_name)
            if not current.verified or _baseline_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.update_clipboard_and_readback(record.policy_name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, SecretPolicyUpdateReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _read_baseline(self, policy_name: str) -> SecretPolicyUpdateBaseline:
        try:
            result = self._transport.read_update_baseline(policy_name)
        except Exception as exc:
            raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, SecretPolicyUpdateBaseline):
            raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _SecretPolicyUpdateRecord:
        if not _valid_ref(preview_ref, "secret-policy-update-preview-"):
            raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _SecretPolicyUpdateRecord:
        if not _valid_ref(authorization_ref, "secret-policy-update-authorized-"):
            raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _SecretPolicyUpdateRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _SecretPolicyUpdateRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _SecretPolicyUpdateRecord,
        current: SecretPolicyUpdateBaseline,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_policy_name": record.policy_name,
                "policy_name_exists": current.policy_name_exists,
                "known_create_baseline_verified": current.verified,
                "ssh_filter_disabled": current.ssh_filter_disabled,
                "rdp_clipboard_block_enabled": current.rdp_clipboard_block_enabled,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "update_secret_policy_rdp_clipboard_via_cli_fallback",
                "policy_name": record.policy_name,
                "configuration_profile": SECRET_POLICY_UPDATE_CONFIGURATION,
                "rdp_clipboard_block": "disable",
                "ssh_filter_changes": False,
                "folder_or_secret_association_changes": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "policy_name_matches": True,
                "policy_name_exists": True,
                "ssh_filter_disabled": True,
                "rdp_clipboard_block_disabled": True,
                "ssh_filter_changes": False,
                "folder_or_secret_association_changes": False,
                "readback_transport": "ssh_cli_fallback",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _SecretPolicyUpdateRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_secret_policy_update_cli_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_confirmed_policy_reconciliation_required",
            "policy_name_returned": False,
            "folder_or_secret_association_changes": False,
            "raw_cli_returned": False,
        }


def _baseline_digest(baseline: SecretPolicyUpdateBaseline) -> str:
    payload = json.dumps(
        {
            "policy_name_exists": baseline.policy_name_exists,
            "ssh_filter_disabled": baseline.ssh_filter_disabled,
            "rdp_clipboard_block_enabled": baseline.rdp_clipboard_block_enabled,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _policy_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise SecretPolicyUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "SecretPolicyUpdateLiveWorkflow",
    "SecretPolicyUpdateLiveWorkflowError",
    "SecretPolicyUpdateLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
