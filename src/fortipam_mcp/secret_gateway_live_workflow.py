"""One live, confirmation-gated FortiPAM Secret Gateway create workflow."""

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

from .secret_gateway_ssh_transport import (
    SECRET_GATEWAY_CONFIGURATION,
    SecretGatewayInspection,
    SecretGatewayReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_secret_gateway_create_cli_fallback_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Secret Gateway create action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"mcp-v4-secret-gateway-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z")


class SecretGatewayLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded Secret Gateway workflow."""


class SecretGatewayLiveWorkflowTransport(Protocol):
    """Exact Secret Gateway preflight and create/readback contract."""

    def inspect(self, gateway_name: str) -> SecretGatewayInspection: ...

    def create_and_readback(self, gateway_name: str) -> SecretGatewayReadback: ...


@dataclass(frozen=True, slots=True)
class _SecretGatewayRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    gateway_name: str
    current_digest: str
    state: str
    expires_at: int


class SecretGatewayCreateLiveWorkflow:
    """Volatile one-confirmation flow for one disabled Forward Secret Gateway."""

    def __init__(
        self,
        transport: SecretGatewayLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _SecretGatewayRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        gateway_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read current state and render C/P/E without a device write."""

        safe_gateway_name = _gateway_name(gateway_name)
        _require_requester(requester_digest)
        current = self._inspect(safe_gateway_name)
        if current.gateway_name_exists:
            raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _SecretGatewayRecord(
            preview_ref="secret-gateway-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            gateway_name=safe_gateway_name,
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
            current = self._inspect(record.gateway_name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "secret-gateway-authorized-" + secrets.token_urlsafe(24)
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
        """Create exactly the confirmed disabled Gateway and categorize readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(record.gateway_name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(record.gateway_name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, SecretGatewayReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, gateway_name: str) -> SecretGatewayInspection:
        try:
            result = self._transport.inspect(gateway_name)
        except Exception as exc:
            raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, SecretGatewayInspection):
            raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _SecretGatewayRecord:
        if not _valid_ref(preview_ref, "secret-gateway-preview-"):
            raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _SecretGatewayRecord:
        if not _valid_ref(authorization_ref, "secret-gateway-authorized-"):
            raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _SecretGatewayRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _SecretGatewayRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _SecretGatewayRecord,
        current: SecretGatewayInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_gateway_name": record.gateway_name,
                "gateway_name_exists": current.gateway_name_exists,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "create_secret_gateway_via_cli_fallback",
                "gateway_name": record.gateway_name,
                "configuration_profile": SECRET_GATEWAY_CONFIGURATION,
                "gateway_status": "disable",
                "gateway_type": "forward",
                "gateway_address_class": "documentation_ipv4",
                "gateway_port": 443,
                "url_map": "tcp",
                "ssl_maximum_version": "tls-1.3",
                "target_or_secret_association_changes": False,
                "gateway_chain_changes": False,
                "reverse_service_changes": False,
                "traffic_forwarding_enabled": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "gateway_name_matches": True,
                "gateway_name_exists": True,
                "status_disabled": True,
                "forward_type_enabled": True,
                "documentation_address_matches": True,
                "port_443_enabled": True,
                "tcp_url_map_enabled": True,
                "tls_1_3_maximum_enabled": True,
                "description_matches": True,
                "target_or_secret_association_changes": False,
                "gateway_chain_changes": False,
                "reverse_service_changes": False,
                "traffic_forwarding_enabled": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _SecretGatewayRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_secret_gateway_create_cli_fallback_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_secret_gateway_delete_action_required",
            "gateway_name_returned": False,
            "target_or_secret_association_changes": False,
            "gateway_chain_changes": False,
            "reverse_service_changes": False,
            "traffic_forwarding_enabled": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: SecretGatewayInspection) -> str:
    payload = json.dumps(
        {"gateway_name_exists": inspection.gateway_name_exists},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _gateway_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise SecretGatewayLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "SecretGatewayCreateLiveWorkflow",
    "SecretGatewayLiveWorkflowError",
    "SecretGatewayLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
