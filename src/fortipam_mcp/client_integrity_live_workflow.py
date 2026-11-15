"""One live, confirmation-gated FortiPAM client-integrity precondition flow."""

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

from .client_integrity_ssh_transport import (
    CLIENT_INTEGRITY_CONFIGURATION,
    ClientIntegrityInspection,
    ClientIntegrityReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_client_integrity_cli_fallback_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 client-integrity action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"mcp-v4-client-integrity-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z")


class ClientIntegrityLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded workflow."""


class ClientIntegrityLiveWorkflowTransport(Protocol):
    """Exact client-software preflight and create/readback contract."""

    def inspect(self, client_software_name: str) -> ClientIntegrityInspection: ...

    def create_and_readback(
        self,
        client_software_name: str,
    ) -> ClientIntegrityReadback: ...


@dataclass(frozen=True, slots=True)
class _ClientIntegrityRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    client_software_name: str
    current_digest: str
    state: str
    expires_at: int


class ClientIntegrityConfigureLiveWorkflow:
    """Volatile one-confirmation flow for one unbound Client Software entry."""

    def __init__(
        self,
        transport: ClientIntegrityLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _ClientIntegrityRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        client_software_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read current state and render the fixed C/P/E without a write."""

        safe_name = _client_software_name(client_software_name)
        _require_requester(requester_digest)
        current = self._inspect(safe_name)
        if current.client_software_name_exists:
            raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _ClientIntegrityRecord(
            preview_ref="client-integrity-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            client_software_name=safe_name,
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
            current = self._inspect(record.client_software_name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "client-integrity-authorized-" + secrets.token_urlsafe(24)
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
        """Create only the confirmed precondition and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(record.client_software_name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(record.client_software_name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, ClientIntegrityReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, client_software_name: str) -> ClientIntegrityInspection:
        try:
            result = self._transport.inspect(client_software_name)
        except Exception as exc:
            raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, ClientIntegrityInspection):
            raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _ClientIntegrityRecord:
        if not _valid_ref(preview_ref, "client-integrity-preview-"):
            raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _ClientIntegrityRecord:
        if not _valid_ref(authorization_ref, "client-integrity-authorized-"):
            raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _ClientIntegrityRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _ClientIntegrityRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _ClientIntegrityRecord,
        current: ClientIntegrityInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_client_software_name": record.client_software_name,
                "client_software_name_exists": current.client_software_name_exists,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "configure_client_integrity_precondition_via_cli_fallback",
                "client_software_name": record.client_software_name,
                "configuration_profile": CLIENT_INTEGRITY_CONFIGURATION,
                "package_architecture": "x64",
                "integrity_check": "certificate",
                "download_source": "external",
                "launcher_or_template_binding_changes": False,
                "secret_or_target_association_changes": False,
                "external_download_or_session_launch_executed": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "client_software_name_matches": True,
                "client_software_name_exists": True,
                "x64_package_present": True,
                "certificate_integrity_check_enabled": True,
                "external_download_enabled": True,
                "external_url_matches": True,
                "ca_certificate_matches": True,
                "putty_client_name_matches": True,
                "launcher_or_template_binding_changes": False,
                "secret_or_target_association_changes": False,
                "session_integrity_enforcement_verified": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _ClientIntegrityRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_client_integrity_cli_fallback_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_client_software_delete_action_required",
            "client_software_name_returned": False,
            "launcher_or_template_binding_changes": False,
            "secret_or_target_association_changes": False,
            "external_download_or_session_launch_executed": False,
            "session_integrity_enforcement_verified": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: ClientIntegrityInspection) -> str:
    payload = json.dumps(
        {"client_software_name_exists": inspection.client_software_name_exists},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _client_software_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ClientIntegrityLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "ClientIntegrityConfigureLiveWorkflow",
    "ClientIntegrityLiveWorkflowError",
    "ClientIntegrityLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
