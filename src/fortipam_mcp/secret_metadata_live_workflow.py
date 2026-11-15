"""One confirmation-gated, metadata-only FortiPAM Secret creation workflow."""

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

from .secret_metadata_http_transport import SecretMetadataInspection, SecretMetadataReadback


WORKFLOW_CONTRACT = "fortipam_v4_secret_metadata_api_workflow_v2"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Secret metadata workflow is unavailable."
_TTL_SECONDS = 600
_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_SECRET_NAME = re.compile(r"mcp-v4-secret-metadata-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")


class SecretMetadataLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded workflow."""


class SecretMetadataLiveWorkflowTransport(Protocol):
    """The exact Secret metadata preflight and create/readback contract."""

    def inspect(
        self,
        folder_path: str,
        secret_name: str,
        template: str,
    ) -> SecretMetadataInspection: ...

    def create_and_readback(
        self,
        folder_path: str,
        secret_name: str,
        template: str,
    ) -> SecretMetadataReadback: ...


@dataclass(frozen=True, slots=True)
class _SecretMetadataRequest:
    folder_path: str
    secret_name: str
    template: str

    @classmethod
    def create(
        cls,
        folder_path: str,
        secret_name: str,
        template: str,
    ) -> "_SecretMetadataRequest":
        if not isinstance(folder_path, str) or not folder_path or len(folder_path) > 255:
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if any(_SEGMENT.fullmatch(part) is None for part in folder_path.split("/")):
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if not isinstance(secret_name, str) or _SECRET_NAME.fullmatch(secret_name) is None:
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if (
            not isinstance(template, str)
            or not template
            or len(template) > 79
            or not template.isascii()
            or "/" in template
            or any(ord(character) < 32 or ord(character) == 127 for character in template)
        ):
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(folder_path=folder_path, secret_name=secret_name, template=template)


@dataclass(frozen=True, slots=True)
class _SecretMetadataRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    request: _SecretMetadataRequest
    current_digest: str
    state: str
    expires_at: int


class SecretMetadataLiveWorkflow:
    """Volatile, one-confirmation workflow that never accepts C3 material."""

    def __init__(
        self,
        transport: SecretMetadataLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _SecretMetadataRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        folder_path: str,
        secret_name: str,
        template: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read actual non-secret state and render Current/Proposed/Expected."""

        request = _SecretMetadataRequest.create(folder_path, secret_name, template)
        _require_requester(requester_digest)
        current = self._inspect(request)
        if current.secret_exists or not current.folder_exists or not current.template_exists:
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _SecretMetadataRecord(
            preview_ref="secret-metadata-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            request=request,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Re-read the exact current state and issue one authorization reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            if _inspection_digest(self._inspect(record.request)) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "secret-metadata-authorized-" + secrets.token_urlsafe(24)
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
        """Execute once after an unchanged re-read and return categorical evidence."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            if _inspection_digest(self._inspect(record.request)) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(
                record.request.folder_path,
                record.request.secret_name,
                record.request.template,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, SecretMetadataReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, request: _SecretMetadataRequest) -> SecretMetadataInspection:
        try:
            result = self._transport.inspect(
                request.folder_path,
                request.secret_name,
                request.template,
            )
        except Exception as exc:
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, SecretMetadataInspection):
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _SecretMetadataRecord:
        if not _valid_ref(preview_ref, "secret-metadata-preview-"):
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _SecretMetadataRecord:
        if not _valid_ref(authorization_ref, "secret-metadata-authorized-"):
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _SecretMetadataRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _SecretMetadataRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _SecretMetadataRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_folder_path": record.request.folder_path,
                "requested_secret_name": record.request.secret_name,
                "requested_template": record.request.template,
                "secret_exists": False,
                "folder_exists": True,
                "template_exists": True,
                "write_transport": "rest_api",
                "credential_material_attached": False,
            },
            "Proposed Changes": {
                "operation": "create_secret_metadata_without_credential_material_via_api",
                "folder_path": record.request.folder_path,
                "secret_name": record.request.secret_name,
                "template": record.request.template,
                "credential_material_supplied": False,
                "credential_material_returned": False,
            },
            "Expected State": {
                "secret_exists": True,
                "secret_name_matches": True,
                "folder_matches": True,
                "template_matches": True,
                "inherit_permission_matches": True,
                "credential_material_attached": False,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _SecretMetadataRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_secret_metadata_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "credential_material_supplied": False,
            "credential_material_returned": False,
            "raw_api_response_returned": False,
        }


def _inspection_digest(inspection: SecretMetadataInspection) -> str:
    payload = json.dumps(
        {
            "secret_exists": inspection.secret_exists,
            "folder_exists": inspection.folder_exists,
            "template_exists": inspection.template_exists,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise SecretMetadataLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "SecretMetadataLiveWorkflow",
    "SecretMetadataLiveWorkflowError",
    "SecretMetadataLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
