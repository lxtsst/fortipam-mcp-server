"""One confirmation-gated FortiPAM CSR generation workflow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
import time
from typing import Protocol

from .certificate_csr_contract import (
    CSR_KEY_SIZE,
    CSR_KEY_TYPE,
    CSR_SCOPE,
    CertificateCsrInspection,
    CertificateCsrReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_certificate_csr_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 certificate CSR workflow is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"mcp-v4-cert-[A-Za-z0-9][A-Za-z0-9._-]{0,50}\Z")


class CertificateCsrLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing workflow failure."""


class CertificateCsrLiveWorkflowTransport(Protocol):
    """Exact preflight and create/readback contract."""

    def inspect(self, certificate_name: str) -> CertificateCsrInspection: ...

    def generate_and_readback(
        self,
        certificate_name: str,
        subject_ipv4: str,
    ) -> CertificateCsrReadback: ...


@dataclass(frozen=True, slots=True)
class _CertificateCsrRequest:
    name: str
    subject_ipv4: str

    @classmethod
    def create(cls, name: str, subject_ipv4: str) -> "_CertificateCsrRequest":
        if not isinstance(name, str) or _NAME.fullmatch(name) is None:
            raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if not isinstance(subject_ipv4, str):
            raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        try:
            normalized_subject = str(ipaddress.IPv4Address(subject_ipv4))
        except ipaddress.AddressValueError as exc:
            raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        return cls(name=name, subject_ipv4=normalized_subject)


@dataclass(frozen=True, slots=True)
class _CertificateCsrRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    name: str
    subject_ipv4: str
    current_digest: str
    state: str
    expires_at: int


class CertificateCsrLiveWorkflow:
    """Volatile C/P/E, confirmation, one execution, and categorical readback."""

    def __init__(
        self,
        transport: CertificateCsrLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _CertificateCsrRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        certificate_name: str,
        subject_ipv4: str,
        requester_digest: str,
    ) -> dict[str, object]:
        request = _CertificateCsrRequest.create(certificate_name, subject_ipv4)
        _require_requester(requester_digest)
        current = self._inspect(request.name)
        if current.exists or not current.name_available:
            raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _CertificateCsrRecord(
            preview_ref="certificate-csr-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            name=request.name,
            subject_ipv4=request.subject_ipv4,
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
            current = self._inspect(record.name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "certificate-csr-authorized-" + secrets.token_urlsafe(24)
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
        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(record.name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.generate_and_readback(
                record.name,
                record.subject_ipv4,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, CertificateCsrReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, certificate_name: str) -> CertificateCsrInspection:
        try:
            result = self._transport.inspect(certificate_name)
        except Exception as exc:
            raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, CertificateCsrInspection):
            raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _CertificateCsrRecord:
        if not _valid_ref(preview_ref, "certificate-csr-preview-"):
            raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _CertificateCsrRecord:
        if not _valid_ref(authorization_ref, "certificate-csr-authorized-"):
            raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _CertificateCsrRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _CertificateCsrRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _CertificateCsrRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_certificate_name": record.name,
                "requested_subject_ipv4": record.subject_ipv4,
                "certificate_entry_exists": False,
                "certificate_name_available": True,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "generate_certificate_signing_request",
                "certificate_name": record.name,
                "subject_type": "host_ipv4",
                "subject_ipv4": record.subject_ipv4,
                "key_type": CSR_KEY_TYPE,
                "key_size": CSR_KEY_SIZE,
                "scope": CSR_SCOPE,
                "organization_units": [],
                "enrollment_method": "file_based",
                "private_key_password_supplied": False,
            },
            "Expected State": {
                "certificate_entry_exists": True,
                "certificate_name_matches": True,
                "csr_present": True,
                "private_key_present": True,
                "certificate_or_private_key_value_returned": False,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _CertificateCsrRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_certificate_csr_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "certificate_name_returned": False,
            "subject_value_returned": False,
            "csr_value_returned": False,
            "certificate_value_returned": False,
            "private_key_value_returned": False,
            "raw_api_response_returned": False,
        }


def _inspection_digest(inspection: CertificateCsrInspection) -> str:
    payload = json.dumps(
        {
            "exists": inspection.exists,
            "name_available": inspection.name_available,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise CertificateCsrLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "CertificateCsrLiveWorkflow",
    "CertificateCsrLiveWorkflowError",
    "CertificateCsrLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
