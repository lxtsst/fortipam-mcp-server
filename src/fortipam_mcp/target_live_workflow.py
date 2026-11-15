"""One live, confirmation-gated FortiPAM Target creation workflow.

The first Target package deliberately supports only an IPv4 SSH Target with
the product's installed ``Unix Account (SSH Password)`` template. The target
address remains only in volatile process memory between preview and execution.
The C/P/E preview echoes the caller's own requested non-secret locator for
confirmation; execution responses and audit projections do not return a target
locator.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import hmac
import ipaddress
import json
import secrets
import threading
import time
from typing import Protocol

from .target_contract import (
    DEFAULT_TEMPLATE,
    TargetInspection,
    TargetReadback,
)
from .target_http_transport import TargetHttpTransportError


WORKFLOW_CONTRACT = "fortipam_v4_target_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Target workflow is unavailable."
_TTL_SECONDS = 600
TARGET_CREATE_PROJECTIONS = {
    ("1.9.1", 1758): "fortipam_1_9_1_frontend_default",
    ("7.0.0", 29): "fortipam_7_0_0_build_29_target_frontend_unparse",
}


class TargetLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded Target workflow."""


class TargetLiveWorkflowTransport(Protocol):
    """The exact Target preflight and create/readback contract."""

    def inspect(self, target_name: str) -> TargetInspection: ...

    def create_and_readback(
        self,
        target_name: str,
        address: str,
        *,
        expected_product_version: str,
        expected_product_build: int,
    ) -> TargetReadback: ...


@dataclass(frozen=True, slots=True)
class _TargetRequest:
    name: str
    address: str

    @classmethod
    def create(cls, name: str, address: str) -> "_TargetRequest":
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 64
            or not name.isascii()
            or not name[0].isalnum()
            or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in name)
        ):
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if not isinstance(address, str):
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        try:
            normalized_address = str(ipaddress.IPv4Address(address))
        except ipaddress.AddressValueError as exc:
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        return cls(name=name, address=normalized_address)


@dataclass(frozen=True, slots=True)
class _TargetRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    name: str
    address: str
    current_digest: str
    product_version: str
    product_build: int
    state: str
    expires_at: int
    failure_stage: str | None = None
    failure_http_status: int | None = None
    failure_product_error_code: int | None = None
    failure_product_status: str | None = None
    failure_product_error_class: str | None = None


class TargetLiveWorkflow:
    """Volatile one-confirmation live workflow for one bounded Target create."""

    def __init__(
        self,
        transport: TargetLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _TargetRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        target_name: str,
        address: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read live Target state and return Current/Proposed/Expected only."""

        request = _TargetRequest.create(target_name, address)
        _require_requester(requester_digest)
        current = self._inspect(request)
        if current.exists:
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if (current.product_version, current.product_build) not in TARGET_CREATE_PROJECTIONS:
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _TargetRecord(
            preview_ref="target-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            name=request.name,
            address=request.address,
            current_digest=_inspection_digest(current),
            product_version=current.product_version or "",
            product_build=current.product_build or 0,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm a still-unchanged preview and issue one execution reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(_TargetRequest(record.name, record.address))
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "target-authorized-" + secrets.token_urlsafe(24)
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
        """Perform one confirmed create and return categorical readback evidence."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(_TargetRequest(record.name, record.address))
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            executing = replace(record, state="executing")
            self._records[record.preview_ref] = executing
        try:
            readback = self._transport.create_and_readback(
                record.name,
                record.address,
                expected_product_version=record.product_version,
                expected_product_build=record.product_build,
            )
        except TargetHttpTransportError as exc:
            with self._lock:
                self._set_failure_locked(
                    record.preview_ref,
                    failure_stage=exc.failure_stage,
                    failure_http_status=exc.http_status,
                    failure_product_error_code=exc.product_error_code,
                    failure_product_status=exc.product_status,
                    failure_product_error_class=exc.product_error_class,
                )
            return self._result(record, idempotent_replay=False)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, TargetReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, request: _TargetRequest) -> TargetInspection:
        try:
            result = self._transport.inspect(request.name)
        except Exception as exc:
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, TargetInspection):
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _TargetRecord:
        if not _valid_ref(preview_ref, "target-preview-"):
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _TargetRecord:
        if not _valid_ref(authorization_ref, "target-authorized-"):
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _TargetRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _TargetRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records[preview_ref] = replace(record, state=state)

    def _set_failure_locked(
        self,
        preview_ref: str,
        *,
        failure_stage: str | None,
        failure_http_status: int | None,
        failure_product_error_code: int | None,
        failure_product_status: str | None,
        failure_product_error_class: str | None,
    ) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records[preview_ref] = replace(
            record,
            state="reconciliation_required",
            failure_stage=failure_stage,
            failure_http_status=failure_http_status,
            failure_product_error_code=failure_product_error_code,
            failure_product_status=failure_product_status,
            failure_product_error_class=failure_product_error_class,
        )

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
    def _preview_projection(record: _TargetRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_target_name": record.name,
                "requested_target_address": record.address,
                "target_exists": False,
                "write_transport": "rest_api",
                "product_version": record.product_version,
                "product_build": record.product_build,
            },
            "Proposed Changes": {
                "operation": "create_target_via_api",
                "request_projection": TARGET_CREATE_PROJECTIONS[
                    (record.product_version, record.product_build)
                ],
                "product_version": record.product_version,
                "product_build": record.product_build,
                "target_name": record.name,
                "target_class": "other",
                "template": DEFAULT_TEMPLATE,
                "endpoint_type": "ipv4",
                "target_address": record.address,
                "web_proxy_status": "disable",
                "owner_binding": "verified_admin_principal",
                "create_secret_group_binding": "everyone",
            },
            "Expected State": {
                "target_exists": True,
                "target_name_matches": True,
                "class_matches": True,
                "template_matches": True,
                "address_matches": True,
                "web_proxy_disabled": True,
                "owner_relation_matches": True,
                "create_secret_group_relation_matches": True,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _TargetRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_target_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "endpoint_value_returned": False,
            "credentials_returned": False,
            "raw_api_response_returned": False,
            "failure_stage": None if succeeded or latest is None else latest.failure_stage,
            "failure_http_status": (
                None if succeeded or latest is None else latest.failure_http_status
            ),
            "failure_product_error_code": (
                None
                if succeeded or latest is None
                else latest.failure_product_error_code
            ),
            "failure_product_status": (
                None if succeeded or latest is None else latest.failure_product_status
            ),
            "failure_product_error_class": (
                None
                if succeeded or latest is None
                else latest.failure_product_error_class
            ),
        }


def _inspection_digest(inspection: TargetInspection) -> str:
    payload = json.dumps(
        {
            "exists": inspection.exists,
            "product_version": inspection.product_version,
            "product_build": inspection.product_build,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise TargetLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "TargetLiveWorkflow",
    "TargetLiveWorkflowError",
    "TargetLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
