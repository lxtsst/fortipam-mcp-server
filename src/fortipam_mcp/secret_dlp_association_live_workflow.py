"""Private same-instance DLP association and independently previewed restoration.

The protected transport owns durable dispatch claims. This workflow cannot
import ownership, recover old refs or retry uncertain attempts after restart.
No transport, action, MCP registration or device activation occurs here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hmac
import re
import secrets
from threading import Lock
import time
from typing import Callable, Literal, Protocol, runtime_checkable

from .secret_dlp_association_contract import (
    SecretDlpAssociationInspection, SecretDlpAssociationReadback,
    validate_secret_dlp_association_inspection,
)


CONTRACT = "fortipam_v4_fixed_secret_dlp_association_700_candidate_v1"
_TTL_SECONDS = 600
_UNAVAILABLE = "FortiPAM fixed Secret DLP association workflow is unavailable."
_Operation = Literal["associate", "restore"]


class SecretDlpAssociationLiveWorkflowError(RuntimeError):
    """Stable failure without identities, witnesses or upstream errors."""


@runtime_checkable
class SecretDlpAssociationTransport(Protocol):
    """All inspections independently obtain fresh qualified native Sensor evidence."""

    def inspect_association(self) -> SecretDlpAssociationInspection: ...

    def associate_and_readback(self, expected_state_digest: str, *, expires_at: int,
                               clock: Callable[[], int]) -> SecretDlpAssociationReadback: ...

    def inspect_owned_restore(self) -> SecretDlpAssociationInspection: ...

    def restore_and_readback(self, expected_state_digest: str, *, expires_at: int,
                             clock: Callable[[], int]) -> SecretDlpAssociationReadback: ...


@dataclass(frozen=True, slots=True, repr=False)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    operation: _Operation
    current: SecretDlpAssociationInspection
    expires_at: int
    state: str = "previewed"
    attempted: bool = False


class SecretDlpAssociationLiveWorkflow:
    """One confirmed association and one separately confirmed owned restoration."""

    def __init__(self, transport: SecretDlpAssociationTransport, *, execution_enabled: bool = False,
                 clock: Callable[[], int] | None = None) -> None:
        if (not isinstance(transport, SecretDlpAssociationTransport) or type(execution_enabled) is not bool
                or (clock is not None and not callable(clock)) or any(not callable(getattr(transport, method, None))
                    for method in ("inspect_association", "associate_and_readback", "inspect_owned_restore", "restore_and_readback"))):
            raise SecretDlpAssociationLiveWorkflowError(_UNAVAILABLE)
        self._transport = transport
        self._execution_enabled = execution_enabled
        self._clock = clock or (lambda: int(time.time()))
        self._last_clock = 0
        self._lock = Lock()
        self._records: dict[str, _Record] = {}
        self._authorizations: dict[str, str] = {}
        self._association_attempted = False
        self._restore_attempted = False
        self._baseline: SecretDlpAssociationInspection | None = None
        self._associated: SecretDlpAssociationInspection | None = None
        self._creator: str | None = None

    def preview_association(self, *, requester_digest: str) -> dict[str, object]:
        return self._preview("associate", requester_digest)

    def preview_restore(self, *, requester_digest: str) -> dict[str, object]:
        return self._preview("restore", requester_digest)

    def _preview(self, operation: _Operation, requester_digest: str) -> dict[str, object]:
        with self._lock:
            try:
                self._requester(requester_digest)
                self._available(operation, requester_digest)
                expires_at = self._now() + _TTL_SECONDS
                current = self._inspect(operation)
                if self._now() >= expires_at:
                    raise ValueError
                record = _Record(self._ref(operation, "preview"), None, requester_digest,
                                 operation, current, expires_at)
                self._records[record.preview_ref] = record
                return {
                    "contract": CONTRACT, "preview_ref": record.preview_ref, "expires_at": expires_at,
                    "Current State": {"dlp": "disabled_without_sensor" if operation == "associate" else "enabled_with_owned_sensor",
                                      "secret_prerequisites": "matched", "sensor_native_profile": "matched",
                                      "preservation_baseline": "bound", "opaque_fields": "privately_witnessed"},
                    "Proposed Changes": {"operation": operation, "other_secret_fields": "preserve"},
                    "Expected State": {"dlp": "enabled_with_fixed_log_only_sensor" if operation == "associate" else "disabled_without_sensor",
                                       "metadata_and_opaque_fields": "unchanged", "file_audit_effect": "unproven"},
                    "device_write_executed": False,
                }
            except Exception:
                raise SecretDlpAssociationLiveWorkflowError(_UNAVAILABLE) from None

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._record(preview_ref, requester_digest)
            try:
                self._require(record, "previewed")
                self._available(record.operation, requester_digest)
                current = self._inspect(record.operation)
                if self._now() >= record.expires_at or current.state_digest != record.current.state_digest:
                    raise ValueError
                authorization = self._ref(record.operation, "authorized")
                self._records[preview_ref] = replace(record, authorization_ref=authorization, state="authorized")
                self._authorizations[authorization] = preview_ref
                return {"contract": CONTRACT, "preview_ref": preview_ref, "authorization_ref": authorization,
                        "confirmation": "recorded", "execution": "authorized_once",
                        "expires_at": record.expires_at, "device_write_executed": False}
            except Exception:
                self._records[preview_ref] = replace(record, state="invalidated")
                raise SecretDlpAssociationLiveWorkflowError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            if type(authorization_ref) is not str or authorization_ref not in self._authorizations:
                raise SecretDlpAssociationLiveWorkflowError(_UNAVAILABLE)
            record = self._record(self._authorizations[authorization_ref], requester_digest)
            if record.state in {"completed", "reconciliation_required", "invalidated"}:
                return self._result(record, replay=True)
            if not self._execution_enabled:
                raise SecretDlpAssociationLiveWorkflowError(_UNAVAILABLE)
            try:
                self._require(record, "authorized")
                self._available(record.operation, requester_digest)
                current = self._inspect(record.operation)
                if self._now() >= record.expires_at or current.state_digest != record.current.state_digest:
                    raise ValueError
            except Exception:
                invalidated = replace(record, state="invalidated")
                self._records[record.preview_ref] = invalidated
                return self._result(invalidated, replay=False)
            # Entering the protected method consumes this operation even if its
            # PUT acknowledgement is missing or the private method raises.
            attempted = replace(record, state="executing", attempted=True)
            self._records[record.preview_ref] = attempted
            if record.operation == "associate":
                self._association_attempted = True
                self._baseline = current
                self._creator = requester_digest
            else:
                self._restore_attempted = True
            try:
                method = (self._transport.associate_and_readback if record.operation == "associate"
                          else self._transport.restore_and_readback)
                readback = method(current.state_digest, expires_at=record.expires_at, clock=self._now)
                after = self._verified_readback(readback, current, record.operation)
                if record.operation == "associate":
                    self._associated = after
                terminal = replace(attempted, state="completed")
            except Exception:
                terminal = replace(attempted, state="reconciliation_required")
            self._records[record.preview_ref] = terminal
            return self._result(terminal, replay=False)

    def _inspect(self, operation: _Operation) -> SecretDlpAssociationInspection:
        method = self._transport.inspect_association if operation == "associate" else self._transport.inspect_owned_restore
        current = validate_secret_dlp_association_inspection(method())
        if current.phase != ("baseline" if operation == "associate" else "associated"):
            raise ValueError
        if operation == "restore":
            if (self._associated is None or self._baseline is None
                    or current.state_digest != self._associated.state_digest
                    or not _preserved(current, self._baseline)):
                raise ValueError
        return current

    def _verified_readback(self, readback: object, before: SecretDlpAssociationInspection,
                           operation: _Operation) -> SecretDlpAssociationInspection:
        if (type(readback) is not SecretDlpAssociationReadback or any(type(value) is not bool or not value for value in (
                readback.acknowledged, readback.logout_verified, readback.opaque_fields_match))):
            raise ValueError
        after = validate_secret_dlp_association_inspection(readback.after)
        if (after.phase != ("associated" if operation == "associate" else "baseline")
                or not _preserved(after, before)
                or (operation == "restore" and (self._baseline is None or after.state_digest != self._baseline.state_digest))):
            raise ValueError
        return after

    def _available(self, operation: _Operation, requester_digest: str) -> None:
        if operation == "associate":
            if self._association_attempted:
                raise ValueError
        elif (self._restore_attempted or self._associated is None or self._baseline is None
              or self._creator is None or not hmac.compare_digest(requester_digest, self._creator)):
            raise ValueError

    def _record(self, preview_ref: str, requester_digest: str) -> _Record:
        try:
            self._requester(requester_digest)
            if type(preview_ref) is not str:
                raise ValueError
            record = self._records[preview_ref]
            if not hmac.compare_digest(record.requester_digest, requester_digest):
                raise ValueError
            return record
        except Exception:
            raise SecretDlpAssociationLiveWorkflowError(_UNAVAILABLE) from None

    def _require(self, record: _Record, state: str) -> None:
        if record.state != state or self._now() >= record.expires_at:
            raise ValueError

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int or value < self._last_clock or value <= 0:
            raise ValueError
        self._last_clock = value
        return value

    @staticmethod
    def _requester(value: object) -> None:
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError

    @staticmethod
    def _ref(operation: _Operation, kind: str) -> str:
        return f"secret-dlp-{operation}-{kind}-" + secrets.token_urlsafe(24)

    @staticmethod
    def _result(record: _Record, *, replay: bool) -> dict[str, object]:
        outcome = {"completed": "succeeded", "invalidated": "not_executed"}.get(
            record.state, "reconciliation_required")
        return {"contract": CONTRACT, "operation": record.operation, "outcome": outcome,
                "verification": "verified" if outcome == "succeeded" else "unknown",
                "idempotent_replay": replay, "device_write_may_have_occurred": record.attempted,
                "credential_values_returned": False, "raw_api_response_returned": False,
                "file_audit_effect": "unproven"}


def _preserved(left: SecretDlpAssociationInspection, right: SecretDlpAssociationInspection) -> bool:
    return (left.identity == right.identity and left.sensor_name == right.sensor_name
            and left.native_sensor_json == right.native_sensor_json
            and all(hmac.compare_digest(getattr(left, field), getattr(right, field)) for field in (
                "actor_digest", "preservation_digest", "opaque_field_digest",
                "redacted_metadata_witness_digest", "sensor_digest")))
