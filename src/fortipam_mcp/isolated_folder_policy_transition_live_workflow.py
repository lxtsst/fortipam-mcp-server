"""Unregistered fixed Folder Policy conversion and same-instance restoration.

The explicitly injected transport owns durable claims and private source
qualification. No ownership is imported after restart or an uncertain attempt.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hmac
import re
import secrets
from threading import Lock
import time
from typing import Callable, Literal, Protocol, runtime_checkable

from .isolated_folder_policy_transition_contract import (
    IsolatedFolderPolicyTransitionInspection, IsolatedFolderPolicyTransitionReadback,
    validate_transition_inspection, validate_transition_readback,
)

CONTRACT = "fortipam_v4_isolated_folder_policy_transition_700_candidate_v1"
_UNAVAILABLE = "The fixed isolated Folder Policy workflow is unavailable."
_TTL_SECONDS = 600
_Operation = Literal["assign", "restore"]


class IsolatedFolderPolicyTransitionLiveWorkflowError(RuntimeError):
    """Stable categorical refusal without private state or upstream errors."""


@runtime_checkable
class IsolatedFolderPolicyTransitionTransport(Protocol):
    def inspect_transition(self) -> IsolatedFolderPolicyTransitionInspection: ...

    def transition_and_readback(self, expected_state_digest: str, *, expires_at: int,
                                clock: Callable[[], int]) -> IsolatedFolderPolicyTransitionReadback: ...

    def inspect_owned_restore(self) -> IsolatedFolderPolicyTransitionInspection: ...

    def restore_and_readback(self, expected_state_digest: str, *, expires_at: int,
                             clock: Callable[[], int]) -> IsolatedFolderPolicyTransitionReadback: ...


@dataclass(frozen=True, slots=True, repr=False)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    operation: _Operation
    current: IsolatedFolderPolicyTransitionInspection
    expires_at: int
    state: str = "previewed"
    attempted: bool = False


class IsolatedFolderPolicyTransitionLiveWorkflow:
    """One confirmed conversion and one separately confirmed owned restoration."""

    def __init__(self, transport: IsolatedFolderPolicyTransitionTransport, *, execution_enabled: bool = False,
                 clock: Callable[[], int] | None = None) -> None:
        if (not isinstance(transport, IsolatedFolderPolicyTransitionTransport)
            or type(execution_enabled) is not bool or clock is not None and not callable(clock)
            or any(not callable(getattr(transport, name, None)) for name in (
                "inspect_transition", "transition_and_readback", "inspect_owned_restore", "restore_and_readback"))):
            raise IsolatedFolderPolicyTransitionLiveWorkflowError(_UNAVAILABLE)
        self._transport = transport
        self._execution_enabled = execution_enabled
        self._clock = clock or (lambda: int(time.time()))
        self._last_clock = 0
        self._lock = Lock()
        self._records: dict[str, _Record] = {}
        self._authorizations: dict[str, str] = {}
        self._assignment_attempted = False
        self._restore_attempted = False
        self._baseline: IsolatedFolderPolicyTransitionInspection | None = None
        self._assigned: IsolatedFolderPolicyTransitionInspection | None = None
        self._creator: str | None = None

    def preview_transition(self, *, requester_digest: str) -> dict[str, object]:
        return self._preview("assign", requester_digest)

    def check_bound_principal(self, principal: object) -> None:
        """The material profile additionally pins the actual original client."""
        from .isolated_folder_policy_transition_http_transport import IsolatedFolderPolicyHttpTransport
        if type(self._transport) is IsolatedFolderPolicyHttpTransport and self._transport._fixture_guard is not None:
            self._transport._fixture_guard.check_principal(principal)

    def preview_restore(self, *, requester_digest: str) -> dict[str, object]:
        return self._preview("restore", requester_digest)

    def _preview(self, operation: _Operation, requester: str) -> dict[str, object]:
        with self._lock:
            try:
                self._requester(requester)
                self._available(operation, requester)
                expires = self._now() + _TTL_SECONDS
                current = self._inspect(operation, requester)
                if self._now() >= expires:
                    raise ValueError
                record = _Record(self._ref(operation, "preview"), None, requester, operation, current, expires)
                self._records[record.preview_ref] = record
                return {
                    "contract": CONTRACT, "preview_ref": record.preview_ref, "expires_at": expires,
                    "Current State": {"creation_ownership_bound": True, "single_secret_verified": True,
                                      "no_child_folders_verified": True, "policy_inheritance_enabled": operation == "assign"},
                    "Proposed Changes": {"operation": operation, "other_fields_preserved": True},
                    "Expected State": {"policy_inheritance_enabled": operation == "restore",
                                       "fixed_policy_relation_enabled": operation == "assign",
                                       "single_secret_scope_preserved": True, "owner_only_preserved": True},
                    "device_write_executed": False,
                }
            except Exception:
                raise IsolatedFolderPolicyTransitionLiveWorkflowError(_UNAVAILABLE) from None

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._record(preview_ref, requester_digest)
            if record.state in {"completed", "reconciliation_required", "invalidated"}:
                raise IsolatedFolderPolicyTransitionLiveWorkflowError(_UNAVAILABLE)
            try:
                self._require(record, "previewed")
                self._available(record.operation, requester_digest)
                current = self._inspect(record.operation, requester_digest)
                if self._now() >= record.expires_at or current.state_digest != record.current.state_digest:
                    raise ValueError
                authorization = self._ref(record.operation, "authorized")
                self._records[preview_ref] = replace(record, authorization_ref=authorization, state="authorized")
                self._authorizations[authorization] = preview_ref
                return {"contract": CONTRACT, "preview_ref": preview_ref, "authorization_ref": authorization,
                        "expires_at": record.expires_at, "confirmation": "recorded", "execution": "authorized_once",
                        "device_write_executed": False}
            except Exception:
                self._records[preview_ref] = replace(record, state="invalidated")
                raise IsolatedFolderPolicyTransitionLiveWorkflowError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            if type(authorization_ref) is not str or authorization_ref not in self._authorizations:
                raise IsolatedFolderPolicyTransitionLiveWorkflowError(_UNAVAILABLE)
            record = self._record(self._authorizations[authorization_ref], requester_digest)
            if record.state in {"completed", "reconciliation_required", "invalidated"}:
                return self._result(record, replay=True)
            if not self._execution_enabled:
                raise IsolatedFolderPolicyTransitionLiveWorkflowError(_UNAVAILABLE)
            try:
                self._require(record, "authorized")
                self._available(record.operation, requester_digest)
                current = self._inspect(record.operation, requester_digest)
                if self._now() >= record.expires_at or current.state_digest != record.current.state_digest:
                    raise ValueError
            except Exception:
                terminal = replace(record, state="invalidated")
                self._records[record.preview_ref] = terminal
                return self._result(terminal, replay=False)
            # Consume before entering the protected transport, even if it refuses
            # before PUT. Durable cross-instance claims belong to that transport.
            attempted = replace(record, state="executing", attempted=True)
            self._records[record.preview_ref] = attempted
            if record.operation == "assign":
                self._assignment_attempted = True
                self._baseline = current
                self._creator = requester_digest
            else:
                self._restore_attempted = True
            try:
                method = (self._transport.transition_and_readback if record.operation == "assign"
                          else self._transport.restore_and_readback)
                readback = method(current.state_digest, expires_at=record.expires_at, clock=self._now)
                after = validate_transition_readback(readback, current, record.operation)
                if after.creator_digest != requester_digest:
                    raise ValueError
                if record.operation == "assign":
                    self._assigned = after
                elif self._baseline is None or after.state_digest != self._baseline.state_digest:
                    raise ValueError
                terminal = replace(attempted, state="completed")
            except Exception:
                terminal = replace(attempted, state="reconciliation_required")
            self._records[record.preview_ref] = terminal
            return self._result(terminal, replay=False)

    def _inspect(self, operation: _Operation, requester: str) -> IsolatedFolderPolicyTransitionInspection:
        method = self._transport.inspect_transition if operation == "assign" else self._transport.inspect_owned_restore
        current = validate_transition_inspection(method())
        if (current.phase != ("inherited" if operation == "assign" else "explicit")
            or not hmac.compare_digest(current.creator_digest, requester)):
            raise ValueError
        if operation == "restore" and (self._assigned is None or self._baseline is None
                                       or current.state_digest != self._assigned.state_digest):
            raise ValueError
        return current

    def _available(self, operation: _Operation, requester: str) -> None:
        if operation == "assign":
            if self._assignment_attempted:
                raise ValueError
        elif (self._restore_attempted or self._assigned is None or self._baseline is None
              or self._creator is None or not hmac.compare_digest(self._creator, requester)):
            raise ValueError

    def _record(self, preview_ref: str, requester: str) -> _Record:
        try:
            self._requester(requester)
            if type(preview_ref) is not str:
                raise ValueError
            record = self._records[preview_ref]
            if not hmac.compare_digest(record.requester_digest, requester):
                raise ValueError
            return record
        except Exception:
            raise IsolatedFolderPolicyTransitionLiveWorkflowError(_UNAVAILABLE) from None

    def _require(self, record: _Record, state: str) -> None:
        if record.state != state or self._now() >= record.expires_at:
            raise ValueError

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int or value <= 0 or value < self._last_clock:
            raise ValueError
        self._last_clock = value
        return value

    @staticmethod
    def _requester(value: object) -> None:
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError

    @staticmethod
    def _ref(operation: _Operation, kind: str) -> str:
        return f"isolated-folder-policy-{operation}-{kind}-" + secrets.token_urlsafe(24)

    @staticmethod
    def _result(record: _Record, *, replay: bool) -> dict[str, object]:
        outcome = {"completed": "succeeded", "invalidated": "not_executed"}.get(record.state, "reconciliation_required")
        return {"contract": CONTRACT, "operation": record.operation, "outcome": outcome,
                "verification": "verified" if outcome == "succeeded" else "unknown", "idempotent_replay": replay,
                "device_write_may_have_occurred": record.attempted, "private_snapshot_returned": False,
                "folder_or_secret_ids_returned": False, "raw_api_response_returned": False}
