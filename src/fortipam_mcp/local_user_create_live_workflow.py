"""One live, confirmation-gated FortiPAM Local User create workflow."""

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

from v4_planning import M4AuditEvent, M4ClaimState, M4Compensation, M4ExecutionResult, M4Outcome, M4Verification
from .m4_execution_store import PersistentM4ExecutionStateStore

from .local_user_create_ssh_transport import (
    DEFAULT_ACCESS_PROFILE,
    LocalUserCreateInspection,
    LocalUserCreateReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_local_user_create_workflow_v1"
BP005_STANDARD_USER_WORKFLOW_CONTRACT = "bp005_standard_user_create_v1"
BP002_ENABLED_GUEST_WORKFLOW_CONTRACT = "bp002_enabled_guest_fixture_create_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Local User create workflow is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_WORKFLOW_CONTRACTS = {
    WORKFLOW_CONTRACT: {
        "result_contract": "fortipam_v4_local_user_create_execution_v1",
        "operation": "create_disabled_local_user",
        "access_profile": DEFAULT_ACCESS_PROFILE,
        "status": "disable",
        "status_field": "status_disabled",
    },
    BP005_STANDARD_USER_WORKFLOW_CONTRACT: {
        "result_contract": "bp005_standard_user_create_execution_v1",
        "operation": "create_enabled_standard_local_user",
        "access_profile": "pam_standard_user",
        "status": "enable",
        "status_field": "status_enabled",
    },
    BP002_ENABLED_GUEST_WORKFLOW_CONTRACT: {
        "result_contract": "bp002_enabled_guest_fixture_create_execution_v1",
        "operation": "create_enabled_guest_fixture",
        "access_profile": "Guest",
        "status": "enable",
        "status_field": "status_enabled",
    },
}


class LocalUserCreateLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded Local User create flow."""


class LocalUserCreateLiveWorkflowTransport(Protocol):
    """The exact Local User preflight and create/readback contract."""

    def inspect(self, username: str) -> LocalUserCreateInspection: ...

    def create_and_readback(self, username: str) -> LocalUserCreateReadback: ...


@dataclass(frozen=True, slots=True)
class _LocalUserCreateRequest:
    username: str

    @classmethod
    def create(cls, username: str) -> "_LocalUserCreateRequest":
        if not isinstance(username, str) or _NAME.fullmatch(username) is None:
            raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(username=username)


@dataclass(frozen=True, slots=True)
class _LocalUserCreateRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    username: str
    workflow_contract: str
    current_digest: str
    state: str
    expires_at: int


class LocalUserCreateLiveWorkflow:
    """Existing intent workflow with optional durable dispatch reservations.

    Intent references remain volatile; the optional M4 ledger protects consumed
    executions, not reconstruction of an expired/lost authorization. REST
    fixture transports require it and bind a stronger private preflight digest.
    """

    def __init__(
        self,
        transport: LocalUserCreateLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
        execution_store: PersistentM4ExecutionStateStore | None = None,
        workflow_contract: str = WORKFLOW_CONTRACT,
    ) -> None:
        if (type(workflow_contract) is not str or workflow_contract not in _WORKFLOW_CONTRACTS
            or execution_store is not None and type(execution_store) is not PersistentM4ExecutionStateStore
            or getattr(transport, "requires_durable_execution", False) and (
                execution_store is None or not callable(getattr(transport, "_create_with_dispatch_guard", None)))):
            raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if workflow_contract != WORKFLOW_CONTRACT:
            if (getattr(transport, "workflow_contract_id", None) != workflow_contract
                or getattr(transport, "requires_durable_execution", False) is not True):
                raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        elif getattr(transport, "workflow_contract_id", None) is not None:
            raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._transport = transport
        self._execution_store = execution_store
        self._clock = clock or _now
        self._workflow_contract = workflow_contract
        self._records: dict[str, _LocalUserCreateRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, username: str, requester_digest: str) -> dict[str, object]:
        """Read live state and prepare Current/Proposed/Expected without a write."""

        request = _LocalUserCreateRequest.create(username)
        _require_requester(requester_digest)
        current = self._inspect(request)
        if current.exists:
            raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _LocalUserCreateRecord(
            preview_ref="local-user-create-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            username=request.username,
            workflow_contract=self._workflow_contract,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm the unchanged absence state and issue one execution reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(_LocalUserCreateRequest(record.username))
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "local-user-create-authorized-" + secrets.token_urlsafe(24)
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": updated.workflow_contract,
            "preview_ref": updated.preview_ref,
            "authorization_ref": authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": updated.expires_at,
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Create exactly the confirmed user and report categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                if self._execution_store is not None:
                    self._execution_store.verify_ready()
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(_LocalUserCreateRequest(record.username))
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "authorized")
            if self._execution_store is not None:
                # Consume the actual existing requester-bound confirmation
                # record, not a newly invented authorization/verifier path.
                try:
                    claim = self._execution_store.claim(**_claim_inputs(record))
                except Exception:
                    self._set_state_locked(record.preview_ref, "reconciliation_required")
                    return self._result(record, idempotent_replay=False)
                if claim.state is not M4ClaimState.NEW:
                    self._set_state_locked(record.preview_ref, "reconciliation_required")
                    return self._result(record, idempotent_replay=True)
            self._records[record.preview_ref] = replace(record, state="executing")
        evidence_digest: str | None = None
        try:
            if getattr(self._transport, "requires_durable_execution", False):
                readback = self._transport._create_with_dispatch_guard(  # type: ignore[attr-defined]
                    record.username, lambda: self._dispatch_guard(record),
                )
            else:
                readback = self._transport.create_and_readback(record.username)
            verified = (isinstance(readback, LocalUserCreateReadback) and readback.verified
                        and getattr(readback, _WORKFLOW_CONTRACTS[record.workflow_contract]["status_field"]) is True)
            if isinstance(readback, LocalUserCreateReadback):
                evidence_digest = readback.evidence_digest
                if evidence_digest is not None:
                    _require_requester(evidence_digest)
            if getattr(self._transport, "requires_durable_execution", False) and evidence_digest is None:
                verified = False
        except Exception:
            verified = False
        if self._execution_store is not None:
            result = M4ExecutionResult(
                M4Outcome.SUCCEEDED if verified else M4Outcome.RECONCILIATION_REQUIRED,
                M4Verification.VERIFIED if verified else M4Verification.UNKNOWN,
                M4Compensation.NOT_REQUESTED if verified else M4Compensation.UNKNOWN, False,
            )
            try:
                claim_inputs = _claim_inputs(record)
                claim_inputs.pop("authorization_digest")
                digest = _digest({"context": claim_inputs["context_digest"], "result": result.as_dict(),
                                  "creation_evidence": evidence_digest})
                self._execution_store.finalize(**claim_inputs, result=result, event=M4AuditEvent(
                    0, "intent_bound", result.outcome, result.verification, result.compensation, digest,
                ))
            except Exception:
                verified = False
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _dispatch_guard(self, record: _LocalUserCreateRecord) -> None:
        with self._lock:
            current = self._records.get(record.preview_ref)
            if current is None or current != replace(record, state="executing"):
                raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(current, record.requester_digest, "executing")
            if self._execution_store is None:
                raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._execution_store.verify_ready()

    def _inspect(self, request: _LocalUserCreateRequest) -> LocalUserCreateInspection:
        try:
            result = self._transport.inspect(request.username)
        except Exception as exc:
            raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, LocalUserCreateInspection):
            raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _LocalUserCreateRecord:
        if not _valid_ref(preview_ref, "local-user-create-preview-"):
            raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _LocalUserCreateRecord:
        if not _valid_ref(authorization_ref, "local-user-create-authorized-"):
            raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _LocalUserCreateRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _LocalUserCreateRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _LocalUserCreateRecord) -> dict[str, object]:
        contract = _WORKFLOW_CONTRACTS[record.workflow_contract]
        return {
            "contract": record.workflow_contract,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_username": record.username,
                "user_exists": False,
            },
            "Proposed Changes": {
                "operation": contract["operation"],
                "username": record.username,
                "access_profile": contract["access_profile"],
                "status": contract["status"],
                "initial_password": "generated_not_returned",
            },
            "Expected State": {
                "username_matches": True,
                "user_exists": True,
                "access_profile_matches": True,
                contract["status_field"]: True,
                "credentials_returned": False,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _LocalUserCreateRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": _WORKFLOW_CONTRACTS[record.workflow_contract]["result_contract"],
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "credentials_returned": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: LocalUserCreateInspection) -> str:
    if type(inspection.exists) is not bool:
        raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    state: dict[str, object] = {"exists": inspection.exists}
    if inspection.state_digest is not None:
        _require_requester(inspection.state_digest)
        state["state_digest"] = inspection.state_digest
    return _digest(state)


def _digest(value: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def _claim_inputs(record: _LocalUserCreateRecord) -> dict[str, str]:
    if record.authorization_ref is None:
        raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return {
        "plan_ref": record.preview_ref, "requester_digest": record.requester_digest,
        "idempotency_digest": _digest({"preview": record.preview_ref}),
        "authorization_digest": _digest({"confirmation": record.authorization_ref}),
        "context_digest": _digest({"contract": record.workflow_contract, "username": record.username,
                                   "current": record.current_digest, "expires_at": record.expires_at}),
    }


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise LocalUserCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "BP002_ENABLED_GUEST_WORKFLOW_CONTRACT",
    "BP005_STANDARD_USER_WORKFLOW_CONTRACT",
    "LocalUserCreateLiveWorkflow",
    "LocalUserCreateLiveWorkflowError",
    "LocalUserCreateLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
