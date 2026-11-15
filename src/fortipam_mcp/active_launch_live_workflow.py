"""Bounded FortiPAM active-launch observation and disconnect workflow.

The workflow retains WAD token IDs in process memory only.  Callers receive
short-lived opaque launch references, never a token, identity, Target, Secret,
or raw CLI output.  A disconnect always targets one reference and cannot invoke
the FortiPAM command form that clears all active launches.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hmac
import re
import secrets
import threading
import time
from typing import Protocol

from v4_planning import (M4AdapterAmbiguous, M4AuthorizationDenied,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, canonical_digest)
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.models import require_digest

from .m4_execution_store import PersistentM4ExecutionStateStore

from .active_launch_ssh_transport import ActiveLaunchClearReadback, ActiveLaunchListing


OBSERVATION_CONTRACT = "fortipam_v4_active_launch_observation_cli_v1"
DISCONNECT_WORKFLOW_CONTRACT = "fortipam_v4_active_launch_disconnect_cli_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 active-launch control is unavailable."
_TTL_SECONDS = 600


class ActiveLaunchLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing active-launch workflow failure."""


class ActiveLaunchLiveWorkflowTransport(Protocol):
    """Fixed active-launch list and exact-token clear transport contract."""

    def list_active_launches(self) -> ActiveLaunchListing: ...

    def clear_active_launch_and_readback(
        self,
        token_id: str,
        *, expected_identity_digest: str | None = None,
        guard: Callable[[], None] | None = None,
    ) -> ActiveLaunchClearReadback: ...


@dataclass(frozen=True, slots=True)
class _ObservedLaunchRecord:
    launch_ref: str
    requester_digest: str
    token_id: str
    expires_at: int


@dataclass(frozen=True, slots=True)
class _DisconnectRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    launch_ref: str
    token_id: str
    state: str
    expires_at: int


class ActiveLaunchLiveWorkflow:
    """Observe active launches and disconnect one previously observed launch."""

    def __init__(
        self,
        transport: ActiveLaunchLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._observed: dict[str, _ObservedLaunchRecord] = {}
        self._disconnect_records: dict[str, _DisconnectRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def observe(self, *, requester_digest: str) -> dict[str, object]:
        """List active launches and return only opaque short-lived references."""

        _require_requester(requester_digest)
        listing = self._listing()
        if not listing.recognized:
            return {
                "contract": OBSERVATION_CONTRACT,
                "observation": "unavailable_or_unrecognized",
                "active_launch_count": None,
                "active_launch_refs": [],
                "raw_cli_returned": False,
                "wad_token_returned": False,
                "identity_target_secret_or_session_data_returned": False,
                "device_write_executed": False,
            }
        with self._lock:
            self._purge_expired_locked()
            references: list[dict[str, object]] = []
            expires_at = self._clock() + _TTL_SECONDS
            for token_id in listing.token_ids:
                launch_ref = "active-launch-ref-" + secrets.token_urlsafe(24)
                self._observed[launch_ref] = _ObservedLaunchRecord(
                    launch_ref=launch_ref,
                    requester_digest=requester_digest,
                    token_id=token_id,
                    expires_at=expires_at,
                )
                references.append(
                    {
                        "launch_ref": launch_ref,
                        "expires_at": expires_at,
                        "token_or_session_data_returned": False,
                    }
                )
        return {
            "contract": OBSERVATION_CONTRACT,
            "observation": "verified",
            "active_launch_count": len(references),
            "active_launch_refs": references,
            "raw_cli_returned": False,
            "wad_token_returned": False,
            "identity_target_secret_or_session_data_returned": False,
            "device_write_executed": False,
        }

    def preview_disconnect(
        self,
        launch_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        """Re-read one opaque active-launch reference and render disconnect C/P/E."""

        with self._lock:
            observed = self._observed_record_locked(launch_ref, requester_digest)
            self._require_selected_launch_present(observed.token_id)
            record = _DisconnectRecord(
                preview_ref="active-launch-disconnect-preview-"
                + secrets.token_urlsafe(24),
                authorization_ref=None,
                requester_digest=requester_digest,
                launch_ref=launch_ref,
                token_id=observed.token_id,
                state="previewed",
                expires_at=self._clock() + _TTL_SECONDS,
            )
            self._disconnect_records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm_disconnect(
        self,
        preview_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        """Record confirmation only after the selected active launch still exists."""

        with self._lock:
            record = self._disconnect_record_locked(preview_ref)
            self._validate_disconnect_record(record, requester_digest, "previewed")
            if not self._selected_launch_present(record.token_id):
                self._disconnect_records[record.preview_ref] = replace(
                    record,
                    state="invalidated",
                )
                raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "active-launch-disconnect-authorized-" + secrets.token_urlsafe(
                24
            )
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._disconnect_records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": DISCONNECT_WORKFLOW_CONTRACT,
            "preview_ref": updated.preview_ref,
            "authorization_ref": authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": updated.expires_at,
            "device_write_executed": False,
        }

    def execute_disconnect(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        """Clear exactly one confirmed active-launch token and verify its absence."""

        with self._lock:
            record = self._authorization_record_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record.requester_digest, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_disconnect_record(record, requester_digest, "authorized")
            if not self._selected_launch_present(record.token_id):
                self._disconnect_records[record.preview_ref] = replace(
                    record,
                    state="invalidated",
                )
                raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._disconnect_records[record.preview_ref] = replace(
                record,
                state="executing",
            )
        try:
            readback = self._transport.clear_active_launch_and_readback(record.token_id)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, ActiveLaunchClearReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _listing(self) -> ActiveLaunchListing:
        try:
            listing = self._transport.list_active_launches()
        except Exception as exc:
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(listing, ActiveLaunchListing):
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return listing

    def _require_selected_launch_present(self, token_id: str) -> None:
        if not self._selected_launch_present(token_id):
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _selected_launch_present(self, token_id: str) -> bool:
        listing = self._listing()
        return listing.recognized and token_id in listing.token_ids

    def _observed_record_locked(
        self,
        launch_ref: str,
        requester_digest: str,
    ) -> _ObservedLaunchRecord:
        if not _valid_ref(launch_ref, "active-launch-ref-"):
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        _require_requester(requester_digest)
        self._purge_expired_locked()
        record = self._observed.get(launch_ref)
        if record is None or self._clock() >= record.expires_at:
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._validate_requester(record.requester_digest, requester_digest)
        return record

    def _disconnect_record_locked(self, preview_ref: str) -> _DisconnectRecord:
        if not _valid_ref(preview_ref, "active-launch-disconnect-preview-"):
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._disconnect_records.get(preview_ref)
        if record is None:
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _authorization_record_locked(self, authorization_ref: str) -> _DisconnectRecord:
        if not _valid_ref(authorization_ref, "active-launch-disconnect-authorized-"):
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._disconnect_records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_disconnect_record(
        self,
        record: _DisconnectRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record.requester_digest, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(stored_digest: str, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(stored_digest, requester_digest):
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._disconnect_records.get(preview_ref)
        if record is None:
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._disconnect_records[preview_ref] = replace(record, state=state)

    def _purge_expired_locked(self) -> None:
        now_epoch = self._clock()
        for launch_ref, record in tuple(self._observed.items()):
            if record.expires_at <= now_epoch:
                self._observed.pop(launch_ref, None)
        for preview_ref, disconnect_record in tuple(self._disconnect_records.items()):
            if (
                disconnect_record.expires_at <= now_epoch
                and disconnect_record.state != "completed"
            ):
                self._disconnect_records.pop(preview_ref, None)
                if disconnect_record.authorization_ref is not None:
                    self._authorization_index.pop(
                        disconnect_record.authorization_ref,
                        None,
                    )

    @staticmethod
    def _preview_projection(record: _DisconnectRecord) -> dict[str, object]:
        return {
            "contract": DISCONNECT_WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_active_launch_reference": record.launch_ref,
                "selected_active_launch_present": True,
                "selected_launch_reference_returned": True,
                "raw_cli_returned": False,
                "wad_token_returned": False,
                "identity_target_secret_or_session_data_returned": False,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "disconnect_exactly_one_previously_observed_active_launch",
                "selected_active_launch_reference": record.launch_ref,
                "selected_launch_reference_returned": True,
                "clear_all_active_launches": False,
                "caller_controlled_cli": False,
                "raw_cli_returned": False,
                "wad_token_returned": False,
                "identity_target_secret_or_session_data_returned": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "selected_active_launch_reference_matches": True,
                "selected_active_launch_present": False,
                "single_active_launch_disconnect_command_used": True,
                "clear_all_active_launches": False,
                "verification_transport": "ssh_cli_fallback",
                "raw_cli_returned": False,
                "wad_token_returned": False,
                "identity_target_secret_or_session_data_returned": False,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _DisconnectRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._disconnect_records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_active_launch_disconnect_cli_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "a_new_secret_launch_is_required_to_restore_a_disconnected_launch",
            "selected_active_launch_disconnected": succeeded,
            "clear_all_active_launches": False,
            "raw_cli_returned": False,
            "wad_token_returned": False,
            "identity_target_secret_or_session_data_returned": False,
        }


def _require_requester(value: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and 24 <= len(value) <= 256
        and re.fullmatch(r"[A-Za-z0-9_-]+", value[len(prefix) :]) is not None
    )


def _now() -> int:
    return int(time.time())


FIXED_DISCONNECT_CONTRACT = "fortipam-fixed-active-launch-disconnect-v1"


@dataclass(frozen=True, slots=True, repr=False)
class FixedActiveLaunchBinding:
    """Private original native record and actual OAuth operator bindings."""

    serial_digest: str
    token_id: str
    identity_digest: str
    owner_name: str
    allowed_requester_digest: str
    allowed_transport_digest: str
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value in (self.serial_digest, self.identity_digest,
                      self.allowed_requester_digest, self.allowed_transport_digest):
            require_digest(value, "fixed launch binding")
        if (not isinstance(self.token_id, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", self.token_id) is None
                or not isinstance(self.owner_name, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.owner_name) is None
                or type(self.issued_at) is not int or type(self.expires_at) is not int
                or not 0 <= self.issued_at < self.expires_at <= self.issued_at + 600):
            raise ValueError(WORKFLOW_UNAVAILABLE)


class _FixedDisconnectAdapter:
    def __init__(self, workflow: FixedActiveLaunchLiveWorkflow,
                 plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> None:
        self._workflow, self._plan, self._authorization = workflow, plan, authorization
        self._readback: ActiveLaunchClearReadback | None = None

    def _guard(self) -> None:
        self._workflow.verify(self._plan, self._authorization, now_epoch=self._workflow._clock())
        _require_m4_dispatch_ownership(self._plan, self._authorization, self._workflow._store)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            self._workflow.verify(plan, self._authorization, now_epoch=self._workflow._clock())
            self._workflow._listing()
            return self._workflow._current_digest
        except Exception:
            raise M4AdapterAmbiguous(WORKFLOW_UNAVAILABLE) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        _require_m4_dispatch_ownership(plan, self._authorization, self._workflow._store)
        try:
            self._workflow.verify(plan, self._authorization, now_epoch=self._workflow._clock())
            # The native adapter repeats identity and serial checks in the same
            # connection as the exact-token command and complete readback.
            self._readback = self._workflow._transport.clear_active_launch_and_readback(
                self._workflow._binding.token_id,
                expected_identity_digest=self._workflow._binding.identity_digest,
                guard=self._guard)
        except Exception:
            raise M4AdapterAmbiguous(WORKFLOW_UNAVAILABLE) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            self._workflow.verify(plan, self._authorization, now_epoch=self._workflow._clock())
            if plan is not self._plan or self._readback is None or not self._readback.verified:
                raise ValueError
            return self._workflow._expected_digest
        except Exception:
            raise M4AdapterAmbiguous(WORKFLOW_UNAVAILABLE)


class FixedActiveLaunchLiveWorkflow(ActiveLaunchLiveWorkflow):
    """One original launch, one durable dispatch, no adoption after restart."""

    def __init__(self, transport: ActiveLaunchLiveWorkflowTransport,
                 binding: FixedActiveLaunchBinding, store: PersistentM4ExecutionStateStore,
                 *, authority_key: bytes, clock: Callable[[], int] | None = None) -> None:
        super().__init__(transport, clock=clock)
        if (type(binding) is not FixedActiveLaunchBinding or type(store) is not PersistentM4ExecutionStateStore
                or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                or hmac.compare_digest(authority_key, store._key)):
            raise ValueError(WORKFLOW_UNAVAILABLE)
        self._binding, self._store, self._key = binding, store, authority_key
        self._last_now = binding.issued_at
        self._deadline = time.monotonic() + max(0, binding.expires_at - self._clock())
        self._closed = False
        # Never include a preview nonce, expiry, client, or new private filename
        # in the object namespace: none may reopen an uncertain native launch.
        self._object_digest = canonical_digest({"contract": FIXED_DISCONNECT_CONTRACT,
            "serial": binding.serial_digest, "token": binding.token_id})
        self._current_digest = canonical_digest({"object": self._object_digest,
            "identity": binding.identity_digest, "present": True})
        self._expected_digest = canonical_digest({"object": self._object_digest,
            "absent": True, "all_original_other_records_preserved": True})
        self._issued: dict[str, tuple[M4ExecutionPlan, M4ExecutionAuthorization]] = {}
        store.verify_ready()
        self._check_fixed(binding.allowed_requester_digest)

    def _check_fixed(self, requester_digest: str) -> int:
        now = self._clock()
        if (self._closed or time.monotonic() >= self._deadline
                or type(now) is not int or not self._last_now <= now < self._binding.expires_at
                or not hmac.compare_digest(requester_digest, self._binding.allowed_requester_digest)):
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._last_now = now
        return now

    def validate_principal(self, requester_digest: str, transport_digest: str) -> None:
        with self._lock:
            self._check_fixed(requester_digest)
            if not hmac.compare_digest(transport_digest, self._binding.allowed_transport_digest):
                raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _unconsumed(self) -> None:
        if self._store.claim_count != 0:
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _listing(self) -> ActiveLaunchListing:
        self._check_fixed(self._binding.allowed_requester_digest)
        listing = super()._listing()
        self._check_fixed(self._binding.allowed_requester_digest)
        identities = listing.record_identities
        if (not listing.recognized or listing.serial_digest != self._binding.serial_digest
                or len(identities) != len(listing.token_ids)
                or tuple(token for token, _ in identities) != listing.token_ids
                or len(set(listing.token_ids)) != len(listing.token_ids)
                or dict(identities).get(self._binding.token_id) != self._binding.identity_digest):
            raise ActiveLaunchLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return ActiveLaunchListing(True, (self._binding.token_id,),
            ((self._binding.token_id, self._binding.identity_digest),), listing.serial_digest)

    def observe(self, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            self._check_fixed(requester_digest)
            return super().observe(requester_digest=requester_digest)

    def preview_disconnect(self, launch_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            self._check_fixed(requester_digest)
            self._unconsumed()
            result = super().preview_disconnect(launch_ref, requester_digest=requester_digest)
            record = self._disconnect_records[str(result["preview_ref"])]
            record = replace(record, expires_at=min(record.expires_at, self._binding.expires_at))
            self._disconnect_records[record.preview_ref] = record
            return self._preview_projection(record)

    def confirm_disconnect(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            self._check_fixed(requester_digest)
            self._unconsumed()
            result = super().confirm_disconnect(preview_ref, requester_digest=requester_digest)
            record = self._disconnect_records[preview_ref]
            self._issued[str(result["authorization_ref"])] = self._derive(record)
            return result

    def _derive(self, record: _DisconnectRecord) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        import hashlib
        from typing import Any
        def mac(purpose: str) -> str:
            return hmac.new(self._key, (FIXED_DISCONNECT_CONTRACT + "\0" + purpose + "\0"
                + record.preview_ref + "\0" + self._object_digest + "\0" + self._binding.identity_digest
                + "\0" + self._binding.owner_name).encode(), hashlib.sha256).hexdigest()
        intent, approval = mac("intent"), mac("standing-lab-approval")
        fields: dict[str, Any] = dict(plan_ref="fixed-launch-" + self._object_digest, revision=1,
            action_id="session-disconnect-fixed", action_version="1.0.0", adapter_ref=FIXED_DISCONNECT_CONTRACT,
            target_ref="fixed-original-owned-active-launch", requester_digest=record.requester_digest,
            summary_digest=mac("summary"), confirmation_digest=intent, approval_digest=approval,
            parameters_digest=canonical_digest({"object": self._object_digest,
                "identity": self._binding.identity_digest}), expected_current_digest=self._current_digest,
            expected_state_digest=self._expected_digest, idempotency_digest=self._object_digest,
            expires_at=record.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
        fields = dict(authorization_ref=record.authorization_ref, plan_ref=plan.plan_ref, plan_digest=plan.plan_digest,
            requester_digest=plan.requester_digest, confirmation_ref="fixed-launch-intent-" + intent,
            confirmation_digest=intent, approval_ref="fixed-launch-approval-" + approval,
            approval_digest=approval, approver_digest=mac("lab-owner"), issued_at=self._binding.issued_at,
            expires_at=record.expires_at, one_time=True, execution_authorized=True)
        return plan, M4ExecutionAuthorization(**fields, authorization_digest=canonical_digest(fields))

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            self._check_fixed(plan.requester_digest)
            issued = self._issued[authorization.authorization_ref]
            record = self._authorization_record_locked(authorization.authorization_ref)
            if (issued[0] is not plan or issued[1] is not authorization or self._derive(record) != issued
                    or not self._binding.issued_at <= now_epoch < plan.expires_at):
                raise ValueError
        except Exception:
            raise M4AuthorizationDenied(WORKFLOW_UNAVAILABLE) from None

    def execute_disconnect(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            self._check_fixed(requester_digest)
            record = self._authorization_record_locked(authorization_ref)
            self._validate_requester(record.requester_digest, requester_digest)
            plan, authorization = self._issued[authorization_ref]
            result = M4ExecutionKernel(_FixedDisconnectAdapter(self, plan, authorization), self, self._store,
                clock=self._clock).execute(plan, authorization)
            self._set_state_locked(record.preview_ref,
                "completed" if result.outcome == "succeeded" else "reconciliation_required")
            return {**self._result(record, idempotent_replay=result.idempotent_replay),
                "audit_recorded": True, "durable_execution_consumed": True}

    def close(self) -> None:
        with self._lock:
            self._closed = True
