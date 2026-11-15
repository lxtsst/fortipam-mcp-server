"""Private, default-closed M4 recovery of one original acknowledged RADIUS pair.

This separate lab-auto authority deletes only the unchanged, zero-reference row
owned by the original HTTP journal. It has no material provider, MCP Tool or
startup registration. Consumed or uncertain DELETE claims never become replayable.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import secrets
from threading import RLock
import time
from typing import Any

from v4_planning import (
    M4AdapterAmbiguous, M4AdapterDenied, M4AuthorizationDenied, M4ClaimState,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, canonical_digest,
)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.models import require_digest, require_ref

from .m4_execution_store import PersistentM4ExecutionStateStore
from .radius_server_pair_contract import RadiusServerPairBinding
from .radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport, _Connection
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from .radius_remote_user_absence_guard import RadiusRemoteUserAbsenceGuard
from .radius_remote_user_preparation_reader import RadiusRemoteUserPreparationReader

ACTION_ID = "radius-server-pair-owned-recover"
ACTION_VERSION = "1.0.0"
ADAPTER_REF = "fortipam-700-build29-radius-pair-owned-recover-v1"
CONTRACT = "fortipam-radius-pair-owned-recovery-private-v1"
_DOMAIN = b"fortipam-radius-pair-owned-recovery-lab-auto-v1\x00"
_ERROR = "The private paired RADIUS recovery workflow is unavailable."
_TTL = 60


class RadiusServerPairRecoveryError(RuntimeError):
    """Categorical refusal without private context or device output."""


@dataclass(frozen=True, slots=True, repr=False)
class _Preview(_OpaqueC3Object):
    owned_digest: str
    state_digest: str
    created_at: int
    expires_at: int
    nonce: str
    preview_ref: str
    signature: str


@dataclass(frozen=True, slots=True, repr=False)
class _Issued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class _Adapter:
    def __init__(self, workflow: RadiusServerPairRecoveryWorkflow) -> None:
        self._workflow = workflow

    def read_current(self, plan: M4ExecutionPlan) -> str:
        w = self._workflow
        w._check_plan(plan)
        try:
            w._inspect_user_absence()
            owned, state = w._transport.inspect_recovery()
            return w._current_digest(owned, state)
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        w = self._workflow
        w._check_plan(plan)
        try:
            w._inspect_user_absence()
            if not w._transport.delete_owned():
                raise ValueError
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        w = self._workflow
        w._check_plan(plan)
        try:
            if not w._transport.inspect_deleted():
                raise ValueError
            return w._expected_digest()
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None


class RadiusServerPairRecoveryWorkflow(_OpaqueC3Object):
    """Separate authenticated lab scope, short-lived HMAC grant and durable M4 use."""

    __slots__ = ("_binding", "_parameters", "_key", "_namespace", "_store", "_enabled",
        "_clock", "_last_clock", "_clock_failed", "_lock", "_transport", "_preview", "_issued", "_started",
        "_composition", "_user_absence")
    _display_name = "RadiusServerPairRecoveryWorkflow"

    def __init__(self, binding: RadiusServerPairBinding, config: SecretMetadataHttpTransportConfig, *,
            expected_serial: str, state_directory: Path, execution_store: PersistentM4ExecutionStateStore,
            authority_key: bytes, environment_ref: str, scope_ref: str, audience_ref: str,
            allowed_requester_digest: str, allowed_transport_digest: str, execution_enabled: bool = False,
            clock: Callable[[], int] | None = None,
            connection_factory: Callable[..., _Connection] | None = None,
            user_absence_guard: RadiusRemoteUserAbsenceGuard | None = None) -> None:
        try:
            if (type(binding) is not RadiusServerPairBinding
                    or type(config) is not SecretMetadataHttpTransportConfig
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or type(execution_enabled) is not bool or clock is not None and not callable(clock)):
                raise ValueError
            if user_absence_guard is not None and type(user_absence_guard) is not RadiusRemoteUserAbsenceGuard: raise ValueError
            self._user_absence = user_absence_guard
            for value in (environment_ref, scope_ref, audience_ref): require_ref(value, "namespace_ref")
            for value in (allowed_requester_digest, allowed_transport_digest): require_digest(value, "identity_digest")
            self._binding, self._parameters, self._key = binding, binding.parameters_digest, authority_key
            self._namespace = {"contract": CONTRACT, "environment_ref": environment_ref,
                "scope_ref": scope_ref, "audience_ref": audience_ref,
                "requester_digest": allowed_requester_digest, "transport_digest": allowed_transport_digest,
                "policy_mode": "lab_auto", "parameters_digest": self._parameters}
            self._store, self._enabled = execution_store, execution_enabled
            self._clock = clock or (lambda: int(time.time()))
            self._lock = RLock()
            self._last_clock: int | None = None
            self._clock_failed = False
            self._preview: _Preview | None = None
            self._issued: _Issued | None = None
            self._started = False
            self._transport = FortiPamRadiusPairHttpTransport(config, binding, expected_serial=expected_serial,
                state_directory=state_directory, recovery_enabled=execution_enabled,
                recovery_authorizer=self._authorize_delete, clock=self._now,
                connection_factory=connection_factory)
            if authority_key == execution_store._key:
                raise ValueError
            self._composition = self._composition_digest()
            self._namespace["composition_digest"] = self._composition
        except Exception:
            raise RadiusServerPairRecoveryError(_ERROR) from None

    def _now(self) -> int:
        with self._lock:
            try:
                now = self._clock()
                if (self._clock_failed or type(now) is not int or now < 0
                        or self._last_clock is not None and now < self._last_clock):
                    raise ValueError
                self._last_clock = now
                return now
            except Exception:
                self._clock_failed = True
                raise RadiusServerPairRecoveryError(_ERROR) from None

    def _identity(self, requester: str, transport: str) -> None:
        require_digest(requester, "requester_digest")
        require_digest(transport, "transport_digest")
        if (not hmac.compare_digest(requester, self._namespace["requester_digest"])
                or not hmac.compare_digest(transport, self._namespace["transport_digest"])
                or self._binding.parameters_digest != self._parameters):
            raise RadiusServerPairRecoveryError(_ERROR)

    def _composition_content(self) -> dict[str, str]:
        t, store = self._transport, self._store
        if (t._binding is not self._binding
                or t._directory in store._path.parents or t._directory in store._key_path.parents
                or t._directory in {store._path, store._key_path}
                or getattr(t._authorize_recovery, "__self__", None) is not self
                or getattr(t._authorize_recovery, "__func__", None) is not RadiusServerPairRecoveryWorkflow._authorize_delete):
            raise ValueError
        content = {"parameters": self._binding.parameters_digest,
            "origin": t._config.base_url, "ca": t._config.ca_file,
            "actor": hashlib.sha256(t._config.bearer_token.encode()).hexdigest(), "serial": t._serial,
            "journal": str(t._directory), "store": str(store._path), "key_path": str(store._key_path),
            "key": hashlib.sha256(store._key).hexdigest()}
        return content

    def _base_composition_digest(self) -> str:
        return canonical_digest(self._composition_content())

    def _composition_digest(self) -> str:
        content = self._composition_content()
        if self._user_absence is not None:
            if type(self._user_absence) is not RadiusRemoteUserAbsenceGuard: raise ValueError
            if not hmac.compare_digest(self._store._load_key(), self._store._key): raise ValueError
            content["associated_user_absence_guard"] = self._user_absence.pin_for(self._transport, self._namespace)
        return canonical_digest(content)

    def _inspect_user_absence(self) -> None:
        if self._user_absence is not None:
            self._user_absence.pin_for(self._transport, self._namespace)
            self._user_absence.inspect()

    def _gate(self) -> None:
        if (self._enabled is not True or self._transport._owned_connect_enabled is not False
                or self._transport._recovery_enabled is not True
                or self._transport._execution_enabled is not False
                or self._transport._binding is not self._binding
                or self._binding.parameters_digest != self._parameters
                or self._composition_digest() != self._composition):
            raise RadiusServerPairRecoveryError(_ERROR)
        if self._user_absence is not None and not hmac.compare_digest(self._store._load_key(), self._store._key):
            raise RadiusServerPairRecoveryError(_ERROR)

    def _unconsumed(self) -> None:
        if self._store.claim_count != 0:
            raise RadiusServerPairRecoveryError(_ERROR)

    def _mac(self, purpose: str, content: object) -> str:
        encoded = json.dumps(content, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + purpose.encode("ascii") + b"\x00" + encoded,
                        hashlib.sha256).hexdigest()

    def _context(self, p: _Preview) -> dict[str, Any]:
        return {**self._namespace, "owned_digest": p.owned_digest, "state_digest": p.state_digest,
            "created_at": p.created_at, "expires_at": p.expires_at, "nonce": p.nonce}

    def _check_preview(self, p: _Preview, now: int) -> None:
        if (type(p) is not _Preview or type(now) is not int or type(p.created_at) is not int
                or type(p.expires_at) is not int or not p.created_at <= now < p.expires_at
                or p.expires_at - p.created_at != _TTL):
            raise RadiusServerPairRecoveryError(_ERROR)
        require_digest(p.owned_digest, "owned_digest")
        require_digest(p.state_digest, "state_digest")
        context = self._context(p)
        if (not hmac.compare_digest(p.signature, self._mac("preview", context))
                or not hmac.compare_digest(p.preview_ref, "radius-pair-recovery-preview-" + self._mac("preview-ref", context))):
            raise RadiusServerPairRecoveryError(_ERROR)

    def _current_digest(self, owned: str, state: str) -> str:
        return canonical_digest({"contract": CONTRACT, "parameters_digest": self._parameters,
                                 "owned_digest": owned, "state_digest": state})

    def _expected_digest(self) -> str:
        p = self._preview
        if p is None: raise RadiusServerPairRecoveryError(_ERROR)
        return canonical_digest({"contract": CONTRACT, "owned_digest": p.owned_digest,
                                 "parameters_digest": self._parameters, "state": "dual-absence-verified"})

    def _derive(self) -> _Issued:
        p = self._preview
        if p is None: raise RadiusServerPairRecoveryError(_ERROR)
        self._check_preview(p, self._now())
        context = self._context(p)
        confirmation, approval = self._mac("standing-intent", context), self._mac("lab-policy", context)
        values: dict[str, Any] = dict(plan_ref="radius-pair-recovery-plan-" + self._mac("plan-ref", context),
            revision=1, action_id=ACTION_ID, action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF,
            target_ref="radius-server-pair-original-owned-row", requester_digest=self._namespace["requester_digest"],
            summary_digest=canonical_digest(self._summary(p)), confirmation_digest=confirmation, approval_digest=approval,
            parameters_digest=self._parameters, expected_current_digest=self._current_digest(p.owned_digest,p.state_digest),
            expected_state_digest=self._expected_digest(), idempotency_digest=self._mac("idempotency", context),
            expires_at=p.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
        signed = {**context, "plan_digest": plan.plan_digest}
        auth: dict[str, Any] = dict(authorization_ref="radius-pair-recovery-auth-" + self._mac("authorization", signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="radius-pair-recovery-intent-" + self._mac("intent-ref", signed),
            confirmation_digest=confirmation, approval_ref="radius-pair-recovery-policy-" + self._mac("policy-ref", signed),
            approval_digest=approval, approver_digest=self._mac("policy-authority", self._namespace),
            issued_at=p.created_at, expires_at=p.expires_at, one_time=True, execution_authorized=True)
        return _Issued(plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth)))

    def _check_plan(self, plan: M4ExecutionPlan) -> None:
        self._gate()
        if self._issued is None or plan is not self._issued.plan or self._issued != self._derive():
            raise M4AdapterDenied(_ERROR)

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            self._check_plan(plan)
            if self._issued is None or self._preview is None or authorization is not self._issued.authorization:
                raise ValueError
            self._check_preview(self._preview, now_epoch)
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _assert_active_claim(self, issued: _Issued) -> None:
        plan, auth = issued.plan, issued.authorization
        _require_m4_dispatch_ownership(plan, auth, self._store)
        claim = self._store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest, authorization_digest=auth.authorization_digest,
            context_digest=canonical_digest({"authorization_digest": auth.authorization_digest,
                "plan_digest": plan.plan_digest, "revision": plan.revision}))
        if claim.state is not M4ClaimState.IN_PROGRESS: raise ValueError

    def _authorize_delete(self, binding: RadiusServerPairBinding, owned: str, state: str) -> bool:
        with self._lock:
            try:
                issued, p = self._issued, self._preview
                if (not self._started or issued is None or p is None or binding is not self._binding
                        or not hmac.compare_digest(owned, p.owned_digest)
                        or not hmac.compare_digest(state, p.state_digest)):
                    raise ValueError
                plan, auth = issued.plan, issued.authorization
                self._assert_active_claim(issued)
                self.verify(plan, auth, now_epoch=self._now())
                self._check_preview(p, self._now())
                self._gate()
                self._inspect_user_absence()
                self._gate()
                self._check_preview(p, self._now())
                self._assert_active_claim(issued)
                return True
            except Exception:
                return False

    def _summary(self, p: _Preview) -> dict[str, object]:
        summary: dict[str, Any] = {"contract": CONTRACT, "policy_mode": "lab_auto", "summary_revision": 1,
            "preview_ref": p.preview_ref, "expires_at": p.expires_at,
            "requester_digest": self._namespace["requester_digest"],
            "environment": "privately_bound_disposable_lab",
            "unchanged_boundary": ["other_identity_servers", "users_groups_and_roles"],
            "Current State": {"original_creation_ack_verified": True, "full_state_unchanged": True,
                "zero_references": True, "observed_at": p.created_at},
            "Proposed Changes": {"operation": "remove_original_owned_radius_pair_row", "material_access": False},
            "Expected State": {"exact_detail_absent": True, "complete_collection_absent": True},
            "dependencies": ["original_pair_creation_ack", "fresh_complete_unchanged_state", "independent_recovery_ledger"],
            "risk_and_effects": {"effect": "remove_one_unassociated_owned_lab_row"},
            "authorization_and_approval": {"mode": "standing_owner_lab_authority", "independent_human_approval": False},
            "facts": {"source": "original_pair_ack_and_fresh_full_cmdb_state", "freshness_seconds": 60},
            "assumptions": ["owner_authorized_disposable_lab_scope"],
            "unresolved_gaps": [],
            "verification": ["original_delete_ack", "dual_absence"],
            "compensation_and_stop": {"uncertain_result": "retain_claims_and_reconcile_without_replay"},
            "device_write_executed": False}
        if self._user_absence is not None:
            summary["Current State"]["associated_user_dual_absence_verified"] = True
            summary["dependencies"].append("fresh_original_user_dual_absence_before_final_dispatch")
            summary["risk_and_effects"]["effect"] = "remove_original_pair_after_owned_user_absence"
            if type(self._user_absence._reader) is RadiusRemoteUserPreparationReader:
                summary["Current State"]["user_preparation_only_zero_claim"] = True
                summary["dependencies"].append("original_preparation_proof_without_declaration_repair")
                summary["risk_and_effects"]["effect"] = "remove_original_pair_after_unattempted_user_absence"
        return summary

    def preview(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                if self._issued is not None or self._composition_digest() != self._composition:
                    raise ValueError
                self._unconsumed()
                created = self._now()
                self._inspect_user_absence()
                owned, state = self._transport.inspect_recovery()
                p = _Preview(owned,state,created,created+_TTL,secrets.token_hex(24),"","")
                context = self._context(p)
                p = _Preview(owned,state,created,p.expires_at,p.nonce,
                    "radius-pair-recovery-preview-"+self._mac("preview-ref",context),self._mac("preview",context))
                self._check_preview(p,self._now())
                self._preview, self._issued, self._started = p, None, False
                summary = self._summary(p)
                return {**summary, "summary_digest": canonical_digest(summary)}
        except Exception:
            raise RadiusServerPairRecoveryError(_ERROR) from None

    def authorize(self, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._gate()
                self._unconsumed()
                if self._issued is not None:
                    raise ValueError
                require_ref(preview_ref,"preview_ref")
                p = self._preview
                if p is None or not hmac.compare_digest(preview_ref,p.preview_ref): raise ValueError
                self._check_preview(p,self._now())
                self._inspect_user_absence()
                if self._transport.inspect_recovery() != (p.owned_digest,p.state_digest): raise ValueError
                self._issued = self._derive()
                return {"contract": CONTRACT,"policy_mode": "lab_auto",
                    "authorization_ref": self._issued.authorization.authorization_ref,"expires_at":p.expires_at}
        except Exception:
            raise RadiusServerPairRecoveryError(_ERROR) from None

    def execute(self, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._gate()
                require_ref(authorization_ref,"authorization_ref")
                issued = self._issued
                if issued is None or not hmac.compare_digest(authorization_ref,issued.authorization.authorization_ref):
                    raise ValueError
                self._check_plan(issued.plan)
                if not self._started: self._unconsumed()
                self._started = True
                result = M4ExecutionKernel(_Adapter(self), self, self._store, clock=self._now).execute(
                    issued.plan, issued.authorization)
                return {"contract":CONTRACT, **result.as_dict()}
        except Exception:
            raise RadiusServerPairRecoveryError(_ERROR) from None

    def reconcile(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                if self._user_absence is None or self._composition_digest() != self._composition: raise ValueError
                if not hmac.compare_digest(self._store._load_key(), self._store._key): raise ValueError
                self._inspect_user_absence()
                if not self._transport.inspect_deleted(): raise ValueError
                self._inspect_user_absence()
                return {"contract": "fortipam-radius-associated-pair-delete-reconciliation-private-v1",
                    "user_absence_verified": True, "pair_absence_verified": True,
                    "mutation_executed": False, "prior_m4_outcome_unchanged": True, "dispatch_retry_allowed": False}
        except Exception:
            raise RadiusServerPairRecoveryError(_ERROR) from None

    def revoke(self) -> None:
        self._enabled = False
        self._transport._recovery_enabled = False
        if self._user_absence is not None: self._user_absence.revoke()

    def close(self) -> None:
        self.revoke()
        with self._lock:
            self._key = b""
            if self._user_absence is not None: self._user_absence.close()
