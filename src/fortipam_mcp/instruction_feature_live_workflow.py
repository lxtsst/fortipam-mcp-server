"""Inactive M4 authority for an owner-admitted shared Instruction setting.

The canonical directory and independent phase authority key are trusted server
startup inputs. They never come from MCP arguments or profile fixture ownership.
This module does not admit owner files, load credentials, or activate a runtime.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import secrets
from threading import RLock
import time
from typing import cast

from v4_planning import (
    M4AdapterAmbiguous, M4AdapterDenied, M4AuthorizationDenied,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, canonical_digest,
    M4ClaimState, M4Compensation, M4Outcome, M4Verification,
)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .instruction_feature_contract import InstructionFeatureTransition
from .instruction_feature_http_transport import (
    CONTRACT, FortiPamInstructionFeatureHttpTransport,
)
from .m4_execution_store import PersistentM4ExecutionStateStore

ACTION_VERSION = "2.0.0"
RECONCILED_RESTORE_ACTION_VERSION = "2.1.0"
RESTORE_RECONCILIATION_CONTRACT = "fortipam-instruction-feature-restore-reconciliation-v2"

_TTL = 60
_DOMAIN = b"fortipam-instruction-feature-lab-auto-v2\x00"
_UNAVAILABLE = "The private Instruction feature workflow is unavailable."


class InstructionFeatureLiveWorkflowError(RuntimeError):
    """Stable value-free refusal."""


@dataclass(frozen=True, slots=True, repr=False)
class _Preview(_OpaqueC3Object):
    nonce: str
    current_digest: str
    expected_digest: str
    created_at: int
    expires_at: int
    preview_ref: str
    signature: str


@dataclass(frozen=True, slots=True, repr=False)
class _Issued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class _LabAutoAuthority(_OpaqueC3Object):
    __slots__ = ("_key", "_binding", "_parameters", "_namespace", "_phase", "_clock", "_preview", "_issued", "_reconciliation")

    def __init__(self, key: bytes, binding: InstructionFeatureTransition, phase: str,
                 namespace: dict[str, str], clock: Callable[[], int]) -> None:
        self._key, self._binding, self._phase = key, binding, phase
        self._parameters, self._namespace, self._clock = binding.digest, namespace, clock
        self._preview: _Preview | None = None
        self._issued: _Issued | None = None
        self._reconciliation: tuple[int, str] | None = None

    def _mac(self, purpose: str, content: Mapping[str, object]) -> str:
        encoded = json.dumps(content, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + purpose.encode("ascii") + b"\x00" + encoded,
                        hashlib.sha256).hexdigest()

    def _context(self, nonce: str, current: str, expected: str, created: int, expires: int) -> dict[str, object]:
        context: dict[str, object] = {**self._namespace, "contract": CONTRACT, "phase": self._phase,
            "action_id": "instruction-feature-" + self._phase, "action_version": ACTION_VERSION,
            "authority_ref": "fortipam-mcp-lab-auto-instruction-feature-" + self._phase,
            "policy_mode": "lab_auto", "preservation_mode": "complete-setting-original-ack-v2",
            "parameters_digest": self._parameters, "nonce": nonce,
            "current_digest": current, "expected_digest": expected,
            "created_at": created, "expires_at": expires}
        if self._reconciliation is not None:
            count, digest = self._reconciliation
            context.update(action_version=RECONCILED_RESTORE_ACTION_VERSION,
                           revision=count + 1, restore_reconciliation_digest=digest)
        return context

    def preview(self, current: str, expected: str, created: int) -> _Preview:
        nonce, expires = secrets.token_hex(24), created + _TTL
        context = self._context(nonce, current, expected, created, expires)
        return _Preview(nonce, current, expected, created, expires,
            "instruction-feature-preview-" + self._mac("preview-ref", context), self._mac("preview", context))

    def check_preview(self, preview: _Preview, now: int) -> dict[str, object]:
        if (type(preview) is not _Preview or type(now) is not int
            or type(preview.created_at) is not int or type(preview.expires_at) is not int
            or not preview.created_at <= now < preview.expires_at
            or preview.expires_at - preview.created_at != _TTL
            or self._binding.digest != self._parameters
            or preview.current_digest != self._binding._current
            or preview.expected_digest != self._binding._expected):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        for digest in (preview.current_digest, preview.expected_digest):
            require_digest(digest, "state_digest")
        context = self._context(preview.nonce, preview.current_digest, preview.expected_digest,
                                preview.created_at, preview.expires_at)
        if (not hmac.compare_digest(preview.signature, self._mac("preview", context))
            or not hmac.compare_digest(preview.preview_ref,
                                      "instruction-feature-preview-" + self._mac("preview-ref", context))):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        return context

    def _derive(self, preview: _Preview, now: int) -> _Issued:
        context = self.check_preview(preview, now)
        approval, confirmation = self._mac("lab-approval", context), self._mac("standing-intent", context)
        plan_ref = "instruction-feature-plan-" + self._mac("plan-ref", context)
        requester = self._namespace["requester_digest"]
        parameters_values: dict[str, object] = {"contract": CONTRACT, "phase": self._phase, "binding": self._parameters, "namespace": self._namespace}
        if self._reconciliation is not None:
            parameters_values["restore_reconciliation_digest"] = self._reconciliation[1]
        parameters = canonical_digest(parameters_values)
        revision = int(cast(int, context.get("revision", 1)))
        version = cast(str, context["action_version"])
        adapter = "fortipam-700-build29-instruction-feature-" + self._phase + ("-reconciled-v2" if self._reconciliation else "-v2")
        plan_values = {
            "plan_ref": plan_ref, "revision": revision, "action_id": "instruction-feature-" + self._phase,
            "action_version": version, "adapter_ref": adapter,
            "target_ref": self._namespace["target_ref"], "requester_digest": requester,
            "summary_digest": self._mac("summary", context), "confirmation_digest": confirmation,
            "approval_digest": approval, "parameters_digest": parameters,
            "expected_current_digest": preview.current_digest, "expected_state_digest": preview.expected_digest,
            "idempotency_digest": self._mac("idempotency", context), "expires_at": preview.expires_at,
            "compensation_ref": None,
        }
        plan = M4ExecutionPlan(plan_ref, revision, "instruction-feature-" + self._phase, version,
            str(plan_values["adapter_ref"]), self._namespace["target_ref"], requester,
            str(plan_values["summary_digest"]), confirmation, approval, parameters,
            preview.current_digest, preview.expected_digest, str(plan_values["idempotency_digest"]),
            preview.expires_at, None, canonical_digest(plan_values))
        signed = {"plan_digest": plan.plan_digest, **context}
        auth_ref = "instruction-feature-auth-" + self._mac("authorization-ref", signed)
        confirmation_ref = "instruction-feature-intent-" + self._mac("intent-ref", signed)
        approval_ref = "instruction-feature-approval-" + self._mac("approval-ref", signed)
        approver = self._mac("lab-policy-authority", {"phase": self._phase, **self._namespace})
        auth_values = {
            "authorization_ref": auth_ref, "plan_ref": plan_ref, "plan_digest": plan.plan_digest,
            "requester_digest": requester, "confirmation_ref": confirmation_ref,
            "confirmation_digest": confirmation, "approval_ref": approval_ref, "approval_digest": approval,
            "approver_digest": approver, "issued_at": preview.created_at, "expires_at": preview.expires_at,
            "one_time": True, "execution_authorized": True,
        }
        auth = M4ExecutionAuthorization(auth_ref, plan_ref, plan.plan_digest, requester,
            confirmation_ref, confirmation, approval_ref, approval, approver,
            preview.created_at, preview.expires_at, True, True, canonical_digest(auth_values))
        return _Issued(plan, auth)

    def issue(self, preview: _Preview) -> _Issued:
        issued = self._derive(preview, self._clock())
        self._preview, self._issued = preview, issued
        return issued

    def resolve(self, authorization_ref: str) -> _Issued:
        if (self._issued is None or not hmac.compare_digest(
                authorization_ref, self._issued.authorization.authorization_ref)):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        self.verify(self._issued.plan, self._issued.authorization, now_epoch=self._clock())
        return self._issued

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        if self._preview is None or self._issued is None:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        expected = self._derive(self._preview, now_epoch)
        if (plan is not self._issued.plan or authorization is not self._issued.authorization
            or plan != expected.plan or authorization != expected.authorization):
            raise M4AuthorizationDenied(_UNAVAILABLE)


class _Adapter:
    def __init__(self, workflow: InstructionFeatureLiveWorkflow, issued: _Issued) -> None:
        self._workflow, self._issued = workflow, issued

    def _check(self, plan: M4ExecutionPlan) -> None:
        try:
            self._workflow._gate()
            if plan is not self._issued.plan:
                raise ValueError
            self._workflow._authority.verify(plan, self._issued.authorization,
                                            now_epoch=self._workflow._now())
            self._workflow._original_m4()
        except Exception:
            raise M4AdapterDenied(_UNAVAILABLE) from None

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self._check(plan)
        try:
            current = self._workflow._transport.inspect_precondition()
            if self._workflow._binding._expected != plan.expected_state_digest:
                raise ValueError
            return current._state
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        self._check(plan)
        try:
            self._workflow._transport.dispatch(expected_current_digest=plan.expected_current_digest,
                plan_digest=plan.plan_digest,
                authorization_digest=self._issued.authorization.authorization_digest,
                expires_at=plan.expires_at, before_send=lambda:self._check(plan))
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self._check(plan)
        try:
            return self._workflow._transport.inspect_postcondition()
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None


class InstructionFeatureLiveWorkflow(_OpaqueC3Object):
    """One admitted phase with a fixed shared object and independent M4 authority."""

    __slots__ = ("_transport", "_binding", "_parameters", "_phase", "_namespace",
                 "_execution_store", "_enabled", "_clock", "_lock", "_last_clock",
                 "_clock_failed", "_requester", "_transport_digest", "_authority",
                 "_preview", "_started", "_directory", "_original_store", "_restore_checkpoint")

    def __init__(self, transport: FortiPamInstructionFeatureHttpTransport, *,
                 canonical_state_directory: Path, execution_store: PersistentM4ExecutionStateStore,
                 authority_key: bytes, environment_ref: str, scope_ref: str, audience_ref: str,
                 allowed_requester_digest: str, allowed_transport_digest: str,
                 execution_enabled: bool = False, clock: Callable[[], int] | None = None,
                 original_enable_store: PersistentM4ExecutionStateStore | None = None) -> None:
        try:
            if (type(transport) is not FortiPamInstructionFeatureHttpTransport
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or type(authority_key) is not bytes or not 32<=len(authority_key)<=4096
                    or hmac.compare_digest(authority_key,transport._key)
                    or type(execution_enabled) is not bool
                    or clock is not None and not callable(clock)
                    or not isinstance(canonical_state_directory,Path)
                    or not canonical_state_directory.is_absolute()
                    or canonical_state_directory.resolve(strict=True)!=canonical_state_directory
                    or canonical_state_directory!=transport._directory
                    or canonical_state_directory.name!="instruction-feature-"+transport._baseline._serial
                    or transport._phase=="enable" and original_enable_store is not None
                    or transport._phase=="restore" and (type(original_enable_store) is not PersistentM4ExecutionStateStore
                        or original_enable_store._path==execution_store._path)):
                raise ValueError
            for ref in (environment_ref,scope_ref,audience_ref):
                require_ref(ref,"namespace_ref")
            for digest in (allowed_requester_digest,allowed_transport_digest):
                require_digest(digest,"identity_digest")
            self._transport, self._binding = transport,transport._binding
            self._parameters,self._phase = self._binding.digest,self._binding._phase
            self._directory,self._namespace = canonical_state_directory,transport._namespace
            self._execution_store,self._enabled = execution_store,execution_enabled
            self._original_store = original_enable_store
            self._clock = clock if clock is not None else lambda:int(time.time())
            self._lock = RLock()
            self._last_clock: int | None = None
            self._clock_failed,self._started = False,False
            self._requester,self._transport_digest = allowed_requester_digest,allowed_transport_digest
            self._authority = _LabAutoAuthority(authority_key,self._binding,self._phase,{
                "environment_ref":environment_ref,"scope_ref":scope_ref,"audience_ref":audience_ref,
                "requester_digest":allowed_requester_digest,"transport_digest":allowed_transport_digest,
                "target_ref":"instruction-feature-"+transport._baseline._serial,
                "state_namespace_digest":transport._namespace,"baseline_digest":transport._baseline._state,
            },self._now)
            self._preview: _Preview | None = None
            self._restore_checkpoint: tuple[int, str] | None = None
        except Exception:
            raise InstructionFeatureLiveWorkflowError(_UNAVAILABLE) from None

    @property
    def phase(self) -> str:
        return self._phase

    def _now(self) -> int:
        with self._lock:
            try:
                now = self._clock()
                if (self._clock_failed or type(now) is not int or now<0
                        or self._last_clock is not None and now<self._last_clock):
                    raise ValueError
            except Exception:
                self._clock_failed = True
                raise InstructionFeatureLiveWorkflowError(_UNAVAILABLE) from None
            self._last_clock = now
            return now

    def _identity(self, requester: str, transport: str) -> None:
        require_digest(requester,"requester_digest")
        require_digest(transport,"transport_digest")
        if (not hmac.compare_digest(requester,self._requester)
                or not hmac.compare_digest(transport,self._transport_digest)
                or self._binding.digest!=self._parameters
                or self._transport._binding is not self._binding
                or self._transport._namespace!=self._namespace
                or self._transport._directory!=self._directory):
            raise InstructionFeatureLiveWorkflowError(_UNAVAILABLE)

    def _gate(self) -> None:
        if self._enabled is not True:
            raise InstructionFeatureLiveWorkflowError(_UNAVAILABLE)

    def _unconsumed(self) -> None:
        if self._execution_store.claim_count == 0:
            return
        if (self._phase != "restore" or self._restore_checkpoint is None
                or self._restore_checkpoint != self._prewrite_history()
                or self._authority._reconciliation != self._restore_checkpoint):
            raise InstructionFeatureLiveWorkflowError(_UNAVAILABLE)

    def _prewrite_history(self) -> tuple[int, str]:
        self._execution_store.verify_ready()
        count = self._execution_store.claim_count
        events = self._execution_store.audit_events
        if (not 1 <= count <= 32 or len(events) != count
                or any(event.authorization != "current_read_unknown"
                       or event.outcome is not M4Outcome.RECONCILIATION_REQUIRED
                       or event.verification is not M4Verification.UNKNOWN
                       or event.compensation is not M4Compensation.NOT_REQUESTED
                       for event in events)):
            raise ValueError
        digest = canonical_digest({"store": self._store_binding(self._execution_store),
            "namespace": self._namespace, "count": count,
            "events": [[event.ordinal, event.authorization, event.outcome.value,
                        event.verification.value, event.compensation.value,
                        event.digest_reference] for event in events]})
        return count, digest

    def reconcile_restore(self, *, requester_digest: str,
                          transport_digest: str) -> dict[str, object]:
        """Observe an unapplied pre-write read failure without reopening execution."""
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                if self._phase != "restore":
                    raise ValueError
                with self._transport.operation_lock():
                    self._original_m4()
                    # A dispatch/postcondition failure or unfinished reservation is
                    # insufficient evidence that the mutation never started.
                    count, _ = self._prewrite_history()
                    # The transport verifies the original enable proof, absence
                    # of every restore native record, and the complete precondition.
                    current = self._transport.inspect_precondition()
                    if current._state != self._binding._current:
                        raise ValueError
                    observed = self._now()
                return {"contract": RESTORE_RECONCILIATION_CONTRACT,
                        "phase": "restore", "outcome": "not-applied-observed",
                        "observed_at": observed, "expires_at": observed + _TTL,
                        "complete_enabled_precondition_verified": True,
                        "original_enable_native_and_m4_verified": True,
                        "native_restore_records_absent": True,
                        "retained_prewrite_claim_count": count,
                        "new_plan_and_authorization_required": True,
                        "execution_authorized": False, "device_write_executed": False}
        except Exception:
            raise InstructionFeatureLiveWorkflowError(_UNAVAILABLE) from None

    def preview_reconciled_restore(self, *, requester_digest: str,
                                   transport_digest: str) -> dict[str, object]:
        """Issue a fresh plan after a new complete read-only reconciliation."""
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                if self._phase != "restore":
                    raise ValueError
                created = self._now()
                with self._transport.operation_lock():
                    self._original_m4()
                    checkpoint = self._prewrite_history()
                    current = self._transport.inspect_precondition()
                    if (current._state != self._binding._current
                            or checkpoint != self._prewrite_history()):
                        raise ValueError
                    self._restore_checkpoint = checkpoint
                    self._authority._reconciliation = checkpoint
                    return self._new_preview(current._state, created)
        except Exception:
            raise InstructionFeatureLiveWorkflowError(_UNAVAILABLE) from None

    @staticmethod
    def _store_binding(store: PersistentM4ExecutionStateStore) -> str:
        return canonical_digest({"database":str(store._path),"key_file":str(store._key_path),
                                 "key_digest":hashlib.sha256(store._key).hexdigest()})

    def _verify_m4_proof(self, proof: dict[str,object], store: PersistentM4ExecutionStateStore) -> None:
        if set(proof)!={"store","plan","plan_ref","requester","idempotency","authorization","context"}:
            raise ValueError
        if proof["store"]!=self._store_binding(store):
            raise ValueError
        if any(type(value) is not str for value in proof.values()):
            raise ValueError
        strings = {key:cast(str,value) for key,value in proof.items()}
        require_ref(strings["plan_ref"],"plan_ref")
        for key in set(proof)-{"plan_ref"}:
            require_digest(strings[key],"proof_digest")
        native = self._transport._claim("enable")
        if native["plan"]!=proof["plan"] or native["authorization"]!=proof["authorization"]:
            raise ValueError
        expected_context = canonical_digest({"authorization_digest":proof["authorization"],
                                            "plan_digest":proof["plan"],"revision":1})
        if expected_context!=proof["context"]:
            raise ValueError
        claim = store.inspect_claim(plan_ref=strings["plan_ref"],requester_digest=strings["requester"],
            idempotency_digest=strings["idempotency"],context_digest=strings["context"],
            authorization_digest=strings["authorization"])
        if (claim.state is not M4ClaimState.REPLAY or claim.result is None
                or claim.result.outcome is not M4Outcome.SUCCEEDED
                or claim.result.verification is not M4Verification.VERIFIED):
            raise ValueError
        self._transport._original_enable()

    def _original_m4(self) -> None:
        if self._phase=="restore":
            if self._original_store is None:
                raise ValueError
            self._verify_m4_proof(self._transport._read("enable.m4.json"),self._original_store)

    def _seal_m4_enable(self, issued: _Issued) -> None:
        plan,auth = issued.plan,issued.authorization
        proof: dict[str,object] = {"store":self._store_binding(self._execution_store),
            "plan":plan.plan_digest,"plan_ref":plan.plan_ref,"requester":plan.requester_digest,
            "idempotency":plan.idempotency_digest,"authorization":auth.authorization_digest,
            "context":canonical_digest({"authorization_digest":auth.authorization_digest,
                                        "plan_digest":plan.plan_digest,"revision":plan.revision})}
        self._verify_m4_proof(proof,self._execution_store)
        if self._transport._exists("enable.m4.json"):
            if self._transport._read("enable.m4.json")!=proof:
                raise ValueError
        else:
            self._transport._write_once("enable.m4.json",proof)

    def preview(self, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest)
                if self._execution_store.claim_count != 0:
                    raise ValueError
                self._unconsumed()
                created = self._now()
                with self._transport.operation_lock():
                    self._unconsumed()
                    self._original_m4()
                    current = self._transport.inspect_precondition()
                    return self._new_preview(current._state, created)
        except Exception:
            raise InstructionFeatureLiveWorkflowError(_UNAVAILABLE) from None

    def _new_preview(self, current: str, created: int) -> dict[str, object]:
        preview = self._authority.preview(current,self._binding._expected,created)
        self._authority.check_preview(preview,self._now())
        self._preview,self._started = preview,False
        self._authority._preview = self._authority._issued = None
        restoring = self._phase=="restore"
        return {"contract":CONTRACT,"phase":self._phase,"policy_mode":"lab_auto",
                    "preview_ref":preview.preview_ref,"expires_at":preview.expires_at,
                    "Current State":{"instruction_enabled":restoring,"complete_setting_verified":True,
                        "original_enable_ack_and_readback_verified":restoring},
                    "Proposed Changes":{"operation":self._phase+"_instruction_feature",
                        "shared_setting_change":True,"other_setting_fields_preserved":True},
                    "Expected State":{"instruction_enabled":not restoring,
                        "complete_setting_verified":True,"original_disabled_state_restored":restoring},
                    "device_write_executed":False}

    def authorize(self, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest)
                self._gate()
                require_ref(preview_ref,"preview_ref")
                preview = self._preview
                if preview is None or not hmac.compare_digest(preview_ref,preview.preview_ref):
                    raise ValueError
                self._authority.check_preview(preview,self._now())
                self._unconsumed()
                with self._transport.operation_lock():
                    self._unconsumed()
                    self._original_m4()
                    if self._transport.inspect_precondition()._state!=preview.current_digest:
                        raise ValueError
                    issued = self._authority.issue(preview)
                return {"contract":CONTRACT,"phase":self._phase,"policy_mode":"lab_auto",
                    "authorization_ref":issued.authorization.authorization_ref,"expires_at":preview.expires_at}
        except Exception:
            raise InstructionFeatureLiveWorkflowError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest)
                self._gate()
                require_ref(authorization_ref,"authorization_ref")
                issued = self._authority.resolve(authorization_ref)
                if not self._started:
                    self._unconsumed()
                with self._transport.operation_lock():
                    if not self._started:
                        self._unconsumed()
                    self._execution_store.verify_ready()
                    self._started = True
                    result = M4ExecutionKernel(_Adapter(self,issued),self._authority,
                        self._execution_store,clock=self._now).execute(issued.plan,issued.authorization)
                    if (self._phase=="enable" and result.outcome is M4Outcome.SUCCEEDED
                            and result.verification is M4Verification.VERIFIED):
                        self._seal_m4_enable(issued)
                return {"contract":CONTRACT,"phase":self._phase,**result.as_dict()}
        except Exception:
            raise InstructionFeatureLiveWorkflowError(_UNAVAILABLE) from None
