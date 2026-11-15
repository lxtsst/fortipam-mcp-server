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
import logging
from pathlib import Path
import secrets
from threading import RLock
import time
from typing import cast

from v4_planning import (
    M4AdapterAmbiguous, M4AdapterDenied, M4AuthorizationDenied,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, canonical_digest,
    M4ClaimState, M4Outcome, M4Verification,
)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .instruction_quota_contract import InstructionQuotaTransition
from .instruction_quota_http_transport import (
    CONTRACT, FortiPamInstructionQuotaHttpTransport, InstructionQuotaTransportError,
)
from .m4_execution_store import PersistentM4ExecutionStateStore

ACTION_VERSION = "1.0.0"
_TTL = 60
_DOMAIN = b"fortipam-instruction-quota-lab-auto-v1\x00"
_UNAVAILABLE = "The private Instruction quota workflow is unavailable."
_LOGGER = logging.getLogger(__name__)
_FAILURE_STAGES = frozenset({"boundary", "initialization", "lock", "authorization",
    "connect", "precondition", "claim", "put", "ack_validation", "ack_persistence",
    "postcondition", "cleanup"})


class InstructionQuotaLiveWorkflowError(RuntimeError):
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
    __slots__ = ("_key", "_binding", "_parameters", "_namespace", "_phase", "_clock", "_preview", "_issued")

    def __init__(self, key: bytes, binding: InstructionQuotaTransition, phase: str,
                 namespace: dict[str, str], clock: Callable[[], int]) -> None:
        self._key, self._binding, self._phase = key, binding, phase
        self._parameters, self._namespace, self._clock = binding.digest, namespace, clock
        self._preview: _Preview | None = None
        self._issued: _Issued | None = None

    def _mac(self, purpose: str, content: Mapping[str, object]) -> str:
        encoded = json.dumps(content, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + purpose.encode("ascii") + b"\x00" + encoded,
                        hashlib.sha256).hexdigest()

    def _context(self, nonce: str, current: str, expected: str, created: int, expires: int) -> dict[str, object]:
        context: dict[str, object] = {**self._namespace, "contract": CONTRACT, "phase": self._phase,
            "action_id": "instruction-quota-" + self._phase, "action_version": ACTION_VERSION,
            "authority_ref": "fortipam-mcp-lab-auto-instruction-quota-" + self._phase,
            "policy_mode": "lab_auto", "preservation_mode": "complete-setting-quota-usage-original-ack-v1",
            "parameters_digest": self._parameters, "nonce": nonce,
            "current_digest": current, "expected_digest": expected,
            "created_at": created, "expires_at": expires}
        return context

    def preview(self, current: str, expected: str, created: int) -> _Preview:
        nonce, expires = secrets.token_hex(24), created + _TTL
        context = self._context(nonce, current, expected, created, expires)
        return _Preview(nonce, current, expected, created, expires,
            "instruction-quota-preview-" + self._mac("preview-ref", context), self._mac("preview", context))

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
                                      "instruction-quota-preview-" + self._mac("preview-ref", context))):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        return context

    def _derive(self, preview: _Preview, now: int) -> _Issued:
        context = self.check_preview(preview, now)
        approval, confirmation = self._mac("lab-approval", context), self._mac("standing-intent", context)
        plan_ref = "instruction-quota-plan-" + self._mac("plan-ref", context)
        requester = self._namespace["requester_digest"]
        parameters_values: dict[str, object] = {"contract": CONTRACT, "phase": self._phase, "binding": self._parameters, "namespace": self._namespace}
        parameters = canonical_digest(parameters_values)
        revision = int(cast(int, context.get("revision", 1)))
        version = cast(str, context["action_version"])
        adapter = "fortipam-700-build29-instruction-quota-" + self._phase + "-v1"
        plan_values = {
            "plan_ref": plan_ref, "revision": revision, "action_id": "instruction-quota-" + self._phase,
            "action_version": version, "adapter_ref": adapter,
            "target_ref": self._namespace["target_ref"], "requester_digest": requester,
            "summary_digest": self._mac("summary", context), "confirmation_digest": confirmation,
            "approval_digest": approval, "parameters_digest": parameters,
            "expected_current_digest": preview.current_digest, "expected_state_digest": preview.expected_digest,
            "idempotency_digest": self._mac("idempotency", context), "expires_at": preview.expires_at,
            "compensation_ref": None,
        }
        plan = M4ExecutionPlan(plan_ref, revision, "instruction-quota-" + self._phase, version,
            str(plan_values["adapter_ref"]), self._namespace["target_ref"], requester,
            str(plan_values["summary_digest"]), confirmation, approval, parameters,
            preview.current_digest, preview.expected_digest, str(plan_values["idempotency_digest"]),
            preview.expires_at, None, canonical_digest(plan_values))
        signed = {"plan_digest": plan.plan_digest, **context}
        auth_ref = "instruction-quota-auth-" + self._mac("authorization-ref", signed)
        confirmation_ref = "instruction-quota-intent-" + self._mac("intent-ref", signed)
        approval_ref = "instruction-quota-approval-" + self._mac("approval-ref", signed)
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
    def __init__(self, workflow: InstructionQuotaLiveWorkflow, issued: _Issued) -> None:
        self._workflow, self._issued = workflow, issued

    def _log_failure(self, operation: str, error: Exception) -> None:
        stage = error.stage if type(error) is InstructionQuotaTransportError else None
        stage = stage if type(stage) is str and stage in _FAILURE_STAGES else "unavailable"
        phase: str = self._workflow._phase
        phase = phase if phase in {"allocate", "restore"} else "unavailable"
        operation = operation if operation in {"current_read", "dispatch", "postcondition_read"} else "unavailable"
        # Fixed categories only: never exception text, identifiers, bodies or traceback.
        try:
            _LOGGER.warning("Instruction quota adapter failure: phase=%s operation=%s stage=%s",
                            phase, operation, stage)
        except Exception:
            # A log-handler failure must not interrupt the durable UNKNOWN transition.
            pass

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
        except Exception as error:
            self._log_failure("current_read", error)
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        self._check(plan)
        try:
            self._workflow._transport.dispatch(expected_current_digest=plan.expected_current_digest,
                plan_digest=plan.plan_digest,
                authorization_digest=self._issued.authorization.authorization_digest,
                expires_at=plan.expires_at, before_send=lambda:self._check(plan))
        except Exception as error:
            self._log_failure("dispatch", error)
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self._check(plan)
        try:
            return self._workflow._transport.inspect_postcondition()
        except Exception as error:
            self._log_failure("postcondition_read", error)
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None


class InstructionQuotaLiveWorkflow(_OpaqueC3Object):
    """One admitted phase with a fixed shared object and independent M4 authority."""

    __slots__ = ("_transport", "_binding", "_parameters", "_phase", "_namespace",
                 "_execution_store", "_enabled", "_clock", "_lock", "_last_clock",
                 "_clock_failed", "_requester", "_transport_digest", "_authority",
                 "_preview", "_started", "_directory", "_original_store")

    def __init__(self, transport: FortiPamInstructionQuotaHttpTransport, *,
                 canonical_state_directory: Path, execution_store: PersistentM4ExecutionStateStore,
                 authority_key: bytes, environment_ref: str, scope_ref: str, audience_ref: str,
                 allowed_requester_digest: str, allowed_transport_digest: str,
                 execution_enabled: bool = False, clock: Callable[[], int] | None = None,
                 original_allocate_store: PersistentM4ExecutionStateStore | None = None) -> None:
        try:
            if (type(transport) is not FortiPamInstructionQuotaHttpTransport
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or type(authority_key) is not bytes or not 32<=len(authority_key)<=4096
                    or hmac.compare_digest(authority_key,transport._key)
                    or type(execution_enabled) is not bool
                    or clock is not None and not callable(clock)
                    or not isinstance(canonical_state_directory,Path)
                    or not canonical_state_directory.is_absolute()
                    or canonical_state_directory.resolve(strict=True)!=canonical_state_directory
                    or canonical_state_directory!=transport._directory
                    or canonical_state_directory.name!="instruction-quota-"+transport._baseline._serial
                    or transport._phase=="allocate" and original_allocate_store is not None
                    or transport._phase=="restore" and (type(original_allocate_store) is not PersistentM4ExecutionStateStore
                        or original_allocate_store._path==execution_store._path)):
                raise ValueError
            for ref in (environment_ref,scope_ref,audience_ref):
                require_ref(ref,"namespace_ref")
            for digest in (allowed_requester_digest,allowed_transport_digest):
                require_digest(digest,"identity_digest")
            self._transport, self._binding = transport,transport._binding
            self._parameters,self._phase = self._binding.digest,self._binding._phase
            self._directory,self._namespace = canonical_state_directory,transport._namespace
            self._execution_store,self._enabled = execution_store,execution_enabled
            self._original_store = original_allocate_store
            self._clock = clock if clock is not None else lambda:int(time.time())
            self._lock = RLock()
            self._last_clock: int | None = None
            self._clock_failed,self._started = False,False
            self._requester,self._transport_digest = allowed_requester_digest,allowed_transport_digest
            self._authority = _LabAutoAuthority(authority_key,self._binding,self._phase,{
                "environment_ref":environment_ref,"scope_ref":scope_ref,"audience_ref":audience_ref,
                "requester_digest":allowed_requester_digest,"transport_digest":allowed_transport_digest,
                "target_ref":"instruction-quota-"+transport._baseline._serial,
                "state_namespace_digest":transport._namespace,"baseline_digest":transport._baseline._state,
            },self._now)
            self._preview: _Preview | None = None
        except Exception:
            raise InstructionQuotaLiveWorkflowError(_UNAVAILABLE) from None

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
                raise InstructionQuotaLiveWorkflowError(_UNAVAILABLE) from None
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
            raise InstructionQuotaLiveWorkflowError(_UNAVAILABLE)

    def _gate(self) -> None:
        if self._enabled is not True:
            raise InstructionQuotaLiveWorkflowError(_UNAVAILABLE)

    def _unconsumed(self) -> None:
        if self._execution_store.claim_count != 0:
            raise InstructionQuotaLiveWorkflowError(_UNAVAILABLE)

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
        native = self._transport._claim("allocate")
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
        self._transport._original_allocate()

    def _original_m4(self) -> None:
        if self._phase=="restore":
            if self._original_store is None:
                raise ValueError
            self._verify_m4_proof(self._transport._read("allocate.m4.json"),self._original_store)

    def _seal_m4_allocate(self, issued: _Issued) -> None:
        plan,auth = issued.plan,issued.authorization
        proof: dict[str,object] = {"store":self._store_binding(self._execution_store),
            "plan":plan.plan_digest,"plan_ref":plan.plan_ref,"requester":plan.requester_digest,
            "idempotency":plan.idempotency_digest,"authorization":auth.authorization_digest,
            "context":canonical_digest({"authorization_digest":auth.authorization_digest,
                                        "plan_digest":plan.plan_digest,"revision":plan.revision})}
        self._verify_m4_proof(proof,self._execution_store)
        if self._transport._exists("allocate.m4.json"):
            if self._transport._read("allocate.m4.json")!=proof:
                raise ValueError
        else:
            self._transport._write_once("allocate.m4.json",proof)

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
            raise InstructionQuotaLiveWorkflowError(_UNAVAILABLE) from None

    def _new_preview(self, current: str, created: int) -> dict[str, object]:
        preview = self._authority.preview(current,self._binding._expected,created)
        self._authority.check_preview(preview,self._now())
        self._preview,self._started = preview,False
        self._authority._preview = self._authority._issued = None
        restoring = self._phase=="restore"
        _, baseline_file, _, _ = self._transport._baseline._quotas
        return {"contract":CONTRACT,"phase":self._phase,"policy_mode":"lab_auto",
            "preview_ref":preview.preview_ref,"expires_at":preview.expires_at,
            "Current State":{"file_storage_quota_percent":baseline_file-1 if restoring else baseline_file,
                "instruction_quota_percent":1 if restoring else 0,
                "complete_setting_and_usage_verified":True,
                "original_allocate_native_and_m4_verified":restoring},
            "Proposed Changes":{"operation":self._phase+"_instruction_quota",
                "file_storage_delta_percent":1 if restoring else -1,
                "instruction_delta_percent":-1 if restoring else 1,
                "video_and_software_preserved":True,"other_setting_fields_preserved":True},
            "Expected State":{"file_storage_quota_percent":baseline_file if restoring else baseline_file-1,
                "instruction_quota_percent":0 if restoring else 1,
                "complete_setting_verified":True,"original_allocation_restored":restoring},
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
            raise InstructionQuotaLiveWorkflowError(_UNAVAILABLE) from None

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
                    if (self._phase=="allocate" and result.outcome is M4Outcome.SUCCEEDED
                            and result.verification is M4Verification.VERIFIED):
                        self._seal_m4_allocate(issued)
                return {"contract":CONTRACT,"phase":self._phase,**result.as_dict()}
        except Exception:
            raise InstructionQuotaLiveWorkflowError(_UNAVAILABLE) from None
