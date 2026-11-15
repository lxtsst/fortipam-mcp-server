"""Default-closed M4 workflows for fixed private profile creation and deletion.

Each fixed phase has independent signed lab intent and a durable M4 claim.
The original creation ownership and complete state stay in the private adapter.
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
    M4AdapterAmbiguous, M4AdapterDenied, M4AuthorizationDenied, M4ClaimState,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, canonical_digest,
)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .ldap_server_http_transport import _Connection
from .instruction_profile_contract import CONTRACT, InstructionProfileCreatePlan
from .instruction_profile_http_transport import FortiPamInstructionProfileHttpTransport, Phase
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig

ACTION_VERSION = "1.0.0"


def _content_mode(binding: InstructionProfileCreatePlan) -> str:
    return "plain-text" if binding.contract == CONTRACT else "rich-structure"


def _action_version(binding: InstructionProfileCreatePlan) -> str:
    return ACTION_VERSION if binding.contract == CONTRACT else "1.2.0"


def _content_revision(binding: InstructionProfileCreatePlan) -> str:
    return "v1" if binding.contract == CONTRACT else "v2"

_TTL = 60
_DOMAIN = b"fortipam-instruction-profile-lab-auto-v1\x00"
_UNAVAILABLE = "The private Instruction Profile workflow is unavailable."


class InstructionProfileLiveWorkflowError(RuntimeError):
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

    def __init__(self, key: bytes, binding: InstructionProfileCreatePlan, phase: str,
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
        return {**self._namespace, "contract": self._binding.contract, "phase": self._phase,
            "action_id": "instruction-profile-" + self._phase, "action_version": _action_version(self._binding),
            "authority_ref": "fortipam-mcp-lab-auto-instruction-profile-" + self._phase,
            "policy_mode": "lab_auto", "preservation_mode": _content_mode(self._binding) + "-owned-lifecycle-" + _content_revision(self._binding),
            "parameters_digest": self._parameters, "nonce": nonce,
            "current_digest": current, "expected_digest": expected,
            "created_at": created, "expires_at": expires}

    def preview(self, current: str, expected: str, created: int) -> _Preview:
        nonce, expires = secrets.token_hex(24), created + _TTL
        context = self._context(nonce, current, expected, created, expires)
        return _Preview(nonce, current, expected, created, expires,
            "instruction-profile-preview-" + self._mac("preview-ref", context), self._mac("preview", context))

    def check_preview(self, preview: _Preview, now: int) -> dict[str, object]:
        if (type(preview) is not _Preview or type(now) is not int
            or type(preview.created_at) is not int or type(preview.expires_at) is not int
            or not preview.created_at <= now < preview.expires_at
            or preview.expires_at - preview.created_at != _TTL
            or self._binding.digest != self._parameters):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        for digest in (preview.current_digest, preview.expected_digest):
            require_digest(digest, "state_digest")
        context = self._context(preview.nonce, preview.current_digest, preview.expected_digest,
                                preview.created_at, preview.expires_at)
        if (not hmac.compare_digest(preview.signature, self._mac("preview", context))
            or not hmac.compare_digest(preview.preview_ref,
                                      "instruction-profile-preview-" + self._mac("preview-ref", context))):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        return context

    def _derive(self, preview: _Preview, now: int) -> _Issued:
        context = self.check_preview(preview, now)
        approval, confirmation = self._mac("lab-approval", context), self._mac("standing-intent", context)
        plan_ref = "instruction-profile-plan-" + self._mac("plan-ref", context)
        requester = self._namespace["requester_digest"]
        parameters = canonical_digest({"contract": self._binding.contract, "phase": self._phase, "binding": self._parameters})
        plan_values = {
            "plan_ref": plan_ref, "revision": 1, "action_id": "instruction-profile-" + self._phase,
            "action_version": _action_version(self._binding), "adapter_ref": "fortipam-700-build29-instruction-profile-" + self._phase + "-" + _content_mode(self._binding) + "-" + _content_revision(self._binding),
            "target_ref": "instruction-profile-" + self._phase, "requester_digest": requester,
            "summary_digest": self._mac("summary", context), "confirmation_digest": confirmation,
            "approval_digest": approval, "parameters_digest": parameters,
            "expected_current_digest": preview.current_digest, "expected_state_digest": preview.expected_digest,
            "idempotency_digest": self._mac("idempotency", context), "expires_at": preview.expires_at,
            "compensation_ref": None,
        }
        plan = M4ExecutionPlan(plan_ref, 1, "instruction-profile-" + self._phase, _action_version(self._binding),
            str(plan_values["adapter_ref"]), "instruction-profile-" + self._phase, requester,
            str(plan_values["summary_digest"]), confirmation, approval, parameters,
            preview.current_digest, preview.expected_digest, str(plan_values["idempotency_digest"]),
            preview.expires_at, None, canonical_digest(plan_values))
        signed = {"plan_digest": plan.plan_digest, **context}
        auth_ref = "instruction-profile-auth-" + self._mac("authorization-ref", signed)
        confirmation_ref = "instruction-profile-intent-" + self._mac("intent-ref", signed)
        approval_ref = "instruction-profile-approval-" + self._mac("approval-ref", signed)
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
    def __init__(self, workflow: InstructionProfileLiveWorkflow, issued: _Issued) -> None:
        self._workflow, self._issued = workflow, issued

    def _check(self, plan: M4ExecutionPlan) -> None:
        try:
            self._workflow._gate()
            if plan is not self._issued.plan:
                raise ValueError
            self._workflow._authority.verify(plan, self._issued.authorization, now_epoch=self._workflow._now())
        except Exception:
            raise M4AdapterDenied(_UNAVAILABLE) from None

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self._check(plan)
        try:
            current = self._workflow._transport.inspect_current()
            if self._workflow._transport.expected_state_digest() != plan.expected_state_digest:
                raise ValueError
            return current.state_digest
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        self._check(plan)
        try:
            self._workflow._transport.dispatch(expected_current_digest=plan.expected_current_digest,
                plan_digest=plan.plan_digest, authorization_digest=self._issued.authorization.authorization_digest,
                expires_at=plan.expires_at, before_send=lambda: self._check(plan))
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self._check(plan)
        try:
            return self._workflow._transport.inspect_postcondition()
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None


class InstructionProfileLiveWorkflow(_OpaqueC3Object):
    """One owner-bound phase, with authenticated caller and durable M4 authority."""

    __slots__ = ("_binding", "_parameters", "_phase", "_execution_store", "_enabled", "_clock", "_lock",
                 "_last_clock", "_clock_failed", "_requester", "_transport_digest", "_authority",
                 "_transport", "_preview", "_started")
    _display_name = "InstructionProfileLiveWorkflow"

    def __init__(self, binding: InstructionProfileCreatePlan, config: SecretMetadataHttpTransportConfig, *,
                 serial_digest: str, schema_digest: str, state_directory: Path, phase: str,
                 execution_store: PersistentM4ExecutionStateStore, authority_key: bytes,
                 environment_ref: str, scope_ref: str, audience_ref: str,
                 allowed_requester_digest: str, allowed_transport_digest: str, execution_enabled: bool = False,
                 clock: Callable[[], int] | None = None,
                 connection_factory: Callable[..., _Connection] | None = None) -> None:
        try:
            if (type(binding) is not InstructionProfileCreatePlan or type(config) is not SecretMetadataHttpTransportConfig
                or type(phase) is not str or phase not in {"create", "delete"}
                or type(execution_store) is not PersistentM4ExecutionStateStore
                or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                or type(execution_enabled) is not bool or clock is not None and not callable(clock)):
                raise ValueError
            for ref in (environment_ref, scope_ref, audience_ref):
                require_ref(ref, "namespace_ref")
            for digest in (allowed_requester_digest, allowed_transport_digest):
                require_digest(digest, "identity_digest")
            self._binding, self._parameters, self._phase = binding, binding.digest, phase
            self._execution_store, self._enabled = execution_store, execution_enabled
            self._clock = clock if clock is not None else lambda: int(time.time())
            self._lock = RLock()
            self._last_clock: int | None = None
            self._clock_failed, self._started = False, False
            self._requester, self._transport_digest = allowed_requester_digest, allowed_transport_digest
            self._authority = _LabAutoAuthority(authority_key, binding, phase, {
                "environment_ref": environment_ref, "scope_ref": scope_ref, "audience_ref": audience_ref,
                "requester_digest": allowed_requester_digest, "transport_digest": allowed_transport_digest,
            }, self._now)
            self._transport = FortiPamInstructionProfileHttpTransport(config, binding,
                serial_digest=serial_digest, schema_digest=schema_digest, state_directory=state_directory, phase=cast(Phase, phase), execution_enabled=execution_enabled,
                clock=self._now, connection_factory=connection_factory)
            self._preview: _Preview | None = None
        except Exception:
            raise InstructionProfileLiveWorkflowError(_UNAVAILABLE) from None

    @property
    def phase(self) -> str:
        return self._phase

    def close(self) -> None:
        """Close both execution gates without discarding historical custody."""
        with self._lock:
            self._enabled = False
            self._transport.close()

    def check_original_creation(self, *, requester_digest: str, transport_digest: str) -> None:
        """Verify original native custody and signed successful M4, without HTTP."""
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                preview, issued = self._preview, self._authority._issued
                if (self._phase != "create" or self._transport._phase != "create"
                        or self._transport._binding is not self._binding
                        or preview is None or issued is None
                        or issued != self._authority._derive(preview, preview.created_at)):
                    raise ValueError
                claim = self._execution_store.inspect_claim(plan_ref=issued.plan.plan_ref,
                    requester_digest=issued.plan.requester_digest, idempotency_digest=issued.plan.idempotency_digest,
                    authorization_digest=issued.authorization.authorization_digest,
                    context_digest=canonical_digest({"authorization_digest": issued.authorization.authorization_digest,
                        "plan_digest": issued.plan.plan_digest, "revision": issued.plan.revision}))
                if (claim.state is not M4ClaimState.REPLAY or claim.result is None
                        or claim.result.as_dict() != {"outcome": "succeeded", "verification": "verified",
                            "compensation": "not_requested", "idempotent_replay": False}):
                    raise ValueError
                with self._transport.operation_lock():
                    self._transport._plan()
                    self._transport._anchors()
                    original = self._transport._read("create.claim.json")
                    if (original.get("plan_digest") != issued.plan.plan_digest
                            or original.get("authorization_digest") != issued.authorization.authorization_digest):
                        raise ValueError
        except Exception:
            raise InstructionProfileLiveWorkflowError(_UNAVAILABLE) from None

    def inspect_owned_reference_state(self, *, expected_reference_count: int,
            requester_digest: str, transport_digest: str) -> str:
        """Fresh fixed full read for association; it grants no reference/write right."""
        try:
            with self._lock:
                if type(expected_reference_count) is not int or expected_reference_count not in {0, 1}:
                    raise ValueError
                self.check_original_creation(requester_digest=requester_digest, transport_digest=transport_digest)
                with self._transport.operation_lock():
                    anchors = self._transport._anchors()
                    current = self._transport._snapshot(exists=True, expected_reference_count=expected_reference_count)
                    expected = {**self._transport._read("created.json")["record"], "q_ref": expected_reference_count}
                    if current != expected:
                        raise ValueError
                self.check_original_creation(requester_digest=requester_digest, transport_digest=transport_digest)
                return canonical_digest({"binding": self._parameters, "anchors": anchors,
                    "references": expected_reference_count})
        except Exception:
            raise InstructionProfileLiveWorkflowError(_UNAVAILABLE) from None

    def _now(self) -> int:
        with self._lock:
            try:
                now = self._clock()
                if (self._clock_failed or type(now) is not int or now < 0
                    or self._last_clock is not None and now < self._last_clock):
                    raise ValueError
            except Exception:
                self._clock_failed = True
                raise InstructionProfileLiveWorkflowError(_UNAVAILABLE) from None
            self._last_clock = now
            return now

    def _identity(self, requester: str, transport: str) -> None:
        require_digest(requester, "requester_digest")
        require_digest(transport, "transport_digest")
        if (not hmac.compare_digest(requester, self._requester)
            or not hmac.compare_digest(transport, self._transport_digest)
            or self._binding.digest != self._parameters):
            raise InstructionProfileLiveWorkflowError(_UNAVAILABLE)

    def _gate(self) -> None:
        if self._enabled is not True:
            raise InstructionProfileLiveWorkflowError(_UNAVAILABLE)

    def _unconsumed(self) -> None:
        if self._execution_store.claim_count != 0:
            raise InstructionProfileLiveWorkflowError(_UNAVAILABLE)

    def preview(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._unconsumed()
                created = self._now()
                with self._transport.operation_lock():
                    self._unconsumed()
                    current = self._transport.inspect_current()
                    expected = self._transport.expected_state_digest()
                    preview = self._authority.preview(current.state_digest, expected, created)
                    self._authority.check_preview(preview, self._now())
                self._preview, self._started = preview, False
                # A new preview invalidates any prior volatile authorization.
                self._authority._preview = self._authority._issued = None
                deleting = self._phase == "delete"
                return {"contract": self._binding.contract, "phase": self._phase, "policy_mode": "lab_auto",
                    "preview_ref": preview.preview_ref, "expires_at": preview.expires_at,
                    "Current State": {"bound_profile_absent": not deleting,
                        "original_creation_ownership_verified": deleting,
                        "complete_state_and_definitions_verified": True},
                    "Proposed Changes": {"operation": self._phase + "_" + _content_mode(self._binding).replace("-", "_") + "_instruction_profile",
                        "content_privately_bound": True, "resource_upload": False,
                        "secret_attachment": False, "feature_change": False},
                    "Expected State": {"owned_zero_reference_profile_verified": not deleting,
                        "original_creation_records_preserved": True, "bound_profile_absent": deleting},
                    "device_write_executed": False}
        except Exception:
            raise InstructionProfileLiveWorkflowError(_UNAVAILABLE) from None

    def authorize(self, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._gate()
                require_ref(preview_ref, "preview_ref")
                preview = self._preview
                if preview is None or not hmac.compare_digest(preview_ref, preview.preview_ref):
                    raise ValueError
                self._authority.check_preview(preview, self._now())
                self._unconsumed()
                with self._transport.operation_lock():
                    self._unconsumed()
                    if (self._transport.inspect_current().state_digest != preview.current_digest
                        or self._transport.expected_state_digest() != preview.expected_digest):
                        raise ValueError
                    issued = self._authority.issue(preview)
                return {"contract": self._binding.contract, "phase": self._phase, "policy_mode": "lab_auto",
                    "authorization_ref": issued.authorization.authorization_ref, "expires_at": preview.expires_at}
        except Exception:
            raise InstructionProfileLiveWorkflowError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                self._gate()
                require_ref(authorization_ref, "authorization_ref")
                issued = self._authority.resolve(authorization_ref)
                if not self._started:
                    self._unconsumed()
                with self._transport.operation_lock():
                    if not self._started:
                        self._unconsumed()
                    self._execution_store.verify_ready()
                    self._started = True
                    result = M4ExecutionKernel(_Adapter(self, issued), self._authority,
                        self._execution_store, clock=self._now).execute(issued.plan, issued.authorization)
                return {"contract": self._binding.contract, "phase": self._phase, **result.as_dict()}
        except Exception:
            raise InstructionProfileLiveWorkflowError(_UNAVAILABLE) from None
