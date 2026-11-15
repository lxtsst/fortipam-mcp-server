"""Default-closed M4 workflows for fixed native-token LDAP update and restore.

The named lab policy derives a separate signed intent for each fixed phase.
Opaque password preservation stays in the private HTTP adapter; this workflow
neither resolves new bind material nor represents a C3 acquire/release event.
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
)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .ldap_server_contract import LdapServerCreateBinding
from .ldap_server_http_transport import _Connection
from .ldap_server_update_contract import CONTRACT, UPDATED_GROUP_FILTER
from .ldap_server_update_http_transport import FortiPamLdapServerUpdateHttpTransport, Phase
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig

ACTION_VERSION = "1.0.0"
_TTL = 60
_DOMAIN = b"fortipam-ldap-native-token-update-lab-auto-v1\x00"
_UNAVAILABLE = "The private LDAP update workflow is unavailable."


class LdapServerUpdateLiveWorkflowError(RuntimeError):
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

    def __init__(self, key: bytes, binding: LdapServerCreateBinding, phase: str,
                 namespace: dict[str, str], clock: Callable[[], int]) -> None:
        self._key, self._binding, self._phase = key, binding, phase
        self._parameters, self._namespace, self._clock = binding.parameters_digest, namespace, clock
        self._preview: _Preview | None = None
        self._issued: _Issued | None = None

    def _mac(self, purpose: str, content: Mapping[str, object]) -> str:
        encoded = json.dumps(content, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + purpose.encode("ascii") + b"\x00" + encoded,
                        hashlib.sha256).hexdigest()

    def _context(self, nonce: str, current: str, expected: str, created: int, expires: int) -> dict[str, object]:
        return {**self._namespace, "contract": CONTRACT, "phase": self._phase,
            "action_id": "ldap-server-" + self._phase, "action_version": ACTION_VERSION,
            "authority_ref": "fortipam-mcp-lab-auto-ldap-" + self._phase,
            "policy_mode": "lab_auto", "preservation_mode": "same-object-native-token-v1",
            "parameters_digest": self._parameters, "nonce": nonce,
            "current_digest": current, "expected_digest": expected,
            "created_at": created, "expires_at": expires}

    def preview(self, current: str, expected: str, created: int) -> _Preview:
        nonce, expires = secrets.token_hex(24), created + _TTL
        context = self._context(nonce, current, expected, created, expires)
        return _Preview(nonce, current, expected, created, expires,
            "ldap-change-preview-" + self._mac("preview-ref", context), self._mac("preview", context))

    def check_preview(self, preview: _Preview, now: int) -> dict[str, object]:
        if (type(preview) is not _Preview or type(now) is not int
            or type(preview.created_at) is not int or type(preview.expires_at) is not int
            or not preview.created_at <= now < preview.expires_at
            or preview.expires_at - preview.created_at != _TTL
            or self._binding.parameters_digest != self._parameters):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        for digest in (preview.current_digest, preview.expected_digest):
            require_digest(digest, "state_digest")
        context = self._context(preview.nonce, preview.current_digest, preview.expected_digest,
                                preview.created_at, preview.expires_at)
        if (not hmac.compare_digest(preview.signature, self._mac("preview", context))
            or not hmac.compare_digest(preview.preview_ref,
                                      "ldap-change-preview-" + self._mac("preview-ref", context))):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        return context

    def _derive(self, preview: _Preview, now: int) -> _Issued:
        context = self.check_preview(preview, now)
        approval, confirmation = self._mac("lab-approval", context), self._mac("standing-intent", context)
        plan_ref = "ldap-change-plan-" + self._mac("plan-ref", context)
        requester = self._namespace["requester_digest"]
        parameters = canonical_digest({"contract": CONTRACT, "phase": self._phase, "binding": self._parameters})
        plan_values = {
            "plan_ref": plan_ref, "revision": 1, "action_id": "ldap-server-" + self._phase,
            "action_version": ACTION_VERSION, "adapter_ref": "fortipam-700-build29-ldap-" + self._phase + "-native-token-v1",
            "target_ref": "ldap-server-" + self._phase, "requester_digest": requester,
            "summary_digest": self._mac("summary", context), "confirmation_digest": confirmation,
            "approval_digest": approval, "parameters_digest": parameters,
            "expected_current_digest": preview.current_digest, "expected_state_digest": preview.expected_digest,
            "idempotency_digest": self._mac("idempotency", context), "expires_at": preview.expires_at,
            "compensation_ref": None,
        }
        plan = M4ExecutionPlan(plan_ref, 1, "ldap-server-" + self._phase, ACTION_VERSION,
            str(plan_values["adapter_ref"]), "ldap-server-" + self._phase, requester,
            str(plan_values["summary_digest"]), confirmation, approval, parameters,
            preview.current_digest, preview.expected_digest, str(plan_values["idempotency_digest"]),
            preview.expires_at, None, canonical_digest(plan_values))
        signed = {"plan_digest": plan.plan_digest, **context}
        auth_ref = "ldap-change-auth-" + self._mac("authorization-ref", signed)
        confirmation_ref = "ldap-change-intent-" + self._mac("intent-ref", signed)
        approval_ref = "ldap-change-approval-" + self._mac("approval-ref", signed)
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
    def __init__(self, workflow: LdapServerUpdateLiveWorkflow, issued: _Issued) -> None:
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


class LdapServerUpdateLiveWorkflow(_OpaqueC3Object):
    """One owner-bound phase, with authenticated caller and durable M4 authority."""

    __slots__ = ("_binding", "_parameters", "_phase", "_execution_store", "_enabled", "_clock", "_lock",
                 "_last_clock", "_clock_failed", "_requester", "_transport_digest", "_authority",
                 "_transport", "_preview", "_started")
    _display_name = "LdapServerUpdateLiveWorkflow"

    def __init__(self, binding: LdapServerCreateBinding, config: SecretMetadataHttpTransportConfig, *,
                 expected_serial: str, creation_state_directory: Path, state_directory: Path, phase: str,
                 execution_store: PersistentM4ExecutionStateStore, authority_key: bytes,
                 environment_ref: str, scope_ref: str, audience_ref: str,
                 allowed_requester_digest: str, allowed_transport_digest: str, execution_enabled: bool = False,
                 clock: Callable[[], int] | None = None,
                 connection_factory: Callable[..., _Connection] | None = None) -> None:
        try:
            if (type(binding) is not LdapServerCreateBinding or type(config) is not SecretMetadataHttpTransportConfig
                or type(phase) is not str or phase not in {"update", "restore"}
                or type(execution_store) is not PersistentM4ExecutionStateStore
                or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                or type(execution_enabled) is not bool or clock is not None and not callable(clock)):
                raise ValueError
            for ref in (environment_ref, scope_ref, audience_ref):
                require_ref(ref, "namespace_ref")
            for digest in (allowed_requester_digest, allowed_transport_digest):
                require_digest(digest, "identity_digest")
            self._binding, self._parameters, self._phase = binding, binding.parameters_digest, phase
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
            self._transport = FortiPamLdapServerUpdateHttpTransport(config, binding,
                expected_serial=expected_serial, creation_state_directory=creation_state_directory,
                state_directory=state_directory, phase=cast(Phase, phase), execution_enabled=execution_enabled,
                clock=self._now, connection_factory=connection_factory)
            self._preview: _Preview | None = None
        except Exception:
            raise LdapServerUpdateLiveWorkflowError(_UNAVAILABLE) from None

    @property
    def phase(self) -> str:
        return self._phase

    def _now(self) -> int:
        with self._lock:
            try:
                now = self._clock()
                if (self._clock_failed or type(now) is not int or now < 0
                    or self._last_clock is not None and now < self._last_clock):
                    raise ValueError
            except Exception:
                self._clock_failed = True
                raise LdapServerUpdateLiveWorkflowError(_UNAVAILABLE) from None
            self._last_clock = now
            return now

    def _identity(self, requester: str, transport: str) -> None:
        require_digest(requester, "requester_digest")
        require_digest(transport, "transport_digest")
        if (not hmac.compare_digest(requester, self._requester)
            or not hmac.compare_digest(transport, self._transport_digest)
            or self._binding.parameters_digest != self._parameters):
            raise LdapServerUpdateLiveWorkflowError(_UNAVAILABLE)

    def _gate(self) -> None:
        if self._enabled is not True:
            raise LdapServerUpdateLiveWorkflowError(_UNAVAILABLE)

    def _unconsumed(self) -> None:
        if self._execution_store.claim_count != 0:
            raise LdapServerUpdateLiveWorkflowError(_UNAVAILABLE)

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
                restoring = self._phase == "restore"
                return {"contract": CONTRACT, "phase": self._phase, "policy_mode": "lab_auto",
                    "preview_ref": preview.preview_ref, "expires_at": preview.expires_at,
                    "Current State": {"original_creation_ownership_verified": True,
                        "zero_references_verified": True, "complete_bound_state_verified": True},
                    "Proposed Changes": {"operation": self._phase + "_ldap_server",
                        "field": "group-filter", "value": "" if restoring else UPDATED_GROUP_FILTER,
                        "same_object_native_password_token_preserved": True},
                    "Expected State": {"complete_bound_state_verified": True,
                        "original_state_restored": restoring, "stored_credential_path_verified": True},
                    "device_write_executed": False}
        except Exception:
            raise LdapServerUpdateLiveWorkflowError(_UNAVAILABLE) from None

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
                return {"contract": CONTRACT, "phase": self._phase, "policy_mode": "lab_auto",
                    "authorization_ref": issued.authorization.authorization_ref, "expires_at": preview.expires_at}
        except Exception:
            raise LdapServerUpdateLiveWorkflowError(_UNAVAILABLE) from None

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
                return {"contract": CONTRACT, "phase": self._phase, **result.as_dict()}
        except Exception:
            raise LdapServerUpdateLiveWorkflowError(_UNAVAILABLE) from None
