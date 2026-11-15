"""Two fixed private lab-auto User actions with independent signed M4 authority.

Create retains one disabled Standard direct-RADIUS user. Remove has a separate
store/key/scope and joins the original create context/ACK before fresh recovery.
No credential provider, login, Tool registration or runtime startup is supplied.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
from pathlib import Path
import secrets
from threading import RLock
import time
from typing import Any, Literal, cast

from v4_planning import (
    M4AdapterAmbiguous, M4AdapterDenied, M4AuthorizationDenied, M4ClaimState,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, M4Outcome,
    M4Verification, M4Compensation, canonical_digest,
)
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .m4_execution_store import PersistentM4ExecutionStateStore
from .ldap_server_projection import _digest
from .radius_remote_user_contract import RadiusRemoteUserBinding
from .radius_remote_user_http_transport import FortiPamRadiusRemoteUserHttpTransport
from .radius_remote_user_owned_target import RadiusRemoteUserOwnedTarget
from .radius_server_pair_http_transport import _Connection
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig

_TTL = 60
_ERROR = "The private RADIUS Remote User workflow is unavailable."
_CREATE_CONTRACT = "fortipam-radius-remote-user-create-lab-auto-private-v1"
_REMOVE_CONTRACT = "fortipam-radius-remote-user-original-recovery-private-v1"
_TARGET = "radius-remote-user-privately-bound-row"


class RadiusRemoteUserWorkflowError(RuntimeError):
    """Value-free refusal; neither an authorization nor a product response."""


@dataclass(frozen=True, slots=True, repr=False)
class _Preview(_OpaqueC3Object):
    facts: tuple[str, ...]
    created_at: int
    expires_at: int
    nonce: str
    preview_ref: str
    signature: str


@dataclass(frozen=True, slots=True, repr=False)
class _Issued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


def _execution_context(plan: M4ExecutionPlan, auth: M4ExecutionAuthorization) -> str:
    return canonical_digest({"plan_digest": plan.plan_digest,
        "authorization_digest": auth.authorization_digest, "revision": plan.revision})


def _store_binding(store: PersistentM4ExecutionStateStore) -> dict[str, str]:
    return {"path": str(store._path), "key_path": str(store._key_path),
        "key_digest": hashlib.sha256(store._key).hexdigest()}


def _composition_payload(reader: FortiPamRadiusRemoteUserHttpTransport,
        stores: list[PersistentM4ExecutionStateStore], authority_key: bytes,
        original_key: bytes | None, contract: str) -> dict[str, Any]:
    """Pure metadata projection shared with preparation-only namespace checks."""
    content = {"contract": contract, "parameters": reader._binding.parameters_digest,
        "origin": reader._config.base_url, "serial": reader._serial, "ca": reader._config.ca_file,
        "actor": hashlib.sha256(reader._config.bearer_token.encode()).hexdigest(),
        "journal": str(reader._directory), "journal_identity": list(reader._directory_identity),
        "stores": [_store_binding(store) for store in stores], "authority_key": hashlib.sha256(authority_key).hexdigest(),
        "original_authority_key": hashlib.sha256(original_key).hexdigest() if original_key is not None else None}
    if reader._target._handoff_digest is not None:
        content["target_handoff_digest"] = reader._target._handoff_digest
    return content


def _create_expected(parameters: str, current: str) -> str:
    return canonical_digest({"contract": _CREATE_CONTRACT, "parameters_digest": parameters,
        "current_digest": current, "state": "disabled-standard-owned-verified"})


def _summary_values(operation: str, contract: str, requester: str, p: _Preview) -> dict[str, object]:
    create = operation == "create"
    return {"contract": contract, "policy_mode": "lab_auto", "summary_revision": 1,
        "preview_ref": p.preview_ref, "expires_at": p.expires_at,
        "requester_digest": requester,
        "environment": "privately_bound_disposable_lab",
        "Current State": {"fresh_source_and_ownership_verified": True, "observed_at": p.created_at,
            "bound_user_absent": create, "original_user_ack_and_context_required": not create},
        "Proposed Changes": {"operation": "create_disabled_remote_user" if create else "remove_original_owned_remote_user",
            "scope": "one_privately_bound_remote_user", "material_access": False,
            "status": "disable", "profile": "Standard", "wildcard": False, "group_association": False},
        "Expected State": {"original_ack_and_full_state_required": True,
            "owned_user_retained": create, "dual_absence_required": not create,
            "user_authentication_qualified": False, "automatic_failover_qualified": False},
        "facts": {"source": "fixed_build29_cmdb_projection", "freshness_seconds": _TTL},
        "authorization_and_approval": {"mode": "standing_owner_lab_authority", "active_m4_required": True,
            "independent_human_approval": False},
        "risk_and_effects": {"class": "C3", "effect": "one_disabled_identity_row" if create else "remove_one_original_owned_identity_row"},
        "dependencies": ["original_owned_radius_pair"] if create else ["original_user_ack_and_signed_context", "original_create_m4_store"],
        "assumptions": ["owner_authorized_disposable_lab_scope"],
        "unresolved_gaps": ["user_enable", "user_authentication", "automatic_failover", "group_mapping", "version_1_9_1"],
        "compensation_and_stop": {"recovery": "separate_original_ack_and_context_m4",
            "uncertain_result": "retain_claims_and_reconcile_without_replay"}, "device_write_executed": False}


def _mac_value(key: bytes, contract: str, purpose: str, content: object) -> str:
    wire = json.dumps(content, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hmac.new(key, (contract + "\x00" + purpose + "\x00").encode() + wire, hashlib.sha256).hexdigest()


def _derive_issued(operation: str, namespace: dict[str, Any], parameters: str, key: bytes,
        p: _Preview) -> _Issued:
    contract = _CREATE_CONTRACT if operation == "create" else _REMOVE_CONTRACT
    action_id = "radius-remote-user-create" if operation == "create" else "radius-remote-user-owned-recover"
    adapter_ref = "fortipam-700-build29-" + action_id + "-v1"
    def mac(purpose: str, content: object) -> str:
        return _mac_value(key, contract, purpose, content)
    current = p.facts[0] if operation == "create" else canonical_digest({"contract": contract,
        "facts": list(p.facts), "parameters": parameters})
    expected = _create_expected(parameters, p.facts[0]) if operation == "create" else canonical_digest({
        "contract": contract, "owned_digest": p.facts[0], "parameters_digest": parameters, "state": "dual-absence-verified"})
    context = {**namespace, "facts": list(p.facts), "created_at": p.created_at, "expires_at": p.expires_at, "nonce": p.nonce}
    confirmation, approval = mac("standing-intent", context), mac("lab-policy", context)
    values: dict[str, Any] = dict(plan_ref="radius-user-plan-" + mac("plan-ref", context),
        revision=1, action_id=action_id, action_version="1.0.0", adapter_ref=adapter_ref,
        target_ref=_TARGET, requester_digest=namespace["requester_digest"],
        summary_digest=canonical_digest(_summary_values(operation, contract, namespace["requester_digest"], p)), confirmation_digest=confirmation, approval_digest=approval,
        parameters_digest=parameters, expected_current_digest=current,
        expected_state_digest=expected, idempotency_digest=mac("idempotency", context),
        expires_at=p.expires_at, compensation_ref=None)
    plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
    signed = {**context, "plan_digest": plan.plan_digest}
    auth: dict[str, Any] = dict(authorization_ref="radius-user-auth-" + mac("authorization", signed),
        plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
        confirmation_ref="radius-user-intent-" + mac("intent-ref", signed),
        confirmation_digest=confirmation, approval_ref="radius-user-policy-" + mac("policy-ref", signed),
        approval_digest=approval, approver_digest=mac("policy-authority", namespace),
        issued_at=p.created_at, expires_at=p.expires_at, one_time=True, execution_authorized=True)
    return _Issued(plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth)))



class _Adapter:
    def __init__(self, workflow: RadiusRemoteUserLiveWorkflow) -> None:
        self._workflow = workflow

    def read_current(self, plan: M4ExecutionPlan) -> str:
        w = self._workflow
        w._check_plan(plan)
        try:
            if w._operation == "create": w._check_retained_authority()
            current = w._current_digest(w._facts())
            if w._operation == "create": w._check_retained_authority()
            return current
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        w = self._workflow
        w._check_plan(plan)
        try:
            issued = w._issued
            if issued is None:
                raise ValueError
            _require_m4_dispatch_ownership(plan, issued.authorization, w._store)
            if w._operation == "create":
                w._check_retained_authority()
                if w._transport.create_and_verify() != "verified_created":
                    raise ValueError
            elif not w._transport.delete_owned():
                raise ValueError
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        w = self._workflow
        w._check_plan(plan)
        try:
            if w._operation == "create":
                w._reader.inspect_recovery()
                w._check_current_create_context()
            else:
                if not w._reader.inspect_deleted():
                    raise ValueError
                w._original_provenance()
            return w._expected_digest()
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None


class RadiusRemoteUserLiveWorkflow(_OpaqueC3Object):
    """Owner-only fixed create/remove instances; each keeps its original M4."""

    _operation: Literal["create", "remove"]
    _binding: RadiusRemoteUserBinding
    _target: RadiusRemoteUserOwnedTarget
    _parameters: str
    _key: bytes
    _store: PersistentM4ExecutionStateStore
    _original_store: PersistentM4ExecutionStateStore | None
    _original_key: bytes | None
    _enabled: bool
    _initial_enabled: bool
    _closed: bool
    _clock: Callable[[], int]
    _clock_pin: Callable[[], int]
    _composition: str
    _namespace_pin: str
    _lock: RLock
    _clock_failed: bool
    _started: bool
    _reader: FortiPamRadiusRemoteUserHttpTransport
    _transport: FortiPamRadiusRemoteUserHttpTransport

    def __init__(self, binding: RadiusRemoteUserBinding, config: SecretMetadataHttpTransportConfig, *,
            target: RadiusRemoteUserOwnedTarget, state_directory: Path,
            execution_store: PersistentM4ExecutionStateStore, authority_key: bytes,
            environment_ref: str, scope_ref: str, audience_ref: str,
            allowed_requester_digest: str, allowed_transport_digest: str,
            operation: Literal["create", "remove"] = "create",
            original_create_store: PersistentM4ExecutionStateStore | None = None,
            original_create_authority_key: bytes | None = None,
            execution_enabled: bool = False, clock: Callable[[], int] | None = None,
            existing_only: bool = False,
            connection_factory: Callable[..., _Connection] | None = None) -> None:
        try:
            if (type(binding) is not RadiusRemoteUserBinding or type(target) is not RadiusRemoteUserOwnedTarget
                    or type(config) is not SecretMetadataHttpTransportConfig
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or type(operation) is not str or operation not in {"create", "remove"}
                    or type(execution_enabled) is not bool or clock is not None and not callable(clock)
                    or type(existing_only) is not bool or existing_only and operation != "remove"
                    or operation == "remove" and type(original_create_store) is not PersistentM4ExecutionStateStore
                    or operation == "remove" and (type(original_create_authority_key) is not bytes
                        or not 32 <= len(original_create_authority_key) <= 4096)
                    or operation == "create" and (original_create_store is not None or original_create_authority_key is not None)):
                raise ValueError
            for value in (environment_ref, scope_ref, audience_ref): require_ref(value, "namespace_ref")
            for value in (allowed_requester_digest, allowed_transport_digest): require_digest(value, "identity_digest")
            self._operation, self._binding, self._target = operation, binding, target
            self._parameters, self._key = binding.parameters_digest, authority_key
            self._store, self._original_store = execution_store, original_create_store
            self._original_key = original_create_authority_key
            self._enabled = self._initial_enabled = execution_enabled
            self._closed = False
            self._namespace: dict[str, Any] = {"contract": self.contract, "environment_ref": environment_ref,
                "scope_ref": scope_ref, "audience_ref": audience_ref,
                "requester_digest": allowed_requester_digest, "transport_digest": allowed_transport_digest,
                "policy_mode": "lab_auto", "parameters_digest": self._parameters}
            self._clock = clock or (lambda: int(time.time()))
            self._clock_pin = self._clock
            self._lock = RLock()
            self._last_clock: int | None = None
            self._clock_failed = False
            self._preview: _Preview | None = None
            self._issued: _Issued | None = None
            self._started = False
            self._reader = FortiPamRadiusRemoteUserHttpTransport(config, binding, target=target,
                state_directory=state_directory, clock=self._now, connection_factory=connection_factory)
            self._transport = self._reader
            self._composition = self._composition_digest()
            self._namespace["composition_digest"] = self._composition
            self._namespace_pin = canonical_digest(self._namespace)
            with self._reader._locked(existing=existing_only):
                self._reader._namespace(existing_only=existing_only)
                name = "user-" + operation + ".runtime.json"
                if not self._reader._exists(name):
                    if existing_only: raise ValueError
                    self._reader._write_once(name, self._namespace)
                if self._reader._read_state(name) != self._namespace:
                    raise ValueError
        except Exception:
            raise RadiusRemoteUserWorkflowError(_ERROR) from None

    @property
    def contract(self) -> str:
        return _CREATE_CONTRACT if self._operation == "create" else _REMOVE_CONTRACT

    @property
    def action_id(self) -> str:
        return "radius-remote-user-create" if self._operation == "create" else "radius-remote-user-owned-recover"

    @property
    def adapter_ref(self) -> str:
        return "fortipam-700-build29-" + self.action_id + "-v1"

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
                raise RadiusRemoteUserWorkflowError(_ERROR) from None

    def _common_namespace(self) -> str:
        return canonical_digest({k: self._namespace[k] for k in (
            "environment_ref", "audience_ref", "requester_digest", "transport_digest")})

    def _composition_digest(self) -> str:
        r, store = self._reader, self._store
        stores = [store, self._target._store]
        if self._original_store is not None: stores.append(self._original_store)
        paths = [path for s in stores for path in (s._path, s._key_path)]
        if (len(set(paths)) != len(paths) or len({s._key for s in stores}) != len(stores)
                or any(self._key == s._key for s in stores)
                or self._original_key is not None and (self._original_key == self._key
                    or any(self._original_key == s._key for s in stores))
                or any(r._directory == p or r._directory in p.parents for p in paths)
                or any(Path(str(p) + suffix) in set(paths) for p in paths for suffix in ("-wal", "-shm", "-journal"))
                or r._binding is not self._binding or r._target is not self._target):
            raise ValueError
        return canonical_digest(_composition_payload(r, stores, self._key, self._original_key, self.contract))

    def _gate(self, *, execute: bool = True) -> None:
        if (self._closed or execute and (not self._enabled or not self._initial_enabled)
                or self._clock is not self._clock_pin
                or self._composition_digest() != self._composition
                or canonical_digest(self._namespace) != self._namespace_pin):
            raise RadiusRemoteUserWorkflowError(_ERROR)
        self._reader._check()
        for store in (self._store, self._original_store, self._target._store):
            if store is not None and not hmac.compare_digest(store._load_key(), store._key):
                raise RadiusRemoteUserWorkflowError(_ERROR)
        if (self._target._handoff_digest is not None and _digest(
                self._reader._read_state("radius-target.handoff.json")) != self._target._handoff_digest):
            raise RadiusRemoteUserWorkflowError(_ERROR)
        if self._reader._read_state("user-" + self._operation + ".runtime.json") != self._namespace:
            raise RadiusRemoteUserWorkflowError(_ERROR)
        if self._issued is not None:
            t = self._transport
            t._check()
            callback = t._authorize_create if self._operation == "create" else t._authorize_recovery
            expected_func = RadiusRemoteUserLiveWorkflow._authorize_create if self._operation == "create" else RadiusRemoteUserLiveWorkflow._authorize_remove
            if (t._config is not self._reader._config or t._directory != self._reader._directory
                    or t._target is not self._target or t._factory is not self._reader._factory
                    or t._execution_enabled != (self._operation == "create")
                    or t._recovery_enabled != (self._operation == "remove")
                    or getattr(callback, "__self__", None) is not self
                    or getattr(callback, "__func__", None) is not expected_func):
                raise RadiusRemoteUserWorkflowError(_ERROR)
            if self._operation == "create" and (t._expected != self._issued.plan.expected_current_digest
                    or t._execution_context != _execution_context(self._issued.plan, self._issued.authorization)):
                raise RadiusRemoteUserWorkflowError(_ERROR)

    def _identity(self, requester: str, transport: str) -> None:
        require_digest(requester, "requester_digest"); require_digest(transport, "transport_digest")
        if (not hmac.compare_digest(requester, self._namespace["requester_digest"])
                or not hmac.compare_digest(transport, self._namespace["transport_digest"])):
            raise RadiusRemoteUserWorkflowError(_ERROR)

    def _unconsumed(self) -> None:
        self._store.verify_ready()
        if self._store.claim_count != 0:
            raise RadiusRemoteUserWorkflowError(_ERROR)
        if self._operation == "create" and self._reader._exists("user-create.authority.json"):
            raise RadiusRemoteUserWorkflowError(_ERROR)

    def _mac(self, purpose: str, content: object) -> str:
        return _mac_value(self._key, self.contract, purpose, content)

    def _context(self, p: _Preview) -> dict[str, Any]:
        return {**self._namespace, "facts": list(p.facts), "created_at": p.created_at,
            "expires_at": p.expires_at, "nonce": p.nonce}

    def _check_preview(self, p: _Preview, now: int) -> None:
        if (type(p) is not _Preview or type(now) is not int or type(p.created_at) is not int
                or type(p.expires_at) is not int or not p.created_at <= now < p.expires_at
                or p.expires_at - p.created_at != _TTL
                or len(p.facts) != (4 if self._operation == "create" else 3)):
            raise RadiusRemoteUserWorkflowError(_ERROR)
        for value in p.facts: require_digest(value, "private_fact")
        if (not hmac.compare_digest(p.signature, self._mac("preview", self._context(p)))
                or not hmac.compare_digest(p.preview_ref, "radius-user-preview-" + self._mac("preview-ref", self._context(p)))):
            raise RadiusRemoteUserWorkflowError(_ERROR)

    def _facts(self) -> tuple[str, ...]:
        if self._operation == "create":
            current = self._reader.inspect_create()
            return (current.state_digest, current.draft.source_defaults_digest,
                current.draft.request_digest, current.target_digest)
        provenance = self._original_provenance()
        owned, state = self._reader.inspect_recovery()
        if self._original_provenance() != provenance:
            raise ValueError
        return owned, state, provenance

    def _current_digest(self, facts: tuple[str, ...]) -> str:
        if self._operation == "create": return facts[0]
        return canonical_digest({"contract": self.contract, "facts": list(facts), "parameters": self._parameters})

    def _expected_digest(self) -> str:
        p = self._preview
        if p is None: raise RadiusRemoteUserWorkflowError(_ERROR)
        if self._operation == "create": return _create_expected(self._parameters, p.facts[0])
        return canonical_digest({"contract": self.contract, "owned_digest": p.facts[0],
            "parameters_digest": self._parameters, "state": "dual-absence-verified"})

    def _derive(self) -> _Issued:
        p = self._preview
        if p is None: raise RadiusRemoteUserWorkflowError(_ERROR)
        self._check_preview(p, self._now())
        return _derive_issued(self._operation, self._namespace, self._parameters, self._key, p)

    def _check_plan(self, plan: M4ExecutionPlan) -> None:
        self._gate()
        if self._issued is None or plan is not self._issued.plan or self._issued != self._derive():
            raise M4AdapterDenied(_ERROR)

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            self._check_plan(plan)
            if self._issued is None or authorization is not self._issued.authorization or self._preview is None:
                raise ValueError
            self._check_preview(self._preview, now_epoch)
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _active(self) -> bool:
        try:
            issued, p = self._issued, self._preview
            if not self._started or issued is None or p is None:
                raise ValueError
            plan, auth = issued.plan, issued.authorization
            _require_m4_dispatch_ownership(plan, auth, self._store)
            self.verify(plan, auth, now_epoch=self._now())
            claim = self._store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
                idempotency_digest=plan.idempotency_digest, context_digest=_execution_context(plan, auth),
                authorization_digest=auth.authorization_digest)
            if claim.state is not M4ClaimState.IN_PROGRESS:
                raise ValueError
            self._gate()
            return True
        except Exception:
            return False

    def _authorize_create(self, binding: RadiusRemoteUserBinding, current: str, request: str, target: str) -> bool:
        with self._lock:
            try:
                p = self._preview
                return (self._operation == "create" and binding is self._binding and p is not None
                    and current == p.facts[0] and request == p.facts[2] and target == p.facts[3] and self._active()
                    and self._reader._read_state("user-create.authority.json") == self._original_packet())
            except Exception:
                return False

    def _authorize_remove(self, binding: RadiusRemoteUserBinding, owned: str, state: str) -> bool:
        with self._lock:
            try:
                p = self._preview
                return (self._operation == "remove" and binding is self._binding and p is not None
                    and (owned, state) == p.facts[:2] and self._original_provenance(locked=True) == p.facts[2] and self._active())
            except Exception:
                return False

    def _original_packet(self) -> dict[str, object]:
        issued, p = self._issued, self._preview
        if self._operation != "create" or issued is None or p is None:
            raise ValueError
        return {"contract": _CREATE_CONTRACT, "parameters_digest": self._parameters,
            "common_namespace_digest": self._common_namespace(), "store": _store_binding(self._store),
            "authority_key_digest": hashlib.sha256(self._key).hexdigest(),
            "namespace": self._namespace, "preview": asdict(p) | {"facts": list(p.facts)},
            "plan": asdict(issued.plan), "authorization": asdict(issued.authorization)}

    def _retain_original_authority(self) -> None:
        if self._operation != "create" or not self._started or self._issued is None: raise ValueError
        self._gate(); self._check_plan(self._issued.plan)
        self._store.verify_ready()
        if self._store.claim_count != 0: raise ValueError
        packet = self._original_packet()
        with self._reader._locked(existing=True):
            self._reader._namespace(existing_only=True)
            if any(self._reader._exists(name) for name in ("create.claim.json", "create-ack.json", "created.json",
                    "delete.claim.json", "delete-ack.json", "deleted.json")): raise ValueError
            self._reader._write_once("user-create.authority.json", packet)
            if self._reader._read_state("user-create.authority.json") != packet:
                raise ValueError

    def _check_retained_authority(self) -> None:
        with self._reader._locked(existing=True):
            self._reader._namespace(existing_only=True)
            if self._reader._read_state("user-create.authority.json") != self._original_packet(): raise ValueError

    def _check_current_create_context(self) -> None:
        issued = self._issued
        if issued is None: raise ValueError
        with self._reader._locked(existing=True):
            claim, _ = self._reader._ownership()
            packet = self._reader._read_state("user-create.authority.json")
            if (claim["execution_context_digest"] != _execution_context(issued.plan, issued.authorization)
                    or packet != self._original_packet()):
                raise ValueError

    def _original_provenance(self, *, locked: bool = False, require_ack: bool = True,
            require_http_claim: bool = True) -> str:
        store = self._original_store
        if (self._operation != "remove" or type(store) is not PersistentM4ExecutionStateStore
                or type(require_ack) is not bool or type(require_http_claim) is not bool
                or require_ack and not require_http_claim):
            raise ValueError
        with nullcontext() if locked else self._reader._locked(existing=True):
            if not require_http_claim:
                if any(self._reader._exists(name) for name in ("create.claim.json", "create-ack.json", "created.json",
                        "delete.claim.json", "delete-ack.json", "deleted.json")): raise ValueError
                claim, ack = None, None
            elif require_ack or self._reader._exists("create-ack.json"):
                claim, ack = self._reader._ownership()
            else:
                claim, ack = self._reader._create_claim(), None
                if any(self._reader._exists(name) for name in ("created.json", "delete.claim.json", "delete-ack.json", "deleted.json")):
                    raise ValueError
            packet = self._reader._read_state("user-create.authority.json")
            original_namespace = self._reader._read_state("user-create.runtime.json")
        if (set(packet) != {"contract", "parameters_digest", "common_namespace_digest", "store",
                "authority_key_digest", "namespace", "preview", "plan", "authorization"}
                or packet["contract"] != _CREATE_CONTRACT or packet["parameters_digest"] != self._parameters
                or packet["common_namespace_digest"] != self._common_namespace()
                or packet["store"] != _store_binding(store) or self._original_key is None
                or packet["authority_key_digest"] != hashlib.sha256(self._original_key).hexdigest()
                or packet["namespace"] != original_namespace
                or original_namespace.get("contract") != _CREATE_CONTRACT
                or original_namespace.get("parameters_digest") != self._parameters
                or original_namespace.get("scope_ref") == self._namespace["scope_ref"]
                or any(original_namespace.get(k) != self._namespace[k] for k in (
                    "environment_ref", "audience_ref", "requester_digest", "transport_digest"))):
            raise ValueError
        if type(packet["authority_key_digest"]) is not str: raise ValueError
        require_digest(packet["authority_key_digest"], "original_authority")
        if type(packet["plan"]) is not dict or type(packet["authorization"]) is not dict:
            raise ValueError
        plan = M4ExecutionPlan(**packet["plan"])
        auth = M4ExecutionAuthorization(**packet["authorization"])
        preview = packet["preview"]
        if type(preview) is not dict or set(preview) != {"facts", "created_at", "expires_at", "nonce", "preview_ref", "signature"}:
            raise ValueError
        facts = preview["facts"]
        if type(facts) is not list or len(facts) != 4: raise ValueError
        for fact in facts: require_digest(fact, "original_fact")
        original_preview = _Preview(**(preview | {"facts": tuple(facts)}))
        if (type(original_preview.created_at) is not int or type(original_preview.expires_at) is not int
                or original_preview.created_at < 0 or original_preview.expires_at - original_preview.created_at != _TTL):
            raise ValueError
        original_context = {**original_namespace, "facts": facts, "created_at": original_preview.created_at,
            "expires_at": original_preview.expires_at, "nonce": original_preview.nonce}
        if (original_preview.signature != _mac_value(self._original_key, _CREATE_CONTRACT, "preview", original_context)
                or original_preview.preview_ref != "radius-user-preview-" + _mac_value(self._original_key, _CREATE_CONTRACT, "preview-ref", original_context)):
            raise ValueError
        expected_original = _derive_issued("create", original_namespace, self._parameters, self._original_key, original_preview)
        if plan != expected_original.plan or auth != expected_original.authorization:
            raise ValueError
        if (plan.action_id != "radius-remote-user-create" or plan.action_version != "1.0.0"
                or plan.adapter_ref != "fortipam-700-build29-radius-remote-user-create-v1"
                or plan.target_ref != _TARGET or plan.parameters_digest != self._parameters
                or plan.expected_current_digest != facts[0]
                or plan.expected_state_digest != _create_expected(self._parameters, facts[0])
                or plan.compensation_ref is not None or auth.plan_ref != plan.plan_ref
                or auth.plan_digest != plan.plan_digest or auth.requester_digest != plan.requester_digest
                or plan.requester_digest != self._namespace["requester_digest"]
                or auth.confirmation_digest != plan.confirmation_digest or auth.approval_digest != plan.approval_digest):
            raise ValueError
        if claim is not None and (claim["current_digest"] != facts[0] or claim["defaults_digest"] != facts[1]
                or claim["request_digest"] != facts[2] or claim["target_digest"] != facts[3]
                or claim["actor_digest"] != hashlib.sha256(self._reader._config.bearer_token.encode()).hexdigest()
                or type(claim["claimed_at"]) is not int
                or not auth.issued_at <= claim["claimed_at"] <= auth.expires_at
                or claim["execution_context_digest"] != _execution_context(plan, auth)):
            raise ValueError
        context = _execution_context(plan, auth)
        store.verify_ready()
        original = store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest, context_digest=context,
            authorization_digest=auth.authorization_digest)
        result = original.result
        if original.state is not M4ClaimState.REPLAY or result is None or result.compensation is not M4Compensation.NOT_REQUESTED:
            raise ValueError
        labels: tuple[str, ...]
        if result.outcome is M4Outcome.SUCCEEDED and result.verification is M4Verification.VERIFIED and ack is not None:
            labels = ("verified",)
        elif result.outcome is M4Outcome.RECONCILIATION_REQUIRED and result.verification is M4Verification.UNKNOWN:
            labels = ("current_read_unknown", "dispatch_unknown") if claim is None else ("dispatch_unknown", "post_read_unknown", "post_read_denied")
        else:
            raise ValueError
        events = [event for event in store.audit_events if event.authorization in labels
            and event.digest_reference == canonical_digest(context + event.authorization)
            and event.outcome is result.outcome and event.verification is result.verification
            and event.compensation is result.compensation]
        if len(events) != 1: raise ValueError
        return canonical_digest({"packet_digest": canonical_digest(packet), "context_digest": context,
            "claim": claim, "ack": ack, "audit": events[0].digest_reference})

    def _cleanup_provenance(self) -> tuple[str, str]:
        if self._operation != "remove" or self._original_store is None: raise ValueError
        with self._reader._locked(existing=True):
            if self._reader._exists("delete.claim.json"):
                return "consumed_delete", self._original_provenance(locked=True)
            if self._reader._exists("create.claim.json"):
                return "consumed_create", self._original_provenance(locked=True, require_ack=False)
            if self._reader._exists("user-create.authority.json"):
                self._store.verify_ready()
                if self._store.claim_count != 0: raise ValueError
                return "terminal_no_http_claim", self._original_provenance(locked=True,
                    require_ack=False, require_http_claim=False)
            if any(self._reader._exists(name) for name in ("user-create.authority.json", "create-ack.json",
                    "created.json", "delete-ack.json", "deleted.json")): raise ValueError
            creator = self._reader._read_state("user-create.runtime.json")
            if (set(creator) != set(self._namespace) or creator["contract"] != _CREATE_CONTRACT
                    or creator["scope_ref"] == self._namespace["scope_ref"]
                    or any(creator[name] != self._namespace[name] for name in ("environment_ref", "audience_ref",
                        "requester_digest", "transport_digest", "policy_mode", "parameters_digest"))): raise ValueError
            scope, composition = creator["scope_ref"], creator["composition_digest"]
            if not isinstance(scope, str) or not isinstance(composition, str): raise ValueError
            require_ref(scope, "original_scope_ref")
            require_digest(composition, "original_composition_digest")
            for store in (self._original_store, self._store):
                store.verify_ready()
                if store.claim_count != 0: raise ValueError
            return "unattempted", canonical_digest({"namespace": self._namespace_pin,
                "creator_namespace": creator, "original_store": _store_binding(self._original_store), "claim_count": 0})

    def inspect_cleanup_state(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        """Observe qualified cleanup state without granting User ownership."""
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest); self._gate(execute=False)
                mode, provenance = self._cleanup_provenance()
                if mode == "consumed_create": observation = self._reader.inspect_uncertain_create()
                elif mode == "terminal_no_http_claim":
                    packet = self._reader._read_state("user-create.authority.json")
                    preview = packet["preview"]
                    if not isinstance(preview, dict): raise ValueError
                    facts = preview["facts"]
                    if not isinstance(facts, list) or len(facts) != 4: raise ValueError
                    defaults, request = facts[1:3]
                    if not isinstance(defaults, str) or not isinstance(request, str): raise ValueError
                    absent = self._reader.inspect_unclaimed_absence(expected_draft=(defaults, request))
                    observation = "absent_observed" if absent else "not_assessed"
                else:
                    absent = self._reader.inspect_deleted() if mode == "consumed_delete" else self._reader.inspect_unclaimed_absence()
                    observation = "absent_observed" if absent else "not_assessed"
                if observation == "not_assessed" or self._cleanup_provenance() != (mode, provenance): raise ValueError
                self._gate(execute=False)
                return {"contract": "fortipam-radius-user-cleanup-observation-private-v1", "evidence_mode": mode,
                    "observation": observation, "user_absence_verified": observation == "absent_observed", "mutation_executed": False,
                    "prior_m4_outcome_unchanged": True, "dispatch_retry_allowed": False,
                    "user_ownership_or_delete_authority_granted": False}
        except Exception:
            raise RadiusRemoteUserWorkflowError(_ERROR) from None

    def inspect_cleanup_absence(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        result = self.inspect_cleanup_state(requester_digest=requester_digest, transport_digest=transport_digest)
        if result["user_absence_verified"] is not True: raise RadiusRemoteUserWorkflowError(_ERROR)
        return result

    def _summary(self, p: _Preview) -> dict[str, object]:
        return _summary_values(self._operation, self.contract, self._namespace["requester_digest"], p)

    def preview(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest); self._gate(execute=False)
                if self._issued is not None: raise ValueError
                self._unconsumed()
                now = self._now(); facts = self._facts()
                p = _Preview(facts, now, now + _TTL, secrets.token_hex(24), "", "")
                p = _Preview(facts, now, p.expires_at, p.nonce,
                    "radius-user-preview-" + self._mac("preview-ref", self._context(p)), self._mac("preview", self._context(p)))
                self._check_preview(p, self._now())
                self._preview = p
                summary = self._summary(p)
                return {**summary, "summary_digest": canonical_digest(summary)}
        except Exception:
            raise RadiusRemoteUserWorkflowError(_ERROR) from None

    def authorize(self, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest); self._gate(); self._unconsumed()
                p = self._preview
                if self._issued is not None or p is None or not hmac.compare_digest(preview_ref, p.preview_ref):
                    raise ValueError
                self._check_preview(p, self._now())
                if self._facts() != p.facts: raise ValueError
                self._issued = self._derive()
                issued = self._issued
                self._transport = FortiPamRadiusRemoteUserHttpTransport(self._reader._config, self._binding,
                    target=self._target, state_directory=self._reader._directory,
                    execution_enabled=self._operation == "create", recovery_enabled=self._operation == "remove",
                    expected_current_digest=issued.plan.expected_current_digest if self._operation == "create" else None,
                    execution_context_digest=_execution_context(issued.plan, issued.authorization) if self._operation == "create" else None,
                    create_authorizer=self._authorize_create if self._operation == "create" else None,
                    recovery_authorizer=self._authorize_remove if self._operation == "remove" else None,
                    clock=self._now, connection_factory=cast(Callable[..., _Connection], self._reader._factory))
                self._gate()
                return {"contract": self.contract, "policy_mode": "lab_auto",
                    "authorization_ref": issued.authorization.authorization_ref, "expires_at": p.expires_at}
        except Exception:
            raise RadiusRemoteUserWorkflowError(_ERROR) from None

    def execute(self, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest); self._gate()
                issued = self._issued
                if issued is None or not hmac.compare_digest(authorization_ref, issued.authorization.authorization_ref):
                    raise ValueError
                self._check_plan(issued.plan)
                if not self._started:
                    self._unconsumed()
                    self._started = True
                    if self._operation == "create":
                        try:
                            self._retain_original_authority()
                            self._gate(); self._check_plan(issued.plan)
                        except BaseException:
                            self.close()
                            raise
                if self._operation == "create": self._check_retained_authority()
                result = M4ExecutionKernel(_Adapter(self), self, self._store, clock=self._now).execute(
                    issued.plan, issued.authorization)
                return {"contract": self.contract, **result.as_dict()}
        except Exception:
            raise RadiusRemoteUserWorkflowError(_ERROR) from None

    def reconcile(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        """Observe a consumed owned DELETE without changing its M4 outcome."""
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest); self._gate(execute=False)
                provenance = self._original_provenance()
                if not self._reader.inspect_deleted() or self._original_provenance() != provenance:
                    raise ValueError
                return {"contract": "fortipam-radius-user-delete-reconciliation-private-v1",
                    "user_absence_verified": True, "mutation_executed": False,
                    "prior_m4_outcome_unchanged": True, "dispatch_retry_allowed": False,
                    "pair_cleanup_performed": False}
        except Exception:
            raise RadiusRemoteUserWorkflowError(_ERROR) from None

    def revoke(self) -> None:
        """Close dispatch before waiting for an in-flight workflow lock."""
        self._closed = True; self._enabled = False
        self._transport.close(); self._reader.close()

    def close(self) -> None:
        self.revoke()
        with self._lock:
            self._key = b""
            self._original_key = None
