"""Default-denied source-bound lab policy for the two fixed JWT fixture actions.

This follows existing standing-lab M4 issuance, not human approval or production
authorization. Trusted composition supplies authenticated identity and a real
startup source guard. No Tool, environment loader or generic action is exposed.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import secrets
from threading import RLock
import time
from typing import Any

from v4_planning import M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .jwt_manual_key_create_http_transport import JwtManualKeyCreateHttpTransport
from .jwt_manual_key_owned_state import expected_jwt_manual_key_created_state
from .jwt_manual_key_preflight_reader import (JwtManualKeyPreflightRead, JwtManualKeyPreflightReader,
    jwt_manual_create_current_from_preflight)
from .jwt_manual_key_recovery import JwtManualKeyRecovery, ACTION_ID as REMOVE, ADAPTER_REF as REMOVE_ADAPTER, TARGET_REF
from .jwt_manual_key_request_contract import JwtManualCreateRequest
from .jwt_manual_key_response_custody import ACTION_ID as CREATE, ADAPTER_REF as CREATE_ADAPTER, _SEND, _RESPONSE, _ACK, _STATE
from .ldap_server_runtime import _key, _private_directory
from .m4_execution_store import PersistentM4ExecutionStateStore

_ERROR = "The private JWT-key lab authorization is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class JwtManualKeyCreateIssued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    baseline: JwtManualKeyPreflightRead


@dataclass(frozen=True, slots=True, repr=False)
class JwtManualKeyRemovalIssued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class _LabPolicy(_OpaqueC3Object):
    """Shared deterministic signing mechanics; subclasses fix both action shapes."""

    def _setup(self, reader: JwtManualKeyPreflightReader, store: PersistentM4ExecutionStateStore,
               authority_file: Path, witness_file: Path, binding: dict[str, Any], *,
               execution_enabled: bool, source_guard: Callable[[], bool] | None, clock: Callable[[], int]) -> None:
        if (type(reader) is not JwtManualKeyPreflightReader or type(store) is not PersistentM4ExecutionStateStore
                or not store.monotonic_checkpoint_protocol_bound or type(execution_enabled) is not bool
                or not callable(clock) or source_guard is not None and not callable(source_guard)):
            raise ValueError
        for key in ("environment", "scope", "audience"): require_ref(binding[key], "jwt_lab_namespace")
        for key in ("requester", "transport"): require_digest(binding[key], "jwt_lab_identity")
        self._reader, self._store, self._binding = reader, store, binding
        self._authority_file, self._witness_file = Path(authority_file), Path(witness_file)
        self._key, self._witness = _key(self._authority_file), _key(self._witness_file)
        if len({store._key, self._key, self._witness}) != 3: raise ValueError
        self._store_pin = (store._path, store._key_path, store._key, store._monotonic_checkpoint, store._checkpoint_store_ref)
        self._binding_pin = canonical_digest(binding)
        self._source_pin = reader._source
        self._namespace = canonical_digest({**binding, "source": reader._source, "ledger": str(store._path),
            "ledger_key_file": str(store._key_path), "ledger_key": hashlib.sha256(store._key).hexdigest(),
            "authority_file": str(self._authority_file), "authority_key": hashlib.sha256(self._key).hexdigest(),
            "witness_file": str(self._witness_file), "witness_key": hashlib.sha256(self._witness).hexdigest()})
        self._namespace_pin = self._namespace
        self._enabled, self._external_guard = execution_enabled, source_guard
        self._external_guard_pin, self._clock = source_guard, clock
        self._epoch = -1; self._clock_failed = False
        self._context: dict[str, Any] | None = None
        self._issued: tuple[M4ExecutionPlan, M4ExecutionAuthorization] | None = None
        self._bound: Any = None
        self._started = self._consumed = False
        self._mutex = RLock()
        self.execution_gate: Callable[[], bool] = lambda: self._enabled
        self.source_guard: Callable[[], bool] = self._runtime_guard
        self._gate_pin, self._guard_pin = self.execution_gate, self.source_guard
        self._integrity()

    def _integrity(self) -> None:
        self._store.verify_ready()
        s = self._store
        if ((s._path, s._key_path, s._key) != self._store_pin[:3]
                or s._monotonic_checkpoint is not self._store_pin[3] or s._checkpoint_store_ref != self._store_pin[4]
                or canonical_digest(self._binding) != self._binding_pin or self._reader._source != self._source_pin
                or self._namespace != self._namespace_pin
                or not hmac.compare_digest(_key(s._key_path), s._key)
                or not hmac.compare_digest(_key(self._authority_file), self._key)
                or not hmac.compare_digest(_key(self._witness_file), self._witness)
                or self.execution_gate is not self._gate_pin or self.source_guard is not self._guard_pin):
            raise ValueError

    def _now(self) -> int:
        value = self._clock()
        if self._clock_failed or type(value) is not int or value < 0 or value < self._epoch:
            self._clock_failed = True; raise ValueError
        self._epoch = value; return value

    def _live(self) -> None:
        self._integrity()
        if (not self._enabled or self._external_guard is None or self._external_guard is not self._external_guard_pin
                or self._external_guard() is not True or self._reader._fingerprint() != self._source_pin):
            raise ValueError
        if self._issued is not None and not self._issued[1].issued_at <= self._now() < self._issued[1].expires_at:
            raise ValueError
        if self._issued is not None and self._issued != self._derive(): raise ValueError

    def _runtime_guard(self) -> bool:
        try:
            with self._mutex:
                self._live()
                if self._bound is None: raise ValueError
                self._check_runtime(self._bound)
                return True
        except Exception: return False

    def _check_runtime(self, runtime: Any) -> None:
        raise NotImplementedError

    def _mac(self, purpose: str, value: Any) -> str:
        return hmac.new(self._key, self._binding["action"].encode() + b"/lab-policy/v1\x00" + purpose.encode()
            + b"\x00" + canonical_digest(value).encode(), hashlib.sha256).hexdigest()

    def _derive(self) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        context = self._context
        if context is None: raise ValueError
        confirmation, approval = self._mac("standing-intent", context), self._mac("lab-policy", context)
        fields: dict[str, Any] = dict(plan_ref="jwt-lab-plan-" + self._mac("slot", self._namespace), revision=1,
            action_id=self._binding["action"], action_version="1.0.0", adapter_ref=self._binding["adapter"],
            target_ref=self._binding["target"], requester_digest=self._binding["requester"],
            summary_digest=self._mac("summary", context), confirmation_digest=confirmation, approval_digest=approval,
            parameters_digest=context["parameters"], expected_current_digest=context["current"],
            expected_state_digest=context["expected"], idempotency_digest=self._mac("idempotency", self._namespace),
            expires_at=context["expires_at"], compensation_ref=None)
        plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
        signed = {**context, "plan_digest": plan.plan_digest}
        values = dict(authorization_ref="jwt-lab-auth-" + self._mac("authorization", signed), plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="jwt-lab-intent-" + self._mac("intent-ref", signed), confirmation_digest=confirmation,
            approval_ref="jwt-lab-policy-" + self._mac("policy-ref", signed), approval_digest=approval,
            approver_digest=self._mac("configured-lab-policy-principal", self._namespace),
            issued_at=context["created_at"], expires_at=context["expires_at"], one_time=True, execution_authorized=True)
        return plan, M4ExecutionAuthorization(**values, authorization_digest=canonical_digest(values))

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._mutex:
                self._live()
                if (self._issued is None or self._bound is None or self._consumed
                        or plan is not self._issued[0] or authorization is not self._issued[1]
                        or self._issued != self._derive() or type(now_epoch) is not int
                        or not authorization.issued_at <= now_epoch <= self._now() < authorization.expires_at):
                    raise ValueError
                self._check_runtime(self._bound)
                claim = self._store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
                    idempotency_digest=plan.idempotency_digest, authorization_digest=authorization.authorization_digest,
                    context_digest=canonical_digest({"plan_digest": plan.plan_digest,
                        "authorization_digest": authorization.authorization_digest, "revision": plan.revision}))
                if claim.result is not None or self._store.claim_count != 1: raise ValueError
                self._consumed = True
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        self._enabled = False


class JwtManualKeyCreateLabAuthority(_LabPolicy):
    def __init__(self, reader: JwtManualKeyPreflightReader, request: JwtManualCreateRequest, *,
                 execution_store: PersistentM4ExecutionStateStore, directory: Path, authority_key_file: Path,
                 witness_key_file: Path, environment_ref: str, scope_ref: str, audience_ref: str,
                 requester_digest: str, transport_digest: str, execution_enabled: bool = False,
                 source_guard: Callable[[], bool] | None = None, clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if type(request) is not JwtManualCreateRequest: raise ValueError
            request.validate(); self._request, self._directory = request, Path(directory)
            _private_directory(self._directory)
            if (self._directory.name != "custody" or execution_store._path != self._directory.parent / "execution.sqlite"
                    or execution_store._key_path != self._directory.parent / "execution.key"
                    or Path(witness_key_file) != self._directory.parent / "witness.key"
                    or Path(authority_key_file) != self._directory.parent / "authority.key"):
                raise ValueError
            self._request_pin = request.digest
            self._baseline: JwtManualKeyPreflightRead | None = None
            self._setup(reader, execution_store, authority_key_file, witness_key_file,
                dict(action=CREATE, adapter=CREATE_ADAPTER, target="bound-manual-jwt-public-key", environment=environment_ref,
                    scope=scope_ref, audience=audience_ref, requester=requester_digest, transport=transport_digest,
                    policy_mode="lab_auto", request=request.digest), execution_enabled=execution_enabled,
                source_guard=source_guard, clock=clock)
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def issue(self, *, requester_digest: str, transport_digest: str) -> JwtManualKeyCreateIssued:
        try:
            with self._mutex:
                self._live(); self._request.validate()
                if (self._started or self._store.claim_count or (requester_digest, transport_digest) !=
                        (self._binding["requester"], self._binding["transport"])
                        or any(os.path.lexists(self._directory / name) for name in (_SEND, _RESPONSE, _ACK, _STATE))):
                    raise ValueError
                self._started = True
                self._baseline = self._reader.observe(); now = self._now()
                self._context = dict(namespace=self._namespace, nonce=secrets.token_hex(24), created_at=now, expires_at=now + 60,
                    parameters=self._request.digest, current=jwt_manual_create_current_from_preflight(self._request, self._baseline),
                    expected=expected_jwt_manual_key_created_state(self._request, self._baseline.state))
                self._issued = self._derive()
                return JwtManualKeyCreateIssued(*self._issued, self._baseline)
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def _check_runtime(self, runtime: Any) -> None:
        self._integrity()
        if type(runtime) is not JwtManualKeyCreateHttpTransport or self._issued is None or self._baseline is None:
            raise ValueError
        c = runtime._custody
        if (runtime._reader is not self._reader or runtime._baseline is not self._baseline or c._request is not self._request
                or c._store is not self._store or c._directory != self._directory or c._key_file != self._witness_file
                or c._plan is not self._issued[0] or c._authorization is not self._issued[1]
                or c._request_digest != self._request_pin or self._request._request_digest() != self._request_pin
                or runtime._source_guard is not self._guard_pin or runtime._enabled is not self._gate_pin
                or c._source_guard is not self._guard_pin or c._execution_enabled is not self._gate_pin
                or c._actor_reader != self._reader.observe_actor
                or self._bound is not None and runtime is not self._bound):
            raise ValueError

    def bind_runtime(self, runtime: JwtManualKeyCreateHttpTransport) -> None:
        try:
            with self._mutex:
                self._live(); self._check_runtime(runtime)
                if self._bound is not None: raise ValueError
                self._bound = runtime
        except Exception: raise M4AuthorizationDenied(_ERROR) from None


class JwtManualKeyRemovalLabAuthority(_LabPolicy):
    def __init__(self, reader: JwtManualKeyPreflightReader, *, execution_store: PersistentM4ExecutionStateStore,
                 authority_key_file: Path, witness_key_file: Path, creation_authority_key_file: Path,
                 environment_ref: str, scope_ref: str, audience_ref: str, requester_digest: str, transport_digest: str,
                 execution_enabled: bool = False, source_guard: Callable[[], bool] | None = None,
                 clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            self._creation_authority_file = Path(creation_authority_key_file)
            self._creation_authority_key = _key(self._creation_authority_file)
            if (Path(authority_key_file) != execution_store._path.parent / "authority.key"
                    or Path(witness_key_file) != execution_store._path.parent / "witness.key"):
                raise ValueError
            self._setup(reader, execution_store, authority_key_file, witness_key_file,
                dict(action=REMOVE, adapter=REMOVE_ADAPTER, target=TARGET_REF, environment=environment_ref,
                    scope=scope_ref, audience=audience_ref, requester=requester_digest, transport=transport_digest,
                    policy_mode="lab_auto"), execution_enabled=execution_enabled, source_guard=source_guard, clock=clock)
            if self._creation_authority_key in (self._key, self._witness, execution_store._key): raise ValueError
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def _check_runtime(self, runtime: Any) -> None:
        self._integrity()
        if (type(runtime) is not JwtManualKeyRecovery or runtime._store is not self._store or runtime._reader is not self._reader
                or runtime._key_file != self._witness_file or runtime._verifier is not self or runtime._verifier_pin is not self
                or runtime._source_guard is not self._guard_pin or runtime._source_guard_pin is not self._guard_pin
                or runtime._original.original_outcome == "in_progress" or not runtime._original.success_ack_retained
                or runtime._custody._plan.requester_digest != self._binding["requester"]
                or self._creation_authority_file != runtime._custody._directory.parent / "authority.key"
                or not hmac.compare_digest(_key(self._creation_authority_file), self._creation_authority_key)
                or self._bound is not None and runtime is not self._bound): raise ValueError
        keys = (runtime._custody._key, runtime._custody._store._key, self._creation_authority_key,
            self._store._key, self._key, self._witness)
        if len(set(keys)) != len(keys): raise ValueError
        if self._issued is not None and (runtime._plan is not None and runtime._plan is not self._issued[0]
                or runtime._authorization is not None and runtime._authorization is not self._issued[1]): raise ValueError

    def validate_recovery_binding(self, runtime: JwtManualKeyRecovery) -> None:
        """Stable key/runtime checks only; historical inspection survives expiry."""
        try:
            with self._mutex: self._check_runtime(runtime)
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def issue(self, runtime: JwtManualKeyRecovery, *, requester_digest: str,
              transport_digest: str) -> JwtManualKeyRemovalIssued:
        try:
            with self._mutex:
                self._live()
                if (self._started or self._store.claim_count or (requester_digest, transport_digest) !=
                        (self._binding["requester"], self._binding["transport"])): raise ValueError
                self._check_runtime(runtime); self._started = True; self._bound = runtime
                preview = runtime.preview(); now = self._now()
                if not now < preview.expires_at <= now + 60: raise ValueError
                self._context = dict(namespace=self._namespace, runtime=runtime._namespace, nonce=secrets.token_hex(24),
                    created_at=now, expires_at=preview.expires_at, parameters=preview.parameters_digest,
                    current=preview.current_digest, expected=preview.expected_digest)
                self._issued = self._derive()
                self._check_runtime(runtime)
                return JwtManualKeyRemovalIssued(*self._issued)
        except Exception: raise M4AuthorizationDenied(_ERROR) from None


__all__ = ["JwtManualKeyCreateIssued", "JwtManualKeyRemovalIssued", "JwtManualKeyCreateLabAuthority", "JwtManualKeyRemovalLabAuthority"]
