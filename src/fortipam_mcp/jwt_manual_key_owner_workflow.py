"""Default-off lab policy and M4 join for the fixed local-Owner JWT package.

Trusted server composition supplies scope, identity, keys and persistent stores.
No Tool or startup loader is registered here. Recovery requires the original
signed grant, original terminal M4 record and original native success ACK.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import time
from typing import Any

from v4_planning import (M4AdapterAmbiguous, M4AuthorizationDenied, M4ExecutionAuthorization,
    M4ExecutionKernel, M4ExecutionPlan, M4ExecutionResult, canonical_digest)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_ref

from .jwt_manual_key_contract import _digest
from .jwt_manual_key_owner_http import (CREATE_ACTION, CREATE_ADAPTER, REMOVE_ACTION, REMOVE_ADAPTER,
    TARGET, JwtManualKeyOwnerHttp)
from .jwt_manual_key_owned_state import expected_jwt_manual_key_created_state
from .ldap_server_runtime import _key, _private_directory
from .m4_execution_store import PersistentM4ExecutionStateStore
from .target_operation_records import _TargetOperationRecords

CONTRACT = "fortipam-build29-jwt-local-owner-lab-policy-v1"
_ERROR = "The fixed Owner JWT workflow is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class JwtManualKeyOwnerPreview(_OpaqueC3Object):
    preview_ref: str
    current_digest: str
    expected_digest: str
    created_at: int
    expires_at: int
    signature: str


def _mac(key: bytes, purpose: str, data: object) -> str:
    return hmac.new(key, (CONTRACT + "\x00" + purpose + "\x00" + canonical_digest(data)).encode(), hashlib.sha256).hexdigest()


def _derive(binding: dict[str, Any], context: dict[str, Any], key: bytes) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
    confirmation, approval = _mac(key, "standing-intent", context), _mac(key, "lab-policy", context)
    remove = binding["phase"] == "remove"
    fields = {"plan_ref": "jwt-owner-plan-" + _mac(key, "plan-ref", context), "revision": 1,
        "action_id": REMOVE_ACTION if remove else CREATE_ACTION, "action_version": "1.0.0",
        "adapter_ref": REMOVE_ADAPTER if remove else CREATE_ADAPTER, "target_ref": TARGET,
        "requester_digest": binding["requester_digest"], "summary_digest": _mac(key, "summary", context),
        "confirmation_digest": confirmation, "approval_digest": approval,
        "parameters_digest": binding["request_digest"], "expected_current_digest": context["current_digest"],
        "expected_state_digest": context["expected_digest"], "idempotency_digest": _mac(key, "once", context),
        "expires_at": context["expires_at"], "compensation_ref": None}
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    auth_fields = {"authorization_ref": "jwt-owner-auth-" + _mac(key, "authorization", plan.canonical_content()),
        "plan_ref": plan.plan_ref, "plan_digest": plan.plan_digest, "requester_digest": plan.requester_digest,
        "confirmation_ref": "jwt-owner-intent-" + _mac(key, "intent-ref", context),
        "confirmation_digest": confirmation, "approval_ref": "jwt-owner-policy-" + _mac(key, "policy-ref", context),
        "approval_digest": approval, "approver_digest": _mac(key, "configured-policy-principal", binding),
        "issued_at": context["created_at"], "expires_at": context["expires_at"],
        "one_time": True, "execution_authorized": True}
    return plan, M4ExecutionAuthorization(**auth_fields, authorization_digest=canonical_digest(auth_fields))


class JwtManualKeyOwnerWorkflow(_TargetOperationRecords):
    """One fresh C/P/E and one real kernel operation, bound to one open session."""

    def __init__(self, source: JwtManualKeyOwnerHttp, store: PersistentM4ExecutionStateStore, *,
            phase: str, directory: Path, authority_key_file: Path,
            environment_ref: str, scope_ref: str, audience_ref: str,
            execution_enabled: bool = False, source_guard: Callable[[], bool] | None = None,
            creation_store: PersistentM4ExecutionStateStore | None = None,
            creation_authority_directory: Path | None = None, creation_authority_key_file: Path | None = None,
            clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(source) is not JwtManualKeyOwnerHttp or type(store) is not PersistentM4ExecutionStateStore
                    or phase not in {"create", "remove"} or type(execution_enabled) is not bool
                    or source_guard is not None and not callable(source_guard) or not callable(clock)):
                raise ValueError
            for value in (environment_ref, scope_ref, audience_ref):
                require_ref(value, "jwt_owner_scope")
            _private_directory(directory)
            self._source, self._store, self._phase = source, store, phase
            self._source_ref, self._store_ref = source, store
            self._directory, self._identity = directory, (directory.stat().st_dev, directory.stat().st_ino)
            self._key_file, self._key = authority_key_file, _key(authority_key_file)
            if len({hashlib.sha256(k).digest() for k in (self._key, source._witness, store._key)}) != 3:
                raise ValueError
            self._binding = self._binding_for(source, store, phase, authority_key_file, self._key,
                environment_ref, scope_ref, audience_ref, directory)
            self._namespace = _digest(self._binding)
            self._session_pin = source._session_digest
            self._enabled, self._guard, self._guard_pin = execution_enabled, source_guard, source_guard
            self._clock, self._last_clock, self._clock_failed = clock, None, False
            self._preview: JwtManualKeyOwnerPreview | None = None
            self._issued: tuple[M4ExecutionPlan, M4ExecutionAuthorization] | None = None
            self._context: dict[str, Any] | None = None
            self._consumed = self._closed = False
            self._creator_store = creation_store
            self._creator_directory = creation_authority_directory
            self._creator_key_file = creation_authority_key_file
            if phase == "create":
                if any(v is not None for v in (creation_store, creation_authority_directory, creation_authority_key_file)):
                    raise ValueError
            elif (type(creation_store) is not PersistentM4ExecutionStateStore or creation_store is store
                    or creation_store._path == store._path or creation_store._key == store._key
                    or creation_authority_directory is None or creation_authority_key_file is None):
                raise ValueError
            self._integrity()
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    @staticmethod
    def _binding_for(source: JwtManualKeyOwnerHttp, store: PersistentM4ExecutionStateStore,
            phase: str, key_file: Path, key: bytes, environment: str, scope: str, audience: str,
            directory: Path) -> dict[str, Any]:
        return {"contract": CONTRACT, "phase": phase, "wire_namespace": source._namespace,
            "source_fingerprint": source._source_pin, "request_digest": source._request.digest,
            "requester_digest": source._config.requester_digest, "transport_digest": source._config.transport_digest,
            "environment_ref": environment, "scope_ref": scope, "audience_ref": audience,
            "store_path": str(store._path), "store_key_file": str(store._key_path),
            "store_key_digest": hashlib.sha256(store._key).hexdigest(),
            "authority_key_file": str(key_file), "authority_key_digest": hashlib.sha256(key).hexdigest(),
            "authority_directory": str(directory),
            "authority_directory_identity": [directory.stat().st_dev, directory.stat().st_ino]}

    def _integrity(self) -> None:
        _private_directory(self._directory)
        if (self._source is not self._source_ref or self._store is not self._store_ref
                or (self._directory.stat().st_dev, self._directory.stat().st_ino) != self._identity
                or not hmac.compare_digest(_key(self._key_file), self._key)
                or not hmac.compare_digest(_key(self._store._key_path), self._store._key)
                or self._binding != self._binding_for(self._source, self._store, self._phase, self._key_file,
                    self._key, self._binding["environment_ref"], self._binding["scope_ref"], self._binding["audience_ref"], self._directory)):
            raise ValueError

    def _live(self, *, execute: bool = False) -> None:
        self._integrity(); self._source._source()
        if (self._closed or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True
                or self._source._session_digest != self._session_pin
                or execute and (not self._enabled or not self._source._enabled)):
            raise ValueError
        if self._issued is not None:
            if (self._context is None or self._issued != _derive(self._binding, self._context, self._key)
                    or not self._issued[1].issued_at <= self._now() < self._issued[1].expires_at):
                raise ValueError

    def _original_creation(self) -> None:
        """Check original grant and terminal ledger before private owned reads."""
        if self._phase != "remove":
            return
        store, directory, key_file = self._creator_store, self._creator_directory, self._creator_key_file
        assert store is not None and directory is not None and key_file is not None
        key = _key(key_file)
        _private_directory(directory)
        if (len({hashlib.sha256(k).digest() for k in (key, self._key, self._source._witness, store._key, self._store._key)}) != 5
                or not hmac.compare_digest(_key(store._key_path), store._key)):
            raise ValueError
        binding = self._binding_for(self._source, store, "create", key_file, key,
            self._binding["environment_ref"], self._binding["scope_ref"], self._binding["audience_ref"], directory)
        reader = _GrantReader(directory, _digest(binding))
        record = reader.read()
        body = {k: v for k, v in record.items() if k != "hmac"}
        if (record.get("binding") != binding or not hmac.compare_digest(record.get("hmac", ""), _mac(key, "grant", body))):
            raise ValueError
        plan, authorization = _derive(binding, record["context"], key)
        if record["plan"] != asdict(plan) or record["authorization"] != asdict(authorization):
            raise ValueError
        native = self._source._sealed("create.claim.json")
        self._source._acknowledged_creation()
        if native["plan"] != asdict(plan) or native["authorization"] != asdict(authorization):
            raise ValueError
        claim = store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest, authorization_digest=authorization.authorization_digest,
            context_digest=canonical_digest({"plan_digest": plan.plan_digest,
                "authorization_digest": authorization.authorization_digest, "revision": plan.revision}))
        if claim.result is None or (claim.result.outcome, claim.result.verification) not in {
                ("succeeded", "verified"), ("reconciliation_required", "unknown")}:
            raise ValueError

    def preview(self, *, requester_digest: str, transport_digest: str) -> JwtManualKeyOwnerPreview:
        try:
            self._live()
            if (self._issued is not None or self._consumed or requester_digest != self._binding["requester_digest"]
                    or transport_digest != self._binding["transport_digest"]):
                raise ValueError
            self._original_creation()
            if self._phase == "create":
                if (self._source._directory / "create.claim.json").exists():
                    raise ValueError
                current = self._source.preflight()
                current_digest = current.current_digest
                expected = expected_jwt_manual_key_created_state(self._source._request, current.state)
            else:
                current_digest, expected = self._source.removal_current()
            now = self._now(); ref = "jwt-owner-preview-" + secrets.token_hex(16)
            data = {"preview_ref": ref, "current_digest": current_digest, "expected_digest": expected,
                    "created_at": now, "expires_at": now + 120}
            self._preview = JwtManualKeyOwnerPreview(ref, current_digest, expected, now, now + 120,
                _mac(self._key, "preview", data))
            return self._preview
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def issue(self, preview: JwtManualKeyOwnerPreview, *, requester_digest: str,
            transport_digest: str) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        try:
            self._live(execute=True)
            if (preview is not self._preview or self._issued is not None or self._consumed
                    or requester_digest != self._binding["requester_digest"]
                    or transport_digest != self._binding["transport_digest"]
                    or not preview.created_at <= self._now() < preview.expires_at):
                raise ValueError
            data = {k: v for k, v in asdict(preview).items() if k != "signature"}
            if not hmac.compare_digest(preview.signature, _mac(self._key, "preview", data)):
                raise ValueError
            self._original_creation()
            self._context = {**data, "source_session": self._session_pin}
            issued = _derive(self._binding, self._context, self._key)
            body = {"namespace": self._namespace, "binding": self._binding, "context": self._context,
                    "plan": asdict(issued[0]), "authorization": asdict(issued[1])}
            with self._lock() as directory:
                self._write(directory, "grant.json", {**body, "hmac": _mac(self._key, "grant", body)})
            self._issued = issued
            return issued
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            self._live(execute=True)
            if (self._issued is None or plan is not self._issued[0] or authorization is not self._issued[1]
                    or self._consumed or type(now_epoch) is not int
                    or not authorization.issued_at <= now_epoch <= self._now() < authorization.expires_at):
                raise ValueError
            self._original_creation()
            claim = self._store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
                idempotency_digest=plan.idempotency_digest, authorization_digest=authorization.authorization_digest,
                context_digest=canonical_digest({"plan_digest": plan.plan_digest,
                    "authorization_digest": authorization.authorization_digest, "revision": plan.revision}))
            if claim.result is not None:
                raise ValueError
            self._consumed = True
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def execute(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> M4ExecutionResult:
        try:
            self._live(execute=True)
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None
        return M4ExecutionKernel(_Adapter(self, authorization), self, self._store, clock=self._now).execute(plan, authorization)

    def close(self) -> None:
        self._enabled = False; self._closed = True


class _GrantReader(_TargetOperationRecords):
    def __init__(self, directory: Path, namespace: str) -> None:
        self._directory, self._namespace = directory, namespace
        self._identity = (directory.stat().st_dev, directory.stat().st_ino)

    def read(self) -> dict[str, Any]:
        with self._lock() as directory:
            return self._read(directory, "grant.json")


class _Adapter:
    def __init__(self, owner: JwtManualKeyOwnerWorkflow, authorization: M4ExecutionAuthorization) -> None:
        self.owner, self.authorization = owner, authorization

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            self.owner._live(execute=True)
            if self.owner._phase == "create":
                return self.owner._source.preflight().current_digest
            self.owner._original_creation()
            return self.owner._source.removal_current()[0]
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        try:
            self.owner._live(execute=True)
            if self.owner._phase == "create":
                self.owner._source.create_under_m4(plan, self.authorization, self.owner._store)
            else:
                self.owner._original_creation()
                self.owner._source.remove_under_m4(plan, self.authorization, self.owner._store)
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            self.owner._live(execute=True)
            if self.owner._phase == "create":
                record = self.owner._source._sealed("create.state.json")
                self.owner._source._acknowledged_creation()
                return str(record["postcondition_digest"])
            record = self.owner._source._sealed("remove.absence.json")
            return str(record["expected_digest"])
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None
