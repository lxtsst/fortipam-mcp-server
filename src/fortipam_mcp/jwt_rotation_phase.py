"""Independent exact-phase M4 authorization for one fixed JWT rotation child.

Trusted composition supplies the parent's standing lab scope, distinct keys and
stores. This private issuer cannot be configured by a Tool argument or witness.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import hmac
from pathlib import Path
import secrets
import time
from typing import Any

from v4_planning import (M4AdapterAmbiguous, M4AuthorizationDenied, M4ExecutionPlan,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionResult, canonical_digest)
from v4_planning.models import require_ref

from .jwt_manual_key_contract import _digest, _require_digest
from .jwt_rotation_owner_source import JwtRotationOwnerSource, PHASES
from .ldap_server_runtime import _key, _private_directory
from .m4_execution_store import PersistentM4ExecutionStateStore
from .target_operation_records import _TargetOperationRecords

CONTRACT = "fortipam-build29-jwt-rotation-phase-lab-v3"
_ERROR = "The fixed JWT rotation phase is unavailable."


class JwtRotationPhase(_TargetOperationRecords):
    def __init__(self, source: JwtRotationOwnerSource, store: PersistentM4ExecutionStateStore, *,
            phase: str, directory: Path, authority_key_file: Path, parent_digest: str,
            environment_ref: str, scope_ref: str, audience_ref: str,
            execution_enabled: bool = False, recovery: bool = False, deadline: int | None = None) -> None:
        try:
            if (type(source) is not JwtRotationOwnerSource or type(store) is not PersistentM4ExecutionStateStore
                    or phase not in PHASES or type(execution_enabled) is not bool or type(recovery) is not bool
                    or recovery and phase not in {"restore","user-remove"} or store._read_only
                    or deadline is not None and (type(deadline) is not int or deadline<=0)):
                raise ValueError
            for value in (environment_ref,scope_ref,audience_ref):
                require_ref(value,"jwt_rotation_scope")
            _require_digest(parent_digest); _private_directory(directory)
            self.source,self.store,self.phase = source,store,phase
            self._source_pin,self._store_pin = source,store
            self._directory,self._identity = directory,(directory.stat().st_dev,directory.stat().st_ino)
            self._key_file,self._key = authority_key_file,_key(authority_key_file)
            if len({self._key,store._key,source._key,source.owner._witness,source.original.store._key,_key(source.original.key_file)}) != 6:
                raise ValueError
            self._binding = {"contract":CONTRACT,"phase":phase,"recovery":recovery,"parent_digest":parent_digest,
                "source_namespace":source._namespace,"session":source.owner._session_digest,
                "parameters":source.parameters(phase),"requester":source.owner._config.requester_digest,
                "transport":source.owner._config.transport_digest,"environment":environment_ref,"scope":scope_ref,"audience":audience_ref,
                "store_path":str(store._path),"store_key_file":str(store._key_path),"store_key":hashlib.sha256(store._key).hexdigest(),
                "authority_file":str(authority_key_file),"authority_key":hashlib.sha256(self._key).hexdigest(),
                "directory":str(directory),"identity":list(self._identity)}
            self._namespace = _digest(self._binding)
            self._enabled,self.recovery = execution_enabled,recovery
            self._deadline = deadline
            self._issued: tuple[M4ExecutionPlan,M4ExecutionAuthorization] | None = None
            self._consumed = self._closed = False
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _mac(self, purpose: str, value: object) -> str:
        return hmac.new(self._key,(CONTRACT+"\x00"+purpose+"\x00"+canonical_digest(value)).encode(),hashlib.sha256).hexdigest()

    def _live(self) -> None:
        self.source.live(); _private_directory(self._directory)
        if (self._closed or self.source is not self._source_pin or self.store is not self._store_pin
                or not self._enabled or not self.source._enabled
                or self.source.owner._session_digest != self._binding["session"]
                or self.source._namespace != self._binding["source_namespace"]
                or self.source.parameters(self.phase) != self._binding["parameters"]
                or (self._directory.stat().st_dev,self._directory.stat().st_ino) != self._identity
                or not hmac.compare_digest(_key(self._key_file),self._key)
                or not hmac.compare_digest(_key(self.store._key_path),self.store._key)):
            raise M4AuthorizationDenied(_ERROR)

    def issue(self) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]:
        """Read a fresh complete C/P/E, then persist one signed lab intent."""
        try:
            self._live()
            if self._issued is not None or self._consumed:
                raise ValueError
            current = self.source.current(self.phase,recovery=self.recovery)
            now = int(time.time())
            expires = min(now+120,self._deadline) if self._deadline is not None else now+120
            if expires<=now:
                raise ValueError
            context = {"binding":self._binding,"current":current.current_digest,"expected":self.source.expected(self.phase),
                "issued_at":now,"expires_at":expires,"nonce":secrets.token_hex(16)}
            intent,policy = self._mac("standing-intent",context),self._mac("configured-lab-policy",context)
            fields: dict[str,Any] = {"plan_ref":"jwt-rotation-plan-"+self._mac("plan-ref",context),"revision":1,
                "action_id":"jwt-rotation-"+self.phase,"action_version":"3.0.0",
                "adapter_ref":"fortipam-build29-jwt-rotation-"+self.phase+"-v3","target_ref":"bound-original-key-and-jwt-user",
                "requester_digest":self._binding["requester"],"summary_digest":self._mac("summary",context),
                "confirmation_digest":intent,"approval_digest":policy,"parameters_digest":self._binding["parameters"],
                "expected_current_digest":current.current_digest,"expected_state_digest":context["expected"],
                "idempotency_digest":self._mac("once",context),"expires_at":expires,"compensation_ref":None}
            plan = M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields))
            auth_fields: dict[str,Any] = {"authorization_ref":"jwt-rotation-auth-"+self._mac("auth-ref",context),
                "plan_ref":plan.plan_ref,"plan_digest":plan.plan_digest,"requester_digest":plan.requester_digest,
                "confirmation_ref":"jwt-rotation-intent-"+self._mac("intent-ref",context),"confirmation_digest":intent,
                "approval_ref":"jwt-rotation-policy-"+self._mac("policy-ref",context),"approval_digest":policy,
                "approver_digest":self._mac("configured-principal",self._binding),"issued_at":now,"expires_at":expires,
                "one_time":True,"execution_authorized":True}
            auth = M4ExecutionAuthorization(**auth_fields,authorization_digest=canonical_digest(auth_fields))
            body = {"namespace":self._namespace,"binding":self._binding,"context":context,"plan":asdict(plan),"authorization":asdict(auth)}
            with self._lock() as directory:
                self._write(directory,"grant.json",{**body,"hmac":self._mac("grant",body)})
            self._issued = (plan,auth)
            return self._issued
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            self._live()
            if (self._issued is None or self._issued[0] is not plan or self._issued[1] is not authorization
                    or self._consumed or type(now_epoch) is not int
                    or not authorization.issued_at<=now_epoch<=int(time.time())<authorization.expires_at):
                raise ValueError
            with self._lock() as directory:
                grant = self._read(directory,"grant.json")
            payload = {k:v for k,v in grant.items() if k != "hmac"}
            if (grant.get("binding") != self._binding or grant.get("plan") != asdict(plan)
                    or grant.get("authorization") != asdict(authorization)
                    or not hmac.compare_digest(grant.get("hmac",""),self._mac("grant",payload))):
                raise ValueError
            claim = self.store.inspect_claim(plan_ref=plan.plan_ref,requester_digest=plan.requester_digest,
                idempotency_digest=plan.idempotency_digest,authorization_digest=authorization.authorization_digest,
                context_digest=canonical_digest({"plan_digest":plan.plan_digest,"authorization_digest":authorization.authorization_digest,"revision":plan.revision}))
            if claim.result is not None:
                raise ValueError
            self._consumed = True
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def execute(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> M4ExecutionResult:
        self._live()
        return M4ExecutionKernel(_Adapter(self,authorization),self,self.store).execute(plan,authorization)

    def close(self) -> None:
        self._enabled = False; self._closed = True


class _Adapter:
    def __init__(self, phase: JwtRotationPhase, authorization: M4ExecutionAuthorization) -> None:
        self.phase,self.auth = phase,authorization

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            self.phase._live()
            return self.phase.source.current(self.phase.phase,recovery=self.phase.recovery).current_digest
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        try:
            self.phase._live()
            self.phase.source.dispatch(self.phase.phase,plan,self.auth,self.phase.store,recovery=self.phase.recovery)
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            self.phase._live()
            record = self.phase.source.sealed(self.phase.phase+".state.json")
            ack = self.phase.source.sealed(self.phase.phase+".ack.json")
            if record["ack_digest"] != _digest(ack):
                raise ValueError
            return str(record["expected_digest"])
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None
