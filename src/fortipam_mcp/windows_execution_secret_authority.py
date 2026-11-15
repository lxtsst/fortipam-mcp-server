"""Default-closed source-bound lab authority for one Windows credential fixture.

This implements the existing standing-owner lab policy, never human approval or
production authority. Trusted composition must supply its actual source guard,
authenticated requester/transport and isolated ledgers. No Tool, actor discovery,
device precondition reader or configuration activation is provided here.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
import secrets
from threading import RLock
import time
from typing import Any

from v4_planning import M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import C3MaterialBinding, MaterialLeaseRequest, MaterialProviderClass, MaterialPurpose, _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .ldap_server_runtime import _key
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_create_lab_authorization import SecretCreateLabAuthorizationVerifier
from .secret_create_m4_runtime import SecretCreateM4ExecutionBinding
from .windows_execution_secret_contract import CONTRACT, REQUEST_UUID, WindowsExecutionSecretBinding, WindowsExecutionSecretDefaults
from .windows_execution_secret_material import ADAPTER_REF, TARGET_REF, windows_execution_secret_parameters_digest

_DOMAIN = b"windows-execution-secret-lab-authority/v1\x00"
_ERROR = "The private Windows execution Secret lab authorization is unavailable."


def windows_execution_secret_state_digest(profile: WindowsExecutionSecretBinding, *, exists: bool) -> str:
    if type(profile) is not WindowsExecutionSecretBinding or type(exists) is not bool:
        raise M4AuthorizationDenied(_ERROR)
    return canonical_digest({"contract": CONTRACT, "parameters": profile.parameters_digest, "exists": exists})


@dataclass(frozen=True, slots=True, repr=False)
class WindowsExecutionSecretCreatePreview(_OpaqueC3Object):
    current_digest: str
    expected_digest: str
    parameters_digest: str
    created_at: int
    expires_at: int
    nonce: str
    signature: str


class WindowsExecutionSecretLabAuthority(_OpaqueC3Object):
    """Trusted source guard checks metadata/custody only, never acquires material."""

    def __init__(self, *, profile: WindowsExecutionSecretBinding, defaults: WindowsExecutionSecretDefaults,
            material_binding: C3MaterialBinding, execution_store: PersistentM4ExecutionStateStore,
            material_store: PersistentMaterialUseStateStore, authority_key_file: Path, witness_key_file: Path,
            source_context_digest: str, requester_digest: str, transport_digest: str,
            environment_ref: str, scope_ref: str, audience_ref: str, check_source: Callable[[], bool],
            execution_enabled: bool = False, clock: Callable[[], int] = lambda:int(time.time())) -> None:
        try:
            if (type(profile) is not WindowsExecutionSecretBinding or type(defaults) is not WindowsExecutionSecretDefaults
                    or type(material_binding) is not C3MaterialBinding
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or type(material_store) is not PersistentMaterialUseStateStore
                    or not execution_store.monotonic_checkpoint_protocol_bound
                    or not material_store.monotonic_checkpoint_protocol_bound
                    or type(execution_enabled) is not bool or not callable(check_source) or not callable(clock)):
                raise ValueError
            for value in (source_context_digest, requester_digest, transport_digest):
                require_digest(value,"windows_lab_binding")
            for value in (environment_ref,scope_ref,audience_ref):
                require_ref(value,"windows_lab_namespace")
            self._profile,self._defaults,self._material_binding=profile,defaults,material_binding
            self._execution_store,self._material_store=execution_store,material_store
            self._key_file,self._witness_file=Path(authority_key_file),Path(witness_key_file)
            self._key,self._witness=_key(self._key_file),_key(self._witness_file)
            if (len({execution_store._path,execution_store._key_path,material_store._path,material_store._key_path,
                     self._key_file,self._witness_file})!=6
                    or len({self._key,self._witness,execution_store._key,material_store._key})!=4):
                raise ValueError
            self._parameters=windows_execution_secret_parameters_digest(profile,defaults,create_uuid=REQUEST_UUID)
            self._binding={"contract":CONTRACT,"source":source_context_digest,"requester":requester_digest,
                "transport":transport_digest,"environment_ref":environment_ref,"scope_ref":scope_ref,"audience_ref":audience_ref,
                "parameters":self._parameters,"policy_mode":"lab_auto"}
            self._namespace=self._namespace_digest()
            self._source,self._clock,self._enabled=check_source,clock,execution_enabled
            self._source_pin=check_source
            self._last_now=-1;self._failed=False;self._verified=False
            self._preview:WindowsExecutionSecretCreatePreview|None=None
            self._issued:SecretCreateM4ExecutionBinding|None=None
            self._verifier:SecretCreateLabAuthorizationVerifier|None=None
            self._lock=RLock()
            self._validate()
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _now(self) -> int:
        value=self._clock()
        if self._failed or type(value) is not int or value<0 or value<self._last_now:
            self._failed=True
            raise M4AuthorizationDenied(_ERROR)
        self._last_now=value
        return value

    def _validate(self) -> None:
        if (not hmac.compare_digest(_key(self._key_file),self._key)
                or not hmac.compare_digest(_key(self._witness_file),self._witness)
                or self._source is not self._source_pin or self._namespace_digest()!=self._namespace
                or windows_execution_secret_parameters_digest(self._profile,self._defaults,create_uuid=REQUEST_UUID)!=self._parameters):
            raise ValueError
        self._execution_store.verify_ready();self._material_store.verify_ready()
        if self._source() is not True:
            raise ValueError

    def _namespace_digest(self) -> str:
        return canonical_digest({**self._binding,"execution_store":str(self._execution_store._path),
            "execution_key_file":str(self._execution_store._key_path),"execution_key":hashlib.sha256(self._execution_store._key).hexdigest(),
            "material_store":str(self._material_store._path),"material_key_file":str(self._material_store._key_path),
            "material_key":hashlib.sha256(self._material_store._key).hexdigest(),"authority_file":str(self._key_file),
            "witness_file":str(self._witness_file),"witness_key":hashlib.sha256(self._witness).hexdigest()})

    def _identity(self,requester_digest:str,transport_digest:str) -> None:
        if (requester_digest!=self._binding["requester"] or transport_digest!=self._binding["transport"]):
            raise ValueError

    def _mac(self,purpose:str,value:object) -> str:
        return hmac.new(self._key,_DOMAIN+purpose.encode()+b"\x00"+canonical_digest(value).encode(),hashlib.sha256).hexdigest()

    def _context(self,preview:WindowsExecutionSecretCreatePreview) -> dict[str,object]:
        return {**self._binding,"namespace":self._namespace,"current":preview.current_digest,
            "expected":preview.expected_digest,"created_at":preview.created_at,"expires_at":preview.expires_at,"nonce":preview.nonce}

    def preview(self, *, current_digest:str, requester_digest:str, transport_digest:str) -> WindowsExecutionSecretCreatePreview:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest);self._validate()
                if (not self._enabled or self._issued is not None or self._execution_store.claim_count
                        or self._material_store.claim_count or current_digest!=windows_execution_secret_state_digest(self._profile,exists=False)):
                    raise ValueError
                now=self._now()
                provisional=WindowsExecutionSecretCreatePreview(current_digest,windows_execution_secret_state_digest(self._profile,exists=True),
                    self._parameters,now,now+60,secrets.token_hex(24),"")
                value=WindowsExecutionSecretCreatePreview(provisional.current_digest,provisional.expected_digest,
                    provisional.parameters_digest,now,now+60,provisional.nonce,self._mac("preview",self._context(provisional)))
                self._preview=value
                return value
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _check(self,preview:WindowsExecutionSecretCreatePreview) -> None:
        self._validate()
        now=self._now()
        if (not self._enabled or preview is not self._preview or not preview.created_at<=now<preview.expires_at
                or preview.expires_at!=preview.created_at+60 or preview.parameters_digest!=self._parameters
                or not hmac.compare_digest(preview.signature,self._mac("preview",self._context(preview)))):
            raise ValueError

    def _derive(self,preview:WindowsExecutionSecretCreatePreview) -> SecretCreateM4ExecutionBinding:
        context=self._context(preview)
        confirmation,approval=self._mac("standing-intent",context),self._mac("lab-policy",context)
        # Stable per private fixture namespace across expiry; an old M4 claim
        # cannot be bypassed by issuing a fresh nonce/time in the same ledgers.
        plan_ref="windows-execution-plan-"+self._mac("slot",self._namespace)
        values:dict[str,Any]=dict(plan_ref=plan_ref,revision=1,action_id="secret-create-from-reference",action_version="1.0.0",
            adapter_ref=ADAPTER_REF,target_ref=TARGET_REF,requester_digest=self._binding["requester"],
            summary_digest=self._mac("summary",context),confirmation_digest=confirmation,approval_digest=approval,
            parameters_digest=self._parameters,expected_current_digest=preview.current_digest,expected_state_digest=preview.expected_digest,
            idempotency_digest=self._mac("idempotency",self._namespace),expires_at=preview.expires_at,compensation_ref=None)
        plan=M4ExecutionPlan(**values,plan_digest=canonical_digest(values))
        signed={**context,"plan_digest":plan.plan_digest}
        auth_values:dict[str,Any]=dict(authorization_ref="windows-execution-auth-"+self._mac("authorization-ref",signed),
            plan_ref=plan_ref,plan_digest=plan.plan_digest,requester_digest=self._binding["requester"],
            confirmation_ref="windows-execution-intent-"+self._mac("intent-ref",signed),confirmation_digest=confirmation,
            approval_ref="windows-execution-policy-"+self._mac("policy-ref",signed),approval_digest=approval,
            approver_digest=self._mac("configured-lab-policy-principal",self._namespace),issued_at=preview.created_at,
            expires_at=preview.expires_at,one_time=True,execution_authorized=True)
        auth=M4ExecutionAuthorization(**auth_values,authorization_digest=canonical_digest(auth_values))
        policy=self._mac("policy",context)
        scope,audience=canonical_digest(self._binding["scope_ref"]),canonical_digest(self._binding["audience_ref"])
        request=MaterialLeaseRequest("secret-create-from-reference","1.0.0",plan.plan_digest,policy,auth.authorization_digest,
            scope,audience,MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE,MaterialPurpose.INITIAL_ONBOARDING,
            preview.created_at,preview.expires_at)
        return SecretCreateM4ExecutionBinding(plan,auth,self._material_binding,request,policy,scope,audience)

    def issue(self,preview:WindowsExecutionSecretCreatePreview,*,requester_digest:str,transport_digest:str) -> SecretCreateM4ExecutionBinding:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest);self._check(preview)
                if self._issued is not None or self._execution_store.claim_count or self._material_store.claim_count:
                    raise ValueError
                issued=self._derive(preview)
                self._verifier=SecretCreateLabAuthorizationVerifier(issued)
                self._issued=issued
                return issued
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def resolve_execution_binding(self,authorization_ref:str) -> SecretCreateM4ExecutionBinding:
        if self._issued is None or authorization_ref!=self._issued.authorization.authorization_ref:
            raise M4AuthorizationDenied(_ERROR)
        self.verify_binding(self._issued)
        return self._issued

    def verify_binding(self,binding:SecretCreateM4ExecutionBinding) -> None:
        try:
            with self._lock:
                if self._preview is None or self._issued is None or binding is not self._issued or self._verifier is None:
                    raise ValueError
                self._check(self._preview)
                expected=self._derive(self._preview)
                if binding!=expected or binding.material_binding is not self._material_binding:
                    raise ValueError
                self._verifier.verify_binding(binding)
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def verify(self,plan:M4ExecutionPlan,authorization:M4ExecutionAuthorization,*,now_epoch:int) -> None:
        try:
            with self._lock:
                if self._issued is None or self._verified or self._verifier is None or now_epoch!=self._now():
                    raise ValueError
                self.verify_binding(self._issued)
                if plan!=self._issued.plan or authorization!=self._issued.authorization:
                    raise ValueError
                claim=self._execution_store.inspect_claim(plan_ref=plan.plan_ref,requester_digest=plan.requester_digest,
                    idempotency_digest=plan.idempotency_digest,authorization_digest=authorization.authorization_digest,
                    context_digest=canonical_digest({"plan_digest":plan.plan_digest,"authorization_digest":authorization.authorization_digest,"revision":plan.revision}))
                if claim.result is not None:raise ValueError
                self._verifier.verify(plan,authorization,now_epoch=now_epoch)
                self._verified=True
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None
