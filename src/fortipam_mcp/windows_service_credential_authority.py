"""Default-closed lab authority for one fixed nonprivileged service credential.

This implements the existing standing-owner lab policy, never human approval or
production authority. Trusted composition must supply its actual source guard,
authenticated requester/transport and isolated ledgers. No Tool, actor discovery,
device precondition reader or configuration activation is provided here. The
source guard must independently qualify original nonadmin SID/material/service,
Folder custody, global new-name absence, exact Target/Template/schema/association,
permission and activity;
this issuer attests none of those native conditions.
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

from v4_planning import M4AuthorizationDenied, M4ClaimState, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import C3MaterialBinding, MaterialLeaseRequest, MaterialProviderClass, MaterialPurpose, _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .ldap_server_runtime import _key
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_create_lab_authorization import SecretCreateLabAuthorizationVerifier
from .secret_create_m4_runtime import SecretCreateM4ExecutionBinding
from .windows_execution_secret_contract import REQUEST_UUID, WindowsExecutionSecretDefaults
from .windows_service_credential_contract import CONTRACT, WindowsServiceCredentialBinding
from .windows_service_credential_owner_auth import WindowsServiceCredentialOwnerBinding
from .windows_service_credential_birth import WindowsServiceCredentialBirthCustody
from .secret_metadata_http_transport import _zeroize_mutable
from .windows_service_credential_material import ADAPTER_REF, TARGET_REF, windows_service_credential_parameters_digest

_DOMAIN = b"windows-service-credential-lab-authority/v1\x00"
_ERROR = "The private Windows service credential lab authorization is unavailable."


def windows_service_credential_state_digest(profile: WindowsServiceCredentialBinding, *, exists: bool) -> str:
    if type(profile) is not WindowsServiceCredentialBinding or type(exists) is not bool:
        raise M4AuthorizationDenied(_ERROR)
    return canonical_digest({"contract": CONTRACT, "parameters": profile.parameters_digest, "exists": exists})


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceCredentialCreatePreview(_OpaqueC3Object):
    current_digest: str
    expected_digest: str
    parameters_digest: str
    created_at: int
    expires_at: int
    nonce: str
    signature: str


class WindowsServiceCredentialLabAuthority(_OpaqueC3Object):
    """Trusted source guard checks metadata/custody only, never acquires material."""

    def __init__(self, *, profile: WindowsServiceCredentialBinding, defaults: WindowsExecutionSecretDefaults,
            material_binding: C3MaterialBinding, execution_store: PersistentM4ExecutionStateStore,
            material_store: PersistentMaterialUseStateStore, authority_key_file: Path, witness_key_file: Path,
            source_context_digest: str, requester_digest: str, transport_digest: str,
            environment_ref: str, scope_ref: str, audience_ref: str, check_source: Callable[[], bool],
            execution_enabled: bool = False, clock: Callable[[], int] = lambda:int(time.time()),
            owner_binding: WindowsServiceCredentialOwnerBinding | None = None) -> None:
        try:
            if (type(profile) is not WindowsServiceCredentialBinding or type(defaults) is not WindowsExecutionSecretDefaults
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
            self._key=bytearray(_key(self._key_file))
            self._witness=bytearray(_key(self._witness_file))
            if (len({p.resolve() for p in (execution_store._path,execution_store._key_path,material_store._path,material_store._key_path,
                     self._key_file,self._witness_file)})!=6
                    or len({hashlib.sha256(k).digest() for k in (self._key,self._witness,execution_store._key,material_store._key)})!=4):
                raise ValueError
            self._parameters=windows_service_credential_parameters_digest(profile,defaults,create_uuid=REQUEST_UUID)
            self._binding={"contract":CONTRACT,"source":source_context_digest,"requester":requester_digest,
                "transport":transport_digest,"environment_ref":environment_ref,"scope_ref":scope_ref,"audience_ref":audience_ref,
                "parameters":self._parameters,"policy_mode":"lab_auto"}
            self._owner_binding = owner_binding
            if owner_binding is not None:
                if (type(owner_binding) is not WindowsServiceCredentialOwnerBinding
                        or owner_binding.serial_digest != profile.serial_digest
                        or owner_binding.folder_context_digest != profile.folder_context_digest):
                    raise ValueError
                self._binding.update(actual_creator_authentication="owner-cookie", creator_binding=owner_binding.binding_digest)
            self._namespace=self._namespace_digest()
            self._source,self._clock,self._enabled=check_source,clock,execution_enabled
            self._source_pin=check_source
            self._clock_pin=clock;self._closed=False
            self._last_now=-1;self._failed=False;self._verified=False
            self._preview:WindowsServiceCredentialCreatePreview|None=None
            self._issued:SecretCreateM4ExecutionBinding|None=None
            self._verifier:SecretCreateLabAuthorizationVerifier|None=None
            self._lock=RLock()
            self._validate()
        except Exception:
            for name in ("_key","_witness"):
                if hasattr(self,name): _zeroize_mutable(getattr(self,name))
            raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed=True
            _zeroize_mutable(self._key);_zeroize_mutable(self._witness)

    def _now(self) -> int:
        if self._closed or self._clock is not self._clock_pin:
            raise M4AuthorizationDenied(_ERROR)
        value=self._clock()
        if self._failed or type(value) is not int or value<0 or value<self._last_now:
            self._failed=True
            raise M4AuthorizationDenied(_ERROR)
        self._last_now=value
        return value

    def _validate(self) -> None:
        if self._owner_binding is not None:
            if (type(self._owner_binding) is not WindowsServiceCredentialOwnerBinding
                    or self._owner_binding.binding_digest != self._binding.get("creator_binding")
                    or self._binding.get("actual_creator_authentication") != "owner-cookie"):
                raise ValueError
        elif "creator_binding" in self._binding or "actual_creator_authentication" in self._binding:
            raise ValueError
        if (self._closed or self._clock is not self._clock_pin or not hmac.compare_digest(_key(self._key_file),self._key)
                or not hmac.compare_digest(_key(self._witness_file),self._witness)
                or self._source is not self._source_pin or self._namespace_digest()!=self._namespace
                or windows_service_credential_parameters_digest(self._profile,self._defaults,create_uuid=REQUEST_UUID)!=self._parameters):
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

    def _context(self,preview:WindowsServiceCredentialCreatePreview) -> dict[str,object]:
        return {**self._binding,"namespace":self._namespace,"current":preview.current_digest,
            "expected":preview.expected_digest,"created_at":preview.created_at,"expires_at":preview.expires_at,"nonce":preview.nonce}

    def preview(self, *, current_digest:str, requester_digest:str, transport_digest:str) -> WindowsServiceCredentialCreatePreview:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest);self._validate()
                if (not self._enabled or self._issued is not None or self._execution_store.claim_count
                        or self._material_store.claim_count or current_digest!=windows_service_credential_state_digest(self._profile,exists=False)):
                    raise ValueError
                now=self._now()
                provisional=WindowsServiceCredentialCreatePreview(current_digest,windows_service_credential_state_digest(self._profile,exists=True),
                    self._parameters,now,now+60,secrets.token_hex(24),"")
                value=WindowsServiceCredentialCreatePreview(provisional.current_digest,provisional.expected_digest,
                    provisional.parameters_digest,now,now+60,provisional.nonce,self._mac("preview",self._context(provisional)))
                self._preview=value
                return value
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _check(self,preview:WindowsServiceCredentialCreatePreview) -> None:
        self._validate()
        now=self._now()
        if (not self._enabled or preview is not self._preview or not preview.created_at<=now<preview.expires_at
                or preview.expires_at!=preview.created_at+60 or preview.parameters_digest!=self._parameters
                or not hmac.compare_digest(preview.signature,self._mac("preview",self._context(preview)))):
            raise ValueError

    def _derive(self,preview:WindowsServiceCredentialCreatePreview) -> SecretCreateM4ExecutionBinding:
        context=self._context(preview)
        confirmation,approval=self._mac("standing-intent",context),self._mac("lab-policy",context)
        # Stable per private fixture namespace across expiry; an old M4 claim
        # cannot be bypassed by issuing a fresh nonce/time in the same ledgers.
        plan_ref="windows-service-credential-plan-"+self._mac("slot",self._namespace)
        values:dict[str,Any]=dict(plan_ref=plan_ref,revision=1,action_id="secret-create-from-reference",action_version="1.0.0",
            adapter_ref=ADAPTER_REF,target_ref=TARGET_REF,requester_digest=self._binding["requester"],
            summary_digest=self._mac("summary",context),confirmation_digest=confirmation,approval_digest=approval,
            parameters_digest=self._parameters,expected_current_digest=preview.current_digest,expected_state_digest=preview.expected_digest,
            idempotency_digest=self._mac("idempotency",self._namespace),expires_at=preview.expires_at,compensation_ref=None)
        plan=M4ExecutionPlan(**values,plan_digest=canonical_digest(values))
        signed={**context,"plan_digest":plan.plan_digest}
        auth_values:dict[str,Any]=dict(authorization_ref="windows-service-credential-auth-"+self._mac("authorization-ref",signed),
            plan_ref=plan_ref,plan_digest=plan.plan_digest,requester_digest=self._binding["requester"],
            confirmation_ref="windows-service-credential-intent-"+self._mac("intent-ref",signed),confirmation_digest=confirmation,
            approval_ref="windows-service-credential-policy-"+self._mac("policy-ref",signed),approval_digest=approval,
            approver_digest=self._mac("configured-lab-policy-principal",self._namespace),issued_at=preview.created_at,
            expires_at=preview.expires_at,one_time=True,execution_authorized=True)
        auth=M4ExecutionAuthorization(**auth_values,authorization_digest=canonical_digest(auth_values))
        policy=self._mac("policy",context)
        scope,audience=canonical_digest(self._binding["scope_ref"]),canonical_digest(self._binding["audience_ref"])
        request=MaterialLeaseRequest("secret-create-from-reference","1.0.0",plan.plan_digest,policy,auth.authorization_digest,
            scope,audience,MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE,MaterialPurpose.INITIAL_ONBOARDING,
            preview.created_at,preview.expires_at)
        return SecretCreateM4ExecutionBinding(plan,auth,self._material_binding,request,policy,scope,audience)

    def issue(self,preview:WindowsServiceCredentialCreatePreview,*,requester_digest:str,transport_digest:str) -> SecretCreateM4ExecutionBinding:
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

    def validate_owner_creation(self, custody: WindowsServiceCredentialBirthCustody) -> None:
        """Bind the actual Owner transport to this issuer's exact original grant."""
        try:
            with self._lock:
                self._validate()
                if (not self._enabled or self._issued is None or self._owner_binding is None
                        or type(custody) is not WindowsServiceCredentialBirthCustody
                        or custody._owner_binding != self._owner_binding
                        or custody._profile != self._profile or custody._defaults != self._defaults
                        or custody._execution_store is not self._execution_store or custody._material_store is not self._material_store
                        or custody._key_file != self._witness_file
                        or custody._plan != self._issued.plan or custody._authorization != self._issued.authorization
                        or custody._request != self._issued.lease_request):
                    raise ValueError
                custody._validate()
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

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
                now=self._now()
                if (self._issued is None or self._verified or self._verifier is None
                        or type(now_epoch) is not int
                        or not authorization.issued_at<=now_epoch<=now<authorization.expires_at):
                    raise ValueError
                self.verify_binding(self._issued)
                if plan!=self._issued.plan or authorization!=self._issued.authorization:
                    raise ValueError
                claim=self._execution_store.inspect_claim(plan_ref=plan.plan_ref,requester_digest=plan.requester_digest,
                    idempotency_digest=plan.idempotency_digest,authorization_digest=authorization.authorization_digest,
                    context_digest=canonical_digest({"plan_digest":plan.plan_digest,"authorization_digest":authorization.authorization_digest,"revision":plan.revision}))
                if claim.state is not M4ClaimState.IN_PROGRESS or claim.result is not None:raise ValueError
                self._verifier.verify(plan,authorization,now_epoch=now_epoch)
                self._verified=True
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None
