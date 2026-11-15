"""Server-held lab-auto authority for one original-owned reset attempt."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
from threading import RLock
import time
from typing import Any

from v4_planning import M4AuthorizationDenied,M4ExecutionPlan,M4ExecutionAuthorization,canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest,require_ref

from .local_user_reset_owned_material import LocalResetOwnedMaterialSource,ACTION_ID,ADAPTER_REF,ACTION_VERSION

_DOMAIN=b"fortipam-original-owned-reset-lab-auto/v1\x00"
_ERROR="The private original-owned reset authority is unavailable."


@dataclass(frozen=True,slots=True,repr=False)
class LocalResetOwnedPreview(_OpaqueC3Object):
    nonce: str
    current_digest: str
    created_at: int
    expires_at: int
    signature: str


@dataclass(frozen=True,slots=True,repr=False)
class LocalResetOwnedIssued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class LocalResetOwnedM4Authority(_OpaqueC3Object):
    def __init__(self,material: LocalResetOwnedMaterialSource,*,authority_key: bytes,
            environment_ref: str,scope_ref: str,audience_ref: str,requester_digest: str,transport_digest: str,
            execution_enabled: bool=False,clock: Callable[[],int]|None=None) -> None:
        try:
            if (type(material) is not LocalResetOwnedMaterialSource or type(authority_key) is not bytes
                    or not 32<=len(authority_key)<=128 or type(execution_enabled) is not bool
                    or clock is not None and not callable(clock)):raise ValueError
            for value in (environment_ref,scope_ref,audience_ref):require_ref(value,"reset_scope")
            for value in (requester_digest,transport_digest):require_digest(value,"reset_identity")
            original=material._inspector._original
            if any(hmac.compare_digest(authority_key,key) for key in (
                    material._key,material._store._key,material._initial._key,original._key,original._store._key)):raise ValueError
            self._material,self._sources=material,material._sources
            self._binding=dict(contract="original-owned-reset-login-authority/v2" if material._verify_login else "original-owned-reset-authority/v1",environment_ref=environment_ref,scope_ref=scope_ref,
                audience_ref=audience_ref,requester_digest=requester_digest,transport_digest=transport_digest,policy_mode="lab_auto",
                source_context_digest=material._source,fixture_creation_digest=material._inspector._creation_digest,
                parameters_digest=material.parameters_digest)
            self._key,self._enabled=authority_key,execution_enabled
            self._closed=self._failed=False;self._last=-1;self._lock=RLock()
            self._clock=clock if clock is not None else lambda:int(time.time())
            self._preview: LocalResetOwnedPreview|None=None;self._issued: LocalResetOwnedIssued|None=None
            self.expected_digest=canonical_digest({**self._binding,"postcondition":"backend_changed_metadata_preserved_login_and_logout_verified" if material._verify_login else "backend_changed_metadata_preserved_login_unverified"})
            self._pins()
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def _now(self) -> int:
        now=self._clock()
        if self._closed or self._failed or type(now) is not int or now<0 or now<self._last:
            self._failed=True;raise M4AuthorizationDenied(_ERROR)
        self._last=now;return now

    def _pins(self) -> None:
        self._material._storage()
        if (self._sources is not self._material._sources or self._sources.source_context_digest!=self._binding["source_context_digest"]
                or self._material.parameters_digest!=self._binding["parameters_digest"]
                or self._material._inspector._creation_digest!=self._binding["fixture_creation_digest"]):raise ValueError

    def _identity(self,requester: str,transport: str) -> None:
        if requester!=self._binding["requester_digest"] or transport!=self._binding["transport_digest"]:raise ValueError

    def _mac(self,purpose: str,value: object) -> str:
        return hmac.new(self._key,_DOMAIN+purpose.encode()+b"\x00"+
            json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode(),hashlib.sha256).hexdigest()

    def _context(self,preview: LocalResetOwnedPreview) -> dict[str,Any]:
        return {**self._binding,"nonce":preview.nonce,"current_digest":preview.current_digest,
            "expected_digest":self.expected_digest,"created_at":preview.created_at,"expires_at":preview.expires_at}

    def _check(self,preview: LocalResetOwnedPreview,now: int) -> None:
        self._pins()
        if (type(preview) is not LocalResetOwnedPreview or preview is not self._preview
                or type(preview.created_at) is not int or type(preview.expires_at) is not int
                or preview.expires_at!=preview.created_at+60 or not preview.created_at<=now<preview.expires_at
                or not hmac.compare_digest(preview.signature,self._mac("preview",self._context(preview)))):raise ValueError

    def preview(self,*,requester_digest: str,transport_digest: str) -> LocalResetOwnedPreview:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest);self._pins();self._material.require_unclaimed()
                self._sources.observe_presence();self._material.check_staged();now=self._now()
                candidate=LocalResetOwnedPreview(secrets.token_hex(24),self._material.current_digest(),now,now+60,"")
                result=LocalResetOwnedPreview(candidate.nonce,candidate.current_digest,now,now+60,
                    self._mac("preview",self._context(candidate)))
                self._preview,self._issued=result,None
                return result
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def _derive(self,preview: LocalResetOwnedPreview) -> LocalResetOwnedIssued:
        context=self._context(preview);confirmation=self._mac("standing-intent",context);approval=self._mac("lab-policy",context)
        action,adapter,version=self._material._action_contract
        values: dict[str,Any]=dict(plan_ref="owned-reset-plan-"+self._mac("plan-ref",context),revision=1,action_id=action,
            action_version=version,adapter_ref=adapter,target_ref="bound-local-reset-fixture",
            requester_digest=self._binding["requester_digest"],summary_digest=self._mac("summary",context),
            confirmation_digest=confirmation,approval_digest=approval,parameters_digest=self._binding["parameters_digest"],
            expected_current_digest=preview.current_digest,expected_state_digest=self.expected_digest,
            idempotency_digest=self._mac("idempotency",context),expires_at=preview.expires_at,compensation_ref=None)
        plan=M4ExecutionPlan(**values,plan_digest=canonical_digest(values));signed={**context,"plan_digest":plan.plan_digest}
        auth: dict[str,Any]=dict(authorization_ref="owned-reset-auth-"+self._mac("authorization-ref",signed),plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest,requester_digest=plan.requester_digest,
            confirmation_ref="owned-reset-intent-"+self._mac("intent-ref",signed),confirmation_digest=confirmation,
            approval_ref="owned-reset-approval-"+self._mac("approval-ref",signed),approval_digest=approval,
            approver_digest=self._mac("lab-policy-authority",self._binding),issued_at=preview.created_at,expires_at=preview.expires_at,
            one_time=True,execution_authorized=True)
        return LocalResetOwnedIssued(plan,M4ExecutionAuthorization(**auth,authorization_digest=canonical_digest(auth)))

    def issue(self,preview: LocalResetOwnedPreview,*,requester_digest: str,transport_digest: str) -> LocalResetOwnedIssued:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest);self._check(preview,self._now());self._material.require_unclaimed()
                if not self._enabled or self._issued is not None:raise ValueError
                self._sources.observe_presence();self._material.check_staged()
                if self._material.current_digest()!=preview.current_digest:raise ValueError
                self._check(preview,self._now());self._issued=self._derive(preview)
                return self._issued
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def _verify_bound(self,plan: M4ExecutionPlan,authorization: M4ExecutionAuthorization,now_epoch: int) -> None:
        now=self._now();preview=self._preview;issued=self._issued
        if not self._enabled or preview is None or issued is None:raise ValueError
        self._check(preview,now);expected=self._derive(preview)
        if (type(now_epoch) is not int or not preview.created_at<=now_epoch<=now
                or plan is not issued.plan or authorization is not issued.authorization
                or plan!=expected.plan or authorization!=expected.authorization
                or self._material.current_digest()!=preview.current_digest):raise ValueError

    def verify(self,plan: M4ExecutionPlan,authorization: M4ExecutionAuthorization,*,now_epoch: int) -> None:
        try:
            with self._lock:
                self._verify_bound(plan,authorization,now_epoch)
                self._material.check_staged()
                self._verify_bound(plan,authorization,self._now())
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def check_current(self,issued: LocalResetOwnedIssued) -> None:
        if issued is not self._issued:raise M4AuthorizationDenied(_ERROR)
        self.verify(issued.plan,issued.authorization,now_epoch=self._now())

    def check_active(self,issued: LocalResetOwnedIssued) -> None:
        """Check cached C/P/E, time and signature between fixed fresh reads."""
        try:
            with self._lock:
                if issued is not self._issued:raise ValueError
                self._verify_bound(issued.plan,issued.authorization,self._now())
        except Exception:raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        with self._lock:self._enabled=False;self._closed=True;self._preview=self._issued=None
