"""Default-closed lab policy for removal of one original service credential.

Trusted composition supplies standing lab scope and authenticated identity.
The issuer obtains preservation C/P/E from the fixed recovery runtime itself.
It neither acquires central material nor grants human or production approval.
There is no Tool, startup activation or qualification of live product behavior.
A real source guard must separately qualify complete association/activity and
effective permissions before the fixed recovery runtime may read or delete.
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

from v4_planning import (
    M4AuthorizationDenied, M4ClaimState, M4ExecutionAuthorization,
    M4ExecutionPlan, canonical_digest,
)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .ldap_server_runtime import _key
from .m4_execution_store import PersistentM4ExecutionStateStore
from .windows_service_credential_birth import WindowsServiceCredentialBirthCustody
from .secret_metadata_http_transport import _zeroize_mutable
from .windows_service_credential_recovery import (
    ACTION_ID, ADAPTER_REF, TARGET_REF, WindowsServiceCredentialRecovery,
    WindowsServiceCredentialRecoveryPreview,
)

_DOMAIN = b"windows-service-credential-remove-lab-authority/v1\x00"
_ERROR = "The private Windows service credential removal authorization is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceCredentialRemovalIssued(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class WindowsServiceCredentialRemovalLabAuthority(_OpaqueC3Object):
    """One independent grant, consumed only inside its durable removal M4."""

    def __init__(self, custody: WindowsServiceCredentialBirthCustody, *,
            execution_store: PersistentM4ExecutionStateStore,
            authority_key_file: Path, witness_key_file: Path,
            environment_ref: str, scope_ref: str, audience_ref: str,
            requester_digest: str, transport_digest: str,
            execution_enabled: bool = False,
            clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(custody) is not WindowsServiceCredentialBirthCustody
                    or type(execution_store) is not PersistentM4ExecutionStateStore
                    or not execution_store.monotonic_checkpoint_protocol_bound
                    or type(execution_enabled) is not bool or not callable(clock)):
                raise ValueError
            for value in (environment_ref, scope_ref, audience_ref):
                require_ref(value, "windows_removal_namespace")
            for value in (requester_digest, transport_digest):
                require_digest(value, "windows_removal_identity")
            custody._validate()
            original = custody.inspect_original_creation()
            if (original.original_outcome == "in_progress" or original.native_uuid is None
                    or requester_digest != custody._plan.requester_digest):
                raise ValueError
            self._custody, self._original, self._store = custody, original, execution_store
            self._key_file, self._witness_file = Path(authority_key_file), Path(witness_key_file)
            self._key = bytearray(_key(self._key_file))
            self._witness = bytearray(_key(self._witness_file))
            paths = (custody._execution_store._path, custody._execution_store._key_path,
                     custody._material_store._path, custody._material_store._key_path,
                     custody._key_file, execution_store._path, execution_store._key_path,
                     self._key_file, self._witness_file)
            keys = (custody._execution_store._key, custody._material_store._key,
                    custody._key, execution_store._key, self._key, self._witness)
            if len({path.resolve() for path in paths}) != len(paths) or len({hashlib.sha256(k).digest() for k in keys}) != len(keys):
                raise ValueError
            self._binding = dict(action=ACTION_ID, version="1.0.0", adapter=ADAPTER_REF,
                target=TARGET_REF, environment_ref=environment_ref, scope_ref=scope_ref,
                audience_ref=audience_ref, requester=requester_digest,
                transport=transport_digest, policy_mode="lab_auto")
            self._namespace = self._binding_digest()
            self._enabled, self._clock = execution_enabled, clock
            self._clock_pin, self._closed = clock, False
            self._runtime: WindowsServiceCredentialRecovery | None = None
            self._preview: WindowsServiceCredentialRecoveryPreview | None = None
            self._issued: WindowsServiceCredentialRemovalIssued | None = None
            self._context: dict[str, object] | None = None
            self._started = self._consumed = self._clock_failed = False
            self._epoch = -1
            self._lock = RLock()
            self._validate()
        except Exception:
            for name in ("_key", "_witness"):
                if hasattr(self, name): _zeroize_mutable(getattr(self, name))
            raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            _zeroize_mutable(self._key)
            _zeroize_mutable(self._witness)

    def _now(self) -> int:
        if self._closed or self._clock is not self._clock_pin:
            raise ValueError
        value = self._clock()
        if self._clock_failed or type(value) is not int or value < 0 or value < self._epoch:
            self._clock_failed = True
            raise ValueError
        self._epoch = value
        return value

    def _binding_digest(self) -> str:
        return canonical_digest({**self._binding, "original": self._original.custody_digest,
            "source": self._custody._context, "store": str(self._store._path),
            "store_key_file": str(self._store._key_path),
            "store_key": hashlib.sha256(self._store._key).hexdigest(),
            "authority_file": str(self._key_file),
            "witness_file": str(self._witness_file),
            "witness_key": hashlib.sha256(self._witness).hexdigest()})

    def _validate(self) -> None:
        if self._closed or self._clock is not self._clock_pin:
            raise ValueError
        self._custody._validate()
        self._store.verify_ready()
        self._custody._execution_store.verify_ready()
        self._custody._material_store.verify_ready()
        if (self._custody.inspect_original_creation() != self._original
                or self._binding_digest() != self._namespace
                or not hmac.compare_digest(_key(self._key_file), self._key)
                or not hmac.compare_digest(_key(self._witness_file), self._witness)):
            raise ValueError

    def validate_recovery_binding(self, runtime: WindowsServiceCredentialRecovery) -> None:
        """Pinned by the recovery runtime and rechecked before each wire action."""
        try:
            with self._lock:
                self._validate()
                if (not self._enabled or type(runtime) is not WindowsServiceCredentialRecovery
                        or runtime._custody is not self._custody or runtime._store is not self._store
                        or runtime._key_file != self._witness_file
                        or not hmac.compare_digest(runtime._key, self._witness)
                        or runtime._original != self._original
                        or runtime._verifier is not self or runtime._verifier_pin is not self
                        or runtime._binding_digest() != runtime._namespace
                        or (self._runtime is not None and runtime is not self._runtime)):
                    raise ValueError
                if self._issued is not None:
                    if (self._preview is not runtime._preview or self._issued != self._derive()
                            or not self._issued.authorization.issued_at <= self._now()
                                < self._issued.authorization.expires_at):
                        raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _mac(self, purpose: str, content: object) -> str:
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00"
            + canonical_digest(content).encode(), hashlib.sha256).hexdigest()

    def _derive(self) -> WindowsServiceCredentialRemovalIssued:
        p, context = self._preview, self._context
        if p is None or context is None or self._runtime is None:
            raise ValueError
        confirmation, approval = self._mac("standing-intent", context), self._mac("lab-policy", context)
        values: dict[str, Any] = dict(
            plan_ref="service-credential-removal-plan-" + self._mac("slot", self._namespace),
            revision=1, action_id=ACTION_ID, action_version="1.0.0",
            adapter_ref=ADAPTER_REF, target_ref=TARGET_REF, requester_digest=p.requester_digest,
            summary_digest=self._mac("summary", context), confirmation_digest=confirmation,
            approval_digest=approval, parameters_digest=p.parameters_digest,
            expected_current_digest=p.current_digest, expected_state_digest=p.expected_digest,
            idempotency_digest=self._mac("idempotency", self._namespace),
            expires_at=p.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
        signed = {**context, "plan_digest": plan.plan_digest}
        auth: dict[str, Any] = dict(
            authorization_ref="service-credential-removal-auth-" + self._mac("authorization", signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="service-credential-removal-intent-" + self._mac("intent-ref", signed),
            confirmation_digest=confirmation,
            approval_ref="service-credential-removal-policy-" + self._mac("policy-ref", signed),
            approval_digest=approval,
            approver_digest=self._mac("configured-lab-policy-principal", self._namespace),
            issued_at=context["created_at"], expires_at=p.expires_at,
            one_time=True, execution_authorized=True)
        return WindowsServiceCredentialRemovalIssued(plan,
            M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth)))

    def issue(self, runtime: WindowsServiceCredentialRecovery, *, requester_digest: str,
            transport_digest: str) -> WindowsServiceCredentialRemovalIssued:
        """Read the original fixture through the runtime, then sign exact C/P/E."""
        try:
            with self._lock:
                self._validate()
                if (not self._enabled or self._started or self._store.claim_count
                        or type(runtime) is not WindowsServiceCredentialRecovery
                        or runtime._preview is not None
                        or (requester_digest, transport_digest) !=
                            (self._binding["requester"], self._binding["transport"])):
                    raise ValueError
                self.validate_recovery_binding(runtime)
                self._started = True
                self._runtime = runtime
                self._preview = runtime.preview()
                now = self._now()
                if (self._preview.requester_digest != requester_digest
                        or not now < self._preview.expires_at <= now + 30):
                    raise ValueError
                self._context = {**self._binding, "namespace": self._namespace,
                    "runtime": runtime._namespace, "nonce": secrets.token_hex(24),
                    "created_at": now, "preview": {
                        "current": self._preview.current_digest,
                        "expected": self._preview.expected_digest,
                        "parameters": self._preview.parameters_digest,
                        "expires_at": self._preview.expires_at}}
                self._issued = self._derive()
                runtime._check_plan(self._issued.plan, self._issued.authorization)
                return self._issued
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            *, now_epoch: int) -> None:
        try:
            with self._lock:
                issued, runtime = self._issued, self._runtime
                if issued is None or runtime is None or self._consumed:
                    raise ValueError
                self.validate_recovery_binding(runtime)
                now = self._now()
                if (plan is not issued.plan or authorization is not issued.authorization
                        or type(now_epoch) is not int
                        or not authorization.issued_at <= now_epoch <= now < authorization.expires_at):
                    raise ValueError
                runtime._check_plan(plan, authorization)
                runtime._unconsumed()
                claim = self._store.inspect_claim(plan_ref=plan.plan_ref,
                    requester_digest=plan.requester_digest,
                    idempotency_digest=plan.idempotency_digest,
                    authorization_digest=authorization.authorization_digest,
                    context_digest=canonical_digest({"plan_digest": plan.plan_digest,
                        "authorization_digest": authorization.authorization_digest,
                        "revision": plan.revision}))
                if claim.state is not M4ClaimState.IN_PROGRESS:
                    raise ValueError
                self._consumed = True
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None
