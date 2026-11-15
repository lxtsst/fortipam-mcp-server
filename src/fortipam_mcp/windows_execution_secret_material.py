"""Private original-M4/C3 composition for the fixed Windows credential body.

No HTTP implementation, Tool, registration, ACK custody or recovery authority
is supplied here. An independently qualified fixed transport must preserve native ACK
and qualified full readback before returning VERIFIED_CREATED. Synthetic peers
can exercise this composition without enabling any device write.
"""
from __future__ import annotations

from collections.abc import Callable
from threading import RLock
from typing import Protocol

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import (
    _require_m4_dispatch_ownership, _require_m4_material_acquisition_ownership,
    _reserve_m4_material_acquisition,
)
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import (
    C3MaterialBinding, MaterialBindingStatus, MaterialLease, MaterialLeaseRequest,
    MaterialProviderClass, MaterialPurpose, _OpaqueC3Object,
)
from v4_planning.material_runtime import MaterialUseClaimState, material_lease_request_digest
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID, SECRET_CREATE_ACTION_VERSION, SecretCreateAdapterOutcome,
)
from v4_planning.secret_create_runtime import SecretCreateMaterialRuntime

from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_create_central_lab_provider import (
    CentralLabInventorySecretCreateProvider, CentralLabSecretCreateResolverLoader,
)
from .windows_execution_secret_contract import (
    CONTRACT, REQUEST_UUID, MachineQualifiedWindowsLocalLoader, WindowsExecutionSecretBinding,
    WindowsExecutionSecretDefaults, WindowsExecutionSecretError, _defaults_digest,
    _zeroize_mutable, build_windows_execution_secret_body,
)

ADAPTER_REF = "fortipam-700-build29-windows-execution-secret-m4-v1"
TARGET_REF = "bound-windows-execution-secret"
_ERROR = "The private Windows execution Secret material lifecycle is unavailable."


def windows_execution_secret_parameters_digest(binding: WindowsExecutionSecretBinding,
        defaults: WindowsExecutionSecretDefaults, *, create_uuid: str) -> str:
    """Bind the fixed profile, qualified defaults and creation UUID into M4."""
    try:
        if (type(binding) is not WindowsExecutionSecretBinding
                or type(defaults) is not WindowsExecutionSecretDefaults
                or defaults.serial_digest != binding.serial_digest
                or defaults.guards_digest != _defaults_digest(defaults.policy_defaults)
                or type(create_uuid) is not str or create_uuid != REQUEST_UUID):
            raise ValueError
        return canonical_digest({"contract": CONTRACT, "binding": binding.parameters_digest,
            "defaults": defaults.guards_digest, "create_uuid": create_uuid})
    except Exception:
        raise WindowsExecutionSecretError(_ERROR) from None


class WindowsExecutionSecretBodyTransport(Protocol):
    """Trusted fixed transport; body and views must never escape its call.

    This is not an authorization issuer. A real implementation still requires
    separately qualified original-ACK custody, exact fixed readback and recovery.
    """

    def _windows_execution_secret_ready(self, binding: WindowsExecutionSecretBinding,
            request: MaterialLeaseRequest) -> bool: ...

    def _create_windows_execution_secret(self, binding: WindowsExecutionSecretBinding,
            request: MaterialLeaseRequest, body: memoryview) -> SecretCreateAdapterOutcome: ...


class _OriginalDispatch(_OpaqueC3Object):
    def __init__(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            execution_store: PersistentM4ExecutionStateStore,
            material_store: PersistentMaterialUseStateStore, request: MaterialLeaseRequest,
            clock: Callable[[], int]) -> None:
        self.plan, self.authorization = plan, authorization
        self.execution_store, self.material_store = execution_store, material_store
        self.request, self.clock = request, clock
        self.last_now = -1
        self.lock = RLock()

    def require(self, *, claimed: bool = False, acquired: bool = False) -> None:
        with self.lock:
            _require_m4_dispatch_ownership(self.plan, self.authorization, self.execution_store)
            if acquired:
                _require_m4_material_acquisition_ownership(self.plan, self.authorization, self.execution_store)
            now = self.clock()
            if (type(now) is not int or now < self.last_now
                    or not self.request.requested_at <= now < self.request.expires_at):
                raise WindowsExecutionSecretError(_ERROR)
            self.last_now = now
            self.execution_store.verify_ready()
            self.material_store.verify_ready()
            claim = self.execution_store.inspect_claim(plan_ref=self.plan.plan_ref,
                requester_digest=self.plan.requester_digest, idempotency_digest=self.plan.idempotency_digest,
                authorization_digest=self.authorization.authorization_digest,
                context_digest=canonical_digest({"plan_digest": self.plan.plan_digest,
                    "authorization_digest": self.authorization.authorization_digest, "revision": self.plan.revision}))
            if claim.result is not None:
                raise WindowsExecutionSecretError(_ERROR)
            if claimed and self.material_store._inspect_claim(
                    request_digest=material_lease_request_digest(self.request),
                    authorization_digest=self.request.authorization_digest).state is not MaterialUseClaimState.IN_PROGRESS:
                raise WindowsExecutionSecretError(_ERROR)


class _GuardedLocalLoader(_OpaqueC3Object):
    def __init__(self, loader: MachineQualifiedWindowsLocalLoader, guard: _OriginalDispatch,
            profile: WindowsExecutionSecretBinding, transport: WindowsExecutionSecretBodyTransport) -> None:
        self.loader, self.guard, self.profile, self.transport = loader, guard, profile, transport

    def _ready(self) -> None:
        if self.transport._windows_execution_secret_ready(self.profile, self.guard.request) is not True:
            raise WindowsExecutionSecretError(_ERROR)

    def validate_prebound(self) -> MaterialBindingStatus:
        try:
            self.guard.require()
            self._ready()
            return self.loader.validate_prebound()
        except Exception:
            return MaterialBindingStatus.UNAVAILABLE

    def load_secret_create_material_once(self) -> tuple[bytearray, bytearray]:
        loaded: tuple[bytearray, bytearray] | None = None
        transferred = False
        try:
            self.guard.require(claimed=True)
            self._ready()
            _reserve_m4_material_acquisition(self.guard.plan, self.guard.authorization, self.guard.execution_store)
            loaded = self.loader.load_secret_create_material_once()
            self.guard.require(claimed=True, acquired=True)
            self._ready()
            transferred = True
            return loaded
        finally:
            if not transferred and loaded is not None:
                for value in loaded:
                    _zeroize_mutable(value)


class _WindowsProvider(CentralLabInventorySecretCreateProvider):
    def _consume_windows_body(self, lease: MaterialLease, request: MaterialLeaseRequest,
            profile: WindowsExecutionSecretBinding, defaults: WindowsExecutionSecretDefaults,
            create_uuid: str, guard: _OriginalDispatch,
            transport: WindowsExecutionSecretBodyTransport) -> SecretCreateAdapterOutcome:
        guard.require(claimed=True, acquired=True)
        record = self._active_record(lease, request)
        record.consumed = True
        body = bytearray()
        view: memoryview | None = None
        try:
            with memoryview(record.username).toreadonly() as username, memoryview(record.password).toreadonly() as password:
                body = build_windows_execution_secret_body(profile, defaults, create_uuid=create_uuid,
                    username=username, password=password)
            guard.require(claimed=True, acquired=True)
            view = memoryview(body).toreadonly()
            outcome = transport._create_windows_execution_secret(profile, request, view)
            guard.require(claimed=True, acquired=True)
            return outcome if type(outcome) is SecretCreateAdapterOutcome else SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
        finally:
            if view is not None:
                view.release()
            _zeroize_mutable(body)
            record.clear()


class _WindowsAdapter(_OpaqueC3Object):
    def __init__(self, provider: _WindowsProvider, profile: WindowsExecutionSecretBinding,
            defaults: WindowsExecutionSecretDefaults, create_uuid: str, guard: _OriginalDispatch,
            transport: WindowsExecutionSecretBodyTransport) -> None:
        self.provider, self.profile, self.defaults = provider, profile, defaults
        self.create_uuid, self.guard, self.transport = create_uuid, guard, transport
        self.attempted = False
        self.lock = RLock()

    def dispatch_create(self, lease: MaterialLease, request: MaterialLeaseRequest) -> SecretCreateAdapterOutcome:
        try:
            with self.lock:
                if self.attempted or request != self.guard.request:
                    raise ValueError
                self.attempted = True
            return self.provider._consume_windows_body(lease, request, self.profile, self.defaults,
                self.create_uuid, self.guard, self.transport)
        except Exception:
            return SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED


def windows_execution_secret_material_runtime(*, profile: WindowsExecutionSecretBinding,
        defaults: WindowsExecutionSecretDefaults, create_uuid: str,
        plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
        execution_store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore,
        material_binding: C3MaterialBinding, request: MaterialLeaseRequest,
        loader: CentralLabSecretCreateResolverLoader, transport: WindowsExecutionSecretBodyTransport,
        clock: Callable[[], int]) -> SecretCreateMaterialRuntime:
    """Compose the existing C3 engine without extending legacy 191/collector types."""
    try:
        if (type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                or type(request) is not MaterialLeaseRequest or type(material_binding) is not C3MaterialBinding
                or type(execution_store) is not PersistentM4ExecutionStateStore
                or type(material_store) is not PersistentMaterialUseStateStore
                or not execution_store.monotonic_checkpoint_protocol_bound
                or not material_store.monotonic_checkpoint_protocol_bound
                or not callable(clock) or not callable(getattr(transport, "_create_windows_execution_secret", None))
                or not callable(getattr(transport, "_windows_execution_secret_ready", None))):
            raise ValueError
        plan.__post_init__()
        authorization.__post_init__()
        request.__post_init__()
        parameters = windows_execution_secret_parameters_digest(profile, defaults, create_uuid=create_uuid)
        if (plan.action_id != SECRET_CREATE_ACTION_ID or plan.action_version != SECRET_CREATE_ACTION_VERSION
                or plan.adapter_ref != ADAPTER_REF or plan.target_ref != TARGET_REF
                or plan.parameters_digest != parameters or plan.compensation_ref is not None
                or request.plan_digest != plan.plan_digest
                or request.authorization_digest != authorization.authorization_digest
                or request.provider_class is not MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE
                or request.purpose is not MaterialPurpose.INITIAL_ONBOARDING
                or request.requested_at < authorization.issued_at
                or request.expires_at > min(authorization.expires_at, plan.expires_at)
                or authorization.plan_digest != plan.plan_digest or authorization.plan_ref != plan.plan_ref
                or authorization.requester_digest != plan.requester_digest
                or authorization.confirmation_digest != plan.confirmation_digest
                or authorization.approval_digest != plan.approval_digest
                or execution_store._path == material_store._path
                or execution_store._key_path == material_store._key_path
                or material_store.uses_key_material(execution_store._key)):
            raise ValueError
        execution_store.verify_ready()
        material_store.verify_ready()
        guard = _OriginalDispatch(plan, authorization, execution_store, material_store, request, clock)
        qualified = MachineQualifiedWindowsLocalLoader(loader, machine_name=profile.machine_name)
        provider = _WindowsProvider(_GuardedLocalLoader(qualified, guard, profile, transport), binding=material_binding,
            request=request, clock=clock)
        adapter = _WindowsAdapter(provider, profile, defaults, create_uuid, guard, transport)
        return SecretCreateMaterialRuntime(provider, material_store, adapter)
    except Exception:
        raise WindowsExecutionSecretError(_ERROR) from None
