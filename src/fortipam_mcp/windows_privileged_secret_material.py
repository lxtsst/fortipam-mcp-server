"""Private M4/C3 composition shared by two closed existing-Target profiles.

The privileged entry retains its exact type; the service entry is separate.
Neither offers a privilege toggle, Tool, registration or authority issuer. An
independently qualified fixed transport must preserve original ACK/full state
before VERIFIED_CREATED. Synthetic peers enable no device write.
"""
from __future__ import annotations

from collections.abc import Callable
from threading import RLock
from typing import Protocol, cast

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import (
    _reserve_m4_material_acquisition,
)
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import (
    C3MaterialBinding, MaterialBindingStatus, MaterialLease, MaterialLeaseRequest,
    MaterialProviderClass, MaterialPurpose, _OpaqueC3Object,
)
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID, SECRET_CREATE_ACTION_VERSION, SecretCreateAdapterOutcome,
)
from v4_planning.secret_create_runtime import SecretCreateMaterialRuntime

from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_create_central_lab_provider import (
    CentralLabInventorySecretCreateProvider, CentralLabSecretCreateResolverLoader,
)
from .secret_metadata_http_transport import _zeroize_mutable
from .windows_execution_secret_contract import (
    REQUEST_UUID, MachineQualifiedWindowsLocalLoader, WindowsExecutionSecretDefaults,
    _defaults_digest,
)
from .windows_privileged_secret_contract import (
    CONTRACT, WindowsPrivilegedSecretBinding, WindowsPrivilegedSecretError,
    build_windows_privileged_secret_body,
)
from .windows_execution_secret_material import _OriginalDispatch
from .windows_service_credential_contract import (
    CONTRACT as _SERVICE_CONTRACT, WindowsServiceCredentialBinding, build_windows_service_credential_body,
)

_ReferenceBinding = WindowsPrivilegedSecretBinding | WindowsServiceCredentialBinding


ADAPTER_REF = "fortipam-700-build29-windows-privileged-existing-target-secret-m4-v1"
TARGET_REF = "bound-windows-privileged-reference-secret"
_ERROR = "The private Windows privileged Secret material lifecycle is unavailable."
_SERVICE_ADAPTER_REF = "fortipam-700-build29-windows-service-credential-existing-target-m4-v1"
_SERVICE_TARGET_REF = "bound-windows-service-reference-credential"



def _reference_profile_refs(binding: _ReferenceBinding) -> tuple[str, str, str]:
    if type(binding) is WindowsPrivilegedSecretBinding:
        return CONTRACT, ADAPTER_REF, TARGET_REF
    if type(binding) is WindowsServiceCredentialBinding:
        return _SERVICE_CONTRACT, _SERVICE_ADAPTER_REF, _SERVICE_TARGET_REF
    raise WindowsPrivilegedSecretError(_ERROR)


def _reference_parameters_digest(binding: _ReferenceBinding,
        defaults: WindowsExecutionSecretDefaults, *, create_uuid: str) -> str:
    try:
        contract, _, _ = _reference_profile_refs(binding)
        if (type(defaults) is not WindowsExecutionSecretDefaults
                or defaults.serial_digest != binding.serial_digest
                or defaults.guards_digest != _defaults_digest(defaults.policy_defaults)
                or type(create_uuid) is not str or create_uuid != REQUEST_UUID):
            raise ValueError
        return canonical_digest({"contract": contract, "binding": binding.parameters_digest,
            "defaults": defaults.guards_digest, "create_uuid": create_uuid})
    except Exception:
        raise WindowsPrivilegedSecretError(_ERROR) from None


def windows_privileged_secret_parameters_digest(binding: WindowsPrivilegedSecretBinding,
        defaults: WindowsExecutionSecretDefaults, *, create_uuid: str) -> str:
    """Bind only the exact privileged profile; accept no service profile/toggle."""
    if type(binding) is not WindowsPrivilegedSecretBinding:
        raise WindowsPrivilegedSecretError(_ERROR)
    return _reference_parameters_digest(binding, defaults, create_uuid=create_uuid)


def _reference_body(profile: _ReferenceBinding, defaults: WindowsExecutionSecretDefaults, *,
        create_uuid: str, username: memoryview, password: memoryview) -> bytearray:
    if type(profile) is WindowsPrivilegedSecretBinding:
        return build_windows_privileged_secret_body(profile, defaults, create_uuid=create_uuid,
            username=username, password=password)
    if type(profile) is WindowsServiceCredentialBinding:
        return build_windows_service_credential_body(profile, defaults, create_uuid=create_uuid,
            username=username, password=password)
    raise WindowsPrivilegedSecretError(_ERROR)


def _transport_methods(profile: _ReferenceBinding, transport: object) -> tuple[
        Callable[[_ReferenceBinding, MaterialLeaseRequest], bool],
        Callable[[_ReferenceBinding, MaterialLeaseRequest, memoryview], SecretCreateAdapterOutcome]]:
    if type(profile) is WindowsPrivilegedSecretBinding:
        ready_name, create_name = "_windows_privileged_secret_ready", "_create_windows_privileged_secret"
    elif type(profile) is WindowsServiceCredentialBinding:
        ready_name, create_name = "_windows_service_credential_ready", "_create_windows_service_credential"
    else:
        raise WindowsPrivilegedSecretError(_ERROR)
    ready, create = getattr(transport, ready_name, None), getattr(transport, create_name, None)
    if not callable(ready) or not callable(create):
        raise WindowsPrivilegedSecretError(_ERROR)
    return (cast(Callable[[_ReferenceBinding, MaterialLeaseRequest], bool], ready),
            cast(Callable[[_ReferenceBinding, MaterialLeaseRequest, memoryview], SecretCreateAdapterOutcome], create))


class WindowsPrivilegedSecretBodyTransport(Protocol):
    """Trusted fixed transport; body and views must never escape its call.

    This is not an authorization issuer. A real implementation still requires
    separately qualified original-ACK custody, exact fixed readback and recovery.
    """

    def _windows_privileged_secret_ready(self, binding: WindowsPrivilegedSecretBinding,
            request: MaterialLeaseRequest) -> bool: ...

    def _create_windows_privileged_secret(self, binding: WindowsPrivilegedSecretBinding,
            request: MaterialLeaseRequest, body: memoryview) -> SecretCreateAdapterOutcome: ...


class _ReferenceDispatch(_OriginalDispatch):
    def __init__(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            execution_store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore,
            request: MaterialLeaseRequest, clock: Callable[[], int], *,
            profile: _ReferenceBinding, defaults: WindowsExecutionSecretDefaults,
            create_uuid: str, transport: object) -> None:
        super().__init__(plan, authorization, execution_store, material_store, request, clock)
        self._profile, self._defaults, self._uuid, self._transport = profile, defaults, create_uuid, transport
        self._ready_method, self._create_method = _transport_methods(profile, transport)

    def require(self, *, claimed: bool = False, acquired: bool = False) -> None:
        super().require(claimed=claimed, acquired=acquired)
        if _reference_parameters_digest(self._profile, self._defaults,
                create_uuid=self._uuid) != self.plan.parameters_digest:
            raise WindowsPrivilegedSecretError(_ERROR)

    def require_inputs(self, profile: _ReferenceBinding, defaults: WindowsExecutionSecretDefaults,
            create_uuid: str, transport: object) -> None:
        self.require()
        if (transport is not self._transport
                or _transport_methods(profile, transport) != (self._ready_method, self._create_method)
                or _reference_parameters_digest(profile, defaults,
                    create_uuid=create_uuid) != self.plan.parameters_digest):
            raise WindowsPrivilegedSecretError(_ERROR)


class _GuardedReferenceLoader(_OpaqueC3Object):
    def __init__(self, loader: MachineQualifiedWindowsLocalLoader, guard: _ReferenceDispatch,
            profile: _ReferenceBinding, transport: object) -> None:
        self.loader, self.guard, self.profile, self.transport = loader, guard, profile, transport

    def _ready(self) -> None:
        self.guard.require_inputs(self.profile, self.guard._defaults, self.guard._uuid, self.transport)
        if self.guard._ready_method(self.profile, self.guard.request) is not True:
            raise WindowsPrivilegedSecretError(_ERROR)

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


class _ReferenceProvider(CentralLabInventorySecretCreateProvider):
    def _consume_reference_body(self, lease: MaterialLease, request: MaterialLeaseRequest,
            profile: _ReferenceBinding, defaults: WindowsExecutionSecretDefaults,
            create_uuid: str, guard: _ReferenceDispatch,
            transport: object) -> SecretCreateAdapterOutcome:
        guard.require_inputs(profile, defaults, create_uuid, transport)
        guard.require(claimed=True, acquired=True)
        record = self._active_record(lease, request)
        record.consumed = True
        body = bytearray()
        view: memoryview | None = None
        try:
            with memoryview(record.username).toreadonly() as username, memoryview(record.password).toreadonly() as password:
                body = _reference_body(profile, defaults, create_uuid=create_uuid,
                    username=username, password=password)
            guard.require_inputs(profile, defaults, create_uuid, transport)
            guard.require(claimed=True, acquired=True)
            view = memoryview(body).toreadonly()
            outcome = guard._create_method(profile, request, view)
            guard.require_inputs(profile, defaults, create_uuid, transport)
            guard.require(claimed=True, acquired=True)
            return outcome if type(outcome) is SecretCreateAdapterOutcome else SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
        finally:
            if view is not None:
                view.release()
            _zeroize_mutable(body)
            record.clear()


class _ReferenceAdapter(_OpaqueC3Object):
    def __init__(self, provider: _ReferenceProvider, profile: _ReferenceBinding,
            defaults: WindowsExecutionSecretDefaults, create_uuid: str, guard: _ReferenceDispatch,
            transport: object) -> None:
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
            return self.provider._consume_reference_body(lease, request, self.profile, self.defaults,
                self.create_uuid, self.guard, self.transport)
        except Exception:
            return SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED


def _reference_secret_material_runtime(*, profile: _ReferenceBinding,
        defaults: WindowsExecutionSecretDefaults, create_uuid: str,
        plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
        execution_store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore,
        material_binding: C3MaterialBinding, request: MaterialLeaseRequest,
        loader: CentralLabSecretCreateResolverLoader, transport: object,
        clock: Callable[[], int]) -> SecretCreateMaterialRuntime:
    """Reuse durable M4/C3 and original-dispatch guards; register no writer/Tool.

    Native Target/subject/Folder admission, original birth custody and independent
    recovery remain responsibilities of the separately qualified fixed transport.
    No supplied digest, callback or synthetic peer establishes those properties.
    """
    try:
        if (type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                or type(request) is not MaterialLeaseRequest or type(material_binding) is not C3MaterialBinding
                or type(execution_store) is not PersistentM4ExecutionStateStore
                or type(material_store) is not PersistentMaterialUseStateStore
                or not execution_store.monotonic_checkpoint_protocol_bound
                or not material_store.monotonic_checkpoint_protocol_bound
                or not callable(clock)):
            raise ValueError
        plan.__post_init__()
        authorization.__post_init__()
        request.__post_init__()
        _, adapter_ref, target_ref = _reference_profile_refs(profile)
        _transport_methods(profile, transport)
        parameters = _reference_parameters_digest(profile, defaults, create_uuid=create_uuid)
        if (plan.action_id != SECRET_CREATE_ACTION_ID or plan.action_version != SECRET_CREATE_ACTION_VERSION
                or plan.adapter_ref != adapter_ref or plan.target_ref != target_ref
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
        guard = _ReferenceDispatch(plan, authorization, execution_store, material_store, request, clock,
            profile=profile, defaults=defaults, create_uuid=create_uuid, transport=transport)
        qualified = MachineQualifiedWindowsLocalLoader(loader, machine_name=profile.machine_name)
        provider = _ReferenceProvider(_GuardedReferenceLoader(qualified, guard, profile, transport), binding=material_binding,
            request=request, clock=clock)
        adapter = _ReferenceAdapter(provider, profile, defaults, create_uuid, guard, transport)
        return SecretCreateMaterialRuntime(provider, material_store, adapter)
    except Exception:
        raise WindowsPrivilegedSecretError(_ERROR) from None


def windows_privileged_secret_material_runtime(*, profile: WindowsPrivilegedSecretBinding,
        defaults: WindowsExecutionSecretDefaults, create_uuid: str,
        plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
        execution_store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore,
        material_binding: C3MaterialBinding, request: MaterialLeaseRequest,
        loader: CentralLabSecretCreateResolverLoader, transport: WindowsPrivilegedSecretBodyTransport,
        clock: Callable[[], int]) -> SecretCreateMaterialRuntime:
    """Public private-profile entry: reject every other exact binding type."""
    if type(profile) is not WindowsPrivilegedSecretBinding:
        raise WindowsPrivilegedSecretError(_ERROR)
    return _reference_secret_material_runtime(profile=profile, defaults=defaults, create_uuid=create_uuid,
        plan=plan, authorization=authorization, execution_store=execution_store, material_store=material_store,
        material_binding=material_binding, request=request, loader=loader, transport=transport, clock=clock)
