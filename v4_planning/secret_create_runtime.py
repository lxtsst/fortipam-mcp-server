"""Private C3 runtime composition for one Secret-create action contract.

The runtime binds the value-free lease request, one material provider, the
single-use lease coordinator, and one action-specific private adapter. It has
no MCP, environment, body-building, product-transport, or registration surface.
The packaged default remains deny-all.
"""

from __future__ import annotations

from .material_provider import (
    C3MaterialBinding,
    DenyAllMaterialProvider,
    MaterialLease,
    MaterialLeaseRequest,
    MaterialProvider,
)
from .material_runtime import (
    InMemoryMaterialUseStateStore,
    MaterialLeaseCoordinator,
    MaterialRuntimeError,
    MaterialRuntimeOutcome,
    MaterialUseOutcome,
    MaterialUseStateStore,
)
from .secret_create_adapter import (
    DenyAllSecretCreatePrivateAdapter,
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
    SecretCreateAdapterOutcome,
    SecretCreatePrivateAdapter,
    require_secret_create_lease_request,
)


class SecretCreateMaterialRuntime:
    """Trusted direct composition for one private Secret-create lease use."""

    __slots__ = ("_adapter", "_coordinator", "_state_store")

    def __init__(
        self,
        provider: MaterialProvider,
        state_store: MaterialUseStateStore,
        adapter: SecretCreatePrivateAdapter,
    ) -> None:
        self._state_store = state_store
        self._coordinator = MaterialLeaseCoordinator(provider, state_store)
        self._adapter = adapter

    def verify_ready(self) -> None:
        """Revalidate persistent replay state when the store supports it."""

        verifier = getattr(self._state_store, "verify_ready", None)
        if verifier is None:
            return
        if not callable(verifier):
            raise MaterialRuntimeError("The private material lifecycle is unavailable.")
        try:
            verifier()
        except Exception:
            raise MaterialRuntimeError(
                "The private material lifecycle is unavailable."
            ) from None

    def execute_once(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
        *,
        now_epoch: int,
    ) -> MaterialRuntimeOutcome:
        """Use one opaque lease through the exact action-specific adapter."""

        exact_request = require_secret_create_lease_request(request)

        def consume(lease: MaterialLease) -> MaterialUseOutcome:
            outcome = self._adapter.dispatch_create(lease, exact_request)
            if outcome is SecretCreateAdapterOutcome.VERIFIED_CREATED:
                return MaterialUseOutcome.VERIFIED
            if outcome is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED:
                return MaterialUseOutcome.AMBIGUOUS
            return MaterialUseOutcome.FAILED

        return self._coordinator.execute_once(
            binding,
            exact_request,
            consume,
            now_epoch=now_epoch,
        )


class PackagedDenyAllSecretCreateMaterialRuntime:
    """Package-owned no-injection composition that cannot acquire material."""

    __slots__ = ("_runtime",)

    def __init__(self) -> None:
        self._runtime = SecretCreateMaterialRuntime(
            DenyAllMaterialProvider(),
            InMemoryMaterialUseStateStore(),
            DenyAllSecretCreatePrivateAdapter(),
        )

    @staticmethod
    def status() -> dict[str, object]:
        return {
            "action_id": SECRET_CREATE_ACTION_ID,
            "action_version": SECRET_CREATE_ACTION_VERSION,
            "adapter_mode": "deny_all",
            "body_builder_available": False,
            "device_access": False,
            "dispatchable": False,
            "material_provider_mode": "deny_all",
            "mcp_exposed": False,
            "private_runtime_packaged": True,
            "product_transport_bound": False,
        }

    def execute_once(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
        *,
        now_epoch: int,
    ) -> MaterialRuntimeOutcome:
        return self._runtime.execute_once(
            binding,
            request,
            now_epoch=now_epoch,
        )

    def verify_ready(self) -> None:
        """Verify the package-owned in-memory deny-all composition."""

        self._runtime.verify_ready()


__all__ = [
    "PackagedDenyAllSecretCreateMaterialRuntime",
    "SecretCreateMaterialRuntime",
]
