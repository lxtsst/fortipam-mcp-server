"""Packaged deny-all M4 execution runtime.

The runtime makes the existing execution kernel an explicit packaged boundary
without exposing it through MCP or binding an authorization verifier, product
adapter, or durable state store. Importing or constructing it cannot authorize
or contact FortiPAM.
"""

from __future__ import annotations

from .adapter_registry import EmptyM4AdapterRegistry, EmptyRegistryM4ExecutionAdapter
from .execution_kernel import (
    M4ExecutionAuthorization,
    M4ExecutionKernel,
    M4ExecutionPlan,
    M4ExecutionResult,
)


class PackagedDenyAllM4ExecutionRuntime:
    """Concrete packaged executor whose only configuration is deny-all."""

    __slots__ = ("_adapter_registry", "_kernel")

    def __init__(self) -> None:
        self._adapter_registry = EmptyM4AdapterRegistry()
        self._kernel = M4ExecutionKernel(
            adapter=EmptyRegistryM4ExecutionAdapter(self._adapter_registry)
        )

    @staticmethod
    def status() -> dict[str, object]:
        return {
            "adapter_registry_bound": True,
            "adapter_registry_mode": "empty_deny_all",
            "authorization_verifier_bound": False,
            "device_access": False,
            "dispatchable": False,
            "durable_state_store_bound": False,
            "executor_mcp_exposed": False,
            "executor_runtime_packaged": True,
            "product_write_enabled": False,
            "registered_adapter_count": 0,
            "runtime_mode": "deny_all",
        }

    def execute(
        self,
        plan: M4ExecutionPlan,
        authorization: M4ExecutionAuthorization,
        *,
        now_epoch: int | None = None,
    ) -> M4ExecutionResult:
        """Delegate to the kernel, whose packaged verifier denies first."""

        return self._kernel.execute(plan, authorization, now_epoch=now_epoch)


__all__ = ["PackagedDenyAllM4ExecutionRuntime"]
