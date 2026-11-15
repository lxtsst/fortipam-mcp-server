"""Typed empty M4 adapter registry.

The packaged registry is a concrete execution dependency, but it contains no
product adapters and has no registration or configuration surface. Resolving
any otherwise valid M4 plan fails with the same closed adapter denial used by
the execution kernel.
"""

from __future__ import annotations

from typing import Protocol

from .execution_kernel import (
    M4AdapterDenied,
    M4ExecutionAdapter,
    M4ExecutionPlan,
)


class M4AdapterRegistry(Protocol):
    """Resolve one exact plan to an already reviewed action adapter."""

    @property
    def registered_adapter_count(self) -> int: ...

    def resolve(self, plan: M4ExecutionPlan) -> M4ExecutionAdapter: ...


class EmptyM4AdapterRegistry:
    """Immutable packaged registry with zero adapters and deny-all routing."""

    __slots__ = ()

    @property
    def registered_adapter_count(self) -> int:
        return 0

    def resolve(self, plan: M4ExecutionPlan) -> M4ExecutionAdapter:
        if not isinstance(plan, M4ExecutionPlan):
            raise M4AdapterDenied("M4 adapter resolution was denied.")
        raise M4AdapterDenied("No M4 product adapter is registered.")


class EmptyRegistryM4ExecutionAdapter:
    """Kernel adapter boundary backed only by the immutable empty registry."""

    __slots__ = ("_registry",)

    def __init__(self, registry: EmptyM4AdapterRegistry) -> None:
        if not isinstance(registry, EmptyM4AdapterRegistry):
            raise M4AdapterDenied("M4 adapter registry binding was denied.")
        self._registry = registry

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self._registry.resolve(plan)
        raise AssertionError("unreachable")

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        self._registry.resolve(plan)

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self._registry.resolve(plan)
        raise AssertionError("unreachable")


__all__ = [
    "EmptyM4AdapterRegistry",
    "EmptyRegistryM4ExecutionAdapter",
    "M4AdapterRegistry",
]
