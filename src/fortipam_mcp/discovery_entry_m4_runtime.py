"""Unregistered BP014 runtime for one authorized disabled-scan source create."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from v4_planning import (
    M4AuthorizationDenied,
    M4AuthorizationVerifier,
    M4ExecutionAuthorization,
    M4ExecutionKernel,
    M4ExecutionPlan,
    M4ExecutionResult,
)

from .discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from .discovery_entry_create_contract import DisabledAdDiscoveryCreateInput
from .discovery_entry_m4_adapter import DiscoveryEntryBinding, DiscoveryEntryM4Adapter
from .m4_execution_store import PersistentM4ExecutionStateStore

if TYPE_CHECKING:
    from .domain_secret_projection_reader import DomainSecretReadTransport


_UNAVAILABLE = "Authorized Discovery source creation is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class DiscoveryEntryExecutionBinding:
    """Private exact M4 plan, authorization, and protected source binding."""

    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    source: DiscoveryEntryBinding

    def __repr__(self) -> str:
        return "<DiscoveryEntryExecutionBinding protected>"


class DiscoveryEntryBindingResolver(Protocol):
    def resolve_execution_binding(
        self, authorization_ref: str
    ) -> DiscoveryEntryExecutionBinding: ...


class ProtectedDiscoveryEntryM4Runtime:
    """Execute only a privately resolved binding through the durable M4 kernel."""

    def __init__(
        self,
        resolver: DiscoveryEntryBindingResolver,
        authorization_verifier: M4AuthorizationVerifier,
        execution_store: PersistentM4ExecutionStateStore,
        transport: FortiPamDiscoveryEntryCreateHttpTransport,
        *,
        authenticated_requester_digest: str,
        clock: Callable[[], int],
        execution_gate_open: bool = False,
        domain_read_transport: DomainSecretReadTransport | None = None,
    ) -> None:
        if (
            type(execution_store) is not PersistentM4ExecutionStateStore
            or type(transport) is not FortiPamDiscoveryEntryCreateHttpTransport
            or type(execution_gate_open) is not bool
        ):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        self._resolver = resolver
        self._verifier = authorization_verifier
        self._store = execution_store
        self._transport = transport
        self._requester = authenticated_requester_digest
        self._clock = clock
        self._gate_open = execution_gate_open
        self._domain_read_transport = domain_read_transport

    def execute_bound(
        self, authorization_ref: str, *, expected_binding_digest: str
    ) -> M4ExecutionResult:
        if not self._gate_open:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        try:
            binding = self._resolver.resolve_execution_binding(authorization_ref)
            if (
                type(binding) is not DiscoveryEntryExecutionBinding
                or binding.authorization.authorization_ref != authorization_ref
                or binding.plan.requester_digest != self._requester
                or binding.authorization.requester_digest != self._requester
                or binding.source.parameters_digest != expected_binding_digest
            ):
                raise ValueError
            def before_dispatch() -> None:
                now = self._clock()
                if (type(now) is not int or not binding.authorization.issued_at <= now
                    or now >= min(binding.plan.expires_at, binding.authorization.expires_at)):
                    raise M4AuthorizationDenied(_UNAVAILABLE)

            adapter = DiscoveryEntryM4Adapter(
                binding.plan, binding.source, self._transport,
                domain_read_transport=self._domain_read_transport,
                before_dispatch=before_dispatch,
            )
            if type(binding.source.request) is DisabledAdDiscoveryCreateInput:
                # Reject missing/drifted dependencies before reserving a claim.
                adapter.read_current(binding.plan)
            else:
                self._transport.inspect_credential_reference(binding.source.request)
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None
        return M4ExecutionKernel(
            adapter, self._verifier, self._store, clock=self._clock,
        ).execute(binding.plan, binding.authorization)
