"""Unregistered runtime assembly for one protected child Folder create.

This module composes the protected Folder authorization store, the persistent
M4 execution ledger, the action-specific adapter, and the generic execution
kernel.  It intentionally provides no MCP/HTTP registration, credential
loader, product endpoint, or transport implementation.

The only per-call input is an opaque authorization reference.  The plan,
authorization, child request, current digest, expected digest, and adapter
binding are all reconstructed from the owner-protected signed store.
"""

from __future__ import annotations

from collections.abc import Callable
import hmac

from v4_planning import M4AuditEvent, M4ExecutionKernel, M4ExecutionResult

from .folder_m4_adapter import (
    ChildFolderCreateM4Adapter,
    ChildFolderMutationTransport,
)
from .folder_m4_authorization import (
    FolderM4AuthorizationError,
    PersistentFolderM4AuthorizationStore,
    ProtectedFolderM4AuthorizationVerifier,
    ProtectedPreparedFolderActionResolver,
)
from .m4_execution_store import (
    PersistentM4ExecutionStateStore,
    PersistentM4ExecutionStoreError,
)


class ProtectedChildFolderM4Runtime:
    """Fail-closed internal service for one protected Folder binding at a time."""

    def __init__(
        self,
        authorization_store: PersistentFolderM4AuthorizationStore,
        execution_store: PersistentM4ExecutionStateStore,
        transport: ChildFolderMutationTransport,
        *,
        authenticated_requester_digest: str,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not authorization_store.monotonic_checkpoint_protocol_bound:
            raise FolderM4AuthorizationError(
                "Protected Folder runtime requires authorization rollback protection."
            )
        if not execution_store.monotonic_checkpoint_protocol_bound:
            raise PersistentM4ExecutionStoreError(
                "Protected Folder runtime requires execution rollback protection."
            )
        _assert_independent_state_domains(authorization_store, execution_store)
        authorization_store.verify_ready()
        execution_store.verify_ready()
        self._authorization_store = authorization_store
        self._authenticated_requester_digest = authenticated_requester_digest
        self._authorization_checkpoint_protocol_bound = True
        self._execution_checkpoint_protocol_bound = (
            execution_store.monotonic_checkpoint_protocol_bound
        )
        resolver = ProtectedPreparedFolderActionResolver(authorization_store)
        verifier = ProtectedFolderM4AuthorizationVerifier(
            authorization_store,
            authenticated_requester_digest,
        )
        adapter = ChildFolderCreateM4Adapter(resolver, transport)
        self._kernel = M4ExecutionKernel(
            adapter,
            verifier,
            execution_store,
            clock=clock,
        )

    @property
    def audit_events(self) -> tuple[M4AuditEvent, ...]:
        """Return the persistent value-free execution audit projection."""

        return self._kernel.audit_events

    @property
    def execution_checkpoint_protocol_bound(self) -> bool:
        """Report whether the execution ledger has external rollback protection."""

        return self._execution_checkpoint_protocol_bound

    @property
    def authorization_checkpoint_protocol_bound(self) -> bool:
        """Report whether the authorization ledger has rollback protection."""

        return self._authorization_checkpoint_protocol_bound

    def execute_bound(
        self,
        authorization_ref: str,
    ) -> M4ExecutionResult:
        """Execute only the exact protected binding selected by an opaque ref.

        Time comes exclusively from the runtime's trusted injected clock.  A
        future MCP or HTTP caller must never be able to supply an execution
        timestamp and bypass authorization expiry.
        """

        binding = self._authorization_store.resolve_execution_binding(
            authorization_ref
        )
        if binding.plan.requester_digest != self._authenticated_requester_digest:
            raise FolderM4AuthorizationError(
                "Protected Folder binding does not match the authenticated requester."
            )
        return self._kernel.execute(
            binding.plan,
            binding.authorization,
        )


def _assert_independent_state_domains(
    authorization_store: PersistentFolderM4AuthorizationStore,
    execution_store: PersistentM4ExecutionStateStore,
) -> None:
    """Reject cross-ledger path, key, or checkpoint-store reuse."""

    try:
        paths = {
            authorization_store._path.resolve(),
            authorization_store._key_path.resolve(),
            authorization_store._promotion_key_path.resolve(),
            execution_store._path.resolve(),
            execution_store._key_path.resolve(),
        }
        independent = (
            len(paths) == 5
            and not hmac.compare_digest(
                authorization_store._key,
                execution_store._key,
            )
            and not hmac.compare_digest(
                authorization_store._promotion_key,
                execution_store._key,
            )
            and authorization_store._checkpoint_store_ref
            != execution_store._checkpoint_store_ref
        )
    except OSError:
        independent = False
    if not independent:
        raise FolderM4AuthorizationError(
            "Protected Folder runtime state domains are not independent."
        )


__all__ = ["ProtectedChildFolderM4Runtime"]
