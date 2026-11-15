"""Reuse the owner-only Unix planning CAS for exact M4 execution-store tails.

This extracts the existing bulk-import bridge. It adds no authority, service,
execution surface or local fallback when the external checkpoint is unavailable.
"""
from __future__ import annotations

from v4_planning import PlanningStoreTail
from v4_planning.models import require_ref

from .m4_execution_store import M4ExecutionStoreTail, M4MonotonicCheckpointError
from .planning_checkpoint_sidecar import UnixPlanningCheckpointClient

_ERROR = "The private M4 execution checkpoint is unavailable."


class UnixM4ExecutionCheckpoint:
    """Preserve all nonempty sequence/HMAC values across the existing protocol."""
    def __init__(self, client: UnixPlanningCheckpointClient, store_ref: str) -> None:
        if type(client) is not UnixPlanningCheckpointClient:
            raise M4MonotonicCheckpointError(_ERROR)
        require_ref(store_ref, 'execution checkpoint store')
        self._client, self._store_ref = client, store_ref
        self.authority_ref = client.authority_ref
        client.verify_ready()

    def _tail(self, tail: M4ExecutionStoreTail) -> PlanningStoreTail:
        if type(tail) is not M4ExecutionStoreTail or tail.store_ref != self._store_ref:
            raise ValueError
        tail.__post_init__()
        return PlanningStoreTail(tail.store_ref, tail.sequence,
            'chain-root' if tail.sequence == 0 else tail.chain_hmac)

    def verify(self, tail: M4ExecutionStoreTail) -> None:
        try:
            self._client.verify(self._tail(tail))
        except Exception:
            raise M4MonotonicCheckpointError(_ERROR) from None

    def advance(self, previous: M4ExecutionStoreTail, current: M4ExecutionStoreTail) -> None:
        try:
            self._client.advance(self._tail(previous), self._tail(current))
        except Exception:
            raise M4MonotonicCheckpointError(_ERROR) from None
