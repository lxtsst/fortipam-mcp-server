"""Fail-closed, single-use orchestration for private C3 material leases.

This runtime is intentionally synchronous and transport-free. It coordinates
one opaque lease around one private consumer call and returns only categorical
outcomes. It does not register providers, resolve bindings, build product
requests, retry uncertain work, or expose a lease to MCP/planning surfaces.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
import re
from typing import Protocol

from .canonical import canonical_digest

from .material_provider import (
    C3MaterialBinding,
    MaterialBindingStatus,
    MaterialLease,
    MaterialLeaseCompletion,
    MaterialLeaseRequest,
    MaterialProvider,
    MaterialRevocationReason,
)


class MaterialRuntimeError(RuntimeError):
    """Raised for a malformed or unavailable private material lifecycle."""


class MaterialUseOutcome(StrEnum):
    VERIFIED = "verified"
    AMBIGUOUS = "ambiguous"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    FAILED = "failed"


class MaterialRuntimeOutcome(StrEnum):
    VERIFIED_AND_RELEASED = "verified_and_released"
    RECONCILIATION_REQUIRED = "reconciliation_required"


class MaterialUseClaimState(StrEnum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    REPLAY = "replay"


@dataclass(frozen=True, slots=True)
class MaterialUseClaim:
    state: MaterialUseClaimState
    outcome: MaterialRuntimeOutcome | None = None

    def __post_init__(self) -> None:
        if (self.state is MaterialUseClaimState.REPLAY) is (self.outcome is None):
            raise MaterialRuntimeError(_UNAVAILABLE)


class MaterialUseStateStore(Protocol):
    """Consume one value-free authorization and persist its closed outcome."""

    def claim(
        self,
        *,
        request_digest: str,
        authorization_digest: str,
    ) -> MaterialUseClaim: ...

    def finalize(
        self,
        *,
        request_digest: str,
        authorization_digest: str,
        outcome: MaterialRuntimeOutcome,
    ) -> None: ...


_DIGEST = re.compile(r"^[a-f0-9]{64}$")


class InMemoryMaterialUseStateStore:
    """Reference one-process claim store; persistent runtimes use SQLite."""

    def __init__(self) -> None:
        self._claims: dict[
            str, tuple[str, MaterialRuntimeOutcome | None]
        ] = {}
        self._authorizations: set[str] = set()

    def claim(
        self,
        *,
        request_digest: str,
        authorization_digest: str,
    ) -> MaterialUseClaim:
        _require_runtime_digest(request_digest)
        _require_runtime_digest(authorization_digest)
        existing = self._claims.get(request_digest)
        if existing is not None:
            if existing[0] != authorization_digest:
                raise MaterialRuntimeError(_UNAVAILABLE)
            if existing[1] is None:
                return MaterialUseClaim(MaterialUseClaimState.IN_PROGRESS)
            return MaterialUseClaim(MaterialUseClaimState.REPLAY, existing[1])
        if authorization_digest in self._authorizations:
            raise MaterialRuntimeError(_UNAVAILABLE)
        self._claims[request_digest] = (authorization_digest, None)
        self._authorizations.add(authorization_digest)
        return MaterialUseClaim(MaterialUseClaimState.NEW)

    def finalize(
        self,
        *,
        request_digest: str,
        authorization_digest: str,
        outcome: MaterialRuntimeOutcome,
    ) -> None:
        _require_runtime_digest(request_digest)
        _require_runtime_digest(authorization_digest)
        existing = self._claims.get(request_digest)
        if (
            existing is None
            or existing[0] != authorization_digest
            or existing[1] is not None
            or not isinstance(outcome, MaterialRuntimeOutcome)
        ):
            raise MaterialRuntimeError(_UNAVAILABLE)
        self._claims[request_digest] = (authorization_digest, outcome)


_UNAVAILABLE = "The private material lifecycle is unavailable."


class MaterialLeaseCoordinator:
    """Coordinate exactly one provider lease and one private consumer call."""

    def __init__(
        self,
        provider: MaterialProvider,
        state_store: MaterialUseStateStore | None = None,
    ) -> None:
        self._provider = provider
        self._state_store = (
            InMemoryMaterialUseStateStore()
            if state_store is None
            else state_store
        )

    def execute_once(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
        consumer: Callable[[MaterialLease], MaterialUseOutcome],
        *,
        now_epoch: int,
    ) -> MaterialRuntimeOutcome:
        if (
            type(now_epoch) is not int
            or now_epoch < request.requested_at
            or now_epoch >= request.expires_at
        ):
            raise MaterialRuntimeError(_UNAVAILABLE)

        try:
            binding_status = self._provider.validate_binding(binding, request)
        except Exception:
            raise MaterialRuntimeError(_UNAVAILABLE) from None
        if binding_status is not MaterialBindingStatus.AVAILABLE:
            raise MaterialRuntimeError(_UNAVAILABLE)

        request_digest = material_lease_request_digest(request)
        return _MaterialLeaseUse(self._state_store,
            acquire=lambda: self._provider.acquire_lease(binding, request),
            release=self._provider.release_lease,
            revoke=lambda lease, reason: self._provider.revoke_lease(lease, reason=reason),
        ).execute_once(request_digest=request_digest,
            authorization_digest=request.authorization_digest, consumer=consumer)


class _MaterialLeaseUse:
    """Shared private claimed-use engine; request/source validation stays outside.

    Normal requests retain their typed action-bound provider contract. Inactive owner-file
    composition reuses this engine with its independently validated private
    context, never relabeling it as an accepted inventory/vault source.
    """

    def __init__(self, state_store: MaterialUseStateStore, *,
                 acquire: Callable[[], MaterialLease],
                 release: Callable[[MaterialLease], MaterialLeaseCompletion],
                 revoke: Callable[[MaterialLease, MaterialRevocationReason], MaterialLeaseCompletion]) -> None:
        self._state_store, self._acquire, self._complete, self._cancel = state_store, acquire, release, revoke

    def execute_once(self, *, request_digest: str, authorization_digest: str,
                     consumer: Callable[[MaterialLease], MaterialUseOutcome]) -> MaterialRuntimeOutcome:
        _require_runtime_digest(request_digest)
        _require_runtime_digest(authorization_digest)
        try:
            claim = self._state_store.claim(
                request_digest=request_digest,
                authorization_digest=authorization_digest,
            )
        except Exception:
            raise MaterialRuntimeError(_UNAVAILABLE) from None
        if claim.state is MaterialUseClaimState.REPLAY:
            assert claim.outcome is not None
            return claim.outcome
        if claim.state is MaterialUseClaimState.IN_PROGRESS:
            return MaterialRuntimeOutcome.RECONCILIATION_REQUIRED

        try:
            lease = self._acquire()
        except Exception:
            return self._finalize(
                request_digest,
                authorization_digest,
                MaterialRuntimeOutcome.RECONCILIATION_REQUIRED,
            )
        if not isinstance(lease, MaterialLease):
            self._finalize(
                request_digest,
                authorization_digest,
                MaterialRuntimeOutcome.RECONCILIATION_REQUIRED,
            )
            raise MaterialRuntimeError(_UNAVAILABLE)

        try:
            use_outcome = consumer(lease)
        except Exception:
            self._revoke(lease, MaterialRevocationReason.RECONCILIATION_REQUIRED)
            return self._finalize(
                request_digest,
                authorization_digest,
                MaterialRuntimeOutcome.RECONCILIATION_REQUIRED,
            )

        if use_outcome is MaterialUseOutcome.VERIFIED:
            return self._finalize(
                request_digest,
                authorization_digest,
                self._release(lease),
            )
        reason = {
            MaterialUseOutcome.AMBIGUOUS: (
                MaterialRevocationReason.RECONCILIATION_REQUIRED
            ),
            MaterialUseOutcome.TIMED_OUT: MaterialRevocationReason.PROVIDER_TIMEOUT,
            MaterialUseOutcome.CANCELLED: MaterialRevocationReason.CANCELLED,
            MaterialUseOutcome.FAILED: MaterialRevocationReason.RECONCILIATION_REQUIRED,
        }.get(use_outcome)
        if reason is None:
            self._revoke(lease, MaterialRevocationReason.RECONCILIATION_REQUIRED)
            self._finalize(
                request_digest,
                authorization_digest,
                MaterialRuntimeOutcome.RECONCILIATION_REQUIRED,
            )
            raise MaterialRuntimeError(_UNAVAILABLE)
        self._revoke(lease, reason)
        return self._finalize(
            request_digest,
            authorization_digest,
            MaterialRuntimeOutcome.RECONCILIATION_REQUIRED,
        )

    def _finalize(
        self,
        request_digest: str,
        authorization_digest: str,
        outcome: MaterialRuntimeOutcome,
    ) -> MaterialRuntimeOutcome:
        try:
            self._state_store.finalize(
                request_digest=request_digest,
                authorization_digest=authorization_digest,
                outcome=outcome,
            )
        except Exception:
            return MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
        return outcome

    def _release(self, lease: MaterialLease) -> MaterialRuntimeOutcome:
        try:
            completion = self._complete(lease)
        except Exception:
            return MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
        if completion is MaterialLeaseCompletion.RELEASED:
            return MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
        return MaterialRuntimeOutcome.RECONCILIATION_REQUIRED

    def _revoke(
        self,
        lease: MaterialLease,
        reason: MaterialRevocationReason,
    ) -> None:
        try:
            self._cancel(lease, reason)
        except Exception:
            pass


def material_lease_request_digest(request: MaterialLeaseRequest) -> str:
    """Digest the complete value-free lease control binding."""

    if not isinstance(request, MaterialLeaseRequest):
        raise MaterialRuntimeError(_UNAVAILABLE)
    return canonical_digest(
        {
            "action_id": request.action_id,
            "action_version": request.action_version,
            "audience_digest": request.audience_digest,
            "authorization_digest": request.authorization_digest,
            "expires_at": request.expires_at,
            "plan_digest": request.plan_digest,
            "policy_decision_digest": request.policy_decision_digest,
            "provider_class": request.provider_class.value,
            "purpose": request.purpose.value,
            "requested_at": request.requested_at,
            "scope_digest": request.scope_digest,
        }
    )


def _require_runtime_digest(value: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise MaterialRuntimeError(_UNAVAILABLE)


__all__ = [
    "InMemoryMaterialUseStateStore",
    "MaterialLeaseCoordinator",
    "MaterialRuntimeError",
    "MaterialRuntimeOutcome",
    "MaterialUseClaim",
    "MaterialUseClaimState",
    "MaterialUseOutcome",
    "MaterialUseStateStore",
    "material_lease_request_digest",
]
