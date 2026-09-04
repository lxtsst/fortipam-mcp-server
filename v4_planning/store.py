"""Append-only protected record store for the repository-only V4 M3 candidate.

The implementation is deliberately in-memory and process-local.  It exposes no
serialization, filesystem, network, MCP, or product adapter surface.  A future
persistent implementation must preserve the same exact binding checks.
"""

from __future__ import annotations

from .models import ConfirmationRecord, FinalIntentSummary, PreparedPlan


class ProtectedStoreError(ValueError):
    """Raised when an immutable planning record cannot be stored safely."""


class InMemoryProtectedPlanningStore:
    """Append-only M3 record store with exact digest and revision bindings."""

    def __init__(self) -> None:
        self._summaries: dict[tuple[str, int], FinalIntentSummary] = {}
        self._confirmations: dict[str, ConfirmationRecord] = {}
        self._plans: dict[str, PreparedPlan] = {}

    def put_summary(self, summary: FinalIntentSummary) -> None:
        key = (summary.summary_ref, summary.revision)
        existing = self._summaries.get(key)
        if existing is not None:
            if existing != summary:
                raise ProtectedStoreError("Summary revision is immutable.")
            return
        if summary.revision > 1 and (summary.summary_ref, summary.revision - 1) not in self._summaries:
            raise ProtectedStoreError("Summary revision history is incomplete.")
        if any(
            ref == summary.summary_ref and revision > summary.revision
            for ref, revision in self._summaries
        ):
            raise ProtectedStoreError("Summary revision cannot move backwards.")
        self._summaries[key] = summary

    def put_confirmation(self, record: ConfirmationRecord) -> None:
        summary = self._summaries.get((record.summary_ref, record.summary_revision))
        if summary is None:
            raise ProtectedStoreError("Confirmation requires the exact stored summary revision.")
        if (
            record.summary_digest != summary.summary_digest
            or record.requester_digest != summary.requester_digest
            or record.audience_ref != summary.audience_ref
            or record.confirmed_at < summary.created_at
            or record.expires_at > summary.expires_at
        ):
            raise ProtectedStoreError("Confirmation is not bound to the stored summary.")
        existing = self._confirmations.get(record.confirmation_ref)
        if existing is not None and existing != record:
            raise ProtectedStoreError("Confirmation record is immutable.")
        self._confirmations[record.confirmation_ref] = record

    def put_plan(self, plan: PreparedPlan) -> None:
        summary = self._summaries.get((plan.summary_ref, plan.summary_revision))
        confirmation = self._confirmations.get(plan.confirmation_ref)
        if summary is None or confirmation is None:
            raise ProtectedStoreError("Plan requires its exact summary and confirmation records.")
        if (
            plan.summary_digest != summary.summary_digest
            or plan.confirmation_digest != confirmation.record_digest
            or plan.requester_digest != summary.requester_digest
            or plan.requester_digest != confirmation.requester_digest
            or plan.created_at < confirmation.confirmed_at
            or plan.expires_at > confirmation.expires_at
            or plan.environment_ref != summary.environment_ref
            or plan.scope_ref != summary.scope_ref
        ):
            raise ProtectedStoreError("Plan is not bound to the stored record chain.")
        existing = self._plans.get(plan.plan_ref)
        if existing is not None and existing != plan:
            raise ProtectedStoreError("Prepared plan is immutable.")
        self._plans[plan.plan_ref] = plan

    def get_summary(self, summary_ref: str, revision: int) -> FinalIntentSummary:
        try:
            return self._summaries[(summary_ref, revision)]
        except KeyError as exc:
            raise ProtectedStoreError("Summary revision is unavailable.") from exc

    def get_confirmation(self, confirmation_ref: str) -> ConfirmationRecord:
        try:
            return self._confirmations[confirmation_ref]
        except KeyError as exc:
            raise ProtectedStoreError("Confirmation record is unavailable.") from exc

    def get_plan(self, plan_ref: str) -> PreparedPlan:
        try:
            return self._plans[plan_ref]
        except KeyError as exc:
            raise ProtectedStoreError("Prepared plan is unavailable.") from exc


__all__ = ["InMemoryProtectedPlanningStore", "ProtectedStoreError"]
