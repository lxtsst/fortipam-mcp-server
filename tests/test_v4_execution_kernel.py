from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from v4_planning import (
    DenyAllM4Adapter,
    InMemoryM4ExecutionStateStore,
    M4AdapterAmbiguous,
    M4AdapterFailure,
    M4AdapterTimeout,
    M4AuthorizationDenied,
    M4Compensation,
    M4ExecutionAuthorization,
    M4ExecutionError,
    M4ExecutionKernel,
    M4ExecutionPlan,
    M4Outcome,
    M4Verification,
    canonical_digest,
)


NOW = 1_000
REQUESTER = "a" * 64
APPROVER = "b" * 64
SUMMARY = "c" * 64
CONFIRMATION = "d" * 64
APPROVAL = "e" * 64
PARAMETERS = "f" * 64
CURRENT = "1" * 64
EXPECTED = "2" * 64
IDEMPOTENCY = "3" * 64


class _Verifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        del plan, authorization, now_epoch
        self.calls += 1


class _Adapter:
    def __init__(self) -> None:
        self.current = CURRENT
        self.postcondition = EXPECTED
        self.error: Exception | None = None
        self.dispatch_error: Exception | None = None
        self.calls: list[str] = []

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self.calls.append("read_current")
        if isinstance(self.error, (M4AdapterTimeout, M4AdapterAmbiguous)):
            raise self.error
        return self.current

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        self.calls.append("dispatch")
        if self.dispatch_error is not None:
            raise self.dispatch_error
        if self.error is not None:
            raise self.error

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self.calls.append("read_postcondition")
        if isinstance(self.error, (M4AdapterTimeout, M4AdapterAmbiguous)):
            raise self.error
        return self.postcondition


def _plan(*, plan_ref: str = "m4-plan-reference-01", compensation_ref: str | None = None) -> M4ExecutionPlan:
    values = {
        "action_id": "folder-create",
        "action_version": "3.2.0",
        "adapter_ref": "synthetic-adapter-01",
        "approval_digest": APPROVAL,
        "compensation_ref": compensation_ref,
        "confirmation_digest": CONFIRMATION,
        "expected_current_digest": CURRENT,
        "expected_state_digest": EXPECTED,
        "expires_at": NOW + 300,
        "idempotency_digest": IDEMPOTENCY,
        "parameters_digest": PARAMETERS,
        "plan_ref": plan_ref,
        "requester_digest": REQUESTER,
        "revision": 1,
        "summary_digest": SUMMARY,
        "target_ref": "public-folder-target-01",
    }
    return M4ExecutionPlan(
        plan_ref=plan_ref,
        revision=1,
        action_id="folder-create",
        action_version="3.2.0",
        adapter_ref="synthetic-adapter-01",
        target_ref="public-folder-target-01",
        requester_digest=REQUESTER,
        summary_digest=SUMMARY,
        confirmation_digest=CONFIRMATION,
        approval_digest=APPROVAL,
        parameters_digest=PARAMETERS,
        expected_current_digest=CURRENT,
        expected_state_digest=EXPECTED,
        idempotency_digest=IDEMPOTENCY,
        expires_at=NOW + 300,
        compensation_ref=compensation_ref,
        plan_digest=canonical_digest(values),
    )


def _authorization(plan: M4ExecutionPlan) -> M4ExecutionAuthorization:
    values = {
        "approval_digest": APPROVAL,
        "approval_ref": "approval-reference-01",
        "approver_digest": APPROVER,
        "authorization_ref": "execution-authorization-01",
        "confirmation_digest": CONFIRMATION,
        "confirmation_ref": "confirmation-reference-01",
        "execution_authorized": True,
        "expires_at": NOW + 120,
        "issued_at": NOW - 1,
        "one_time": True,
        "plan_digest": plan.plan_digest,
        "plan_ref": plan.plan_ref,
        "requester_digest": REQUESTER,
    }
    return M4ExecutionAuthorization(
        authorization_ref="execution-authorization-01",
        plan_ref=plan.plan_ref,
        plan_digest=plan.plan_digest,
        requester_digest=REQUESTER,
        confirmation_ref="confirmation-reference-01",
        confirmation_digest=CONFIRMATION,
        approval_ref="approval-reference-01",
        approval_digest=APPROVAL,
        approver_digest=APPROVER,
        issued_at=NOW - 1,
        expires_at=NOW + 120,
        one_time=True,
        execution_authorized=True,
        authorization_digest=canonical_digest(values),
    )


def test_success_is_bounded_read_dispatch_readback() -> None:
    adapter = _Adapter()
    result = M4ExecutionKernel(adapter, _Verifier()).execute(
        _plan(), _authorization(_plan()), now_epoch=NOW
    )

    assert result.as_dict() == {
        "compensation": "not_requested",
        "idempotent_replay": False,
        "outcome": "succeeded",
        "verification": "verified",
    }
    assert adapter.calls == ["read_current", "dispatch", "read_postcondition"]


def test_default_authorization_verifier_denies_before_adapter() -> None:
    adapter = _Adapter()
    with pytest.raises(M4AuthorizationDenied):
        M4ExecutionKernel(adapter).execute(_plan(), _authorization(_plan()), now_epoch=NOW)
    assert adapter.calls == []


def test_default_adapter_is_denied_without_product_transport() -> None:
    result = M4ExecutionKernel(
        DenyAllM4Adapter(), _Verifier()
    ).execute(_plan(), _authorization(_plan()), now_epoch=NOW)
    assert result.outcome is M4Outcome.DENIED
    assert result.verification is M4Verification.NOT_STARTED


def test_authorization_binding_mismatch_is_rejected_before_claim() -> None:
    plan = _plan()
    authorization = _authorization(plan)
    changed_values = dict(authorization.canonical_content())
    changed_values["confirmation_digest"] = "9" * 64
    changed = replace(
        authorization,
        confirmation_digest="9" * 64,
        authorization_digest=canonical_digest(changed_values),
    )

    with pytest.raises(M4AuthorizationDenied):
        M4ExecutionKernel(_Adapter(), _Verifier()).execute(plan, changed, now_epoch=NOW)


def test_prewrite_drift_never_dispatches() -> None:
    adapter = _Adapter()
    adapter.current = "9" * 64
    result = M4ExecutionKernel(adapter, _Verifier()).execute(
        _plan(), _authorization(_plan()), now_epoch=NOW
    )
    assert result.outcome is M4Outcome.PRECONDITION_FAILED
    assert adapter.calls == ["read_current"]


def test_unknown_current_read_never_requests_compensation() -> None:
    adapter = _Adapter()
    adapter.error = M4AdapterTimeout()
    plan = _plan(compensation_ref="folder-delete-compensation-01")
    result = M4ExecutionKernel(adapter, _Verifier()).execute(
        plan, _authorization(plan), now_epoch=NOW
    )
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert result.compensation is M4Compensation.NOT_REQUESTED
    assert adapter.calls == ["read_current"]


@pytest.mark.parametrize("error", [M4AdapterTimeout(), M4AdapterAmbiguous()])
def test_dispatch_uncertainty_requires_reconciliation_and_never_retries(error: Exception) -> None:
    store = InMemoryM4ExecutionStateStore()
    adapter = _Adapter()
    adapter.dispatch_error = error
    plan = _plan(compensation_ref="folder-delete-compensation-01")
    authorization = _authorization(plan)
    first = M4ExecutionKernel(adapter, _Verifier(), store).execute(plan, authorization, now_epoch=NOW)
    adapter.dispatch_error = None
    second = M4ExecutionKernel(adapter, _Verifier(), store).execute(plan, authorization, now_epoch=NOW)

    assert first.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert first.compensation is M4Compensation.REQUIRED
    assert second.idempotent_replay is True
    assert second.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert adapter.calls == ["read_current", "dispatch"]


def test_postcondition_mismatch_is_not_success() -> None:
    adapter = _Adapter()
    adapter.postcondition = "8" * 64
    plan = _plan(compensation_ref="folder-delete-compensation-01")
    result = M4ExecutionKernel(adapter, _Verifier()).execute(
        plan, _authorization(plan), now_epoch=NOW
    )
    assert result.outcome is M4Outcome.VERIFICATION_FAILED
    assert result.verification is M4Verification.FAILED
    assert result.compensation is M4Compensation.REQUIRED


def test_declared_execution_error_is_bounded_and_replayed() -> None:
    store = InMemoryM4ExecutionStateStore()
    adapter = _Adapter()
    adapter.error = M4AdapterFailure()
    plan = _plan()
    authorization = _authorization(plan)
    first = M4ExecutionKernel(adapter, _Verifier(), store).execute(plan, authorization, now_epoch=NOW)
    second = M4ExecutionKernel(adapter, _Verifier(), store).execute(plan, authorization, now_epoch=NOW)
    assert first.outcome is M4Outcome.EXECUTION_FAILED
    assert second.idempotent_replay is True
    assert adapter.calls == ["read_current", "dispatch"]


def test_existing_in_progress_claim_is_restart_safe_and_not_redispatched() -> None:
    store = InMemoryM4ExecutionStateStore()
    plan = _plan()
    authorization = _authorization(plan)
    context = canonical_digest(
        {
            "authorization_digest": authorization.authorization_digest,
            "plan_digest": plan.plan_digest,
            "revision": plan.revision,
        }
    )
    store.claim(
        plan_ref=plan.plan_ref,
        requester_digest=plan.requester_digest,
        idempotency_digest=plan.idempotency_digest,
        context_digest=context,
        authorization_digest=authorization.authorization_digest,
    )
    adapter = _Adapter()
    result = M4ExecutionKernel(adapter, _Verifier(), store).execute(plan, authorization, now_epoch=NOW)
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert result.idempotent_replay is True
    assert adapter.calls == []


def test_same_idempotency_namespace_with_changed_context_is_rejected() -> None:
    store = InMemoryM4ExecutionStateStore()
    plan = _plan()
    authorization = _authorization(plan)
    kernel = M4ExecutionKernel(_Adapter(), _Verifier(), store)
    kernel.execute(plan, authorization, now_epoch=NOW)
    changed_values = dict(plan.canonical_content())
    changed_values["expected_state_digest"] = "7" * 64
    changed = replace(
        plan,
        expected_state_digest="7" * 64,
        plan_digest=canonical_digest(changed_values),
    )
    changed_auth_values = dict(authorization.canonical_content())
    changed_auth_values["plan_digest"] = changed.plan_digest
    changed_auth = replace(
        authorization,
        plan_digest=changed.plan_digest,
        authorization_digest=canonical_digest(changed_auth_values),
    )
    with pytest.raises(M4ExecutionError, match="idempotency context conflict"):
        kernel.execute(changed, changed_auth, now_epoch=NOW)


def test_kernel_audit_is_value_free() -> None:
    adapter = _Adapter()
    plan = _plan()
    kernel = M4ExecutionKernel(adapter, _Verifier())
    kernel.execute(plan, _authorization(plan), now_epoch=NOW)
    rendered = str(kernel.audit_events)
    for value in (
        plan.target_ref,
        plan.plan_ref,
        "approval-reference-01",
        "confirmation-reference-01",
    ):
        assert value not in rendered


def test_kernel_has_no_transport_or_mcp_registration_surface() -> None:
    source = (Path(__file__).parents[1] / "v4_planning" / "execution_kernel.py").read_text()
    for forbidden in ("import httpx", "import requests", "import socket", "from mcp"):
        assert forbidden not in source
