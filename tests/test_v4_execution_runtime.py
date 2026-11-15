from __future__ import annotations

import inspect

import pytest

from v4_planning.canonical import canonical_digest
from v4_planning.execution_kernel import (
    M4AdapterDenied,
    M4AuthorizationDenied,
    M4ExecutionAuthorization,
    M4ExecutionPlan,
)
from v4_planning.adapter_registry import (
    EmptyM4AdapterRegistry,
    EmptyRegistryM4ExecutionAdapter,
)
from v4_planning.execution_runtime import PackagedDenyAllM4ExecutionRuntime


NOW = 1_900_000_000
REQUESTER = "1" * 64
APPROVER = "2" * 64
SUMMARY = "3" * 64
CONFIRMATION = "4" * 64
APPROVAL = "5" * 64
PARAMETERS = "6" * 64
CURRENT = "7" * 64
EXPECTED = "8" * 64
IDEMPOTENCY = "9" * 64


def _plan() -> M4ExecutionPlan:
    values = {
        "action_id": "folder-create",
        "action_version": "3.2.0",
        "adapter_ref": "packaged-deny-adapter-01",
        "approval_digest": APPROVAL,
        "compensation_ref": None,
        "confirmation_digest": CONFIRMATION,
        "expected_current_digest": CURRENT,
        "expected_state_digest": EXPECTED,
        "expires_at": NOW + 300,
        "idempotency_digest": IDEMPOTENCY,
        "parameters_digest": PARAMETERS,
        "plan_ref": "packaged-m4-plan-ref-01",
        "requester_digest": REQUESTER,
        "revision": 1,
        "summary_digest": SUMMARY,
        "target_ref": "packaged-target-ref-01",
    }
    return M4ExecutionPlan(
        plan_ref="packaged-m4-plan-ref-01",
        revision=1,
        action_id="folder-create",
        action_version="3.2.0",
        adapter_ref="packaged-deny-adapter-01",
        target_ref="packaged-target-ref-01",
        requester_digest=REQUESTER,
        summary_digest=SUMMARY,
        confirmation_digest=CONFIRMATION,
        approval_digest=APPROVAL,
        parameters_digest=PARAMETERS,
        expected_current_digest=CURRENT,
        expected_state_digest=EXPECTED,
        idempotency_digest=IDEMPOTENCY,
        expires_at=NOW + 300,
        compensation_ref=None,
        plan_digest=canonical_digest(values),
    )


def _authorization(plan: M4ExecutionPlan) -> M4ExecutionAuthorization:
    values = {
        "approval_digest": APPROVAL,
        "approval_ref": "packaged-approval-ref-01",
        "approver_digest": APPROVER,
        "authorization_ref": "packaged-authorization-ref-01",
        "confirmation_digest": CONFIRMATION,
        "confirmation_ref": "packaged-confirmation-ref-01",
        "execution_authorized": True,
        "expires_at": NOW + 120,
        "issued_at": NOW - 1,
        "one_time": True,
        "plan_digest": plan.plan_digest,
        "plan_ref": plan.plan_ref,
        "requester_digest": REQUESTER,
    }
    return M4ExecutionAuthorization(
        authorization_ref="packaged-authorization-ref-01",
        plan_ref=plan.plan_ref,
        plan_digest=plan.plan_digest,
        requester_digest=REQUESTER,
        confirmation_ref="packaged-confirmation-ref-01",
        confirmation_digest=CONFIRMATION,
        approval_ref="packaged-approval-ref-01",
        approval_digest=APPROVAL,
        approver_digest=APPROVER,
        issued_at=NOW - 1,
        expires_at=NOW + 120,
        one_time=True,
        execution_authorized=True,
        authorization_digest=canonical_digest(values),
    )


def test_packaged_runtime_status_is_explicitly_deny_all() -> None:
    assert PackagedDenyAllM4ExecutionRuntime.status() == {
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


def test_packaged_runtime_denies_before_adapter_or_state_claim() -> None:
    plan = _plan()

    with pytest.raises(M4AuthorizationDenied, match="No trusted M4"):
        PackagedDenyAllM4ExecutionRuntime().execute(
            plan,
            _authorization(plan),
            now_epoch=NOW,
        )


def test_packaged_runtime_has_no_injection_or_mcp_configuration_surface() -> None:
    assert tuple(inspect.signature(PackagedDenyAllM4ExecutionRuntime).parameters) == ()
    assert tuple(PackagedDenyAllM4ExecutionRuntime.__slots__) == (
        "_adapter_registry",
        "_kernel",
    )
    assert not hasattr(PackagedDenyAllM4ExecutionRuntime, "register_adapter")
    assert not hasattr(PackagedDenyAllM4ExecutionRuntime, "configure")


def test_empty_registry_has_no_registration_surface_and_denies_every_plan() -> None:
    registry = EmptyM4AdapterRegistry()
    adapter = EmptyRegistryM4ExecutionAdapter(registry)
    plan = _plan()

    assert registry.registered_adapter_count == 0
    assert tuple(EmptyM4AdapterRegistry.__slots__) == ()
    assert not hasattr(registry, "register")
    assert not hasattr(registry, "configure")
    with pytest.raises(M4AdapterDenied, match="No M4 product adapter"):
        registry.resolve(plan)
    with pytest.raises(M4AdapterDenied, match="No M4 product adapter"):
        adapter.read_current(plan)
