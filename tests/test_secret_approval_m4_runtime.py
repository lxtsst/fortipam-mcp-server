from __future__ import annotations

from dataclasses import replace

import pytest

from fortipam_mcp.approval_and_observe_projection_source import (
    ApprovalAndObserveBinding,
    approval_and_observe_projection_contract,
)
from fortipam_mcp.secret_approval_m4_runtime import (
    ProtectedSecretApprovalM4Runtime,
    SECRET_APPROVAL_ACTION_ID,
    SECRET_APPROVAL_ACTION_VERSION,
    SECRET_APPROVAL_ADAPTER_REF,
    SecretApprovalM4ExecutionBinding,
    secret_approval_binding_digest,
    secret_approval_parameters_digest,
)
from fortipam_mcp.secret_metadata_http_transport import (
    SecretApprovalProjectionInspection,
)
from test_v4_execution_kernel import NOW, _authorization, _plan
from v4_planning import (
    AuthoritativeProjection,
    InMemoryM4ExecutionStateStore,
    M4ExecutionAuthorization,
    M4ExecutionPlan,
    M4AuthorizationDenied,
    M4Outcome,
    M4Verification,
    ObjectClass,
    canonical_digest,
)


def _binding() -> ApprovalAndObserveBinding:
    return ApprovalAndObserveBinding(
        approval_profile_object_ref="approval-profile-object-ref01",
        approval_profile_ref="approval-profile-ref0001",
        approval_profile_name="mcp-v4-approval-profile-01",
        secret_approval_object_ref="secret-approval-object-ref01",
        folder_path="Public/folder",
        secret_name="mcp-v4-secret-metadata-01",
        secret_id=42,
    )


def _state_digest(*, enabled: bool) -> str:
    return AuthoritativeProjection.from_mapping(
        contract=approval_and_observe_projection_contract(
            ObjectClass.SECRET_APPROVAL_BINDING
        ),
        object_ref=_binding().secret_approval_object_ref,
        observed_at=0,
        fresh_until=1,
        fields={
            "exists": True,
            "approval_profile_attached": enabled,
            "interactive_approval_required": enabled,
            "job_approval_required": False,
            "owner_bypass_allowed": False,
        },
    ).state_digest


def _approval_plan() -> M4ExecutionPlan:
    base = _plan()
    content = dict(base.canonical_content())
    content.update(
        {
            "action_id": SECRET_APPROVAL_ACTION_ID,
            "action_version": SECRET_APPROVAL_ACTION_VERSION,
            "adapter_ref": SECRET_APPROVAL_ADAPTER_REF,
            "target_ref": _binding().secret_approval_object_ref,
            "parameters_digest": secret_approval_parameters_digest(_binding()),
            "expected_current_digest": _state_digest(enabled=False),
            "expected_state_digest": _state_digest(enabled=True),
        }
    )
    return replace(
        base,
        action_id=SECRET_APPROVAL_ACTION_ID,
        action_version=SECRET_APPROVAL_ACTION_VERSION,
        adapter_ref=SECRET_APPROVAL_ADAPTER_REF,
        target_ref=_binding().secret_approval_object_ref,
        parameters_digest=secret_approval_parameters_digest(_binding()),
        expected_current_digest=_state_digest(enabled=False),
        expected_state_digest=_state_digest(enabled=True),
        plan_digest=canonical_digest(content),
    )


class _Resolver:
    def __init__(self, binding: SecretApprovalM4ExecutionBinding) -> None:
        self.binding = binding

    def resolve_execution_binding(self, authorization_ref: str):
        assert authorization_ref == self.binding.authorization.authorization_ref
        return self.binding


class _Verifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(
        self,
        plan: M4ExecutionPlan,
        authorization: M4ExecutionAuthorization,
        *,
        now_epoch: int,
    ) -> None:
        assert authorization.plan_digest == plan.plan_digest
        assert now_epoch == NOW
        self.calls += 1


class _State:
    def __init__(self) -> None:
        self.enabled = False
        self.write_calls: list[tuple[int, str]] = []
        self.read_calls = 0

    def enable_interactive_approval(
        self,
        secret_id: int,
        approval_profile_name: str,
    ) -> None:
        self.write_calls.append((secret_id, approval_profile_name))
        self.enabled = True

    def inspect_approval_projection(
        self,
        folder_path: str,
        secret_name: str,
        approval_profile_name: str,
        *,
        expected_secret_id: int,
    ) -> SecretApprovalProjectionInspection:
        assert (
            folder_path,
            secret_name,
            approval_profile_name,
            expected_secret_id,
        ) == (
            "Public/folder",
            "mcp-v4-secret-metadata-01",
            "mcp-v4-approval-profile-01",
            42,
        )
        self.read_calls += 1
        return SecretApprovalProjectionInspection(
            True,
            self.enabled,
            False,
            False,
            self.enabled,
            not self.enabled,
            True,
        )


def _runtime(state: _State) -> tuple[ProtectedSecretApprovalM4Runtime, _Verifier]:
    plan = _approval_plan()
    authorization = _authorization(plan)
    verifier = _Verifier()
    runtime = ProtectedSecretApprovalM4Runtime(
        _Resolver(SecretApprovalM4ExecutionBinding(plan, authorization, _binding())),
        verifier,
        InMemoryM4ExecutionStateStore(),
        state,
        state,
        authenticated_requester_digest=plan.requester_digest,
        clock=lambda: NOW,
    )
    return runtime, verifier


def test_m4_secret_approval_is_authorized_read_write_readback() -> None:
    state = _State()
    runtime, verifier = _runtime(state)

    result = runtime.execute_bound(
        "execution-authorization-01",
        expected_approval_binding_digest=secret_approval_binding_digest(_binding()),
    )

    assert result.outcome is M4Outcome.SUCCEEDED
    assert result.verification is M4Verification.VERIFIED
    assert verifier.calls == 1
    assert state.write_calls == [(42, "mcp-v4-approval-profile-01")]
    assert state.read_calls == 2


def test_m4_secret_approval_drift_stops_before_write() -> None:
    state = _State()
    state.enabled = True
    runtime, verifier = _runtime(state)

    result = runtime.execute_bound(
        "execution-authorization-01",
        expected_approval_binding_digest=secret_approval_binding_digest(_binding()),
    )

    assert result.outcome is M4Outcome.PRECONDITION_FAILED
    assert verifier.calls == 1
    assert state.write_calls == []
    assert state.read_calls == 1


def test_m4_approval_incomplete_http_projection_cannot_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fortipam_mcp.secret_metadata_http_transport as metadata
    from test_secret_metadata_http_transport import (
        _Client, _DetailConnection, _DetailResponse, _Response, _config,
    )

    response = _DetailResponse({"results": [{
        "id": 42,
        "name": _binding().secret_name,
        "need-approval-job": "disable",
        "bypass-approval": "disable",
        "approval-profile": "",
        "field": [{"name": "Password", "value": "never-decode"}],
    }]})
    monkeypatch.setattr(metadata, "_ssl_context", lambda _: object())
    reader = metadata.FortiPamSecretMetadataHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": {"id": 42}})], [],
        ),
        detail_connection_factory=lambda *_a, **_k: _DetailConnection(response, []),
    )
    plan = _approval_plan()
    state = _State()
    runtime = ProtectedSecretApprovalM4Runtime(
        _Resolver(SecretApprovalM4ExecutionBinding(plan, _authorization(plan), _binding())),
        _Verifier(),
        InMemoryM4ExecutionStateStore(),
        state,
        reader,
        authenticated_requester_digest=plan.requester_digest,
        clock=lambda: NOW,
    )

    result = runtime.execute_bound(
        "execution-authorization-01",
        expected_approval_binding_digest=secret_approval_binding_digest(_binding()),
    )

    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert state.write_calls == []
    assert response.closed is True


def test_m4_secret_approval_rejects_private_binding_drift_before_read() -> None:
    state = _State()
    runtime, verifier = _runtime(state)

    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(
            "execution-authorization-01",
            expected_approval_binding_digest="0" * 64,
        )

    assert verifier.calls == 0
    assert state.write_calls == []
    assert state.read_calls == 0


def test_m4_secret_approval_rejects_parameter_binding_drift_before_read() -> None:
    state = _State()
    plan = _approval_plan()
    content = dict(plan.canonical_content())
    content["parameters_digest"] = "0" * 64
    drifted = replace(
        plan,
        parameters_digest="0" * 64,
        plan_digest=canonical_digest(content),
    )
    authorization = _authorization(drifted)
    verifier = _Verifier()
    runtime = ProtectedSecretApprovalM4Runtime(
        _Resolver(
            SecretApprovalM4ExecutionBinding(
                drifted,
                authorization,
                _binding(),
            )
        ),
        verifier,
        InMemoryM4ExecutionStateStore(),
        state,
        state,
        authenticated_requester_digest=drifted.requester_digest,
        clock=lambda: NOW,
    )

    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(
            authorization.authorization_ref,
            expected_approval_binding_digest=secret_approval_binding_digest(
                _binding()
            ),
        )

    assert verifier.calls == 0
    assert state.write_calls == []
    assert state.read_calls == 0
