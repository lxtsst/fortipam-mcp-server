from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from fortipam_mcp.controlled_operations import (
    ActionContract, ActionRegistry, ApprovalBinding, ApprovalRejected, AuthenticatedPrincipal,
    ControlledOperationEngine, ControlledOperationError, ControlledOperationRequest,
    DenyAllControlledOperationAdapter, IdempotencyConflict, OperationAmbiguousError,
    OperationExecutionError, ParameterKind, ParameterSpec,
    PublicOutcome, RollbackContract, VerifiedApprovalClaims,
)


CURRENT = "a" * 64
PRINCIPAL = AuthenticatedPrincipal("trusted-operator-0001", "operator")


class _Verifier:
    """Test-only opaque issuer; callers receive references, never claims or its store."""
    def __init__(self) -> None: self._claims: dict[str, VerifiedApprovalClaims] = {}
    def issue(self, reference: str, binding: ApprovalBinding) -> str:
        self._claims[reference] = VerifiedApprovalClaims("receipt-test-00001", binding, "b" * 64, 200); return reference
    def verify(self, approval_reference: str, principal: AuthenticatedPrincipal, binding: ApprovalBinding, *, now_epoch: int) -> VerifiedApprovalClaims:
        claims = self._claims.get(approval_reference)
        if claims is None or claims.binding != binding: raise ApprovalRejected("test approval rejected")
        return claims


class _Adapter:
    def __init__(self) -> None: self.current = CURRENT; self.execute_calls = 0; self.rollback_calls = 0; self.verify = True; self.error: Exception | None = None
    def read_current(self, request: object) -> str: return self.current
    def execute(self, request: object) -> None:
        self.execute_calls += 1
        if self.error: raise self.error
    def verify_postcondition(self, request: object) -> bool: return self.verify
    def rollback(self, request: object) -> None:
        self.rollback_calls += 1
        if self.error: raise self.error
    def verify_rollback_postcondition(self, request: object) -> bool: return self.verify


def _registry() -> ActionRegistry:
    params = (ParameterSpec("enabled", ParameterKind.BOOLEAN), ParameterSpec("state", ParameterKind.ENUM, frozenset({"on", "off"})), ParameterSpec("scope_ref", ParameterKind.IDENTIFIER))
    forward = ActionContract("synthetic-toggle", "3.0.0", "synthetic-target", "synthetic-fixture", "0.0.0", params, "synthetic-restore", "3.0.0")
    rollback = RollbackContract("synthetic-restore", "3.0.0", "synthetic-target", "synthetic-fixture", "0.0.0", params, "synthetic-toggle", "3.0.0")
    return ActionRegistry((forward,), (rollback,))


def _request(**changes: object) -> ControlledOperationRequest:
    base = ControlledOperationRequest("synthetic-toggle", "3.0.0", "target-ref-000001", {"enabled": True, "state": "on", "scope_ref": "scope-ref-000001"}, CURRENT, "idempotency-key-000001", "approval-reference-00001")
    return replace(base, **changes)  # type: ignore[arg-type]


def _binding(request: ControlledOperationRequest, purpose: str, principal: AuthenticatedPrincipal = PRINCIPAL) -> ApprovalBinding:
    import hashlib, json
    digest = lambda value: hashlib.sha256(value.encode()).hexdigest()
    params = hashlib.sha256(json.dumps(request.parameters, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return ApprovalBinding(purpose, digest(principal.subject_ref), request.action_id, request.action_version, digest(request.target_ref), params, request.expected_current_digest)


def _engine(request: ControlledOperationRequest, purpose: str = "forward") -> tuple[ControlledOperationEngine, _Adapter]:
    verifier = _Verifier(); verifier.issue(request.approval_reference, _binding(request, purpose)); adapter = _Adapter()
    return ControlledOperationEngine(_registry(), adapter, verifier), adapter


def test_verified_opaque_approval_and_trusted_principal_allow_bounded_success() -> None:
    request = _request(); engine, adapter = _engine(request)
    result = engine.execute(request, PRINCIPAL, now_epoch=100)
    assert result.as_dict() == {"outcome": "succeeded", "verification": "verified", "rollback": "not_requested", "idempotent_replay": False}
    assert adapter.execute_calls == 1


@pytest.mark.parametrize("changed", ({"target_ref": "other-target-ref01"}, {"parameters": {"enabled": False, "state": "on", "scope_ref": "scope-ref-000001"}}, {"expected_current_digest": "b" * 64}, {"action_id": "synthetic-restore"}))
def test_approval_binding_mismatch_and_wrong_principal_are_denied(changed: dict[str, object]) -> None:
    original = _request(); engine, adapter = _engine(original)
    expected_error = ControlledOperationError if "action_id" in changed else ApprovalRejected
    with pytest.raises(expected_error): engine.execute(_request(**changed), PRINCIPAL, now_epoch=100)
    with pytest.raises(ApprovalRejected): engine.execute(original, AuthenticatedPrincipal("different-user-ref01", "operator"), now_epoch=100)
    assert adapter.execute_calls == 0


def test_missing_verifier_fails_closed_without_adapter_call() -> None:
    adapter = _Adapter()
    with pytest.raises(ApprovalRejected): ControlledOperationEngine(_registry(), adapter).execute(_request(), PRINCIPAL, now_epoch=100)
    assert adapter.execute_calls == 0


def test_empty_registry_and_deny_all_adapter_expose_no_product_action() -> None:
    engine = ControlledOperationEngine(
        ActionRegistry((), ()),
        DenyAllControlledOperationAdapter(),
    )
    with pytest.raises(ControlledOperationError, match="not registered"):
        engine.execute(_request(), PRINCIPAL, now_epoch=100)
    assert engine.audit_events[-1].authorization == "denied"


def test_expired_verified_receipt_is_rejected_before_adapter_call() -> None:
    request = _request(); engine, adapter = _engine(request)
    with pytest.raises(ApprovalRejected): engine.execute(request, PRINCIPAL, now_epoch=200)
    assert adapter.execute_calls == 0


def test_idempotent_replay_reverifies_same_principal_and_receipt() -> None:
    request = _request(); engine, adapter = _engine(request)
    assert engine.execute(request, PRINCIPAL, now_epoch=100).outcome is PublicOutcome.SUCCEEDED
    assert engine.execute(request, PRINCIPAL, now_epoch=100).idempotent_replay is True
    assert adapter.execute_calls == 1
    with pytest.raises(ApprovalRejected): engine.execute(request, AuthenticatedPrincipal("different-user-ref01", "operator"), now_epoch=100)


def test_idempotency_conflict_and_receipt_replay_are_rejected() -> None:
    request = _request(); engine, adapter = _engine(request); engine.execute(request, PRINCIPAL, now_epoch=100)
    changed = _request(target_ref="other-target-ref01")
    verifier = engine._verifier  # type: ignore[attr-defined]
    assert isinstance(verifier, _Verifier)
    verifier.issue(changed.approval_reference, _binding(changed, "forward"))
    with pytest.raises(IdempotencyConflict): engine.execute(changed, PRINCIPAL, now_epoch=100)
    replay = _request(idempotency_key="idempotency-key-000002")
    with pytest.raises(ApprovalRejected): engine.execute(replay, PRINCIPAL, now_epoch=100)
    assert adapter.execute_calls == 1


def test_precondition_and_ambiguous_execution_never_succeed() -> None:
    request = _request(); engine, adapter = _engine(request); adapter.current = "c" * 64
    assert engine.execute(request, PRINCIPAL, now_epoch=100).outcome is PublicOutcome.PRECONDITION_FAILED
    request = _request(approval_reference="approval-reference-00002", idempotency_key="idempotency-key-000003"); engine, adapter = _engine(request); adapter.error = OperationAmbiguousError()
    assert engine.execute(request, PRINCIPAL, now_epoch=100).outcome is PublicOutcome.VERIFICATION_UNKNOWN


def test_only_declared_execution_error_maps_to_bounded_execution_failed() -> None:
    request = _request(); engine, adapter = _engine(request); adapter.error = OperationExecutionError()
    result = engine.execute(request, PRINCIPAL, now_epoch=100)
    assert result.outcome is PublicOutcome.EXECUTION_FAILED
    assert engine.audit_events[-1].outcome == "execution_failed"


def test_unexpected_adapter_programming_error_propagates_without_pseudo_audit() -> None:
    request = _request(); engine, adapter = _engine(request); adapter.error = RuntimeError("programming defect")
    with pytest.raises(RuntimeError, match="programming defect"):
        engine.execute(request, PRINCIPAL, now_epoch=100)
    assert adapter.execute_calls == 1
    assert engine.audit_events == ()


def test_claimed_operation_is_not_reexecuted_after_ambiguous_process_failure() -> None:
    request = _request()
    engine, adapter = _engine(request)
    adapter.error = RuntimeError("programming defect")

    with pytest.raises(RuntimeError, match="programming defect"):
        engine.execute(request, PRINCIPAL, now_epoch=100)
    adapter.error = None

    result = engine.execute(request, PRINCIPAL, now_epoch=100)

    assert result.outcome is PublicOutcome.VERIFICATION_UNKNOWN
    assert result.verification.value == "unknown"
    assert result.idempotent_replay is True
    assert adapter.execute_calls == 1
    assert engine.audit_events[-1].authorization == "idempotent_in_progress"


@pytest.mark.parametrize("now_epoch", (True, False, -1, 4_102_444_801))
def test_invalid_operation_clock_is_rejected_before_adapter_call(now_epoch: object) -> None:
    request = _request(); engine, adapter = _engine(request)
    with pytest.raises(ControlledOperationError, match="clock"):
        engine.execute(request, PRINCIPAL, now_epoch=now_epoch)  # type: ignore[arg-type]
    assert adapter.execute_calls == 0


def test_rollback_uses_separate_contract_approval_and_adapter_method_only() -> None:
    request = _request(action_id="synthetic-restore", approval_reference="approval-reference-rollback", idempotency_key="rollback-key-fake-0001")
    engine, adapter = _engine(request, "rollback")
    result = engine.rollback(request, PRINCIPAL, now_epoch=100)
    assert result.rollback.value == "verified" and adapter.rollback_calls == 1 and adapter.execute_calls == 0


def test_unknown_action_and_invalid_request_create_safe_denial_audit() -> None:
    request = _request(action_id="unknown-action")
    engine, _ = _engine(_request())
    with pytest.raises(ControlledOperationError): engine.execute(request, PRINCIPAL, now_epoch=100)
    event = engine.audit_events[-1]
    assert event.authorization == "denied" and event.target_class == "unrecognized"


def test_contracts_reject_free_form_parameters_and_audit_has_no_raw_input() -> None:
    with pytest.raises(ControlledOperationError): ParameterSpec("command_text", ParameterKind.IDENTIFIER)
    request = _request(); engine, _ = _engine(request); engine.execute(request, PRINCIPAL, now_epoch=100)
    rendered = str(engine.audit_events)
    for value in (request.target_ref, request.idempotency_key, request.approval_reference, "scope-ref-000001"):
        assert value not in rendered


def test_core_has_no_v2_credential_or_network_imports() -> None:
    source = (Path(__file__).parents[1] / "src/fortipam_mcp/controlled_operations.py").read_text()
    for forbidden in ("FortiPamConfig", "load_config", "httpx", "asyncssh", "requests", "socket"):
        assert f"import {forbidden}" not in source and f"from {forbidden}" not in source
