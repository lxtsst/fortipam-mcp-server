from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.secret_approval_build29_m4_authorization import (
    PROJECTION_CONTRACT, SOURCE_REF,
    PlanningChainSecretApprovalBuild29M4AuthorizationVerifier,
    SecretApprovalBuild29M4AuthorizationError,
    promote_secret_approval_build29_m4_binding, validate_build29_planning_chain,
)
from fortipam_mcp.secret_approval_build29_m4_runtime import (
    ACTION_ID, ADAPTER_REF, RESTORE_ACTION_ID,
    assemble_secret_approval_build29_m4_runtime,
    secret_approval_build29_transport_binding_digest,
)
from fortipam_mcp.secret_approval_build29_projection_source import secret_approval_build29_projection_contract
from test_secret_approval_build29_m4_runtime import _binding as _transport_binding
from test_secret_approval_m4_authorization import _binding, _ClaimedPlanningReader
from test_v4_m3 import ExactApproverAuthority
from test_v4_planning import (
    NOW, Authorizer, Issuer, _approval_and_observe_draft, _interaction,
    _projection, _promoted_registry,
)
from v4_planning import (
    AuthenticatedRequester, InMemoryM4ExecutionStateStore, M2PlanningEngine,
    M4AdapterDenied, ObjectClass, canonical_digest,
)
from v4_planning.approval import ApprovalReceiptAuthenticator, AuthenticatedApprover, M3ApprovalGate
from v4_planning.policy import M3PlanPolicy
from v4_planning.store import InMemoryProtectedPlanningStore


def _claimed_chain(
    *, old_source: bool = False, source_version: str = "1.0.0", current_flag: str | None = None,
) -> tuple[Any, ...]:
    draft = _approval_and_observe_draft()
    issuer = Issuer()
    def contract(_scheme: Any, object_class: ObjectClass) -> Any:
        value = replace(secret_approval_build29_projection_contract(object_class), version=source_version)
        return replace(value, source_ref="fortipam-191-approval-observe-projection") if old_source else value
    engine = M2PlanningEngine(
        _promoted_registry(), issuer,
        Authorizer((draft,), projection_source_ref=("fortipam-191-approval-observe-projection" if old_source else SOURCE_REF)),
        projection_contract_resolver=contract,
    )
    requester = AuthenticatedRequester(
        "operator-subject-0001", "operator", identity_authority_ref="identity-authority-ref01",
        subject_namespace="workforce-namespace-v1",
    )
    desired = {item.object_class: item for item in draft.desired_objects}
    current_fields = {"exists": True, "approval_profile_attached": False, "interactive_approval_required": False,
                      "job_approval_required": False, "owner_bypass_allowed": False}
    if current_flag is not None:
        current_fields[current_flag] = True
    current = (
        _projection(engine, draft.scheme_id, desired[ObjectClass.APPROVAL_PROFILE_BINDING],
                    {"exists": True, "profile_mode": "single_tier", "profile_ref": "approval-profile-ref0001"},
                    fresh_until=NOW + 100),
        _projection(engine, draft.scheme_id, desired[ObjectClass.SECRET_APPROVAL_BINDING],
                    current_fields, fresh_until=NOW + 100),
    )
    summary = engine.compile_summary(draft, requester, current, now_epoch=NOW)
    confirmation = engine.confirm_intent(summary.summary_ref, requester, _interaction(summary, requester), now_epoch=NOW + 1)
    plan = engine.prepare_plan(summary.summary_ref, confirmation.confirmation_ref, requester, now_epoch=NOW + 2)
    decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 3)
    authenticator = ApprovalReceiptAuthenticator(b"a" * 32)
    receipt = M3ApprovalGate(issuer, receipt_authenticator=authenticator, approver_authorizer=ExactApproverAuthority()).approve(
        decision, AuthenticatedApprover("approver-subject-0001", identity_authority_ref="identity-authority-ref01",
                                       subject_namespace="workforce-namespace-v1"),
        now_epoch=NOW + 4, plan=plan, requester=requester,
    )
    store = InMemoryProtectedPlanningStore(clock=lambda: NOW + 5, approval_receipt_authenticator=authenticator)
    store.put_summary(summary)
    store.put_confirmation(confirmation)
    store.put_plan(plan)
    store.put_policy_decision(decision)
    store.put_approval_receipt(receipt)
    claim = store.claim_approval(receipt.receipt_ref, plan.plan_ref, requester.digest)
    return _ClaimedPlanningReader(store, claim), authenticator, requester, plan, receipt


def _inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, old_source: bool = False,
    source_version: str = "1.0.0", current_flag: str | None = None,
) -> dict[str, Any]:
    reader, authenticator, requester, plan, receipt = _claimed_chain(
        old_source=old_source, source_version=source_version, current_flag=current_flag,
    )
    bound, calls = _transport_binding(tmp_path, monkeypatch)
    transport = bound.transport
    assert transport._mutation is not None
    binding = replace(_binding(), folder_path=transport._folder_path,
                      secret_name=str(transport._identity["name"]), secret_id=int(transport._identity["id"]),
                      approval_profile_name=transport._mutation.approval_profile_name)
    baseline = transport._transition_state(("disable", "disable", "disable", ""), "a" * 64, "b" * 64, "c" * 64)
    expected = transport._transition_state(("enable", "disable", "disable", binding.approval_profile_name), "a" * 64, "b" * 64, "c" * 64)
    # Any accidental protected read or material provider invocation must fail.
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("Unexpected protected read")
    for name in ("inspect", "inspect_transition", "_read_transition", "_read_private_projection"):
        monkeypatch.setattr(transport, name, forbidden)
    monkeypatch.setattr(transport._owner, "authenticated", forbidden)
    values = {
        "planning": reader, "receipt_authenticator": authenticator, "approval_binding": binding,
        "source_plan_ref": plan.plan_ref, "approval_receipt_ref": receipt.receipt_ref,
        "approver_authority_ref": "approver-authority-ref01", "authenticated_requester_digest": requester.digest,
        "authorized_environment_ref": plan.environment_ref, "authorized_scope_ref": plan.scope_ref,
        "now_epoch": NOW + 5, "authorization_ref": "build29-authorization-ref01",
        "transport": transport, "baseline": baseline, "expected_private_state": expected,
        "expected_binding_digest": secret_approval_build29_transport_binding_digest(transport, binding.secret_approval_object_ref),
    }
    assert calls == {"read": 0, "write": 0}
    return values


def _validate(values: dict[str, Any]) -> Any:
    return validate_build29_planning_chain(**{
        key: value for key, value in values.items()
        if key not in {"authorization_ref", "transport", "baseline", "expected_private_state", "expected_binding_digest"}
    })


class _OverrideReader:
    def __init__(self, reader: Any, method: str, value: Any) -> None:
        self._reader, self._method, self._value = reader, method, value

    def __getattr__(self, name: str) -> Any:
        return (lambda *_args: self._value) if name == self._method else getattr(self._reader, name)


def _tampered(record: Any, field: str, value: Any) -> Any:
    result = copy.copy(record)
    object.__setattr__(result, field, value)
    return result


def test_claimed_build29_chain_binds_private_full_transition_without_material_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path, monkeypatch)
    chain = _validate(values)
    result = promote_secret_approval_build29_m4_binding(**values)
    assert result.operation == "enable"
    assert result.plan.action_id == ACTION_ID and result.plan.adapter_ref == ADAPTER_REF
    assert result.plan.expected_current_digest == values["baseline"].state_digest
    assert result.plan.expected_state_digest == values["expected_private_state"].state_digest
    assert result.plan.expected_current_digest != chain.plan.lines[0].expected_current_digest
    assert result.plan.summary_digest == chain.summary.summary_digest
    assert result.authorization.approval_digest == chain.receipt.receipt_digest
    assert result.authorization.issued_at == chain.claim.claimed_at
    assert result.authorization.expires_at == chain.receipt.expires_at < NOW + 100
    assert promote_secret_approval_build29_m4_binding(**values) == result
    verifier = PlanningChainSecretApprovalBuild29M4AuthorizationVerifier(**{
        key: value for key, value in values.items() if key != "now_epoch"
    })
    verifier.verify(result.plan, result.authorization, now_epoch=NOW + 6)
    assert repr(result).startswith("<") and values["approval_binding"].secret_name not in repr(result)
    # Promotion establishes intent authority, never the default execution Gate.
    runtime = assemble_secret_approval_build29_m4_runtime(
        result, authorization_verifier=verifier, execution_store=InMemoryM4ExecutionStateStore(),
        authenticated_requester_digest=chain.plan.requester_digest, clock=lambda: NOW + 6,
    )
    with pytest.raises(M4AdapterDenied):
        runtime.execute_bound(result.authorization.authorization_ref,
                              expected_binding_digest=values["expected_binding_digest"])


@pytest.mark.parametrize("field,value", [
    ("authenticated_requester_digest", "f" * 64),
    ("authorized_environment_ref", "other-environment-ref01"),
    ("authorized_scope_ref", "other-scope-ref01"),
    ("approver_authority_ref", "other-approver-authority-ref01"),
    ("source_plan_ref", "other-plan-ref01"),
    ("approval_receipt_ref", "other-receipt-ref01"),
    ("now_epoch", NOW + 100), ("now_epoch", NOW + 3), ("now_epoch", True),
])
def test_material_free_predicate_rejects_wrong_actor_scope_refs_and_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: Any,
) -> None:
    values = _inputs(tmp_path, monkeypatch)
    values[field] = value
    with pytest.raises(SecretApprovalBuild29M4AuthorizationError) as failure:
        _validate(values)
    assert failure.value.__cause__ is None


def test_authenticated_old_source_cannot_be_promoted_as_build29(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    values = _inputs(tmp_path, monkeypatch, old_source=True)
    with pytest.raises(SecretApprovalBuild29M4AuthorizationError):
        promote_secret_approval_build29_m4_binding(**values)


@pytest.mark.parametrize("flag", ["approval_profile_attached", "interactive_approval_required",
                                  "job_approval_required", "owner_bypass_allowed"])
def test_authenticated_chain_requires_the_exact_disabled_unattached_current_subset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str,
) -> None:
    values = _inputs(tmp_path, monkeypatch, current_flag=flag)
    with pytest.raises(SecretApprovalBuild29M4AuthorizationError):
        _validate(values)


def test_authenticated_different_source_version_is_not_compatible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    values = _inputs(tmp_path, monkeypatch, source_version="2.0.0")
    with pytest.raises(SecretApprovalBuild29M4AuthorizationError):
        _validate(values)


@pytest.mark.parametrize("method,field,value", [
    ("get_summary", "scope_ref", "other-scope-ref01"),
    ("get_summary", "summary_digest", "f" * 64),
    ("get_plan", "plan_digest", "f" * 64),
    ("get_confirmation", "record_digest", "f" * 64),
    ("get_policy_decision", "decision_digest", "f" * 64),
    ("get_approval_receipt", "receipt_mac", "f" * 64),
    ("get_approval_receipt", "approver_digest", "f" * 64),
    ("get_approval_receipt", "approver_authority_ref", "other-approver-authority-ref01"),
    ("get_approval_claim", "receipt_digest", "f" * 64),
    ("get_approval_claim", "execution_authorized", True),
    ("get_approval_claim", "claimed_at", NOW + 6),
])
def test_signed_record_and_claim_mismatch_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, field: str, value: Any,
) -> None:
    values = _inputs(tmp_path, monkeypatch)
    chain = _validate(values)
    records = {"get_summary": chain.summary, "get_plan": chain.plan, "get_confirmation": chain.confirmation,
               "get_policy_decision": chain.decision, "get_approval_receipt": chain.receipt, "get_approval_claim": chain.claim}
    values["planning"] = _OverrideReader(values["planning"], method, _tampered(records[method], field, value))
    with pytest.raises(SecretApprovalBuild29M4AuthorizationError):
        _validate(values)


@pytest.mark.parametrize("field,value", [
    ("secret_id", 25), ("secret_name", "another-unit-secret"), ("folder_path", "Public/another-folder"),
    ("approval_profile_name", "another-unit-profile"),
])
def test_private_transition_must_match_the_sealed_secret_and_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: Any,
) -> None:
    values = _inputs(tmp_path, monkeypatch)
    values["approval_binding"] = replace(values["approval_binding"], **{field: value})
    with pytest.raises(SecretApprovalBuild29M4AuthorizationError) as failure:
        promote_secret_approval_build29_m4_binding(**values)
    assert value not in str(failure.value) if isinstance(value, str) else True


@pytest.mark.parametrize("change", [
    "binding", "baseline_hash", "expected_hash", "metadata", "profile", "native", "bypass", "job", "restore",
])
def test_private_states_reject_unbound_hashes_preservation_drift_and_other_transitions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    values = _inputs(tmp_path, monkeypatch)
    expected, baseline, transport = values["expected_private_state"], values["baseline"], values["transport"]
    if change == "binding":
        values["expected_binding_digest"] = "f" * 64
    elif change in {"baseline_hash", "expected_hash"}:
        name = "baseline" if change == "baseline_hash" else "expected_private_state"
        values[name] = replace(values[name], state_digest="f" * 64)
    elif change in {"metadata", "profile", "native"}:
        parts = [expected.metadata_digest, expected.profile_digest, expected.native_digest]
        parts[{"metadata": 0, "profile": 1, "native": 2}[change]] = "f" * 64
        values["expected_private_state"] = transport._transition_state(expected.approval_values, *parts)
    elif change in {"bypass", "job"}:
        approvals = list(baseline.approval_values)
        approvals[2 if change == "bypass" else 1] = "enable"
        values["baseline"] = transport._transition_state(tuple(approvals), baseline.metadata_digest,
                                                         baseline.profile_digest, baseline.native_digest)
    else:
        values["baseline"], values["expected_private_state"] = expected, baseline
    with pytest.raises(SecretApprovalBuild29M4AuthorizationError):
        promote_secret_approval_build29_m4_binding(**values)


def test_authorizer_rechecks_records_transport_and_does_not_authorize_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path, monkeypatch)
    promoted = promote_secret_approval_build29_m4_binding(**values)
    verifier = PlanningChainSecretApprovalBuild29M4AuthorizationVerifier(**{
        key: value for key, value in values.items() if key != "now_epoch"
    })
    restore = replace(promoted.plan, action_id=RESTORE_ACTION_ID,
                      plan_digest=canonical_digest({**promoted.plan.canonical_content(), "action_id": RESTORE_ACTION_ID}))
    with pytest.raises(SecretApprovalBuild29M4AuthorizationError):
        verifier.verify(restore, promoted.authorization, now_epoch=NOW + 6)
    with pytest.raises(SecretApprovalBuild29M4AuthorizationError):
        verifier.verify(promoted.plan, promoted.authorization, now_epoch=NOW + 100)
    values["transport"]._serial = "ANOTHERUNITSERIAL"
    with pytest.raises(SecretApprovalBuild29M4AuthorizationError):
        verifier.verify(promoted.plan, promoted.authorization, now_epoch=NOW + 6)


def test_public_projection_digest_is_recomputed_not_merely_forwarded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    values = _inputs(tmp_path, monkeypatch)
    chain = _validate(values)
    secret = next(change for change in chain.summary.object_changes if change.object_class is ObjectClass.SECRET_APPROVAL_BINDING)
    assert secret.projection_contract_ref == PROJECTION_CONTRACT
    # Even a typed fake preserving both source line hashes cannot substitute a
    # categorical object/state hash unrelated to this exact source contract.
    corrupt = _tampered(secret, "current_projection_digest", "f" * 64)
    changes = tuple(corrupt if change is secret else change for change in chain.summary.object_changes)
    summary = _tampered(chain.summary, "object_changes", changes)
    values["planning"] = _OverrideReader(values["planning"], "get_summary", summary)
    with pytest.raises(SecretApprovalBuild29M4AuthorizationError):
        _validate(values)
