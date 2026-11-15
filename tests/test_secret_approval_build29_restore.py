"""Real M3 signing/delegation/claim with an entirely simulated product transport."""

from dataclasses import asdict, replace
import json
import os
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.secret_approval_build29_m4_authorization import (
    PlanningChainSecretApprovalBuild29M4AuthorizationVerifier,
    promote_secret_approval_build29_m4_binding,
)
from fortipam_mcp.secret_approval_build29_m4_runtime import (
    RESTORE_ACTION_ID, assemble_secret_approval_build29_m4_runtime,
)
from fortipam_mcp.secret_approval_build29_http_transport import SecretApprovalBuild29Readback
from fortipam_mcp.secret_approval_build29_projection_source import (
    FortiPamSecretApprovalBuild29ProjectionSource, SecretApprovalBuild29ProfileInspection,
    secret_approval_build29_projection_contract,
)
from fortipam_mcp.secret_approval_build29_restore import (
    RESTORE_OUTCOME, RESTORE_SOURCE_REF, SecretApprovalBuild29OwnedRestoreSource,
    SecretApprovalBuild29RestoreError, PlanningChainSecretApprovalBuild29RestoreAuthorizationVerifier,
    promote_secret_approval_build29_restore_binding,
    secret_approval_build29_restore_projection_contract, validate_secret_approval_build29_restore_chain,
)
from fortipam_mcp.secret_metadata_http_transport import SecretApprovalProjectionInspection
from test_approver_authority import _ExternalApproverCheckpoint, CHECKPOINT_STORE_REF
from test_secret_approval_build29_m4_authorization import _inputs, _OverrideReader, _tampered
from test_secret_approval_build29_runtime_provider import _body, _write, _verifier
from test_secret_approval_m4_authorization import _ClaimedPlanningReader
from test_v4_planning import NOW, Authorizer, Issuer, _approval_and_observe_draft, _interaction, _promoted_registry
from v4_planning import (
    AuthenticatedApprover, InMemoryM4ExecutionStateStore, InMemoryProtectedPlanningStore,
    M2PlanningEngine, M3ApprovalGate, M3PlanOnlyWorkflowService, M3PlanPolicy,
    M4AdapterDenied, M4Outcome, ObjectClass, PersistentApproverAuthorizationAuthority,
    PlanningDenied, canonical_digest,
)


class _Qualifier:
    def verify(self, **kwargs: Any) -> None:
        assert kwargs["now_epoch"] >= NOW


class _CountingStore(InMemoryM4ExecutionStateStore):
    def __init__(self) -> None:
        super().__init__()
        self.claim_calls = 0

    def claim(self, **kwargs: Any) -> Any:
        self.claim_calls += 1
        return super().claim(**kwargs)


def _applied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    values = _inputs(tmp_path, monkeypatch)
    forward = promote_secret_approval_build29_m4_binding(**values)
    private = {"current": values["baseline"]}
    calls = {"read": 0, "write": 0, "categories": 0}

    def inspect() -> Any:
        calls["read"] += 1
        return private["current"]

    def enable(expected: Any, **kwargs: Any) -> Any:
        assert expected == values["baseline"]
        calls["write"] += 1
        private["current"] = values["expected_private_state"]
        forward.transport._ownership = (expected, private["current"])
        return SecretApprovalBuild29Readback(True, True, True, True)

    def restore(expected: Any, **kwargs: Any) -> Any:
        assert expected == values["expected_private_state"]
        assert forward.transport._ownership == (values["baseline"], expected)
        calls["write"] += 1
        private["current"] = values["baseline"]
        forward.transport._ownership = None
        return SecretApprovalBuild29Readback(True, True, True, True)

    monkeypatch.setattr(forward.transport, "inspect_transition", inspect)
    monkeypatch.setattr(forward.transport, "enable_and_readback", enable)
    monkeypatch.setattr(forward.transport, "restore_and_readback", restore)
    store = _CountingStore()
    enable_verifier = PlanningChainSecretApprovalBuild29M4AuthorizationVerifier(**{
        key: value for key, value in values.items() if key != "now_epoch"
    })
    runtime = assemble_secret_approval_build29_m4_runtime(
        forward, authorization_verifier=enable_verifier, execution_store=store,
        authenticated_requester_digest=values["authenticated_requester_digest"],
        qualification_verifier=_Qualifier(), execution_enabled=True, clock=lambda: NOW + 5,
    )
    assert runtime.execute_bound(values["authorization_ref"], expected_binding_digest=values["expected_binding_digest"]).outcome is M4Outcome.SUCCEEDED
    requester = values["planning"]._store.get_plan(values["source_plan_ref"])
    # Reuse the actual requester instance from the material-free enable test chain.
    from v4_planning import AuthenticatedRequester
    identity = AuthenticatedRequester("operator-subject-0001", "operator",
                                      identity_authority_ref="identity-authority-ref01",
                                      subject_namespace="workforce-namespace-v1")
    assert identity.digest == requester.requester_digest

    class Resolver:
        def resolve(self, draft: Any, current: Any) -> Any:
            assert current == identity
            return values["approval_binding"]

    class Profile:
        def readback(self, name: str) -> Any:
            return SecretApprovalBuild29ProfileInspection(True, True, True, True, True, True, True, True)

    class Secret:
        def inspect_approval_projection(self, *_args: Any, **_kwargs: Any) -> Any:
            calls["categories"] += 1
            enabled = private["current"] == values["expected_private_state"]
            return SecretApprovalProjectionInspection(
                secret_exists=True, interactive_approval_required=enabled, job_approval_required=False,
                owner_bypass_allowed=False, approval_profile_matches=enabled,
                approval_profile_unset=not enabled, field_values_attached=False,
            )

    categorical = FortiPamSecretApprovalBuild29ProjectionSource(Secret(), Profile(), Resolver(), contract_registered=True)
    source = SecretApprovalBuild29OwnedRestoreSource(
        categorical, _approval_and_observe_draft(), identity, forward,
        ownership_evidence_ref="owned-approval-evidence-ref01",
    )
    return dict(values=values, forward=forward, private=private, calls=calls, source=source,
                requester=identity, execution_store=store, categorical=categorical)


def _chain(
    fixture: dict[str, Any], tmp_path: Path, *, claim: bool = True,
    draft_overrides: dict[str, Any] | None = None, self_approval: bool = False,
) -> dict[str, Any]:
    source, requester = fixture["source"], fixture["requester"]
    draft = replace(source.draft, **(draft_overrides or {}))
    issuer = Issuer()
    issuer._counter = 1000
    engine = M2PlanningEngine(
        _promoted_registry(), issuer, Authorizer((draft,), projection_source_ref=RESTORE_SOURCE_REF),
        projection_contract_resolver=lambda _scheme, kind: secret_approval_build29_restore_projection_contract(kind),
        approval_restore_profile_enabled=True,
    )
    authenticator = fixture["values"]["receipt_authenticator"]
    approver = AuthenticatedApprover(requester.subject_ref if self_approval else "restore-approver-subject01", identity_authority_ref=requester.identity_authority_ref,
                                     subject_namespace=requester.subject_namespace)
    authority_root = tmp_path / "restore-authority"
    authority_root.mkdir(mode=0o700)
    key = authority_root / "authority.key"
    key.write_bytes(b"u" * 32)
    os.chmod(key, 0o600)
    authority = PersistentApproverAuthorizationAuthority(
        authority_root / "authority.sqlite3", key, authority_ref="restore-approver-authority-ref01",
        monotonic_checkpoint=_ExternalApproverCheckpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF,
        clock=lambda: NOW + 10,
    )
    authority.issue(approver, environment_ref=draft.environment_ref, scope_ref=draft.scope_ref,
                    action_bindings=(("approval-checkout-jit-and-jobs-plan", "1.0.0"),), policy_version="1.0.0",
                    expires_at=NOW + 200, now_epoch=NOW + 10)
    store = InMemoryProtectedPlanningStore(clock=lambda: NOW + 15, approval_receipt_authenticator=authenticator)
    workflow = M3PlanOnlyWorkflowService(engine, store, M3PlanPolicy(issuer), M3ApprovalGate(
        issuer, receipt_authenticator=authenticator, approver_authorizer=authority,
    ))
    projections = source.project(source.draft, requester, now_epoch=NOW + 10)
    summary = workflow.compile_summary(draft, requester, projections, now_epoch=NOW + 10)
    interaction = replace(_interaction(summary, requester), confirmed_at=NOW + 11)
    confirmation = workflow.confirm_intent(summary.summary_ref, requester, interaction, now_epoch=NOW + 11)
    plan = workflow.prepare_plan(summary.summary_ref, confirmation.confirmation_ref, requester, now_epoch=NOW + 12)
    decision = workflow.request_approval(plan.plan_ref, requester, now_epoch=NOW + 13)
    receipt = workflow.approve(decision.decision_ref, approver, requester=requester, now_epoch=NOW + 14)
    if claim:
        assert workflow.claim_approval(receipt.receipt_ref, plan.plan_ref, requester).approval_validated
        record = store._claims[receipt.receipt_ref]
    else:
        record = None
    reader = _ClaimedPlanningReader(store, record)
    pins = dict(source_plan_ref=plan.plan_ref, approval_receipt_ref=receipt.receipt_ref,
                approver_authority_ref=authority.authority_ref)
    return dict(planning=reader, receipt_authenticator=authenticator, source=source, pins=pins,
                summary=summary, confirmation=confirmation, plan=plan, decision=decision, receipt=receipt,
                workflow=workflow, engine=engine, projections=projections)


def _promote(chain: dict[str, Any], *, now: int = NOW + 15) -> Any:
    return promote_secret_approval_build29_restore_binding(
        chain["planning"], chain["receipt_authenticator"], chain["source"], **chain["pins"],
        authorization_ref="restore-m4-authorization-ref01", now_epoch=now,
    )


def test_signed_owned_restore_uses_new_authority_claim_and_same_transport_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _applied(tmp_path, monkeypatch)
    chain = _chain(fixture, tmp_path)
    baseline_reads = fixture["calls"]["read"]
    validate_secret_approval_build29_restore_chain(chain["planning"], chain["receipt_authenticator"], chain["source"],
                                                 **chain["pins"], now_epoch=NOW + 15)
    assert fixture["calls"]["read"] == baseline_reads
    binding = _promote(chain)
    forward = fixture["forward"]
    assert binding.operation == "restore" and binding.plan.action_id == RESTORE_ACTION_ID
    assert binding.transport is forward.transport
    assert binding.plan.plan_ref != forward.plan.plan_ref
    assert binding.plan.idempotency_digest != forward.plan.idempotency_digest
    assert binding.authorization.approval_ref != forward.authorization.approval_ref
    assert binding.plan.expected_state_digest == forward.plan.expected_current_digest
    assert binding.plan.expected_current_digest == forward.plan.expected_state_digest
    verifier = PlanningChainSecretApprovalBuild29RestoreAuthorizationVerifier(
        chain["planning"], chain["receipt_authenticator"], chain["source"], **chain["pins"],
        authorization_ref=binding.authorization.authorization_ref,
    )
    runtime = assemble_secret_approval_build29_m4_runtime(
        binding, authorization_verifier=verifier, execution_store=fixture["execution_store"],
        authenticated_requester_digest=fixture["requester"].digest,
        qualification_verifier=_Qualifier(), execution_enabled=True, clock=lambda: NOW + 15,
    )
    assert runtime.execute_bound(binding.authorization.authorization_ref,
                                 expected_binding_digest=fixture["values"]["expected_binding_digest"]).outcome is M4Outcome.SUCCEEDED
    assert fixture["private"]["current"] == forward.baseline
    assert fixture["calls"]["write"] == 2 and fixture["execution_store"].claim_calls == 2
    with pytest.raises(M4AdapterDenied):
        runtime.execute_bound(binding.authorization.authorization_ref, expected_binding_digest=fixture["values"]["expected_binding_digest"])
    assert fixture["calls"]["write"] == 2 and fixture["execution_store"].claim_calls == 2


def test_public_restore_artifacts_exclude_all_private_state_and_execution_digests(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _applied(tmp_path, monkeypatch)
    chain = _chain(fixture, tmp_path)
    public = json.dumps({"draft": asdict(chain["source"].draft),
                         "summary": chain["summary"].canonical_content(),
                         "plan": chain["plan"].canonical_content()}, sort_keys=True)
    values, forward = fixture["values"], fixture["forward"]
    for protected in (
        values["baseline"].state_digest, values["expected_private_state"].state_digest,
        values["baseline"].metadata_digest, values["baseline"].native_digest, values["baseline"].profile_digest,
        values["expected_binding_digest"], forward.plan.plan_digest, forward.authorization.authorization_digest,
        values["approval_binding"].secret_name, values["approval_binding"].folder_path,
    ):
        assert protected not in public
    assert "ownership_evidence_ref" in public and RESTORE_OUTCOME in public


@pytest.mark.parametrize("failure", ["enable_receipt", "unsigned", "missing_claim", "expiry", "wrong_authority", "summary_tamper"])
def test_invalid_signed_chain_denies_before_private_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    fixture = _applied(tmp_path, monkeypatch)
    chain = _chain(fixture, tmp_path, claim=failure != "missing_claim")
    if failure == "enable_receipt":
        chain["planning"] = fixture["values"]["planning"]
        chain["pins"] = {**chain["pins"], "source_plan_ref": fixture["values"]["source_plan_ref"],
                         "approval_receipt_ref": fixture["values"]["approval_receipt_ref"]}
    elif failure == "unsigned":
        chain["planning"] = _OverrideReader(chain["planning"], "get_approval_receipt", _tampered(chain["receipt"], "receipt_mac", "0" * 64))
    elif failure == "wrong_authority":
        chain["pins"]["approver_authority_ref"] = "wrong-restore-authority-ref01"
    elif failure == "summary_tamper":
        chain["planning"] = _OverrideReader(chain["planning"], "get_summary", _tampered(chain["summary"], "outcome_code", "require_interactive_approval"))
    reads = fixture["calls"]["read"]
    with pytest.raises(SecretApprovalBuild29RestoreError):
        _promote(chain, now=NOW + 300 if failure == "expiry" else NOW + 15)
    assert fixture["calls"]["read"] == reads and fixture["calls"]["write"] == 1


@pytest.mark.parametrize("failure", ["lost_ownership", "native_drift", "metadata_drift", "routing_drift", "wrong_requester"])
def test_owned_current_and_binding_drift_denies_restore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    fixture = _applied(tmp_path, monkeypatch)
    chain = _chain(fixture, tmp_path)
    transport = fixture["forward"].transport
    if failure == "lost_ownership":
        transport._ownership = None
    elif failure.endswith("_drift") and failure != "routing_drift":
        state = fixture["private"]["current"]
        attribute = "native_digest" if failure == "native_drift" else "metadata_digest"
        fixture["private"]["current"] = replace(state, **{attribute: "f" * 64})
    elif failure == "routing_drift":
        mutation = transport._mutation
        transport._mutation = replace(mutation, web_fields=replace(mutation.web_fields, web_url="https://other.invalid/"))
    else:
        chain["source"]._requester = replace(fixture["requester"], subject_ref="other-requester-subject01")
    with pytest.raises(SecretApprovalBuild29RestoreError):
        _promote(chain)
    assert fixture["calls"]["write"] == 1 and fixture["execution_store"].claim_calls == 1


@pytest.mark.parametrize("failure", ["gate", "qualification"])
def test_restore_runtime_stays_closed_without_gate_or_independent_qualification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    fixture = _applied(tmp_path, monkeypatch)
    chain = _chain(fixture, tmp_path)
    binding = _promote(chain)
    verifier = PlanningChainSecretApprovalBuild29RestoreAuthorizationVerifier(
        chain["planning"], chain["receipt_authenticator"], chain["source"], **chain["pins"],
        authorization_ref=binding.authorization.authorization_ref,
    )
    runtime = assemble_secret_approval_build29_m4_runtime(
        binding, authorization_verifier=verifier, execution_store=fixture["execution_store"],
        authenticated_requester_digest=fixture["requester"].digest,
        qualification_verifier=None if failure == "qualification" else _Qualifier(),
        execution_enabled=failure != "gate", clock=lambda: NOW + 15,
    )
    reads = fixture["calls"]["read"]
    with pytest.raises(M4AdapterDenied):
        runtime.execute_bound(binding.authorization.authorization_ref, expected_binding_digest=fixture["values"]["expected_binding_digest"])
    assert fixture["calls"]["read"] == reads and fixture["execution_store"].claim_calls == 1


def test_new_profile_requires_explicit_planner_switch_and_its_exact_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _applied(tmp_path, monkeypatch)
    source, requester = fixture["source"], fixture["requester"]
    projections = source.project(source.draft, requester, now_epoch=NOW + 10)
    for enabled, contract in ((False, secret_approval_build29_restore_projection_contract),
                              (True, secret_approval_build29_projection_contract)):
        engine = M2PlanningEngine(
            _promoted_registry(), Issuer(), Authorizer((source.draft,), projection_source_ref=RESTORE_SOURCE_REF),
            projection_contract_resolver=lambda _scheme, kind: contract(kind),
            approval_restore_profile_enabled=enabled,
        )
        with pytest.raises(PlanningDenied):
            engine.compile_summary(source.draft, requester, projections, now_epoch=NOW + 10)


@pytest.mark.parametrize("attribute", ["environment_ref", "scope_ref", "owner_ref", "audience_ref"])
def test_valid_signed_chain_in_different_scope_is_rejected_before_private_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attribute: str) -> None:
    fixture = _applied(tmp_path, monkeypatch)
    chain = _chain(fixture, tmp_path, draft_overrides={attribute: "different-authorized-scope-ref01"})
    reads = fixture["calls"]["read"]
    with pytest.raises(SecretApprovalBuild29RestoreError):
        _promote(chain)
    assert fixture["calls"]["read"] == reads and fixture["calls"]["write"] == 1


def test_restore_reuses_actual_approver_separation_not_a_local_boolean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _applied(tmp_path, monkeypatch)
    from v4_planning import ApprovalDenied
    reads = fixture["calls"]["read"]
    with pytest.raises(ApprovalDenied):
        _chain(fixture, tmp_path, self_approval=True)
    assert fixture["calls"]["read"] == reads and fixture["calls"]["write"] == 1


def test_restore_requires_qualification_for_the_new_exact_m4_plan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _applied(tmp_path, monkeypatch)
    chain = _chain(fixture, tmp_path)
    binding = _promote(chain)
    qualifier_path = tmp_path / "restore-qualification.json"
    body = {**_body(), "binding_digest": fixture["values"]["expected_binding_digest"],
            "plan_digest": fixture["forward"].plan.plan_digest, "issued_at": NOW + 10, "expires_at": NOW + 200}
    _write(qualifier_path, body)
    verifier = PlanningChainSecretApprovalBuild29RestoreAuthorizationVerifier(
        chain["planning"], chain["receipt_authenticator"], chain["source"], **chain["pins"],
        authorization_ref=binding.authorization.authorization_ref,
    )
    runtime = assemble_secret_approval_build29_m4_runtime(
        binding, authorization_verifier=verifier, execution_store=fixture["execution_store"],
        authenticated_requester_digest=fixture["requester"].digest,
        qualification_verifier=_verifier(qualifier_path), execution_enabled=True, clock=lambda: NOW + 15,
    )
    reads = fixture["calls"]["read"]
    with pytest.raises(M4AdapterDenied):
        runtime.execute_bound(binding.authorization.authorization_ref, expected_binding_digest=fixture["values"]["expected_binding_digest"])
    assert fixture["calls"]["read"] == reads and fixture["execution_store"].claim_calls == 1
    _write(qualifier_path, {**body, "plan_digest": binding.plan.plan_digest})
    assert runtime.execute_bound(binding.authorization.authorization_ref,
                                 expected_binding_digest=fixture["values"]["expected_binding_digest"]).outcome is M4Outcome.SUCCEEDED
