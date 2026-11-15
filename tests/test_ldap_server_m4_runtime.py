"""Synthetic joins of real LDAP HTTP, material leases, M4 and both ledgers."""
from __future__ import annotations

import copy
from dataclasses import asdict, replace
import os
from pathlib import Path
import pickle
from typing import Any
from urllib.parse import urlsplit

import pytest

from fortipam_mcp.ldap_server_contract import ACTION_ID, ACTION_VERSION, LdapServerCreateBinding
from fortipam_mcp.ldap_server_http_transport import FortiPamLdapServerHttpTransport
from fortipam_mcp.ldap_server_m4_runtime import (
    ADAPTER_REF, TARGET_REF, LdapServerM4ExecutionBinding,
    ProtectedLdapServerM4Runtime, expected_state_digest,
)
from fortipam_mcp.ldap_server_material_provider import LdapServerMaterialProvider
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning import (
    M4AdapterDenied, M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionPlan,
    M4Outcome, M4Verification, canonical_digest,
)
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import MaterialAccessDenied, MaterialLeaseRequest
from v4_planning.material_runtime import MaterialRuntimeOutcome, material_lease_request_digest

from test_ldap_server_http_transport import Loader, binding, request, setup
from test_ldap_server_projection import SERIAL


class _Resolver:
    def __init__(self, selected: LdapServerM4ExecutionBinding) -> None:
        self.selected = selected
        self.calls = 0

    def resolve_execution_binding(self, authorization_ref: str) -> LdapServerM4ExecutionBinding:
        self.calls += 1
        return self.selected


class _Verifier:
    def __init__(self, selected: LdapServerM4ExecutionBinding) -> None:
        self.selected = selected
        self.calls = 0
        self.denied = False

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        self.calls += 1
        if (self.denied or plan is not self.selected.plan
            or authorization is not self.selected.authorization or now_epoch != 100):
            raise M4AuthorizationDenied("Synthetic authorization denied.")


def _plan(selected: LdapServerCreateBinding, current: str, **changes: Any) -> M4ExecutionPlan:
    values: dict[str, Any] = {
        "plan_ref": "ldap-plan-synthetic-01", "revision": 1,
        "action_id": ACTION_ID, "action_version": ACTION_VERSION,
        "adapter_ref": ADAPTER_REF, "target_ref": TARGET_REF,
        "requester_digest": "1" * 64, "summary_digest": "2" * 64,
        "confirmation_digest": "3" * 64, "approval_digest": "4" * 64,
        "parameters_digest": selected.parameters_digest, "expected_current_digest": current,
        "expected_state_digest": expected_state_digest(selected),
        "idempotency_digest": "5" * 64, "expires_at": 160, "compensation_ref": None,
    }
    values.update(changes)
    return M4ExecutionPlan(**values, plan_digest=canonical_digest(values))


def _authorization(plan: M4ExecutionPlan, **changes: Any) -> M4ExecutionAuthorization:
    values: dict[str, Any] = {
        "authorization_ref": "ldap-authorization-synthetic-01", "plan_ref": plan.plan_ref,
        "plan_digest": plan.plan_digest, "requester_digest": plan.requester_digest,
        "confirmation_ref": "ldap-confirmation-synthetic-01", "confirmation_digest": plan.confirmation_digest,
        "approval_ref": "ldap-approval-synthetic-01", "approval_digest": plan.approval_digest,
        "approver_digest": "6" * 64, "issued_at": 100, "expires_at": 160,
        "one_time": True, "execution_authorized": True,
    }
    values.update(changes)
    return M4ExecutionAuthorization(**values, authorization_digest=canonical_digest(values))


def _execution_binding(selected: LdapServerCreateBinding, plan: M4ExecutionPlan,
        auth: M4ExecutionAuthorization, req: MaterialLeaseRequest) -> LdapServerM4ExecutionBinding:
    return LdapServerM4ExecutionBinding(plan, auth, selected, req,
        req.policy_decision_digest, req.scope_digest, req.audience_digest)


def _stores(tmp_path: Path) -> Any:
    values = []
    for name, store_type in (("m4", PersistentM4ExecutionStateStore),
                             ("material", PersistentMaterialUseStateStore)):
        directory = tmp_path / name
        directory.mkdir(mode=0o700, exist_ok=True)
        key = directory / "key"
        if not key.exists():
            key.write_bytes(os.urandom(32))
            key.chmod(0o600)
        values.append(store_type(directory / "ledger.sqlite", key))
    return tuple(values)


def _compose(tmp_path: Path, peer: Any, state: Path, now: list[int],
        selected: LdapServerM4ExecutionBinding, *, enabled: bool | None = True) -> Any:
    transport = FortiPamLdapServerHttpTransport(
        SecretMetadataHttpTransportConfig("https://pam.example", "synthetic-token", 5, None),
        peer.binding, expected_serial=SERIAL, state_directory=state,
        execution_request=selected.lease_request, expected_current_digest=selected.plan.expected_current_digest,
        execution_enabled=True, clock=lambda: now[0], connection_factory=peer.connection,
    )
    loader = Loader(peer.binding)
    provider = LdapServerMaterialProvider(loader, binding=peer.binding,
        request=selected.lease_request, clock=lambda: now[0])
    resolver, verifier = _Resolver(selected), _Verifier(selected)
    execution_store, material_store = _stores(tmp_path)
    kwargs: dict[str, Any] = {} if enabled is None else {"execution_enabled": enabled}
    runtime = ProtectedLdapServerM4Runtime(resolver, verifier, execution_store, material_store,
        provider, transport, authenticated_requester_digest="1" * 64, clock=lambda: now[0], **kwargs)
    return runtime, loader, resolver, verifier, execution_store, material_store


def _setup(tmp_path: Path, *, enabled: bool | None = True,
        plan_changes: dict[str, Any] | None = None, auth_changes: dict[str, Any] | None = None) -> Any:
    preview, peer, state, now = setup(tmp_path)
    current = preview.inspect_create().state_digest
    plan = _plan(peer.binding, current, **(plan_changes or {}))
    auth = _authorization(plan, **(auth_changes or {}))
    req = replace(request(), plan_digest=plan.plan_digest, authorization_digest=auth.authorization_digest)
    selected = _execution_binding(peer.binding, plan, auth, req)
    composed = _compose(tmp_path, peer, state, now, selected, enabled=enabled)
    return peer, state, now, selected, composed


def test_verified_http_creation_and_two_store_restart_replay(tmp_path: Path) -> None:
    peer, state, now, selected, composed = _setup(tmp_path)
    runtime, loader, _, verifier, execution_store, _ = composed
    ref = selected.authorization.authorization_ref
    assert runtime.inspect_execution_plan(ref) is selected.plan
    assert runtime.inspect_binding_digest(ref) == peer.binding.parameters_digest
    result = runtime.execute_bound(ref)
    assert result.outcome is M4Outcome.SUCCEEDED
    assert result.verification is M4Verification.VERIFIED and not result.idempotent_replay
    assert loader.loads == peer.posts == peer.binds == verifier.calls == 1
    assert loader.buffers is not None and not any(any(value) for value in loader.buffers)
    assert peer.row is not None and peer.deletes == 0
    assert execution_store.claim_count == 1
    connections = len(peer.connections)
    restarted, fresh_loader, _, fresh_verifier, restarted_m4, _ = _compose(tmp_path, peer, state, now, selected)
    replay = restarted.execute_bound(ref)
    assert replay.outcome is M4Outcome.SUCCEEDED and replay.idempotent_replay
    assert fresh_loader.loads == fresh_verifier.calls == 0
    assert len(peer.connections) == connections and peer.posts == peer.binds == 1
    assert restarted_m4.claim_count == 1


@pytest.mark.parametrize("failure", ["post_ack", "detail"])
def test_uncertain_http_creation_is_terminal_across_restart(tmp_path: Path, failure: str) -> None:
    peer, state, now, selected, composed = _setup(tmp_path)
    peer.lost_post_ack = failure == "post_ack"
    peer.first_detail_failure = failure == "detail"
    runtime, loader, _, _, _, _ = composed
    result = runtime.execute_bound(selected.authorization.authorization_ref)
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert result.verification is M4Verification.UNKNOWN
    assert loader.loads == peer.posts == 1 and peer.deletes == 0
    assert loader.buffers is not None and not any(any(value) for value in loader.buffers)
    connections = len(peer.connections)
    restarted, fresh_loader, _, fresh_verifier, _, _ = _compose(tmp_path, peer, state, now, selected)
    replay = restarted.execute_bound(selected.authorization.authorization_ref)
    assert replay.outcome is M4Outcome.RECONCILIATION_REQUIRED and replay.idempotent_replay
    assert fresh_loader.loads == fresh_verifier.calls == 0
    assert peer.posts == 1 and len(peer.connections) == connections


def test_outer_postcondition_requires_fresh_owned_readback(tmp_path: Path) -> None:
    peer, _, _, selected, composed = _setup(tmp_path)
    runtime, loader, _, _, _, _ = composed
    handle = peer.handle
    successful_details = []
    def drift_after_inner_readback(method: str, url: str, body: memoryview | None) -> Any:
        response = handle(method, url, body)
        if (method == "GET" and peer.row is not None
            and urlsplit(url).path.endswith("/" + peer.binding.name)):
            successful_details.append(True)
            if len(successful_details) == 1:
                peer.row["obtain-user-info"] = "synthetic-drift-after-inner-verification"
        return response
    peer.handle = drift_after_inner_readback
    result = runtime.execute_bound(selected.authorization.authorization_ref)
    assert len(successful_details) == 2
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert result.verification is M4Verification.UNKNOWN
    assert loader.loads == peer.posts == peer.binds == 1 and peer.deletes == 0


@pytest.mark.parametrize("terminal", [False, True])
def test_existing_material_claim_cannot_reload_or_dispatch_after_restart(tmp_path: Path, terminal: bool) -> None:
    peer, state, now, selected, composed = _setup(tmp_path)
    material = composed[-1]
    digest = material_lease_request_digest(selected.lease_request)
    material.claim(request_digest=digest, authorization_digest=selected.authorization.authorization_digest)
    if terminal:
        material.finalize(request_digest=digest, authorization_digest=selected.authorization.authorization_digest,
                          outcome=MaterialRuntimeOutcome.RECONCILIATION_REQUIRED)
    runtime, loader, _, verifier, _, _ = _compose(tmp_path, peer, state, now, selected)
    result = runtime.execute_bound(selected.authorization.authorization_ref)
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert verifier.calls == 1 and loader.loads == peer.posts == peer.binds == peer.deletes == 0


def test_unfinished_m4_claim_is_not_redispatched_after_restart(tmp_path: Path) -> None:
    peer, state, now, selected, composed = _setup(tmp_path)
    m4 = composed[-2]
    plan, auth = selected.plan, selected.authorization
    m4.claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
        idempotency_digest=plan.idempotency_digest, authorization_digest=auth.authorization_digest,
        context_digest=canonical_digest({"authorization_digest": auth.authorization_digest,
            "plan_digest": plan.plan_digest, "revision": plan.revision}))
    connections = len(peer.connections)
    runtime, loader, _, verifier, _, _ = _compose(tmp_path, peer, state, now, selected)
    result = runtime.execute_bound(auth.authorization_ref)
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED and result.idempotent_replay
    assert verifier.calls == loader.loads == peer.posts == 0
    assert len(peer.connections) == connections


@pytest.mark.parametrize("enabled", [None, False])
def test_default_and_explicit_closed_gate_deny_before_resolution_or_claim(tmp_path: Path, enabled: bool | None) -> None:
    peer, _, _, selected, composed = _setup(tmp_path, enabled=enabled)
    runtime, loader, resolver, verifier, m4, _ = composed
    connections = len(peer.connections)
    with pytest.raises(M4AdapterDenied):
        runtime.execute_bound(selected.authorization.authorization_ref)
    assert resolver.calls == verifier.calls == loader.loads == m4.claim_count == peer.posts == 0
    assert len(peer.connections) == connections


@pytest.mark.parametrize("changes", [
    {"action_id": "folder-create"}, {"action_version": "1.0.1"},
    {"adapter_ref": "another-adapter"}, {"target_ref": "another-target"},
    {"parameters_digest": "9" * 64}, {"expected_state_digest": "9" * 64},
    {"requester_digest": "8" * 64}, {"compensation_ref": "automatic-delete"},
    {"expires_at": 159},
])
def test_plan_linkage_is_rejected_before_current_reads_or_claims(tmp_path: Path, changes: dict[str, Any]) -> None:
    peer, _, _, selected, composed = _setup(tmp_path, plan_changes=changes)
    runtime, loader, _, verifier, m4, _ = composed
    connections = len(peer.connections)
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(selected.authorization.authorization_ref)
    assert loader.loads == verifier.calls == m4.claim_count == peer.posts == 0
    assert len(peer.connections) == connections


@pytest.mark.parametrize("changes", [
    {"plan_ref": "different-plan-ref"}, {"plan_digest": "9" * 64},
    {"requester_digest": "8" * 64}, {"confirmation_digest": "9" * 64},
    {"approval_digest": "9" * 64}, {"issued_at": 101}, {"expires_at": 159},
])
def test_authorization_linkage_is_rejected_before_every_effect(tmp_path: Path, changes: dict[str, Any]) -> None:
    peer, _, _, selected, composed = _setup(tmp_path, auth_changes=changes)
    runtime, loader, _, verifier, m4, _ = composed
    connections = len(peer.connections)
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(selected.authorization.authorization_ref)
    assert loader.loads == verifier.calls == m4.claim_count == peer.posts == 0
    assert len(peer.connections) == connections


@pytest.mark.parametrize("field", ["policy_decision_digest", "scope_digest", "audience_digest", "material_binding", "lease_request"])
def test_protected_context_cannot_diverge_from_provider_and_transport(tmp_path: Path, field: str) -> None:
    peer, _, _, selected, composed = _setup(tmp_path)
    runtime, loader, _, verifier, m4, _ = composed
    changed = (binding() if field == "material_binding" else
               replace(selected.lease_request, audience_digest="9" * 64) if field == "lease_request" else "9" * 64)
    object.__setattr__(selected, field, changed)
    connections = len(peer.connections)
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(selected.authorization.authorization_ref)
    assert loader.loads == verifier.calls == m4.claim_count == peer.posts == 0
    assert len(peer.connections) == connections


def test_transport_expected_state_and_binding_are_exact(tmp_path: Path) -> None:
    peer, _, _, selected, composed = _setup(tmp_path)
    runtime, loader, _, _, m4, _ = composed
    runtime._transport._request = replace(selected.lease_request, audience_digest="9" * 64)
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(selected.authorization.authorization_ref)
    runtime._transport._request = selected.lease_request
    runtime._transport._expected = "9" * 64
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(selected.authorization.authorization_ref)
    runtime._transport._expected = selected.plan.expected_current_digest
    runtime._transport._binding = binding()
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(selected.authorization.authorization_ref)
    assert loader.loads == m4.claim_count == peer.posts == 0


def test_protected_binding_is_nonrendering_and_not_serializable(tmp_path: Path) -> None:
    peer, _, _, selected, composed = _setup(tmp_path)
    runtime = composed[0]
    for value in (runtime, selected):
        assert peer.binding.username not in repr(value)
        assert peer.binding.name not in str(value)
        with pytest.raises(TypeError):
            asdict(value)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied):
                operation(value)
    with pytest.raises(M4AuthorizationDenied):
        selected.audience_digest = "9" * 64
    with pytest.raises(M4AuthorizationDenied):
        del selected.audience_digest


def test_m4_authorizer_remains_mandatory(tmp_path: Path) -> None:
    peer, _, _, selected, composed = _setup(tmp_path)
    runtime, loader, _, verifier, m4, _ = composed
    verifier.denied = True
    connections = len(peer.connections)
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(selected.authorization.authorization_ref)
    assert verifier.calls == m4.claim_count == 1
    assert loader.loads == peer.posts == 0 and len(peer.connections) == connections
