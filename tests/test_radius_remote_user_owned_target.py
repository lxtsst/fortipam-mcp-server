"""Original pair M4/ACK dependency joins with real local ledgers, synthetic HTTP."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import pickle
from typing import Any

import pytest

from fortipam_mcp.radius_remote_user_contract import RadiusRemoteUserBinding, RadiusRemoteUserError
from fortipam_mcp.radius_remote_user_owned_target import RadiusRemoteUserOwnedTarget
from fortipam_mcp.radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport
from fortipam_mcp.radius_server_pair_contract import RadiusServerPairError
from test_radius_server_pair_live_workflow import setup, grant, IDENTITY


def prepared(root: Path, *, lost_ack: bool = False) -> tuple[Any, ...]:
    workflow, peer, now, factory, values = setup(root)
    peer.lost_post_ack = lost_ack
    reference = grant(workflow)
    issued = workflow._authority._issued
    result = workflow.execute(reference, **IDENTITY)
    binding = RadiusRemoteUserBinding('mcp-v4-radius-user-01234567', peer.binding, 'c' * 64)
    target = FortiPamRadiusPairHttpTransport(workflow._config, peer.binding,
        expected_serial=workflow._serial, state_directory=workflow._directory,
        connection_factory=peer.connection, clock=lambda: now[0])
    selected = RadiusRemoteUserOwnedTarget(binding, target, issued, workflow._execution_store)
    return selected, workflow, peer, now, factory, values, result


def snapshot(directory: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file()}


def test_original_successful_m4_and_ack_qualify_after_close_without_material_or_writes(tmp_path: Path) -> None:
    guard, workflow, peer, now, factory, _, result = prepared(tmp_path)
    assert result['outcome'] == 'succeeded'
    workflow.close()
    now[0] = 1000  # Original provenance remains valid after its dispatch expiry.
    before = snapshot(workflow._directory)
    sources = len(factory.calls)
    counts = (workflow._execution_store.claim_count, len(workflow._execution_store.audit_events))
    first = guard.inspect()
    with guard.hold(first.observation_digest) as second:
        assert first == second
        blocked = FortiPamRadiusPairHttpTransport(guard._target._config, peer.binding,
            expected_serial=workflow._serial, state_directory=workflow._directory,
            connection_factory=peer.connection, recovery_enabled=True,
            recovery_authorizer=lambda *args: True)
        with pytest.raises(RadiusServerPairError):
            blocked.delete_owned()
    assert snapshot(workflow._directory) == before
    assert len(factory.calls) == sources and peer.posts == 1 and peer.deletes == 0
    assert counts == (workflow._execution_store.claim_count, len(workflow._execution_store.audit_events))
    assert len(first.provenance_digest) == len(first.state_digest) == 64
    assert peer.binding.name not in repr(first) and str(tmp_path) not in repr(guard)
    with pytest.raises(Exception):
        pickle.dumps(first)


@pytest.mark.parametrize('fault', [
    'missing_ack', 'missing_created', 'claim_request', 'claim_actor', 'delete_claim',
    'reference', 'secondary', 'opaque', 'defaults', 'factory', 'api', 'gate',
    'store_key', 'execution_request', 'execution_plan', 'fresh_digest',
])
def test_foreign_incomplete_consumed_or_drifting_target_never_qualifies(tmp_path: Path, fault: str) -> None:
    guard, workflow, peer, _, factory, _, _ = prepared(tmp_path)
    root = workflow._directory
    if fault == 'missing_ack':
        (root / 'create-ack.json').unlink()
    elif fault == 'missing_created':
        (root / 'created.json').unlink()
    elif fault in {'claim_request', 'claim_actor'}:
        path = root / 'create.claim.json'
        claim = json.loads(path.read_text())
        claim['request_digest' if fault == 'claim_request' else 'actor_digest'] = 'f' * 64
        path.write_text(json.dumps(claim))
    elif fault == 'delete_claim':
        (root / 'delete.claim.json').write_text('{}')
    elif fault == 'reference':
        peer.row['q_ref'] = 1
    elif fault == 'secondary':
        peer.row['secondary-server'] = '192.0.2.88'
    elif fault == 'opaque':
        peer.row['secondary-secret'] = 'SYNTHETIC_CHANGED'
    elif fault == 'defaults':
        peer.defaults['timeout'] = 15
    elif fault == 'factory':
        guard._target._factory = lambda *a, **k: None
    elif fault == 'api':
        guard._target._config = replace(guard._target._config, base_url='https://foreign.example')
    elif fault == 'gate':
        guard._target._execution_enabled = True
    elif fault == 'store_key':
        guard._store._key = b'changed-synthetic-key-00000000000'
    elif fault == 'execution_request':
        object.__setattr__(guard._execution.lease_request, 'plan_digest', 'f' * 64)
    elif fault == 'execution_plan':
        object.__setattr__(guard._execution.plan, 'expected_current_digest', 'f' * 64)
    sources = len(factory.calls)
    before = snapshot(root)
    with pytest.raises(RadiusRemoteUserError):
        if fault == 'fresh_digest':
            with guard.hold('f' * 64):
                pytest.fail('A foreign preview digest must never yield.')
        else:
            guard.inspect()
    assert snapshot(root) == before
    assert len(factory.calls) == sources and peer.posts == 1 and peer.deletes == 0


def test_lost_original_ack_and_unknown_m4_are_not_dependency_ownership(tmp_path: Path) -> None:
    guard, _, peer, _, factory, _, result = prepared(tmp_path, lost_ack=True)
    assert result['outcome'] == 'reconciliation_required'
    before = len(factory.calls)
    with pytest.raises(RadiusRemoteUserError):
        guard.inspect()
    assert peer.posts == 1 and peer.deletes == 0 and len(factory.calls) == before


def test_an_unrelated_successful_m4_cannot_qualify_a_different_pair_journal(tmp_path: Path) -> None:
    left = tmp_path / 'left'; left.mkdir(mode=0o700)
    right = tmp_path / 'right'; right.mkdir(mode=0o700)
    guard, _, peer, _, _, _, _ = prepared(left)
    foreign, _, _, _, _, _, _ = prepared(right)
    # Even an equal-looking typed pair from another operation is insufficient.
    with pytest.raises(RadiusRemoteUserError):
        RadiusRemoteUserOwnedTarget(guard._binding, guard._target,
            foreign._execution, foreign._store)
    assert peer.deletes == 0


def test_same_binding_with_foreign_success_store_does_not_supply_original_claim(tmp_path: Path) -> None:
    left = tmp_path / 'left'; left.mkdir(mode=0o700)
    right = tmp_path / 'right'; right.mkdir(mode=0o700)
    guard, _, peer, _, _, _, _ = prepared(left)
    foreign, _, _, _, _, _, _ = prepared(right)
    selected = RadiusRemoteUserOwnedTarget(guard._binding, guard._target,
        guard._execution, foreign._store)
    before = snapshot(guard._target._directory)
    with pytest.raises(RadiusRemoteUserError):
        selected.inspect()
    assert snapshot(guard._target._directory) == before and peer.deletes == 0


def test_pending_original_m4_cannot_yield_dependency_during_create(tmp_path: Path) -> None:
    workflow, peer, _, _, _ = setup(tmp_path)
    reference = grant(workflow)
    issued = workflow._authority._issued
    user = RadiusRemoteUserBinding('mcp-v4-radius-user-01234567', peer.binding, 'c' * 64)
    target = FortiPamRadiusPairHttpTransport(workflow._config, peer.binding,
        expected_serial=workflow._serial, state_directory=workflow._directory,
        connection_factory=peer.connection)
    guard = RadiusRemoteUserOwnedTarget(user, target, issued, workflow._execution_store)
    attempted = []
    def during_create() -> None:
        if (workflow._directory / 'create.claim.json').exists() and not attempted:
            attempted.append(True)
            with pytest.raises(RadiusRemoteUserError):
                guard.inspect()
    peer.on_connect = during_create
    result = workflow.execute(reference, **IDENTITY)
    assert attempted and result['outcome'] == 'succeeded'
    assert guard.inspect().binding_digest == user.parameters_digest


@pytest.mark.parametrize('deadline', [0, float('nan'), float('inf'), True])
def test_target_deadline_cannot_outlive_or_bypass_the_child_deadline(tmp_path: Path, deadline: Any) -> None:
    guard, _, peer, _, _, _, _ = prepared(tmp_path)
    before = len(peer.connections)
    with pytest.raises(RadiusRemoteUserError):
        with guard.hold(stop=deadline):
            pytest.fail('An invalid deadline cannot qualify the target.')
    assert len(peer.connections) == before
