"""Independent active-M4 native observation, no material intake or live device."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.radius_server_owned_connect_workflow import (
    RadiusServerOwnedConnectWorkflow, RadiusServerOwnedConnectError,
)
from fortipam_mcp.radius_server_owned_connect_contract import CONNECT_PATH
from fortipam_mcp.radius_server_contract import RadiusServerCandidateError
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_radius_server_material_runtime import AUTHORITY_KEY, IDENTITY, stores
from test_radius_server_recovery_workflow import setup as created, recovery, grant as recover_grant
from test_radius_server_http_transport import Response
from test_radius_server_projection import SERIAL, envelope
from v4_planning import canonical_digest


def setup(root: Path) -> tuple[Any, Any, Any]:
    peer, now, loader, result = created(root)
    assert result['outcome'] == 'succeeded'
    original = peer.handle
    peer.native_posts = 0
    peer.native_status = 'reachable'
    peer.native_fault = None
    def native(method: str, path: str, body: Any) -> Any:
        if method != 'POST' or path != CONNECT_PATH:
            return original(method, path, body)
        peer.native_posts += 1
        assert json.loads(bytes(body)) == {'mkey': peer.binding.name, 'server': peer.binding.server,
                                          'auth_type': 'auto', 'ordinal': 'primary'}
        if peer.native_fault == 'lost':raise TimeoutError('Synthetic response lost.')
        if peer.native_fault == 'drift':peer.row['timeout'] = 99
        return Response(envelope(http_method='POST', action='test-connect', mkey=peer.binding.name,
                                 results={'status': peer.native_status}))
    peer.handle = native
    return peer, now, loader


def connect(root: Path, peer: Any, now: list[int], *, enabled: bool | None = True,
            store: Any = None, **changes: Any) -> RadiusServerOwnedConnectWorkflow:
    if store is None:
        ledger = root/'native-ledger';ledger.mkdir(mode=0o700, exist_ok=True)
        store, _ = stores(ledger)
    args = dict(expected_serial=SERIAL, state_directory=root/'http', execution_store=store,
        authority_key=AUTHORITY_KEY, environment_ref='synthetic-radius-environment',
        scope_ref='synthetic-radius-owned-native', audience_ref='synthetic-radius-audience',
        allowed_requester_digest=IDENTITY['requester_digest'], allowed_transport_digest=IDENTITY['transport_digest'],
        clock=lambda:now[0], connection_factory=peer.connection)
    if enabled is not None:args['execution_enabled'] = enabled
    args.update(changes)
    return RadiusServerOwnedConnectWorkflow(peer.binding,
        SecretMetadataHttpTransportConfig('https://pam.example', 'synthetic-token', 1, None), **args)


def grant(selected: RadiusServerOwnedConnectWorkflow) -> str:
    preview = selected.preview(**IDENTITY)
    assert preview['Expected State']['connectivity_qualified'] is False
    return selected.authorize(preview['preview_ref'], **IDENTITY)['authorization_ref']


@pytest.mark.parametrize('status', ['reachable', 'invalid_secret', 'SYNTHETIC_UNKNOWN'])
def test_m4_verifies_only_observation_and_preserves_independent_recovery(tmp_path: Path, status: str) -> None:
    peer, now, loader = setup(tmp_path)
    peer.native_status = status
    selected = connect(tmp_path, peer, now)
    reference = grant(selected)
    result = selected.execute(reference, **IDENTITY)
    assert result['outcome'] == 'succeeded' and result['verification'] == 'verified'
    assert result['execution_scope'] == 'native_response_observation_only' and not result['connectivity_qualified']
    assert not result['observation']['connectivity_qualified']
    assert peer.native_posts == selected._store.claim_count == loader.loads == 1
    count = len(peer.connections)
    replay = selected.execute(reference, **IDENTITY)
    assert replay['idempotent_replay'] and len(peer.connections) == count and peer.native_posts == 1
    selected.close()
    assert not selected._transport._owned_connect_enabled and selected._key == b''
    recovered = recovery(tmp_path, peer, now)
    assert recovered.execute(recover_grant(recovered), **IDENTITY)['outcome'] == 'succeeded'
    assert peer.row is None and peer.deletes == 1 and loader.loads == 1
    encoded = json.dumps(result)
    for value in (peer.binding.name, peer.binding.server, peer.binding.private_nonce, SERIAL, 'SYNTHETIC_UNKNOWN'):
        assert value not in encoded


@pytest.mark.parametrize('fault', ['default', 'expiry', 'clock_rollback', 'identity', 'gate', 'plan', 'namespace'])
def test_invalid_m4_context_never_dispatches(tmp_path: Path, fault: str) -> None:
    peer, now, _ = setup(tmp_path)
    selected = connect(tmp_path, peer, now, enabled=None if fault == 'default' else True)
    if fault == 'default':
        p = selected.preview(**IDENTITY)
        with pytest.raises(RadiusServerOwnedConnectError):selected.authorize(p['preview_ref'], **IDENTITY)
    else:
        reference = grant(selected);identity = dict(IDENTITY)
        if fault == 'expiry':now[0] = 160
        elif fault == 'clock_rollback':now[0] = 99
        elif fault == 'identity':identity['transport_digest'] = '3'*64
        elif fault == 'gate':selected.close()
        elif fault == 'plan':object.__setattr__(selected._issued.plan, 'summary_digest', 'f'*64)
        elif fault == 'namespace':selected._namespace['scope_ref'] = 'other-scope'
        with pytest.raises(RadiusServerOwnedConnectError):selected.execute(reference, **identity)
    assert peer.native_posts == selected._store.claim_count == 0
    assert not (tmp_path/'http/native-owned-connect.claim.json').exists()


@pytest.mark.parametrize('fault', ['lost', 'drift', 'expiry_at_connect', 'gate_at_connect'])
def test_uncertain_native_consumes_once_and_fresh_ledger_cannot_reopen(tmp_path: Path, fault: str) -> None:
    peer, now, loader = setup(tmp_path)
    selected = connect(tmp_path, peer, now)
    reference = grant(selected)
    peer.native_fault = fault
    if fault.endswith('_at_connect'):
        def on_connect() -> None:
            if (tmp_path/'http/native-owned-connect.claim.json').exists():
                if fault == 'expiry_at_connect':now[0] = 160
                else:selected.close()
        peer.on_connect = on_connect
    result = selected.execute(reference, **IDENTITY)
    assert result['outcome'] == 'reconciliation_required' and not result['connectivity_qualified']
    assert selected._store.claim_count == 1 and (tmp_path/'http/native-owned-connect.claim.json').exists()
    assert peer.native_posts == int(fault in ('lost', 'drift')) and loader.loads == 1
    # A genuinely empty alternative ledger still cannot clear the HTTP native claim.
    ledger = tmp_path/'different-ledger';ledger.mkdir(mode=0o700);store, _ = stores(ledger)
    fresh = connect(tmp_path, peer, now, store=store)
    before = len(peer.connections)
    with pytest.raises(RadiusServerOwnedConnectError):fresh.preview(**IDENTITY)
    assert len(peer.connections) == before and store.claim_count == 0


def test_orphaned_in_progress_claim_does_not_grant_dispatch_ownership(tmp_path: Path) -> None:
    peer, now, _ = setup(tmp_path)
    selected = connect(tmp_path, peer, now)
    reference = grant(selected);issued = selected._issued;plan, auth = issued.plan, issued.authorization
    selected._store.claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
        idempotency_digest=plan.idempotency_digest, authorization_digest=auth.authorization_digest,
        context_digest=canonical_digest({'plan_digest':plan.plan_digest, 'revision':plan.revision,
                                        'authorization_digest':auth.authorization_digest}))
    selected._started = True
    p = selected._preview
    assert not selected._authorize_connect(peer.binding, p.owned_digest, p.state_digest)
    assert selected.execute(reference, **IDENTITY)['outcome'] == 'reconciliation_required'
    assert peer.native_posts == 0 and not (tmp_path/'http/native-owned-connect.claim.json').exists()


@pytest.mark.parametrize('change', ['claim', 'qualified', 'unknown_status', 'numeric_false', 'diagnostic', 'row_drift'])
def test_persisted_observation_requires_original_claim_and_full_state(tmp_path: Path, change: str) -> None:
    peer, now, _ = setup(tmp_path)
    selected = connect(tmp_path, peer, now)
    assert selected.execute(grant(selected), **IDENTITY)['outcome'] == 'succeeded'
    path = tmp_path/'http/native-owned-connect-result.json'
    result = json.loads(path.read_bytes())
    if change == 'claim':result['claim_digest'] = 'f'*64
    elif change == 'qualified':result['observation']['connectivity_qualified'] = True
    elif change == 'unknown_status':result['observation']['status_token'] = 'SYNTHETIC_PRIVATE'
    elif change == 'numeric_false':result['observation']['connectivity_qualified'] = 0
    elif change == 'diagnostic':(tmp_path/'http/native-owned-connect-diagnostic.json').write_text('{}')
    elif change == 'row_drift':peer.row['timeout'] = 99
    path.write_text(json.dumps(result))
    with pytest.raises(RadiusServerCandidateError):selected._transport.inspect_owned_connect_observation()
    assert peer.native_posts == 1


def test_recovery_authorization_cannot_authorize_native_observation(tmp_path: Path) -> None:
    peer, now, _ = setup(tmp_path)
    recover = recovery(tmp_path, peer, now)
    reference = recover_grant(recover)
    selected = connect(tmp_path, peer, now);grant(selected)
    with pytest.raises(RadiusServerOwnedConnectError):selected.execute(reference, **IDENTITY)
    assert peer.native_posts == selected._store.claim_count == peer.deletes == 0
