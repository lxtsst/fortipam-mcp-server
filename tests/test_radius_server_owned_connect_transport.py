"""Synthetic original-ACK native observation and independent recovery checks."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.radius_server_contract import RadiusServerCandidateError, RadiusServerCreateOutcome
from fortipam_mcp.radius_server_owned_connect_contract import CONNECT_PATH
from test_radius_server_http_transport import Response, create, setup, transport
from test_radius_server_projection import envelope


def fixture(tmp_path: Path, *, fault: str | None = None) -> tuple[Any, Any, Any, Any]:
    peer, state, now, digest = setup(tmp_path)
    if fault == 'lost_create_ack':
        peer.lost_post_ack = True
    outcome = create(state, peer, now, digest)
    assert outcome is (RadiusServerCreateOutcome.RECONCILIATION_REQUIRED if fault == 'lost_create_ack'
                       else RadiusServerCreateOutcome.VERIFIED_CREATED)
    original = peer.handle
    peer.native_posts = 0
    def native(method: str, path: str, body: Any) -> Any:
        if method != 'POST' or path != CONNECT_PATH:
            return original(method, path, body)
        peer.native_posts += 1
        assert json.loads(bytes(body)) == {'mkey': peer.binding.name, 'server': peer.binding.server,
                                   'auth_type': 'auto', 'ordinal': 'primary'}
        assert b'secret' not in bytes(body)
        if fault == 'lost_native_ack':
            raise TimeoutError('Synthetic native response lost.')
        if fault == 'post_drift':
            peer.row['timeout'] = 99
        document = envelope(http_method='POST', action='test-connect', mkey=peer.binding.name,
                            results={'status': 'reachable'})
        if fault == 'reject_only':
            document['results'] = {'status': 'ok', 'access_status': 'Access-Reject',
                                   'access_message': 'SYNTHETIC_PRIVATE_MESSAGE'}
        if fault == 'contradiction':
            document['error'] = 0
        return Response(document)
    peer.handle = native
    return peer, state, now, digest


def test_owned_native_is_single_use_omits_material_and_preserves_recovery(tmp_path: Path) -> None:
    peer, state, now, _ = fixture(tmp_path)
    selected = transport(state, peer, now, owned_connect_enabled=True, owned_connect_authorizer=lambda *a: True)
    observed = selected.observe_owned_connect()
    assert observed.status_token == 'reachable' and not observed.as_dict()['connectivity_qualified']
    assert peer.native_posts == 1 and peer.posts == 1
    assert (state/'native-owned-connect-result.json').exists()
    with pytest.raises(RadiusServerCandidateError):
        selected.observe_owned_connect()
    restarted = transport(state, peer, now, owned_connect_enabled=True, owned_connect_authorizer=lambda *a: True)
    before = len(peer.connections)
    with pytest.raises(RadiusServerCandidateError):
        restarted.observe_owned_connect()
    assert len(peer.connections) == before and peer.native_posts == 1
    selected.close_owned_connect()
    selected.close_owned_connect()
    assert not selected._owned_connect_enabled
    recovered = transport(state, peer, now, recover=True)
    assert recovered.delete_owned() and recovered.inspect_deleted() and peer.deletes == 1


@pytest.mark.parametrize('fault', ['default_closed', 'authorizer', 'lost_create_ack', 'references', 'scalar', 'deleted', 'gate_in_callback'])
def test_owned_connect_refuses_before_native_claim(tmp_path: Path, fault: str) -> None:
    peer, state, now, _ = fixture(tmp_path, fault=fault)
    enabled = fault != 'default_closed'
    holder = []
    def authorize(*args: Any) -> bool:
        if fault == 'gate_in_callback':
            holder[0].close_owned_connect()
        return fault != 'authorizer'
    selected = transport(state, peer, now, owned_connect_enabled=enabled, owned_connect_authorizer=authorize)
    holder.append(selected)
    if fault == 'references':peer.row['q_ref'] = 1
    elif fault == 'scalar':peer.row['timeout'] = 99
    elif fault == 'deleted':assert transport(state, peer, now, recover=True).delete_owned()
    with pytest.raises(RadiusServerCandidateError):
        selected.observe_owned_connect()
    assert peer.native_posts == 0 and not (state/'native-owned-connect.claim.json').exists()


@pytest.mark.parametrize('fault', ['lost_native_ack', 'contradiction', 'post_drift', 'connect_revoke'])
def test_consumed_or_uncertain_native_observation_never_replays(tmp_path: Path, fault: str) -> None:
    peer, state, now, _ = fixture(tmp_path, fault=fault)
    selected = transport(state, peer, now, owned_connect_enabled=True, owned_connect_authorizer=lambda *a: True)
    if fault == 'connect_revoke':
        def revoke() -> None:
            if (state/'native-owned-connect.claim.json').exists():selected.close_owned_connect()
        peer.on_connect = revoke
    with pytest.raises(RadiusServerCandidateError):
        selected.observe_owned_connect()
    assert (state/'native-owned-connect.claim.json').exists()
    assert not (state/'native-owned-connect-result.json').exists()
    assert (state/'native-owned-connect-diagnostic.json').exists()
    before = (len(peer.connections), peer.native_posts)
    restarted = transport(state, peer, now, owned_connect_enabled=True, owned_connect_authorizer=lambda *a: True)
    with pytest.raises(RadiusServerCandidateError):restarted.observe_owned_connect()
    assert before == (len(peer.connections), peer.native_posts)


def test_minimized_shape_is_claim_linked_before_failed_projection_wipes_response(tmp_path: Path,
                                                                              monkeypatch: Any) -> None:
    from fortipam_mcp import radius_server_http_transport as module
    from fortipam_mcp.ldap_server_projection import _digest
    peer, state, now, _ = fixture(tmp_path, fault='contradiction')
    selected = transport(state, peer, now, owned_connect_enabled=True, owned_connect_authorizer=lambda *a: True)
    retained = []
    original = module.project_owned_connect_observation
    def project(raw: bytearray, *args: Any, **kwargs: Any) -> Any:
        retained.append(raw)
        return original(raw, *args, **kwargs)
    monkeypatch.setattr(module, 'project_owned_connect_observation', project)
    with pytest.raises(RadiusServerCandidateError):selected.observe_owned_connect()
    record = json.loads((state/'native-owned-connect-shape.json').read_bytes())
    marker = json.loads((state/'native-owned-connect.claim.json').read_bytes())
    assert record['claim_digest'] == _digest(marker) and record['http_status'] == 200
    shape = record['shape']
    assert shape['route_matches'] and shape['device_build_match'] and shape['diagnosis_complete']
    assert shape['status_token'] == 'reachable' and not shape['connectivity_qualified']
    assert retained and all(not raw for raw in retained)
    assert not (state/'native-owned-connect-result.json').exists()
    assert transport(state, peer, now, recover=True).delete_owned()
    assert peer.native_posts == peer.deletes == 1


def test_shape_persistence_failure_consumes_native_and_clears_response(tmp_path: Path, monkeypatch: Any) -> None:
    from fortipam_mcp import radius_server_http_transport as module
    peer, state, now, _ = fixture(tmp_path)
    selected = transport(state, peer, now, owned_connect_enabled=True, owned_connect_authorizer=lambda *a: True)
    write = module.FortiPamRadiusServerHttpTransport._write_once
    diagnose = module.diagnose_owned_connect_shape
    retained = []
    def fail_shape(self: Any, name: str, value: Any) -> None:
        if name == 'native-owned-connect-shape.json':raise OSError('Synthetic persistence failure.')
        write(self, name, value)
    def capture(raw: bytearray, *args: Any, **kwargs: Any) -> Any:
        retained.append(raw)
        return diagnose(raw, *args, **kwargs)
    monkeypatch.setattr(module.FortiPamRadiusServerHttpTransport, '_write_once', fail_shape)
    monkeypatch.setattr(module, 'diagnose_owned_connect_shape', capture)
    with pytest.raises(RadiusServerCandidateError):selected.observe_owned_connect()
    assert retained and all(not raw for raw in retained)
    assert not peer.bodies[-1] and peer.native_posts == 1
    diagnostic = json.loads((state/'native-owned-connect-diagnostic.json').read_bytes())
    assert diagnostic['stage'] == 'observation_shape'
    assert not (state/'native-owned-connect-result.json').exists()
    with pytest.raises(RadiusServerCandidateError):selected.observe_owned_connect()
    assert peer.native_posts == 1


@pytest.mark.parametrize('fault', [None, 'reject_only'])
def test_grammar_fact_requires_complete_original_observation_and_unchanged_state(tmp_path: Path,
                                                                               fault: str | None) -> None:
    peer, state, now, _ = fixture(tmp_path, fault=fault)
    selected = transport(state, peer, now, owned_connect_enabled=True, owned_connect_authorizer=lambda *a: True)
    observed = selected.observe_owned_connect()
    selected.close_owned_connect()
    assert selected.inspect_owned_connect_grammar() is (fault == 'reject_only')
    assert not observed.as_dict()['connectivity_qualified'] and peer.native_posts == 1
    assert transport(state, peer, now, recover=True).delete_owned()
    with pytest.raises(RadiusServerCandidateError):selected.inspect_owned_connect_grammar()
    assert peer.native_posts == 1 and peer.deletes == 1


@pytest.mark.parametrize('fault', ['claim', 'contract', 'status', 'nonboolean', 'extra', 'state', 'missing_result'])
def test_grammar_metadata_cannot_replace_ownership_or_successful_observation(tmp_path: Path, fault: str) -> None:
    peer, state, now, _ = fixture(tmp_path, fault='reject_only')
    selected = transport(state, peer, now, owned_connect_enabled=True, owned_connect_authorizer=lambda *a: True)
    selected.observe_owned_connect()
    path = state/'native-owned-connect-grammar.json'
    record = json.loads(path.read_bytes())
    if fault == 'claim':record['claim_digest'] = 'a'*64
    elif fault == 'contract':record['contract'] = 'other'
    elif fault == 'status':record['http_status'] = True
    elif fault == 'nonboolean':record['matches_reject_only_response'] = 1
    elif fault == 'extra':record['SYNTHETIC_PRIVATE_KEY'] = 'SYNTHETIC_PRIVATE_VALUE'
    elif fault == 'state':peer.row['timeout'] = 99
    elif fault == 'missing_result':(state/'native-owned-connect-result.json').unlink()
    path.write_text(json.dumps(record))
    with pytest.raises(RadiusServerCandidateError):selected.inspect_owned_connect_grammar()
    assert peer.native_posts == 1


def test_orphan_grammar_file_blocks_native_replay_and_preserves_independent_recovery(tmp_path: Path) -> None:
    peer, state, now, _ = fixture(tmp_path)
    selected = transport(state, peer, now, owned_connect_enabled=True, owned_connect_authorizer=lambda *a: True)
    selected._write_once('native-owned-connect-grammar.json', {})
    with pytest.raises(RadiusServerCandidateError):selected.observe_owned_connect()
    assert peer.native_posts == 0
    assert transport(state, peer, now, recover=True).delete_owned()


def test_grammar_persistence_failure_wipes_response_and_keeps_dispatch_consumed(tmp_path: Path,
                                                                              monkeypatch: Any) -> None:
    from fortipam_mcp import radius_server_http_transport as module
    peer, state, now, _ = fixture(tmp_path, fault='reject_only')
    selected = transport(state, peer, now, owned_connect_enabled=True, owned_connect_authorizer=lambda *a: True)
    write = module.FortiPamRadiusServerHttpTransport._write_once
    predicate = module.matches_reject_only_connect_response
    retained = []
    def fail(self: Any, name: str, value: Any) -> None:
        if name == 'native-owned-connect-grammar.json':raise OSError('Synthetic persistence failure.')
        write(self, name, value)
    def capture(raw: bytearray, *args: Any, **kwargs: Any) -> bool:
        retained.append(raw)
        return predicate(raw, *args, **kwargs)
    monkeypatch.setattr(module.FortiPamRadiusServerHttpTransport, '_write_once', fail)
    monkeypatch.setattr(module, 'matches_reject_only_connect_response', capture)
    with pytest.raises(RadiusServerCandidateError):selected.observe_owned_connect()
    assert retained and all(not raw for raw in retained) and peer.native_posts == 1
    with pytest.raises(RadiusServerCandidateError):selected.inspect_owned_connect_grammar()
    assert not (state/'native-owned-connect-result.json').exists()
    assert transport(state, peer, now, recover=True).delete_owned()
