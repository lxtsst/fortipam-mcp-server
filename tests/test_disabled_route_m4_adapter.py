"""Fixed synthetic HTTP peer through the real durable M4 kernel, never a device."""
from copy import deepcopy
from dataclasses import replace
import json

import httpx
import pytest
from v4_planning import M4AdapterDenied, M4AuthorizationDenied, M4ExecutionKernel, M4ExecutionPlan, canonical_digest

from fortipam_mcp.disabled_route_contract import CONTRACT, PATH, prepare_disabled_route
from fortipam_mcp.disabled_route_m4_adapter import DisabledRouteM4Adapter
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_disabled_route_contract import SERIAL, envelope, fixture, metadata
from test_v4_execution_kernel import _authorization


class Verifier:
    def __init__(self, plan, auth):
        self.plan, self.auth = plan, auth

    def verify(self, plan, authorization, *, now_epoch):
        if plan != self.plan or authorization != self.auth or now_epoch != 1000:
            raise M4AuthorizationDenied('Synthetic authority denied.')


def issue(binding, prepared, phase='create'):
    from test_v4_execution_kernel import REQUESTER, CONFIRMATION, APPROVAL
    fields = dict(plan_ref='disabled-route-' + phase + '-' + binding.parameters_digest,
                  revision=1, action_id='disabled-route-' + phase, action_version='1.0.0',
                  adapter_ref=CONTRACT, target_ref='bound-disabled-route', requester_digest=REQUESTER,
                  summary_digest='a' * 64, confirmation_digest=CONFIRMATION, approval_digest=APPROVAL,
                  parameters_digest=binding.parameters_digest,
                  expected_current_digest=prepared.current_digest if phase == 'create' else prepared.expected_digest,
                  expected_state_digest=prepared.expected_digest if phase == 'create' else prepared.current_digest,
                  idempotency_digest=canonical_digest({'binding': binding.parameters_digest, 'phase': phase}),
                  expires_at=1300, compensation_ref=None)
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    auth = _authorization(plan)
    return plan, auth, Verifier(plan, auth)


class Peer:
    def __init__(self, fault='none'):
        self.schema, self.defaults, self.table, self.binding = fixture()
        self.writes, self.fault = [], fault

    def client(self):
        return httpx.Client(base_url='https://synthetic.example', transport=httpx.MockTransport(self.handle))

    def handle(self, request):
        assert request.url.path in {PATH, PATH + '/' + str(self.binding.sequence)}
        if request.method == 'GET':
            if request.url.query == b'action=schema&with_meta=true':
                payload = self.schema
            elif request.url.query == b'action=default&with_meta=true':
                payload = self.defaults
            else:
                assert request.url.query == b'with_meta=true'
                payload = deepcopy(self.table)
                if self.writes and self.fault == 'partial':
                    payload['matched_count'] += 1
            return httpx.Response(200, json=payload)
        self.writes.append(request.method)
        if request.method == 'POST':
            body = json.loads(request.content)
            assert body == self.binding.body
            self.table = envelope([*self.table['results'], metadata(body)])
            if self.fault == 'drift':
                self.table['results'][0]['distance'] = 20
            if self.fault == 'lost-ack':
                raise httpx.ReadTimeout('Synthetic lost ACK.')
        else:
            assert request.method == 'DELETE' and not request.content
            self.table = envelope([r for r in self.table['results'] if r['seq-num'] != self.binding.sequence])
        ack = dict(version='v7.0.0', build=29, path='router', name='static',
                   http_method=request.method, http_status=200, status='success',
                   serial='synthetic-appliance', mkey=self.binding.sequence)
        if self.fault == 'wrong-ack':
            ack['mkey'] += 1
        return httpx.Response(200, json=ack)


def make(tmp_path, peer, **changes):
    key = tmp_path / 'key'
    if not key.exists():
        key.write_bytes(b'k' * 32)
        key.chmod(0o600)
    tmp_path.chmod(0o700)
    store = PersistentM4ExecutionStateStore(tmp_path / 'm4.sqlite', key)
    prepared = prepare_disabled_route(peer.schema, peer.defaults, peer.table, serial_digest=SERIAL, binding=peer.binding)
    plan, auth, verifier = issue(peer.binding, prepared)
    options = dict(serial_digest=SERIAL, execution_enabled=True, clock=lambda: 1000, client_factory=peer.client)
    options.update(changes)
    adapter = DisabledRouteM4Adapter(SecretMetadataHttpTransportConfig('https://synthetic.example', 'synthetic', 5, None),
        peer.binding, prepared, plan, auth, verifier, store, **options)
    return adapter, prepared, plan, auth, verifier, store


def test_create_and_owned_recovery_use_two_original_claims_and_preserve_other_routes(tmp_path):
    peer = Peer()
    before = deepcopy(peer.table)
    adapter, prepared, plan, auth, verifier, store = make(tmp_path, peer)
    kernel = M4ExecutionKernel(adapter, verifier, store, clock=lambda: 1000)
    assert kernel.execute(plan, auth).outcome == 'succeeded'
    assert kernel.execute(plan, auth).idempotent_replay is True
    p2, a2, v2 = issue(peer.binding, prepared, 'recover')
    recovery = adapter.bind_recovery(p2, a2, v2, execution_enabled=True)
    restored = M4ExecutionKernel(recovery, v2, store, clock=lambda: 1000).execute(p2, a2)
    assert restored.outcome == 'succeeded' and restored.verification == 'verified'
    assert peer.table == before and peer.writes == ['POST', 'DELETE'] and store.claim_count == 2
    assert 'synthetic-appliance' not in repr(adapter)
    # A fresh recovery object still consumes the original tuple, never another DELETE.
    duplicate = adapter.bind_recovery(p2, a2, v2, execution_enabled=True)
    assert M4ExecutionKernel(duplicate, v2, store, clock=lambda: 1000).execute(p2, a2).idempotent_replay
    assert peer.writes == ['POST', 'DELETE']


@pytest.mark.parametrize('fault', ['lost-ack', 'wrong-ack', 'drift', 'partial'])
def test_uncertain_or_failed_create_cannot_be_adopted_recovered_or_resent(tmp_path, fault):
    peer = Peer(fault)
    adapter, prepared, plan, auth, verifier, store = make(tmp_path, peer)
    kernel = M4ExecutionKernel(adapter, verifier, store, clock=lambda: 1000)
    result = kernel.execute(plan, auth)
    assert result.outcome != 'succeeded'
    assert kernel.execute(plan, auth).idempotent_replay is True
    p2, a2, v2 = issue(peer.binding, prepared, 'recover')
    with pytest.raises(M4AdapterDenied):
        adapter.bind_recovery(p2, a2, v2, execution_enabled=True)
    assert peer.writes == ['POST'] and store.claim_count == 1


def test_gate_direct_dispatch_and_tampered_body_never_write(tmp_path):
    peer = Peer()
    adapter, prepared, plan, auth, verifier, store = make(tmp_path, peer, execution_enabled=False)
    result = M4ExecutionKernel(adapter, verifier, store, clock=lambda: 1000).execute(plan, auth)
    assert result.outcome == 'denied' and peer.writes == []
    adapter._enabled = True
    with pytest.raises(M4AuthorizationDenied):
        adapter.dispatch(plan)
    altered = json.loads(prepared.body_bytes)
    altered['status'] = 'enable'
    with pytest.raises(M4AdapterDenied):
        DisabledRouteM4Adapter(adapter._config, peer.binding, replace(prepared, body_bytes=json.dumps(altered).encode()),
                              plan, auth, verifier, store, serial_digest=SERIAL)
    assert peer.writes == []
