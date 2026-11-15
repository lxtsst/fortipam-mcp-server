"""Scoped lab issuer through original custody, full producers and real M4 store."""
import pytest

from fortipam_mcp import web_secret_fixture_recovery_authority as a
from fortipam_mcp import web_secret_fixture_recovery_runtime as w
from v4_planning import M4AuthorizationDenied, M4ExecutionPlan
from test_web_secret_fixture_recovery_runtime import fixture as runtime_fixture


def fixture(tmp_path, monkeypatch, *, enabled=True):
    inert, guard, record, inputs, clients, connections, events, _, now = runtime_fixture(tmp_path, monkeypatch)
    requester = record._execution_binding.plan.requester_digest
    authority = a.WebSecretFixtureRecoveryAuthority(guard, authority_key=b'synthetic-recovery-authority-key-32',
        environment_ref='synthetic-lab', scope_ref='synthetic-disposable-web-fixture',
        audience_ref='synthetic-oauth-client', requester_digest=requester, transport_digest='a' * 64,
        execution_enabled=enabled)
    runtime = w.WebSecretFixtureRecoveryRuntime(guard, authorization_verifier=authority,
        delete_status='success', execution_enabled=True, connection_factory=inert._factory)
    return authority, runtime, record, inputs, clients, connections, events, now


def issue(authority, runtime, record, **overrides):
    identity = dict(requester_digest=record._execution_binding.plan.requester_digest,
        transport_digest='a' * 64)
    identity.update(overrides)
    return authority.issue(runtime, **identity)


def test_scoped_authority_issues_distinct_grant_and_real_kernel_consumes_once(tmp_path, monkeypatch):
    authority, runtime, record, _, clients, connections, events, _ = fixture(tmp_path, monkeypatch)
    original = record.read_acknowledged_creation()
    issued = issue(authority, runtime, record)
    assert issued.plan.action_id == w.ACTION
    assert issued.authorization != record._execution_binding.authorization
    assert issued.plan.requester_digest == record._execution_binding.plan.requester_digest
    assert events == ['full-read', 'full-read'] and not authority._consumed
    with pytest.raises(M4AuthorizationDenied):
        authority.verify(issued.plan, issued.authorization, now_epoch=100)
    assert not authority._consumed and not any(connection.calls for connection in connections)
    assert runtime.execute(issued.plan, issued.authorization).as_dict()['outcome'] == 'succeeded'
    assert authority._consumed
    assert events == ['full-read', 'full-read', 'tls', 'full-read', 'DELETE', 'tls', 'GET']
    assert all(len(client.calls) == 7 and client.is_closed for client in clients)
    assert record.read_acknowledged_creation() == original
    with pytest.raises(M4AuthorizationDenied): issue(authority, runtime, record)
    with pytest.raises(M4AuthorizationDenied):
        authority.verify(issued.plan, issued.authorization, now_epoch=100)
    with pytest.raises(w.WebSecretFixtureRecoveryError): runtime.execute(issued.plan, issued.authorization)
    assert all(len(connection.calls) == 1 for connection in connections)
    authority.close()


@pytest.mark.parametrize('fault', ['disabled', 'requester', 'transport', 'runtime-verifier', 'external-preview'])
def test_issue_requires_exact_trusted_runtime_and_identity(tmp_path, monkeypatch, fault):
    authority, runtime, record, _, clients, connections, _, _ = fixture(tmp_path, monkeypatch,
        enabled=fault != 'disabled')
    overrides = {}
    if fault == 'requester': overrides['requester_digest'] = 'b' * 64
    if fault == 'transport': overrides['transport_digest'] = 'b' * 64
    if fault == 'runtime-verifier': runtime._verifier = object()
    if fault == 'external-preview': runtime.preview()
    with pytest.raises(M4AuthorizationDenied) as caught: issue(authority, runtime, record, **overrides)
    assert str(caught.value) == a._ERROR
    assert not any(connection.calls for connection in connections)
    if fault != 'external-preview': assert not any(client.calls for client in clients)


@pytest.mark.parametrize('fault', ['copied-plan', 'expired', 'source-drift', 'closed'])
def test_issued_grant_refuses_forged_expired_or_changed_context(tmp_path, monkeypatch, fault):
    authority, runtime, record, inputs, clients, connections, _, now = fixture(tmp_path, monkeypatch)
    issued = issue(authority, runtime, record)
    plan = issued.plan
    if fault == 'copied-plan':
        plan = M4ExecutionPlan(**plan.canonical_content(), plan_digest=plan.plan_digest)
    elif fault == 'expired': now[0] = issued.authorization.expires_at
    elif fault == 'source-drift': authority._guard_source._source = 'b' * 64
    else: authority.close()
    with pytest.raises(w.WebSecretFixtureRecoveryError): runtime.execute(plan, issued.authorization)
    assert not any(connection.calls for connection in connections)
    assert all(len(client.calls) <= 7 for client in clients)
    if fault == 'copied-plan':
        assert (inputs['directory'] / w._ATTEMPT).exists()
        with pytest.raises(w.WebSecretFixtureRecoveryError): runtime.execute(issued.plan, issued.authorization)


def test_authority_constructor_rejects_non_original_requester(tmp_path, monkeypatch):
    _, guard, _, _, clients, connections, _, _, _ = runtime_fixture(tmp_path, monkeypatch)
    with pytest.raises(M4AuthorizationDenied):
        a.WebSecretFixtureRecoveryAuthority(guard, authority_key=b'k' * 32,
            environment_ref='synthetic-lab', scope_ref='synthetic-scope', audience_ref='synthetic-client',
            requester_digest='b' * 64, transport_digest='a' * 64, execution_enabled=True)
    assert not any(client.calls for client in clients) and not any(connection.calls for connection in connections)


@pytest.mark.parametrize('drift', [False, True])
def test_recovery_retains_own_pre_association_baseline(tmp_path, monkeypatch, drift):
    authority, runtime, record, _, clients, connections, events, _ = fixture(tmp_path, monkeypatch)
    runtime._guard_source.capture_baseline_once()
    assert events == ['full-read']
    if drift:
        for index in (1, 5):
            clients[1].responses[index].content = clients[1].responses[index].content.replace(
                b'synthetic-password', b'changed-password')
        with pytest.raises(M4AuthorizationDenied): issue(authority, runtime, record)
        assert events == ['full-read', 'full-read']
        assert not any(connection.calls for connection in connections)
        with pytest.raises(M4AuthorizationDenied): issue(authority, runtime, record)
    else:
        issued = issue(authority, runtime, record)
        assert events == ['full-read', 'full-read']
        assert runtime.execute(issued.plan, issued.authorization).as_dict()['outcome'] == 'succeeded'
        assert events == ['full-read', 'full-read', 'tls', 'full-read', 'DELETE', 'tls', 'GET']
    assert len(clients[0].calls) == 7
