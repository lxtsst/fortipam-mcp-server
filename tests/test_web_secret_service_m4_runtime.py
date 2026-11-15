from dataclasses import replace
from types import SimpleNamespace

import pytest
from v4_planning import InMemoryM4ExecutionStateStore, M4AuthorizationDenied, canonical_digest
from test_v4_execution_kernel import NOW, REQUESTER, _plan, _authorization, _Verifier
from test_web_secret_service_m4_adapter import _case
from fortipam_mcp.web_secret_service_ssh_transport import FortiPamWebSecretServiceSshTransport
from fortipam_mcp.web_secret_service_m4_adapter import WebSecretServiceBinding, parameters_digest
from fortipam_mcp.web_secret_service_m4_runtime import (
    ProtectedWebSecretServiceM4Runtime, WebSecretServiceExecutionBinding,
)


def _runtime(requester=REQUESTER, store=None):
    _, values, reader, mock_writer = _case()
    original = _plan()
    content = {**original.canonical_content(), **vars(values)}
    plan = replace(original, **vars(values), plan_digest=canonical_digest(content))
    authorization = _authorization(plan)
    service = WebSecretServiceBinding("web-service-ref", "Public/lab", "lab-web", 24)
    binding = WebSecretServiceExecutionBinding(plan, authorization, service)
    writer = object.__new__(FortiPamWebSecretServiceSshTransport)
    writer.enable_http_service = mock_writer.enable_http_service
    resolver = SimpleNamespace(resolve_execution_binding=lambda ref: binding)
    verifier = _Verifier()
    runtime = ProtectedWebSecretServiceM4Runtime(
        resolver, verifier, store if store is not None else InMemoryM4ExecutionStateStore(), reader, writer,
        authenticated_requester_digest=requester, clock=lambda: NOW,
    )
    return runtime, binding, mock_writer, verifier


def test_kernel_authorization_and_one_time_dispatch():
    runtime, binding, writer, verifier = _runtime()
    kwargs = {"expected_binding_digest": parameters_digest(binding.service)}
    first = runtime.execute_bound(binding.authorization.authorization_ref, **kwargs)
    second = runtime.execute_bound(binding.authorization.authorization_ref, **kwargs)
    assert first.idempotent_replay is False
    assert second.idempotent_replay is True
    assert writer.calls == 1
    assert verifier.calls >= 1


@pytest.mark.parametrize("failure", ["requester", "reference", "binding"])
def test_wrong_authority_or_binding_never_writes(failure):
    runtime, binding, writer, _ = _runtime("0" * 64 if failure == "requester" else REQUESTER)
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(
            "wrong-reference" if failure == "reference" else binding.authorization.authorization_ref,
            expected_binding_digest="0" * 64 if failure == "binding" else parameters_digest(binding.service),
        )
    assert writer.calls == 0


def test_persistent_ledger_prevents_dispatch_after_runtime_reconstruction(tmp_path):
    from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    key = state / "execution.key"
    key.write_bytes(b"synthetic-web-service-test-key-32bytes")
    key.chmod(0o600)
    database = state / "execution.sqlite3"
    runtime, binding, writer, _ = _runtime(
        store=PersistentM4ExecutionStateStore(database, key),
    )
    kwargs = {"expected_binding_digest": parameters_digest(binding.service)}
    first = runtime.execute_bound(binding.authorization.authorization_ref, **kwargs)
    assert not first.idempotent_replay
    assert writer.calls == 1
    restarted, _, restarted_writer, _ = _runtime(
        store=PersistentM4ExecutionStateStore(database, key),
    )
    second = restarted.execute_bound(binding.authorization.authorization_ref, **kwargs)
    assert second.idempotent_replay
    assert second.outcome == first.outcome
    assert restarted_writer.calls == 0
