"""Separate retained-fixture cleanup with real signed custody; synthetic I/O."""
from copy import deepcopy
import hashlib
import hmac
import http.client
import json

import pytest

from v4_planning import M4ExecutionResult, M4AuditEvent, M4Outcome, M4Verification, M4Compensation
from fortipam_mcp import web_secret_fixture_api_preservation_reader as reader
from fortipam_mcp import web_secret_fixture_recovery_guard as guards
from fortipam_mcp import web_secret_fixture_recovery_runtime as runtime_module
from fortipam_mcp.web_secret_fixture_reconciled_source import (
    WebSecretFixtureReconciledSource, WebSecretFixtureReconciledSourceError, _DOMAIN,
)
from fortipam_mcp.web_secret_fixture_recovery_authority import WebSecretFixtureRecoveryAuthority
from test_web_secret_fixture_source_observation import source_fixture
from test_web_secret_fixture_recovery_runtime import NativeConnection


def fixture(tmp_path, monkeypatch, *, normal=False):
    observer, record, factory, clients, directory, store, create, binding = source_fixture(tmp_path, monkeypatch, normal=normal)
    clients.append(deepcopy(clients[0]))
    observer.read_once()
    # Preserve a consumed unknown claim and original markers; never replay them.
    old = dict(plan_ref="old-delete-plan", requester_digest="a" * 64, idempotency_digest="b" * 64,
        authorization_digest="c" * 64, context_digest="d" * 64)
    store.claim(**old)
    store.finalize(plan_ref=old["plan_ref"], requester_digest=old["requester_digest"],
        idempotency_digest=old["idempotency_digest"], context_digest=old["context_digest"],
        result=M4ExecutionResult(M4Outcome.RECONCILIATION_REQUIRED, M4Verification.UNKNOWN,
            M4Compensation.NOT_REQUESTED, False),
        event=M4AuditEvent(0, "verified", M4Outcome.RECONCILIATION_REQUIRED, M4Verification.UNKNOWN,
            M4Compensation.NOT_REQUESTED, "e" * 64))
    for name in ("recovery.delete.attempt", "api-preservation.recovery-dispatch.attempt"):
        path = directory / name
        path.write_bytes(b"synthetic-consumed-unknown\n")
        path.chmod(0o600)
    if normal:
        (directory / "instruction.attach.attempt").write_bytes(b"synthetic-consumed-unknown-attach")
        (directory / "instruction.attach.attempt").chmod(0o600)
    recon = reader.WebSecretFixtureApiPreservationReader(record, instruction_profile_name="",
        credential_envelope=None, totp_envelope=None, phase="reconciliation", client_factory=factory)
    witness = recon.read_once()
    password, totp = recon.observed_envelopes()
    original_files = {"creation/" + name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for name in ("creation.record", "creation.ack", "creation.attempt", "api-preservation.source.attempt",
                     "recovery.delete.attempt", "api-preservation.recovery-dispatch.attempt")
        if not normal or name != "api-preservation.source.attempt"}
    if normal:
        original_files.update({"creation/"+name: hashlib.sha256((directory/name).read_bytes()).hexdigest()
            for name in ("api-preservation.baseline.attempt", "instruction.attach.attempt")})
    value = dict(contract="retained-owned-web-reconciled-source/v1", namespace=record._namespace,
        creation_digest=record.read_creation().creation_digest, observed_at=0, completed_at=0,
        preservation_digest=witness.preservation_digest, credential=password, totp=totp,
        original_claim_count=store.claim_count, original_files=original_files,
        observer_attempt_digest=hashlib.sha256((directory / "api-preservation.reconciliation.attempt").read_bytes()).hexdigest(),
        execution_authority=False)
    path = tmp_path / "reconciled-source.private.json"
    def seal():
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
        signature = hmac.new(record._key, _DOMAIN + record._namespace.encode("ascii") + b"\0" + raw,
            hashlib.sha256).hexdigest()
        path.write_text(json.dumps(dict(value=value, seal=signature)))
        path.chmod(0o600)
    seal()
    return record, factory, clients, store, create, binding, value, path, seal, old


def compose(record, factory, binding, path, *, enabled=True):
    source = WebSecretFixtureReconciledSource(record, path)
    guard = guards.WebSecretFixtureRecoveryGuard(record, credential_envelope=source._value["credential"],
        totp_envelope=source._value["totp"], reconciled_source=source, client_factory=factory, clock=binding._clock)
    authority = WebSecretFixtureRecoveryAuthority(guard, authority_key=b"synthetic-reconciled-cleanup-00001",
        environment_ref=binding._promoter._environment_ref, scope_ref=binding._promoter._scope_ref,
        audience_ref="synthetic-cleanup-client", requester_digest=record._execution_binding.plan.requester_digest,
        transport_digest="a" * 64, execution_enabled=enabled)
    events = []
    connections = [NativeConnection("DELETE", events)] + [NativeConnection("GET", events) for _ in range(3)]
    pending = iter(connections)
    runtime = runtime_module.WebSecretFixtureRecoveryRuntime(guard, authorization_verifier=authority,
        delete_status="success", execution_enabled=enabled, connection_factory=lambda *a, **k: next(pending))
    return guard, authority, runtime, connections


@pytest.mark.parametrize("normal", [False, True])
@pytest.mark.parametrize("fault", [None, "baseline", "current", "dispatch", "absence_once", "absence_exhausted"])
def test_separate_cleanup_preserves_unknown_claim_and_rejects_full_material_drift(tmp_path, monkeypatch, fault, normal):
    record, factory, clients, store, create, binding, value, path, seal, old = fixture(tmp_path, monkeypatch, normal=normal)
    old_claim = store.inspect_claim(**old)
    original_bytes = {name: (record._directory / name.split("/", 1)[1]).read_bytes() for name in value["original_files"]}
    if fault in {"baseline", "current", "dispatch"}:
        index = {"baseline": 2, "current": 3, "dispatch": 4}[fault]
        for slot in (1, 5):
            clients[index].responses[slot].content = clients[index].responses[slot].content.replace(
                b"synthetic-password", b"changed-password")
    guard, authority, runtime, connections = compose(record, factory, binding, path)
    if fault in {"absence_once", "absence_exhausted"}:
        for connection in connections[1:2] if fault == "absence_once" else connections[1:]:
            def disconnect(connection=connection):
                connection.response.close()
                raise http.client.RemoteDisconnected("Synthetic absence failure")
            connection.getresponse = disconnect
    if fault in {"baseline", "current"}:
        with pytest.raises(ValueError):
            authority.issue(runtime, requester_digest=record._execution_binding.plan.requester_digest,
                transport_digest="a" * 64)
        assert store.claim_count == 2 and not any(c.calls for c in connections)
    else:
        issued = authority.issue(runtime, requester_digest=record._execution_binding.plan.requester_digest,
            transport_digest="a" * 64)
        assert (issued.plan.action_id, issued.plan.action_version, issued.plan.adapter_ref) == (
            runtime_module.RECONCILED_ACTION, "1.0.0", runtime_module.RECONCILED_ADAPTER)
        result = runtime.execute(issued.plan, issued.authorization).as_dict()
        if fault == "dispatch":
            assert result["outcome"] == "denied" and not any(c.calls for c in connections)
        else:
            assert result["outcome"] == ("reconciliation_required" if fault == "absence_exhausted" else "succeeded")
            assert sum(call[0] == "DELETE" for c in connections for call in c.calls) == 1
            assert (record._directory / "reconciled-cleanup.delete.ack").is_file()
        assert store.claim_count == 3
        with pytest.raises(runtime_module.WebSecretFixtureRecoveryError):
            runtime.execute(issued.plan, issued.authorization)
        with pytest.raises(runtime_module.WebSecretFixtureRecoveryError):
            runtime_module.WebSecretFixtureRecoveryRuntime(guard, delete_status="success", execution_enabled=True)
    assert store.inspect_claim(**old) == old_claim
    assert all((record._directory / name.split("/", 1)[1]).read_bytes() == data for name, data in original_bytes.items())
    assert not (record._directory / "recovery.delete.ack").exists() and create.posts == 1
    authority.close()
    runtime.close()
    assert not authority._enabled and not runtime._enabled and guard._state == "closed"
    assert all(c.is_closed for c in clients if c.calls)


@pytest.mark.parametrize("fault", ["seal", "namespace", "authority", "count", "marker", "ack", "mode", "memory"])
def test_unqualified_capsule_or_changed_original_source_refuses_before_http(tmp_path, monkeypatch, fault):
    record, factory, clients, store, create, binding, value, path, seal, old = fixture(tmp_path, monkeypatch)
    if fault in {"namespace", "authority", "count"}:
        value[{"namespace": "namespace", "authority": "execution_authority", "count": "original_claim_count"}[fault]] = (
            "a" * 64 if fault == "namespace" else True if fault == "authority" else 1)
        seal()
    elif fault in {"marker", "ack"}:
        target = record._directory / ("creation.ack" if fault == "ack" else "api-preservation.reconciliation.attempt")
        target.write_bytes(b"changed-original\n")
    elif fault == "mode":
        path.chmod(0o644)
    elif fault == "seal":
        payload = json.loads(path.read_text()); payload["seal"] = "0" * 64
        path.write_text(json.dumps(payload))
    if fault == "memory":
        source = WebSecretFixtureReconciledSource(record, path)
        source._value["preservation_digest"] = "a" * 64
        with pytest.raises(WebSecretFixtureReconciledSourceError): source._guard()
    else:
        with pytest.raises(WebSecretFixtureReconciledSourceError): WebSecretFixtureReconciledSource(record, path)
    assert not any(c.calls for c in clients[2:]) and store.claim_count == 2


def test_cleanup_defaults_closed_and_cannot_become_instruction_or_source_recovery(tmp_path, monkeypatch):
    record, factory, clients, store, create, binding, value, path, seal, old = fixture(tmp_path, monkeypatch)
    guard, authority, runtime, connections = compose(record, factory, binding, path, enabled=False)
    with pytest.raises(ValueError):
        authority.issue(runtime, requester_digest=record._execution_binding.plan.requester_digest, transport_digest="a" * 64)
    with pytest.raises(runtime_module.WebSecretFixtureRecoveryError):
        runtime_module.WebSecretFixtureRecoveryRuntime(guard, observe_delete_source=True, execution_enabled=True)
    with pytest.raises(guards.WebSecretFixtureRecoveryGuardError): guard.bind_instruction_profile("synthetic-profile")
    assert not any(c.calls for c in clients[2:]) and store.claim_count == 2


def test_reconciled_delete_mode_drift_is_denied_before_a_claim_or_dispatch(tmp_path, monkeypatch):
    record, factory, clients, store, create, binding, value, path, seal, old = fixture(tmp_path, monkeypatch)
    guard, authority, runtime, connections = compose(record, factory, binding, path)
    issued = authority.issue(runtime, requester_digest=record._execution_binding.plan.requester_digest,
        transport_digest="a" * 64)
    runtime._observe_delete_source = True
    with pytest.raises(runtime_module.WebSecretFixtureRecoveryError):
        runtime.execute(issued.plan, issued.authorization)
    assert store.claim_count == 2 and not any(c.calls for c in connections) and not clients[4].calls
    assert not (record._directory / "reconciled-cleanup.delete.attempt").exists()
    authority.close()


@pytest.mark.parametrize('missing', ['creation/api-preservation.baseline.attempt','creation/instruction.attach.attempt'])
def test_normal_reconciliation_requires_original_baseline_and_consumed_attach(tmp_path, monkeypatch, missing):
    record, factory, clients, store, create, binding, value, path, seal, old = fixture(tmp_path, monkeypatch, normal=True)
    value['original_files'].pop(missing); seal()
    with pytest.raises(WebSecretFixtureReconciledSourceError): WebSecretFixtureReconciledSource(record,path)
    assert store.claim_count==2 and create.posts==1
