"""Actual fixed Owner issuers, HTTP child adapter and persistent M4 stores."""
from pathlib import Path
from dataclasses import asdict
import json
import os
import subprocess
import sys

import pytest

from fortipam_mcp.jwt_manual_key_owner_workflow import JwtManualKeyOwnerWorkflow
from fortipam_mcp.jwt_manual_key_owner_http import JwtManualKeyOwnerHttp, JwtManualKeyOwnerHttpError
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_jwt_manual_key_owner_http import Lab
from test_jwt_manual_key_contract import synthetic_key
from test_v4_execution_kernel import REQUESTER
from v4_planning import M4AuthorizationDenied, canonical_digest

IDENTITY = {"environment_ref":"synthetic-owner-lab", "scope_ref":"synthetic-owner-scope",
            "audience_ref":"synthetic-owner-audience"}
TRANSPORT = "d" * 64


def workflow(lab, session, store, phase, *, enabled=True, original=None):
    directory = lab.root / (phase + "-authority"); directory.mkdir(mode=0o700)
    key = directory / "authority.key"; key.write_bytes((b"a" if phase == "create" else b"b") * 32); key.chmod(0o600)
    extra = {} if original is None else {"creation_store":original._store,
        "creation_authority_directory":original._directory,"creation_authority_key_file":original._key_file}
    return JwtManualKeyOwnerWorkflow(session, store, phase=phase, directory=directory,
        authority_key_file=key, **IDENTITY, execution_enabled=enabled, source_guard=lambda:lab.source,
        clock=lambda:1000, **extra)


def run(authority):
    preview = authority.preview(requester_digest=REQUESTER, transport_digest=TRANSPORT)
    plan, auth = authority.issue(preview, requester_digest=REQUESTER, transport_digest=TRANSPORT)
    return authority.execute(plan, auth), plan, auth


@pytest.mark.parametrize("fault", ["none", "bad-post"])
def test_real_create_and_independent_recovery_keep_original_grants_and_ledgers(tmp_path, synthetic_key, monkeypatch, fault):
    lab = Lab(tmp_path, synthetic_key, monkeypatch, fault)
    with lab.session() as source:
        creator = workflow(lab, source, lab.store("create"), "create")
        result, plan, auth = run(creator)
        assert result.outcome == ("succeeded" if fault == "none" else "reconciliation_required")
        assert lab.posts == 1 and creator._consumed
        tail = creator._store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest, authorization_digest=auth.authorization_digest,
            context_digest=canonical_digest({"plan_digest":plan.plan_digest,"authorization_digest":auth.authorization_digest,"revision":plan.revision}))
        grant = (creator._directory / "grant.json").read_bytes()
    creator.close(); lab.fault = "none"
    with lab.session() as recovery:
        remover = workflow(lab, recovery, lab.store("remove"), "remove", original=creator)
        removed, _, _ = run(remover)
        assert removed.outcome == "succeeded" and lab.deletes == 1 and not lab.exists
        remover.close()
    assert (creator._directory / "grant.json").read_bytes() == grant
    assert creator._store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
        idempotency_digest=plan.idempotency_digest, authorization_digest=auth.authorization_digest,
        context_digest=canonical_digest({"plan_digest":plan.plan_digest,"authorization_digest":auth.authorization_digest,"revision":plan.revision})) == tail


@pytest.mark.parametrize("fault", ["403", "timeout"])
def test_missing_original_native_ack_never_allows_recovery_adoption(tmp_path, synthetic_key, monkeypatch, fault):
    lab = Lab(tmp_path, synthetic_key, monkeypatch, fault)
    with lab.session() as source:
        creator = workflow(lab, source, lab.store("create"), "create")
        result, _, _ = run(creator); assert result.outcome == "reconciliation_required"
    lab.fault = "none"
    with lab.session() as recovery:
        remover = workflow(lab, recovery, lab.store("remove"), "remove", original=creator)
        with pytest.raises(M4AuthorizationDenied):
            remover.preview(requester_digest=REQUESTER, transport_digest=TRANSPORT)
    assert lab.posts == 1 and lab.deletes == 0 and lab.full_reads == 0


@pytest.mark.parametrize("fault", ["wrong-requester", "wrong-transport", "closed-policy"])
def test_identity_and_policy_gates_precede_creation_sources(tmp_path, synthetic_key, monkeypatch, fault):
    lab = Lab(tmp_path, synthetic_key, monkeypatch)
    with lab.session() as source:
        creator = workflow(lab, source, lab.store("create"), "create", enabled=fault != "closed-policy")
        calls = len(lab.calls)
        if fault == "closed-policy":
            preview = creator.preview(requester_digest=REQUESTER, transport_digest=TRANSPORT)
            with pytest.raises(M4AuthorizationDenied): creator.issue(preview, requester_digest=REQUESTER, transport_digest=TRANSPORT)
        else:
            with pytest.raises(M4AuthorizationDenied):
                creator.preview(requester_digest="f"*64 if fault == "wrong-requester" else REQUESTER,
                    transport_digest="f"*64 if fault == "wrong-transport" else TRANSPORT)
            assert len(lab.calls) == calls
    assert lab.posts == 0


@pytest.mark.parametrize("fault", ["authority-key", "source", "rebound-runtime", "store-key"])
def test_post_preview_policy_or_source_drift_denies_before_native_post(tmp_path, synthetic_key, monkeypatch, fault):
    lab = Lab(tmp_path, synthetic_key, monkeypatch)
    with lab.session() as source:
        creator = workflow(lab, source, lab.store("create"), "create")
        preview = creator.preview(requester_digest=REQUESTER, transport_digest=TRANSPORT)
        plan, auth = creator.issue(preview, requester_digest=REQUESTER, transport_digest=TRANSPORT)
        if fault == "authority-key": creator._key_file.write_bytes(b"z"*32)
        if fault == "store-key": creator._store._key_path.write_bytes(b"z"*32)
        if fault == "source": lab.source = False
        if fault == "rebound-runtime": creator._source = lab.session()
        with pytest.raises((M4AuthorizationDenied, ValueError)):
            creator.execute(plan, auth)
        assert lab.posts == 0


def test_one_time_policy_requires_original_kernel_claim_and_cannot_be_reissued(tmp_path, synthetic_key, monkeypatch):
    lab = Lab(tmp_path, synthetic_key, monkeypatch)
    with lab.session() as source:
        creator = workflow(lab, source, lab.store("create"), "create")
        preview = creator.preview(requester_digest=REQUESTER, transport_digest=TRANSPORT)
        plan, auth = creator.issue(preview, requester_digest=REQUESTER, transport_digest=TRANSPORT)
        with pytest.raises(M4AuthorizationDenied): creator.verify(plan, auth, now_epoch=1000)
        assert not creator._consumed
        result = creator.execute(plan, auth); assert result.outcome == "succeeded"
        replay = creator.execute(plan, auth); assert replay.idempotent_replay and lab.posts == 1
        with pytest.raises(M4AuthorizationDenied): creator.issue(preview, requester_digest=REQUESTER, transport_digest=TRANSPORT)


def test_tampered_original_grant_is_refused_before_any_owned_key_body(tmp_path, synthetic_key, monkeypatch):
    lab = Lab(tmp_path, synthetic_key, monkeypatch)
    with lab.session() as source:
        creator = workflow(lab, source, lab.store("create"), "create"); run(creator)
    original = creator._directory / "grant.json"; original.write_bytes(original.read_bytes().replace(b'"phase":"create"',b'"phase":"remove"'))
    before = lab.full_reads
    with lab.session() as recovery:
        remover = workflow(lab, recovery, lab.store("remove"), "remove", original=creator)
        with pytest.raises(M4AuthorizationDenied): remover.preview(requester_digest=REQUESTER, transport_digest=TRANSPORT)
    assert lab.full_reads == before and lab.deletes == 0


def test_original_complete_poststate_cannot_be_replaced_by_a_fresh_changed_owned_row(tmp_path, synthetic_key, monkeypatch):
    lab = Lab(tmp_path, synthetic_key, monkeypatch)
    with lab.session() as source:
        creator = workflow(lab, source, lab.store("create"), "create"); run(creator)
    original = (lab.wire / "create.state.json").read_bytes()
    lab.row["last-update-time"] = "synthetic-later-change"
    with lab.session() as recovery:
        remover = workflow(lab, recovery, lab.store("remove"), "remove", original=creator)
        with pytest.raises(M4AuthorizationDenied): remover.preview(requester_digest=REQUESTER, transport_digest=TRANSPORT)
    assert lab.deletes == 0 and not (lab.wire / "remove.claim.json").exists()
    assert (lab.wire / "create.state.json").read_bytes() == original


def test_closed_original_metadata_restores_in_new_process_and_removes_with_original_readonly_ledger(tmp_path, synthetic_key, monkeypatch):
    lab = Lab(tmp_path, synthetic_key, monkeypatch, "bad-post")
    with lab.session() as source:
        creator = workflow(lab, source, lab.store("create"), "create")
        result, _, _ = run(creator); assert result.outcome == "reconciliation_required"
    original_claim = (lab.wire / "create.claim.json").read_bytes()
    data = {"config":asdict(lab.config), "directory":str(lab.wire), "witness":str(lab.key)}
    script = '''
import json, sys
from pathlib import Path
from fortipam_mcp.jwt_manual_key_owner_http import JwtManualKeyOwnerHttp, JwtManualKeyOwnerHttpConfig
from fortipam_mcp.jwt_manual_key_contract import JwtManualKeyContractError
d=json.loads(sys.stdin.read())
s=JwtManualKeyOwnerHttp.from_original_creation(JwtManualKeyOwnerHttpConfig(**d["config"]),
    lambda: (_ for _ in ()).throw(AssertionError("No login during metadata restoration")),
    directory=Path(d["directory"]), witness_key_file=Path(d["witness"]))
assert s._request._closed and not s._request._body and s._session is None
try: s._request.borrow_body()
except JwtManualKeyContractError: pass
else: raise AssertionError("A restored create body must remain unavailable")
print("closed-original-metadata-restored")
'''
    completed = subprocess.run([sys.executable, "-c", script], input=json.dumps(data),
        capture_output=True, text=True, env={**os.environ,"PYTHONPATH":str(Path(__file__).resolve().parents[1] / "src")}, timeout=15)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "closed-original-metadata-restored"
    readonly = PersistentM4ExecutionStateStore(creator._store._path, creator._store._key_path,
        read_only=True, monotonic_checkpoint=creator._store._monotonic_checkpoint,
        checkpoint_store_ref=creator._store._checkpoint_store_ref)
    lab.fault = "none"
    with JwtManualKeyOwnerHttp.from_original_creation(lab.config, source._credentials,
            directory=lab.wire, witness_key_file=lab.key, source_guard=lambda:lab.source,
            execution_enabled=True, client_factory=lab.factory, clock=lambda:1000) as recovered:
        remover = workflow(lab, recovered, lab.store("remove"), "remove", original=creator)
        remover._creator_store = readonly
        removed, _, _ = run(remover)
        assert removed.outcome == "succeeded" and lab.posts == lab.deletes == 1
    assert (lab.wire / "create.claim.json").read_bytes() == original_claim


@pytest.mark.parametrize("fault", ["tampered-claim", "missing-ack", "foreign-directory"])
def test_metadata_restoration_refuses_unauthenticated_or_foreign_originals_before_login(tmp_path, synthetic_key, monkeypatch, fault):
    lab = Lab(tmp_path, synthetic_key, monkeypatch)
    with lab.session() as source:
        run(workflow(lab, source, lab.store("create"), "create"))
    directory = lab.wire
    if fault == "tampered-claim":
        path = lab.wire / "create.claim.json"
        path.write_bytes(path.read_bytes().replace(b'"request_digest":"',b'"request_digest":"0'))
    if fault == "missing-ack": (lab.wire / "create.ack.json").unlink()
    if fault == "foreign-directory":
        import shutil
        directory = tmp_path / "foreign"; shutil.copytree(lab.wire, directory)
    before = len(lab.calls)
    with pytest.raises(JwtManualKeyOwnerHttpError):
        JwtManualKeyOwnerHttp.from_original_creation(lab.config, source._credentials,
            directory=directory, witness_key_file=lab.key, client_factory=lab.factory)
    assert len(lab.calls) == before and lab.posts == 1 and lab.deletes == 0
