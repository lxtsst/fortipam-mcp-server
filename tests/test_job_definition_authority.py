"""Server-held lab-auto authority binds actual sources and original full custody."""
from dataclasses import replace

import pytest
from v4_planning import M4AdapterAmbiguous, M4AuthorizationDenied, M4ExecutionKernel

from fortipam_mcp.job_definition_authority import JobDefinitionM4Authority, RECOVER_ACTION
from fortipam_mcp.job_definition_ack_custody import JobDefinitionAckCustody
from fortipam_mcp.job_definition_create_contract import DisabledJobCreateAckPins
from fortipam_mcp.job_definition_create_m4_adapter import JobDefinitionCreateM4Adapter
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_job_definition_sources import make, CANDIDATE
from test_job_definition_create_m4_adapter import Native
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF

IDENTITY = dict(environment_ref="job-lab-environment", scope_ref="job-lab-scope", audience_ref="job-lab-audience",
    requester_digest="b" * 64, transport_digest="c" * 64)


def authority(source, *, phase="create", original=None, enabled=True, clock=lambda: 1000):
    return JobDefinitionM4Authority(source, phase=phase, original=original, authority_key=b"j" * 32,
        execution_enabled=enabled, clock=clock, **IDENTITY)


def issued(source, issuer):
    preview = issuer.preview(source.observe_absence(), requester_digest=IDENTITY["requester_digest"],
        transport_digest=IDENTITY["transport_digest"])
    packet = issuer.issue(preview, source.observe_absence(), requester_digest=IDENTITY["requester_digest"],
        transport_digest=IDENTITY["transport_digest"])
    return preview, packet


def creation(tmp_path, monkeypatch, *, unknown=False, in_progress_probe=False):
    source, api, *_ = make(tmp_path, monkeypatch)
    issuer = authority(source)
    preview, packet = issued(source, issuer)
    (tmp_path / "custody").mkdir(mode=0o700)
    for name, value in (("execution.key", b"e" * 32), ("witness.key", b"w" * 32)):
        (tmp_path / name).write_bytes(value); (tmp_path / name).chmod(0o600)
    store = PersistentM4ExecutionStateStore(tmp_path / "execution.sqlite", tmp_path / "execution.key",
        monotonic_checkpoint=_ExternalM4Checkpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)
    pins = DisabledJobCreateAckPins(CANDIDATE, source._candidate._serial_digest, IDENTITY["requester_digest"],
        source._body_digest, packet.plan.plan_digest, packet.authorization.authorization_digest, "7" * 64)
    original = JobDefinitionAckCustody(tmp_path / "custody", tmp_path / "witness.key", pins,
        packet.plan, packet.authorization, store, clock=issuer._now)
    native = Native(api, original, pins)
    adapter = JobDefinitionCreateM4Adapter(source, original, execution_enabled=True, connection_factory=native.factory)
    if unknown:
        def postcondition_unavailable(plan):raise M4AdapterAmbiguous("Synthetic terminal read unavailable.")
        monkeypatch.setattr(adapter,"read_postcondition",postcondition_unavailable)
    if in_progress_probe:
        dispatch = adapter.dispatch
        def observe_before_terminal(plan):
            dispatch(plan)
            assert original.inspect_original_full_state().original_ack.original_outcome == "in_progress"
            with pytest.raises(M4AuthorizationDenied): authority(source, phase="recover", original=original)
        monkeypatch.setattr(adapter, "dispatch", observe_before_terminal)
    result = M4ExecutionKernel(adapter, issuer, store, clock=issuer._now).execute(packet.plan, packet.authorization)
    assert str(result.outcome) == ("reconciliation_required" if unknown else "succeeded")
    assert store.claim_count == len(native.calls) == 1
    return source, issuer, original, store, adapter


def test_actual_server_authorization_drives_one_original_http_m4(tmp_path, monkeypatch):
    source, issuer, original, store, adapter = creation(tmp_path, monkeypatch, in_progress_probe=True)
    assert original.inspect_original_full_state().original_ack.original_verification == "verified"
    issuer.close(); adapter.close(); source.close()


@pytest.mark.parametrize("unknown", [False, True])
def test_recovery_authority_requires_terminal_original_full_seal_without_rewriting_it(tmp_path, monkeypatch, unknown):
    source, create, original, store, adapter = creation(tmp_path, monkeypatch, unknown=unknown)
    before = {p.name: p.read_bytes() for p in original._directory.iterdir()}
    issuer = authority(source, phase="recover", original=original)
    observed = source.observe_candidate_presence()
    preview = issuer.preview(observed, requester_digest=IDENTITY["requester_digest"], transport_digest=IDENTITY["transport_digest"])
    packet = issuer.issue(preview, observed, requester_digest=IDENTITY["requester_digest"], transport_digest=IDENTITY["transport_digest"])
    issuer.verify(packet.plan, packet.authorization, now_epoch=1000)
    issuer.check_current(packet, observed)
    assert packet.plan.action_id == RECOVER_ACTION and packet.plan.parameters_digest != source._body_digest
    assert original.inspect_original_full_state().original_ack.original_verification == ("unknown" if unknown else "verified")
    assert before == {p.name: p.read_bytes() for p in original._directory.iterdir()} and store.claim_count == 1
    issuer.close(); create.close(); adapter.close(); source.close()


@pytest.mark.parametrize("fault", ["gate", "copy-preview", "tamper", "requester", "transport", "expiry", "copy-plan"])
def test_missing_fresh_intent_identity_or_server_binding_cannot_issue_or_verify(tmp_path, monkeypatch, fault):
    source, api, *_ = make(tmp_path, monkeypatch)
    now = [1000]
    issuer = authority(source, enabled=fault != "gate", clock=lambda: now[0])
    observed = source.observe_absence()
    args = dict(requester_digest=IDENTITY["requester_digest"], transport_digest=IDENTITY["transport_digest"])
    preview = issuer.preview(observed, **args)
    if fault == "copy-preview": preview = replace(preview)
    if fault == "tamper": object.__setattr__(preview, "current_digest", "f" * 64)
    if fault == "requester": args["requester_digest"] = "f" * 64
    if fault == "transport": args["transport_digest"] = "f" * 64
    if fault == "expiry": now[0] = preview.expires_at
    calls = len(api.calls)
    if fault == "copy-plan":
        packet = issuer.issue(preview, observed, **args)
        with pytest.raises(M4AuthorizationDenied): issuer.verify(replace(packet.plan), packet.authorization, now_epoch=1000)
    else:
        with pytest.raises(M4AuthorizationDenied): issuer.issue(preview, observed, **args)
    assert len(api.calls) == calls
    issuer.close(); source.close()


def test_missing_original_custody_cannot_become_recovery_authority(tmp_path, monkeypatch):
    source, *_ = make(tmp_path, monkeypatch)
    with pytest.raises(M4AuthorizationDenied): authority(source, phase="recover")
    source.close()
