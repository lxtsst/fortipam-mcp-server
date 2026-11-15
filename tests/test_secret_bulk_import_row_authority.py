"""Exact remote Reference permission and original NEW dispatch; synthetic source."""

from dataclasses import replace

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import secret_bulk_import_row_authority as boundary
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_file import PinnedBulkImportFile
from fortipam_mcp.reference_authority_sidecar import (
    UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings,
    create_reference_authority_sidecar_app,
)
from test_secret_bulk_import_reference_eligibility import AUTHORITY, REFERENCE, source
from test_secret_bulk_import_row_loader import ProbeAdapter, run, setup
from v4_planning import M4Verification


class DependencyReader:
    def __init__(self, plan):
        self.plan, self.calls, self.drift = plan, 0, False

    def read_current(self, plan):
        assert plan == self.plan
        self.calls += 1
        return "a" * 64 if self.drift else plan.expected_current_digest

    def read_postcondition(self, plan):
        assert plan == self.plan
        self.calls += 1
        return "a" * 64 if getattr(self, "post_drift", False) else plan.expected_state_digest


def configured(tmp_path, monkeypatch, *, issue=True, change=None, index=0, values=None, snapshot=None, capture=None, file_parent=False):
    make, session, state, _, values, binding, _, _ = setup(tmp_path, "encrypted", values=values, snapshot=snapshot,
        capture=capture, file_parent=file_parent)
    loader = make(index)
    clocks = [1000.0, 100.0]
    root, kwargs, grant, _ = source(tmp_path, binding, clocks,
        requester=loader._plan.requester_digest)
    transport = TestClient(create_reference_authority_sidecar_app(root))
    client = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(tmp_path / "reference.sock", AUTHORITY))
    monkeypatch.setattr(UnixReferenceAuthorityClient, "_post",
                        lambda self, path, payload: transport.post(path, json=payload))
    reader = DependencyReader(loader._plan)
    issued = loader._issuer._issued if file_parent else None
    authority = boundary.PinnedOriginalRowAcquisitionAuthority(binding, loader._plan, loader._authorization,
        policy_decision_digest=issued.policy_decision_digest if issued else '5' * 64,
        scope_digest=binding.scope_digest, audience_digest=issued.audience_digest if issued else '6' * 64,
        authority=client, authority_ref=AUTHORITY, reference=REFERENCE,
        scope_key_path=kwargs["scope_key_path"], scope_key_sha256=kwargs["scope_key_sha256"],
        projection_reader=reader, clock=lambda: int(clocks[0]))
    grant.update(reference_kind=boundary.REFERENCE_KIND, scope_ref=authority._checker._scope)
    if change:
        grant.update(change)
    handle = root.issue(REFERENCE, **grant) if issue else None
    loader._authority = authority
    return loader, session, state, values, root, handle, reader, clocks, transport


def test_remote_child_permission_uses_existing_checkpoint_rpc_and_cannot_issue_a_grant(tmp_path, monkeypatch, capfd):
    loader, session, state, values, root, handle, reader, _, transport = configured(tmp_path, monkeypatch)
    before = root._path.read_bytes()
    try:
        with transport:
            result, adapter = run(loader, state, ProbeAdapter(loader, values[0]))
        assert result.verification is M4Verification.VERIFIED
        assert root._path.read_bytes() == before and handle is not None
        assert reader.calls == 3
        assert loader._authority.acquisition_expires_at() == 1060
        assert all(not any(value) for value in adapter.owned._buffers)
        assert type(loader._authority._checker._authority) is UnixReferenceAuthorityClient
        assert not hasattr(loader._authority, "issue")
        assert capfd.readouterr() == ("", "")
    finally:
        session.close()


@pytest.mark.parametrize('fault', ['none', 'disabled', 'wrong-requester', 'key-reuse', 'drift',
                                  'invalidated', 'expired', 'rollback', 'late-claim', 'tamper'])
def test_original_parent_issuer_preserves_identity_and_refuses_unqualified_reissue(tmp_path, fault):
    from v4_planning import M4AuthorizationDenied, M4ExecutionPlan, canonical_digest
    capture = {}
    make, session, state, _, values, _, _, _ = setup(tmp_path, file_parent=True, capture=capture)
    clock = [1000]
    class Projection:
        def read_current(self, plan):
            if fault == 'late-claim':
                state.claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
                    idempotency_digest=plan.idempotency_digest, context_digest='a' * 64, authorization_digest='b' * 64)
            return 'f' * 64 if fault == 'drift' else plan.expected_current_digest
        def read_postcondition(self, plan): return plan.expected_state_digest
    try:
        factory = capture['make_issuer']
        changes = dict(clock=lambda: clock[0], projection_reader=Projection())
        if fault in ('wrong-requester', 'key-reuse'):
            changes.update({'authenticated_requester_digest': '8' * 64} if fault == 'wrong-requester'
                           else {'authority_key': b'i' * 32})
            with pytest.raises(M4AuthorizationDenied):
                factory(0, **changes)
            assert state.claim_count == 0
            return
        issuer = factory(0, execution_enabled=fault != 'disabled', **changes)
        if fault == 'expired': clock[0] = 1060
        if fault == 'rollback': clock[0] = 999
        if fault == 'invalidated':
            issuer._parent_store.invalidate_plan(issuer._parent.plan_ref, evaluated_at=1000,
                                                 reason_codes=('current_state_drift',))
        before = state._monotonic_checkpoint.tail
        if fault not in ('none', 'tamper'):
            with pytest.raises(M4AuthorizationDenied):
                issuer.issue()
            assert state.claim_count == (1 if fault == 'late-claim' else 0)
            if fault != 'late-claim': assert state._monotonic_checkpoint.tail == before
            return
        pins = issuer.issue()
        issuer.verify(pins.plan, pins.authorization, now_epoch=1000)
        assert state.claim_count == 0 and state._monotonic_checkpoint.tail == before
        if fault == 'tamper':
            fields = pins.plan.canonical_content()
            fields['parameters_digest'] = 'f' * 64
            changed = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
            with pytest.raises(M4AuthorizationDenied):
                issuer.verify(changed, pins.authorization, now_epoch=1000)
            issuer.close()
            with pytest.raises(M4AuthorizationDenied):
                issuer.verify(pins.plan, pins.authorization, now_epoch=1000)
            return
        original_loader = make(0)
        assert original_loader._issuer._issued == pins
        result, _ = run(original_loader, state, ProbeAdapter(original_loader, values[0]))
        assert result.verification is M4Verification.VERIFIED and state.claim_count == 1
        for key in (b'j' * 32, b'k' * 32):
            replacement = factory(0, authority_key=key)
            with pytest.raises(M4AuthorizationDenied):
                replacement.issue()
        assert state.claim_count == 1
    finally:
        session.close()


@pytest.mark.parametrize("fault", ["missing", "projection-only", "session-only", "wrong-requester",
                                  "wrong-scope", "revoked", "dependency-drift", "expired"])
def test_partial_or_wrong_remote_permission_never_reads_row(tmp_path, monkeypatch, fault):
    changes = {"projection-only": {"reference_kind": "owner_file_dependency_projection"},
        "session-only": {"reference_kind": "owner_file_source_session"},
        "wrong-requester": {"requester_digest": "8" * 64}, "wrong-scope": {"scope_ref": "wrong-row-scope"}}
    loader, session, state, _, root, handle, reader, clocks, transport = configured(
        tmp_path, monkeypatch, issue=fault != "missing", change=changes.get(fault))
    if fault == "revoked":
        root.revoke(handle, now_epoch=1000)
    if fault == "dependency-drift":
        reader.drift = True
    if fault == "expired":
        clocks[0] = session._transaction._binding.expires_at
    monkeypatch.setattr(PinnedBulkImportFile, "decode", lambda *_a, **_k: pytest.fail("Unqualified source read"))
    try:
        with transport:
            result, _ = run(loader, state)
        assert result.verification is M4Verification.UNKNOWN
    finally:
        session.close()


@pytest.mark.parametrize("field", ["workload_digest", "file_sha256", "batch_digest", "subject"])
def test_exact_permission_cannot_authorize_another_source_binding(tmp_path, monkeypatch, field):
    loader, session, _, _, _, _, _, _, transport = configured(tmp_path, monkeypatch)
    original = session._transaction._binding
    changed = replace(original, **{field: "other-human" if field == "subject" else "8" * 64})
    try:
        with transport, pytest.raises(BulkImportIntakeError):
            loader._authority.verify_row_acquisition(loader._plan, loader._authorization, changed, now_epoch=1000)
    finally:
        session.close()


def test_short_remote_decision_caps_owned_row_and_later_grant_checks_never_renew_it(tmp_path, monkeypatch):
    loader, session, state, _, _, _, _, _, transport = configured(
        tmp_path, monkeypatch, change={"expires_at": 1001})
    held = []

    class HoldProbe(ProbeAdapter):
        def dispatch(self, plan):
            held.append(loader._load_once())

    try:
        with transport:
            result, _ = run(loader, state, HoldProbe(loader))
        assert result.verification is M4Verification.VERIFIED
        assert loader._authority.acquisition_expires_at() == 1001
        row = held[0]
        assert row._lifetime.deadline == loader._acquisition_deadline
        row._watchdog.join(1.5)
        assert not row._watchdog.is_alive() and all(not any(value) for value in row._buffers)
        assert not session._transaction._closed.is_set()
    finally:
        for row in held:
            row.close()
        session.close()
