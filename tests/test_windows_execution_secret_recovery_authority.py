"""Independent lab HMAC policy with real removal M4 and synthetic product IO."""
from dataclasses import replace

import pytest

from fortipam_mcp import windows_execution_secret_recovery as r
from fortipam_mcp import windows_execution_secret_recovery_authority as a
from test_windows_execution_secret_recovery import components
from v4_planning import M4AuthorizationDenied, M4Outcome


def setup(tmp_path, monkeypatch, **options):
    cmp = components(tmp_path, monkeypatch, **options)
    path = tmp_path / "remove-authority.key"
    path.write_bytes(b"h" * 32)
    path.chmod(0o600)
    identity = dict(requester_digest=cmp["custody"]._plan.requester_digest,
                    transport_digest="b" * 64)
    kwargs = dict(execution_store=cmp["remove_store"], authority_key_file=path,
        witness_key_file=tmp_path / "remove-witness.key", environment_ref="owner-lab-development",
        scope_ref="one-private-windows-fixture", audience_ref="fixed-test-client",
        execution_enabled=True, clock=lambda: cmp["now"][0], **identity)
    authority = a.WindowsExecutionSecretRemovalLabAuthority(cmp["custody"], **kwargs)
    recovery_kwargs = {**cmp["recovery_kwargs"], "authorization_verifier": authority,
                       "clock": lambda: cmp["now"][0]}
    recovery = r.WindowsExecutionSecretRecovery(cmp["custody"], **recovery_kwargs)
    cmp.update(authority=authority, authority_kwargs=kwargs, identity=identity,
               recovery=recovery, recovery_kwargs=recovery_kwargs)
    return cmp


def issue(cmp):
    return cmp["authority"].issue(cmp["recovery"], **cmp["identity"])


@pytest.mark.parametrize("original_unknown", [False, True])
def test_independent_signed_removal_joins_original_ack_without_promoting_or_reloading_creation(
        tmp_path, monkeypatch, original_unknown):
    cmp = setup(tmp_path, monkeypatch, original_unknown=original_unknown)
    issued = issue(cmp)
    assert issued.plan.action_id == r.ACTION_ID
    assert issued.plan.plan_digest != cmp["custody"]._plan.plan_digest
    assert issued.authorization.requester_digest != issued.authorization.approver_digest
    assert cmp["remove_store"].claim_count == 0
    assert cmp["recovery"].execute(issued.plan, issued.authorization).outcome is M4Outcome.SUCCEEDED
    assert cmp["authority"]._consumed and cmp["remove_store"].claim_count == 1
    assert cmp["methods"] == ["DELETE", "GET"]
    assert len(cmp["source"].requests) == 21 and all(conn.closed for conn in cmp["connections"])
    assert cmp["loader"].loads == cmp["execution"].claim_count == cmp["material"].claim_count == 1
    assert cmp["custody"].inspect_original_creation() == cmp["original"]
    with pytest.raises(M4AuthorizationDenied): issue(cmp)
    with pytest.raises(r.WindowsExecutionSecretRecoveryError):
        cmp["recovery"].execute(issued.plan, issued.authorization)
    rebuilt = a.WindowsExecutionSecretRemovalLabAuthority(cmp["custody"], **cmp["authority_kwargs"])
    new_runtime = r.WindowsExecutionSecretRecovery(cmp["custody"],
        **{**cmp["recovery_kwargs"], "authorization_verifier": rebuilt})
    with pytest.raises(M4AuthorizationDenied): rebuilt.issue(new_runtime, **cmp["identity"])
    assert cmp["methods"] == ["DELETE", "GET"] and len(cmp["source"].requests) == 21


def test_manual_verification_without_durable_removal_claim_does_not_consume_grant(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    issued = issue(cmp)
    with pytest.raises(M4AuthorizationDenied):
        cmp["authority"].verify(issued.plan, issued.authorization, now_epoch=cmp["now"][0])
    assert not cmp["authority"]._consumed and cmp["remove_store"].claim_count == 0
    assert cmp["recovery"].execute(issued.plan, issued.authorization).outcome is M4Outcome.SUCCEEDED


def test_clock_tick_after_kernel_claim_keeps_the_same_unexpired_grant_valid(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    issued = issue(cmp)
    verify = cmp["authority"].verify
    def after_tick(plan, authorization, *, now_epoch):
        cmp["now"][0] += 1
        verify(plan, authorization, now_epoch=now_epoch)
    monkeypatch.setattr(cmp["authority"], "verify", after_tick)
    assert cmp["recovery"].execute(issued.plan, issued.authorization).outcome is M4Outcome.SUCCEEDED
    assert cmp["methods"] == ["DELETE", "GET"] and cmp["authority"]._consumed


@pytest.mark.parametrize("fault", ["disabled", "requester", "transport", "foreign-runtime", "preclaimed-preview"])
def test_missing_scope_identity_or_trusted_runtime_cannot_issue(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path, monkeypatch)
    identity = dict(cmp["identity"])
    runtime = cmp["recovery"]
    if fault == "disabled": cmp["authority"]._enabled = False
    if fault == "requester": identity["requester_digest"] = "f" * 64
    if fault == "transport": identity["transport_digest"] = "f" * 64
    if fault == "foreign-runtime": runtime = object()
    if fault == "preclaimed-preview": runtime.preview()
    count = len(cmp["source"].requests)
    with pytest.raises(M4AuthorizationDenied): cmp["authority"].issue(runtime, **identity)
    assert not cmp["methods"] and cmp["remove_store"].claim_count == 0
    assert len(cmp["source"].requests) == count


def test_authority_is_disabled_by_default(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    kwargs = {key: value for key, value in cmp["authority_kwargs"].items() if key != "execution_enabled"}
    closed = a.WindowsExecutionSecretRemovalLabAuthority(cmp["custody"], **kwargs)
    with pytest.raises(M4AuthorizationDenied): closed.issue(cmp["recovery"], **cmp["identity"])
    assert not cmp["methods"] and len(cmp["source"].requests) == 7


@pytest.mark.parametrize("fault", ["key", "witness", "namespace", "source", "preview", "expiry", "clock"])
def test_source_or_grant_drift_stops_before_claim_and_dispatch(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path, monkeypatch)
    issued = issue(cmp)
    if fault == "key": (tmp_path / "remove-authority.key").write_bytes(b"z" * 32)
    if fault == "witness": (tmp_path / "remove-witness.key").write_bytes(b"z" * 32)
    if fault == "namespace": cmp["authority"]._binding["scope_ref"] = "other-scope"
    if fault == "source":
        object.__setattr__(cmp["custody"]._config, "bearer_token", "changed-synthetic-token")
    if fault == "preview":
        cmp["recovery"]._preview = replace(cmp["recovery"]._preview, expected_digest="f" * 64)
    if fault == "expiry": cmp["now"][0] = issued.authorization.expires_at
    if fault == "clock": cmp["now"][0] = True
    with pytest.raises(r.WindowsExecutionSecretRecoveryError):
        cmp["recovery"].execute(issued.plan, issued.authorization)
    assert not cmp["methods"] and cmp["remove_store"].claim_count == 0
    assert len(cmp["source"].requests) == 14


def test_issuer_key_drift_during_fresh_preservation_stops_before_delete(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    issued = issue(cmp)
    def drift():
        if len(cmp["source"].requests) == 15:
            (tmp_path / "remove-authority.key").write_bytes(b"z" * 32)
    cmp["source"].hook = drift
    assert cmp["recovery"].execute(issued.plan, issued.authorization).outcome is not M4Outcome.SUCCEEDED
    assert cmp["authority"]._consumed and cmp["remove_store"].claim_count == 1
    assert not cmp["methods"] and not (cmp["directory"] / r._SEND).exists()
    assert cmp["custody"].inspect_original_creation() == cmp["original"]


def test_replacing_the_startup_pinned_authority_guard_cannot_bypass_key_check(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    issued = issue(cmp)
    cmp["authority"].validate_recovery_binding = lambda runtime: None
    with pytest.raises(r.WindowsExecutionSecretRecoveryError):
        cmp["recovery"].execute(issued.plan, issued.authorization)
    assert not cmp["methods"] and cmp["remove_store"].claim_count == 0


@pytest.mark.parametrize("source", ["creation", "material", "custody", "removal", "witness"])
def test_authority_key_cannot_reuse_any_creation_or_removal_key(tmp_path, monkeypatch, source):
    cmp = setup(tmp_path, monkeypatch)
    values = dict(creation=cmp["execution"]._key, material=cmp["material"]._key,
        custody=cmp["custody"]._key, removal=cmp["remove_store"]._key, witness=b"w" * 32)
    (tmp_path / "remove-authority.key").write_bytes(values[source])
    with pytest.raises(M4AuthorizationDenied):
        a.WindowsExecutionSecretRemovalLabAuthority(cmp["custody"], **cmp["authority_kwargs"])
    assert not cmp["methods"] and len(cmp["source"].requests) == 7


@pytest.mark.parametrize("fault", ["send", "absence-status", "crash"])
def test_unknown_or_interrupted_removal_cannot_get_another_grant(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path, monkeypatch, fault=fault)
    issued = issue(cmp)
    if fault == "crash":
        with pytest.raises(KeyboardInterrupt): cmp["recovery"].execute(issued.plan, issued.authorization)
    else:
        assert cmp["recovery"].execute(issued.plan, issued.authorization).outcome is M4Outcome.RECONCILIATION_REQUIRED
    rebuilt = a.WindowsExecutionSecretRemovalLabAuthority(cmp["custody"], **cmp["authority_kwargs"])
    runtime = r.WindowsExecutionSecretRecovery(cmp["custody"],
        **{**cmp["recovery_kwargs"], "authorization_verifier": rebuilt})
    before = len(cmp["source"].requests)
    with pytest.raises(M4AuthorizationDenied): rebuilt.issue(runtime, **cmp["identity"])
    assert len(cmp["source"].requests) == before and cmp["methods"].count("DELETE") == 1
    assert cmp["loader"].loads == 1


def test_copied_or_forged_grant_is_not_the_original_issued_authorization(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    issued = issue(cmp)
    forged = replace(issued.authorization)
    with pytest.raises(r.WindowsExecutionSecretRecoveryError):
        cmp["recovery"].execute(issued.plan, forged)
    assert not cmp["methods"] and not cmp["authority"]._consumed
    assert cmp["remove_store"].claim_count == 1


def test_real_creation_and_removal_issuers_form_one_separate_grant_chain(tmp_path, monkeypatch):
    import ssl
    from fortipam_mcp import windows_execution_secret_preservation as p
    from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
    from test_m4_execution_store import _ExternalM4Checkpoint
    from test_windows_execution_secret_authority import setup as create_setup, issue as create_issue, bind
    from test_windows_execution_secret_preservation import Source, reader
    from test_windows_execution_secret_recovery import Connection

    cmp = create_setup(tmp_path)
    _, creation = create_issue(cmp)
    protected, custody, _ = bind(cmp, tmp_path, monkeypatch, creation)
    assert protected.execute_bound(creation.authorization.authorization_ref).outcome is M4Outcome.SUCCEEDED
    original = custody.inspect_original_creation()
    cmp.update(custody=custody, directory=tmp_path / "custody")
    cmp["now"][0] = 2000
    source = Source()
    monkeypatch.setattr(p, "_ssl_context", lambda config: ssl.create_default_context())
    monkeypatch.setattr(r, "_ssl_context", lambda config: ssl.create_default_context())
    reader(cmp, source).read_once()
    for name, key in (("remove.key", b"r" * 32), ("remove-witness.key", b"s" * 32),
                      ("remove-authority.key", b"h" * 32)):
        path = tmp_path / name
        path.write_bytes(key)
        path.chmod(0o600)
    store = PersistentM4ExecutionStateStore(tmp_path / "remove.sqlite", tmp_path / "remove.key",
        monotonic_checkpoint=_ExternalM4Checkpoint("windows-removal-state"),
        checkpoint_store_ref="windows-removal-state")
    identity = dict(requester_digest=creation.plan.requester_digest, transport_digest="b" * 64)
    authority = a.WindowsExecutionSecretRemovalLabAuthority(custody, execution_store=store,
        authority_key_file=tmp_path / "remove-authority.key", witness_key_file=tmp_path / "remove-witness.key",
        environment_ref="owner-lab-development", scope_ref="one-private-windows-fixture",
        audience_ref="fixed-test-client", execution_enabled=True, clock=lambda: cmp["now"][0], **identity)
    methods = []
    recovery = r.WindowsExecutionSecretRecovery(custody, execution_store=store,
        witness_key_file=tmp_path / "remove-witness.key", authorization_verifier=authority,
        execution_enabled=True, client_factory=source.factory,
        connection_factory=lambda *args, **kwargs: Connection(methods),
        clock=lambda: cmp["now"][0], http_clock=lambda: 0)
    removal = authority.issue(recovery, **identity)
    assert recovery.execute(removal.plan, removal.authorization).outcome is M4Outcome.SUCCEEDED
    assert cmp["authority"]._verified and authority._consumed and methods == ["DELETE", "GET"]
    assert cmp["execution"].claim_count == cmp["material"].claim_count == store.claim_count == 1
    assert cmp["loader"].loads == 1 and custody.inspect_original_creation() == original
