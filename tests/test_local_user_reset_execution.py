from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import pickle
import threading
from types import SimpleNamespace
from typing import Any

import pytest

from fortipam_mcp.local_user_reset_execution import (
    FortiPamLocalUserResetExecution, LocalUserResetExecutionError, LocalUserResetRunIntent,
)
from fortipam_mcp.local_user_reset_http_transport import FortiPamLocalUserResetHttpTransport, LocalUserResetMaterialLease
from fortipam_mcp.local_user_reset_policy_reader import LocalUserResetPolicySnapshot
from fortipam_mcp.local_user_reset_preview import FortiPamLocalUserResetPreviewReader
import fortipam_mcp.local_user_reset_owner_session as owner_module
from v4_planning import InMemoryM4ExecutionStateStore, M4ClaimState, M4Outcome, M4Verification
from v4_planning.material_provider import MaterialAccessDenied

from test_local_user_reset_http_transport import Harness, Response, _baseline
from test_m4_execution_store import _store
from test_local_user_reset_owner_session import _Harness as OwnerHarness


def _intent(**updates: Any) -> LocalUserResetRunIntent:
    return replace(LocalUserResetRunIntent(
        plan_ref="bp002-reset-synthetic-plan", requester_digest="1" * 64,
        authorization_digest="2" * 64, idempotency_digest="3" * 64,
        summary_digest="4" * 64, scope_digest="5" * 64, issued_at=1000, expires_at=1060,
    ), **updates)


class Verifier:
    def __init__(self, outcome: Any = True) -> None:
        self.calls: list[tuple[LocalUserResetRunIntent, str, int]] = []
        self.outcome = outcome
        self.hook: Any = lambda *_args: None

    def verify(self, intent: LocalUserResetRunIntent, *, context_digest: str, now_epoch: int) -> bool:
        self.calls.append((intent, context_digest, now_epoch))
        self.hook(intent, context_digest)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def _policy(**updates: Any) -> LocalUserResetPolicySnapshot:
    return replace(LocalUserResetPolicySnapshot(
        minimum_length=8, min_change_characters=0,
        min_upper_case_letter=0, min_lower_case_letter=0,
        min_number=0, min_non_alphanumeric=0,
        status="disable", reuse_password="enable", expire_status="disable",
    ), **updates)


class PolicyInspector:
    def __init__(self, snapshot: LocalUserResetPolicySnapshot) -> None:
        self.snapshot = snapshot
        self.reads = 0

    def read_policy_snapshot(self) -> LocalUserResetPolicySnapshot:
        self.reads += 1
        return self.snapshot


def _preview(h: Harness, policy: LocalUserResetPolicySnapshot):
    inspector = PolicyInspector(policy)
    return FortiPamLocalUserResetPreviewReader(
        h.binding, h, policy, inspector, clock=lambda: 1000,
    ).read_preview()


def _runner(h: Harness, store: Any, verifier: Verifier | None, **updates: Any) -> FortiPamLocalUserResetExecution:
    values = {
        "intent": _intent(), "authenticated_requester_digest": "1" * 64,
        "authorized_scope_digest": "5" * 64, "authorization_verifier": verifier,
        "policy_snapshot": _policy(), "policy_inspector": PolicyInspector(_policy()),
        "enabled": True, "clock": lambda: 1000,
    }
    values.update(updates)
    return FortiPamLocalUserResetExecution(h.transport(), store, **values)


def _claim(store: Any, runner: FortiPamLocalUserResetExecution):
    intent = runner._intent
    return store.claim(
        plan_ref=intent.plan_ref, requester_digest=intent.requester_digest,
        idempotency_digest=intent.idempotency_digest, context_digest=runner._context,
        authorization_digest=intent.authorization_digest,
    )


def test_execution_binds_fresh_preflight_summary_without_issuing_authority(tmp_path: Path) -> None:
    h, policy = Harness(), _policy()
    preview = _preview(h, policy)
    intent = _intent(summary_digest=preview.summary_digest)
    runner = _runner(h, _store(tmp_path), Verifier(False), intent=intent,
                     policy_snapshot=policy, preflight_preview=preview)
    assert runner.execute().outcome is M4Outcome.DENIED
    assert h.calls == []
    assert _store(tmp_path).audit_events[0].authorization == "denied"

    with pytest.raises(LocalUserResetExecutionError):
        _runner(Harness(), _store(tmp_path / "wrong-summary"), Verifier(),
                preflight_preview=preview)
    with pytest.raises(LocalUserResetExecutionError):
        _runner(Harness(), _store(tmp_path / "wrong-policy"), Verifier(),
                intent=intent, preflight_preview=preview,
                policy_snapshot=_policy(minimum_length=12))
    with pytest.raises(LocalUserResetExecutionError):
        _runner(Harness(), _store(tmp_path / "expired"), Verifier(),
                intent=_intent(summary_digest=preview.summary_digest,
                               issued_at=1250, expires_at=1301),
                preflight_preview=preview)


def test_preflight_tamper_denies_before_durable_claim(tmp_path: Path) -> None:
    h, policy = Harness(), _policy()
    preview = _preview(h, policy)
    runner = _runner(h, _store(tmp_path), Verifier(),
                     intent=_intent(summary_digest=preview.summary_digest),
                     policy_snapshot=policy, preflight_preview=preview)
    object.__setattr__(preview, "current_state_digest", "0" * 64)
    assert runner.execute().outcome is M4Outcome.DENIED
    assert _store(tmp_path).audit_events == ()
    assert h.calls == []


def test_real_adapter_claim_precedes_authority_material_and_posts_and_restart_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    h, verifier, store = Harness(), Verifier(), _store(tmp_path)
    runner = _runner(h, store, verifier)
    observed: list[str] = []

    def already_claimed(label: str) -> None:
        assert _claim(_store(tmp_path), runner).state is M4ClaimState.IN_PROGRESS
        observed.append(label)

    verifier.hook = lambda *_args: already_claimed("authorization")
    original_material = h.material
    original_connection = h.local_user_reset_connection

    def material():
        already_claimed("material")
        return original_material()

    def connection(*args: Any, **kwargs: Any):
        already_claimed(kwargs["operation"])
        return original_connection(*args, **kwargs)

    # Bind the instrumentation before constructing the immutable composition.
    monkeypatch.setattr(h, "material", material)
    monkeypatch.setattr(h, "local_user_reset_connection", connection)
    runner = _runner(h, store, verifier)
    result = runner.execute()
    assert result.outcome is M4Outcome.SUCCEEDED and result.verification is M4Verification.VERIFIED
    assert not result.idempotent_replay
    assert observed == ["authorization", "material", "policy_conform", "change_password"]
    assert len(verifier.calls) == 1 and len(h.calls) == 2
    h.assert_disposed()

    other_h, other_verifier = Harness(), Verifier(RuntimeError("must not verify twice"))
    replay = _runner(other_h, _store(tmp_path), other_verifier).execute()
    assert replay == replace(result, idempotent_replay=True)
    assert other_verifier.calls == [] and other_h.events == []
    events = _store(tmp_path).audit_events
    assert len(events) == 1 and events[0].authorization == "verified"
    assert events[0].outcome is M4Outcome.SUCCEEDED
    persisted = (tmp_path / "state/execution.sqlite3").read_bytes()
    for forbidden in (b"synthetic-old", b"synthetic-new", b"pam.example.test", h.baseline.username.encode()):
        assert forbidden not in persisted
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("enabled,verifier_present,transport_enabled", [
    (False, True, True), (True, False, True), (True, True, False),
])
def test_closed_or_unbound_path_has_no_claim_or_side_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    enabled: bool, verifier_present: bool, transport_enabled: bool,
) -> None:
    h, store, verifier = Harness(), _store(tmp_path), Verifier()
    runner = _runner(h, store, verifier if verifier_present else None, enabled=enabled)
    runner._transport._enabled = transport_enabled

    def forbidden(**_kwargs: Any):
        pytest.fail("closed path must not reserve an execution")

    monkeypatch.setattr(store, "claim", forbidden)
    assert runner.execute().outcome is M4Outcome.DENIED
    assert h.events == [] and verifier.calls == []


def test_unfinished_claim_survives_reconstruction_without_authorization_or_material(tmp_path: Path) -> None:
    h, store, verifier = Harness(), _store(tmp_path), Verifier()
    runner = _runner(h, store, verifier)
    assert _claim(store, runner).state is M4ClaimState.NEW
    result = _runner(h, _store(tmp_path), verifier).execute()
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED and result.idempotent_replay
    assert h.events == [] and verifier.calls == [] and store.audit_events == ()


def test_process_exit_during_authority_consumption_is_durably_non_replayable(tmp_path: Path) -> None:
    h, verifier = Harness(), Verifier(SystemExit(7))
    with pytest.raises(SystemExit):
        _runner(h, _store(tmp_path), verifier).execute()
    assert len(verifier.calls) == 1 and h.events == []
    restarted = Verifier()
    result = _runner(Harness(), _store(tmp_path), restarted).execute()
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED and result.idempotent_replay
    assert restarted.calls == []


@pytest.mark.parametrize("decision", [False, None, 1, "true", TimeoutError("synthetic-private-echo")])
def test_authority_requires_exact_true_and_denial_is_terminal(tmp_path: Path, decision: Any) -> None:
    h, verifier = Harness(), Verifier(decision)
    result = _runner(h, _store(tmp_path), verifier).execute()
    assert result.outcome is M4Outcome.DENIED and result.verification is M4Verification.NOT_STARTED
    assert len(verifier.calls) == 1 and h.events == []
    other = Verifier()
    replay = _runner(Harness(), _store(tmp_path), other).execute()
    assert replay == replace(result, idempotent_replay=True) and other.calls == []
    assert _store(tmp_path).audit_events[0].authorization == "denied"


def test_error_after_claim_commit_never_reaches_authority_and_restart_cannot_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    h, store, verifier = Harness(), _store(tmp_path), Verifier()
    original = store.claim

    def lost_result(**kwargs: Any):
        original(**kwargs)
        raise OSError("synthetic-private-echo")

    monkeypatch.setattr(store, "claim", lost_result)
    result = _runner(h, store, verifier).execute()
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert h.events == [] and verifier.calls == []
    replay = _runner(h, _store(tmp_path), verifier).execute()
    assert replay.outcome is M4Outcome.RECONCILIATION_REQUIRED and replay.idempotent_replay
    assert h.events == [] and verifier.calls == []


@pytest.mark.parametrize("committed", [False, True])
def test_finalization_failure_never_exposes_success_or_reacquires_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, committed: bool,
) -> None:
    h, store = Harness(), _store(tmp_path)
    original = store.finalize

    def lost_result(**kwargs: Any):
        if committed:
            original(**kwargs)
        raise OSError("synthetic-private-echo")

    monkeypatch.setattr(store, "finalize", lost_result)
    first = _runner(h, store, Verifier()).execute()
    assert first.outcome is M4Outcome.RECONCILIATION_REQUIRED and len(h.calls) == 2
    h.assert_disposed()
    other_h, verifier = Harness(), Verifier()
    replay = _runner(other_h, _store(tmp_path), verifier).execute()
    expected = M4Outcome.SUCCEEDED if committed else M4Outcome.RECONCILIATION_REQUIRED
    assert replay.outcome is expected and replay.idempotent_replay
    assert other_h.events == [] and verifier.calls == []


@pytest.mark.parametrize("change", ["origin", "baseline", "summary", "expiry", "authorization"])
def test_same_idempotency_rejects_changed_complete_context_before_authority(tmp_path: Path, change: str) -> None:
    first = _runner(Harness(), _store(tmp_path), Verifier())
    assert _claim(_store(tmp_path), first).state is M4ClaimState.NEW
    h = Harness(baseline=_baseline(nonmaterial_state_digest="b" * 64)) if change == "baseline" else Harness()
    intent = _intent(**{
        "summary": {"summary_digest": "6" * 64}, "expiry": {"expires_at": 1059},
        "authorization": {"authorization_digest": "7" * 64},
    }.get(change, {}))
    verifier = Verifier()
    transport = h.transport()
    if change == "origin":
        transport._port = 8443
    runner = FortiPamLocalUserResetExecution(
        transport, _store(tmp_path), intent=intent, authenticated_requester_digest="1" * 64,
        authorized_scope_digest="5" * 64, authorization_verifier=verifier,
        policy_snapshot=_policy(), policy_inspector=PolicyInspector(_policy()),
        enabled=True, clock=lambda: 1000,
    )
    assert runner.execute().outcome is M4Outcome.DENIED
    assert h.events == [] and verifier.calls == []


def test_same_authorization_cannot_move_to_another_plan_namespace(tmp_path: Path) -> None:
    first = _runner(Harness(), _store(tmp_path), Verifier())
    assert _claim(_store(tmp_path), first).state is M4ClaimState.NEW
    h, verifier = Harness(), Verifier()
    result = _runner(h, _store(tmp_path), verifier, intent=_intent(plan_ref="another-synthetic-plan")).execute()
    assert result.outcome is M4Outcome.DENIED and h.events == [] and verifier.calls == []


def test_policy_snapshot_changes_context_and_drift_denies_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _policy()
    inspector = PolicyInspector(expected)
    h, store, verifier = Harness(), _store(tmp_path), Verifier()
    runner = _runner(h, store, verifier, policy_snapshot=expected, policy_inspector=inspector)
    changed = _runner(Harness(), _store(tmp_path), Verifier(),
                      policy_snapshot=_policy(minimum_length=9),
                      policy_inspector=PolicyInspector(_policy(minimum_length=9)))
    assert runner._context != changed._context
    inspector.snapshot = _policy(minimum_length=9)

    def forbidden(**_kwargs: Any) -> Any:
        pytest.fail("Policy drift must not claim execution authority")

    monkeypatch.setattr(store, "claim", forbidden)
    assert runner.execute().outcome is M4Outcome.DENIED
    assert h.events == [] and verifier.calls == [] and inspector.reads == 1


def test_enabled_runner_requires_policy_binding_even_with_synthetic_material(tmp_path: Path) -> None:
    with pytest.raises(LocalUserResetExecutionError):
        _runner(Harness(), _store(tmp_path), Verifier(),
                policy_snapshot=None, policy_inspector=None)


def test_policy_drift_after_conform_post_blocks_change_and_consumes_claim(tmp_path: Path) -> None:
    expected = _policy()
    h, verifier, store = Harness(), Verifier(), _store(tmp_path)

    class DriftingPolicyInspector(PolicyInspector):
        def read_policy_snapshot(self) -> LocalUserResetPolicySnapshot:
            self.reads += 1
            return _policy(minimum_length=9) if "policy_conform" in h.events else expected

    inspector = DriftingPolicyInspector(expected)
    result = _runner(h, store, verifier,
                     policy_snapshot=expected, policy_inspector=inspector).execute()
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert len(h.calls) == 1 and h.calls[0][0].endswith("password-policy-conform/")
    assert len(verifier.calls) == 1 and inspector.reads > 1
    assert _store(tmp_path).audit_events[0].outcome is M4Outcome.RECONCILIATION_REQUIRED
    h.assert_disposed()


@pytest.mark.parametrize("updates", [
    {"authenticated_requester_digest": "8" * 64}, {"authorized_scope_digest": "8" * 64},
    {"clock": lambda: 999}, {"clock": lambda: 1060}, {"clock": lambda: True}, {"clock": lambda: 1000.0},
])
def test_wrong_principal_scope_or_invalid_initial_time_never_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, updates: dict[str, Any],
) -> None:
    h, store, verifier = Harness(), _store(tmp_path), Verifier()

    def forbidden(**_kwargs: Any):
        pytest.fail("invalid identity/time must not reserve an execution")

    monkeypatch.setattr(store, "claim", forbidden)
    assert _runner(h, store, verifier, **updates).execute().outcome is M4Outcome.DENIED
    assert h.events == [] and verifier.calls == []


@pytest.mark.parametrize("stage,expected_posts,expected_loads", [
    ("first_read", 0, 0), ("lease_provider", 0, 0), ("material_loader", 0, 1),
    ("policy_factory", 0, 1), ("second_read", 1, 1), ("change_factory", 1, 1),
])
def test_expiry_at_each_material_or_dispatch_boundary_prevents_the_next_post(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str, expected_posts: int, expected_loads: int,
) -> None:
    h, now, loads = Harness(), [1000], []
    original_read, original_connection = h.read_nonmaterial_baseline, h.local_user_reset_connection

    def read():
        result = original_read()
        if (stage == "first_read" and h.reads == 1) or (stage == "second_read" and h.reads == 2):
            now[0] = 1060
        return result

    def load():
        loads.append(True)
        if stage == "material_loader":
            now[0] = 1060
        return memoryview(h.old), memoryview(h.new)

    def material():
        h.leases += 1
        if stage == "lease_provider":
            now[0] = 1060
        return LocalUserResetMaterialLease(load)

    def connection(*args: Any, **kwargs: Any):
        result = original_connection(*args, **kwargs)
        if ((stage == "policy_factory" and kwargs["operation"] == "policy_conform")
            or (stage == "change_factory" and kwargs["operation"] == "change_password")):
            now[0] = 1060
        return result

    monkeypatch.setattr(h, "read_nonmaterial_baseline", read)
    monkeypatch.setattr(h, "material", material)
    monkeypatch.setattr(h, "local_user_reset_connection", connection)
    runner = _runner(h, _store(tmp_path), Verifier(), clock=lambda: now[0])
    result = runner.execute()
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert len(h.calls) == expected_posts and len(loads) == expected_loads
    if expected_loads:
        h.assert_disposed()
    else:
        assert any(h.old) and any(h.new)
    # Reconstruct with the same valid synthetic time solely to test ledger state.
    other, verifier = Harness(), Verifier()
    replay = _runner(other, _store(tmp_path), verifier).execute()
    assert replay == replace(result, idempotent_replay=True)
    assert other.events == [] and verifier.calls == []


def test_clock_rollback_after_policy_never_sends_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h, now = Harness(), [1000]
    original = h.read_nonmaterial_baseline

    def read():
        result = original()
        now[0] = 1001 if h.reads == 1 else 1000
        return result

    monkeypatch.setattr(h, "read_nonmaterial_baseline", read)
    result = _runner(h, _store(tmp_path), Verifier(), clock=lambda: now[0]).execute()
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED and len(h.calls) == 1
    h.assert_disposed()


def test_swapped_private_binding_after_authorization_is_rejected_before_reads(tmp_path: Path) -> None:
    h, verifier = Harness(), Verifier()
    runner = _runner(h, _store(tmp_path), verifier)
    verifier.hook = lambda *_args: setattr(runner._transport, "_binding", Harness().binding)
    assert runner.execute().outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert h.events == []


@pytest.mark.parametrize("expire_during", [None, "policy_conform", "change_password"])
def test_real_owner_adapter_and_ledger_join_checks_deadline_after_body_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, expire_during: str | None,
) -> None:
    h, now, verifier = OwnerHarness(), [1000], Verifier()
    buffers = [bytearray(b"synthetic-before"), bytearray(b"synthetic-after")]
    original = owner_module._body_tags

    def body_tags(*args: Any):
        result = original(*args)
        if args[2] == expire_during:
            now[0] = 1060
        return result

    monkeypatch.setattr(owner_module, "_body_tags", body_tags)
    transport = FortiPamLocalUserResetHttpTransport(
        h.config, binding=h.binding,
        inspector=SimpleNamespace(read_nonmaterial_baseline=lambda: h.binding.expected),
        owner_session=h.owner,
        material_lease_provider=lambda: LocalUserResetMaterialLease(
            lambda: (memoryview(buffers[0]), memoryview(buffers[1])),
        ), enabled=True,
    )
    runner = FortiPamLocalUserResetExecution(
        transport, _store(tmp_path), intent=_intent(), authenticated_requester_digest="1" * 64,
        authorized_scope_digest="5" * 64, authorization_verifier=verifier,
        policy_snapshot=_policy(), policy_inspector=PolicyInspector(_policy()),
        enabled=True, clock=lambda: now[0],
    )
    with h.owner.authenticated():
        result = runner.execute()
    expected_posts = {None: 2, "policy_conform": 0, "change_password": 1}[expire_during]
    assert len(h.writes) == expected_posts
    expected_outcome = M4Outcome.SUCCEEDED if expire_during is None else M4Outcome.RECONCILIATION_REQUIRED
    assert result.outcome is expected_outcome
    assert all(not any(buffer) for buffer in buffers)
    assert h.owner.logout_verified and all(raw.closed for raw in h.raws)


def test_concurrent_reconstructed_runner_observes_unfinished_claim(tmp_path: Path) -> None:
    first_h, other_h, entered, release = Harness(), Harness(), threading.Event(), threading.Event()
    verifier, other_verifier = Verifier(), Verifier()

    def block(*_args: Any) -> None:
        entered.set()
        assert release.wait(5)

    verifier.hook = block
    first = _runner(first_h, _store(tmp_path), verifier)
    second = _runner(other_h, _store(tmp_path), other_verifier)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(first.execute)
        try:
            assert entered.wait(5)
            assert first.execute().outcome is M4Outcome.RECONCILIATION_REQUIRED
            result = second.execute()
            assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED and result.idempotent_replay
            assert other_h.events == [] and other_verifier.calls == []
        finally:
            release.set()
        assert future.result(timeout=5).outcome is M4Outcome.SUCCEEDED
    assert len(first_h.calls) == 2


@pytest.mark.parametrize("case,outcome", [
    ("drift", M4Outcome.PRECONDITION_FAILED), ("policy", M4Outcome.EXECUTION_FAILED),
    ("post_read_drift", M4Outcome.RECONCILIATION_REQUIRED), ("lost_change", M4Outcome.RECONCILIATION_REQUIRED),
])
def test_real_adapter_failures_are_persisted_without_password_success_claim(
    tmp_path: Path, case: str, outcome: M4Outcome,
) -> None:
    h = Harness()
    if case == "drift":
        h.snapshots[0] = _baseline(nonmaterial_state_digest="b" * 64)
    elif case == "policy":
        h.responses["policy_conform"] = Response(b'{"results":{"valid":false}}')
    elif case == "post_read_drift":
        h.snapshots[2] = _baseline(nonmaterial_state_digest="b" * 64)
    else:
        h.fail_at = "response_change_password"
    result = _runner(h, _store(tmp_path), Verifier()).execute()
    assert result.outcome is outcome and result.verification is not M4Verification.VERIFIED
    replay_h, verifier = Harness(), Verifier()
    replay = _runner(replay_h, _store(tmp_path), verifier).execute()
    assert replay == replace(result, idempotent_replay=True)
    assert replay_h.events == [] and verifier.calls == []


@pytest.mark.parametrize("updates", [
    {"plan_ref": "bad"}, {"requester_digest": "not-a-digest"}, {"summary_digest": None},
    {"issued_at": True}, {"expires_at": 1000.0}, {"issued_at": -1},
    {"expires_at": 1000}, {"expires_at": 1301},
])
def test_malformed_intent_has_a_fixed_error(updates: dict[str, Any]) -> None:
    with pytest.raises(LocalUserResetExecutionError, match="^The private Local User reset execution candidate is unavailable.$"):
        _intent(**updates)


def test_intent_is_opaque_and_not_serializable() -> None:
    intent = _intent()
    assert intent.plan_ref not in repr(intent) and intent.authorization_digest not in str(intent)
    with pytest.raises(MaterialAccessDenied):
        pickle.dumps(intent)


def test_volatile_state_cannot_replace_the_durable_execution_store() -> None:
    h = Harness()
    with pytest.raises(LocalUserResetExecutionError, match="candidate is unavailable"):
        _runner(h, InMemoryM4ExecutionStateStore(), Verifier())
    assert h.events == []
