from __future__ import annotations

from fortipam_mcp.secret_metadata_http_transport import SecretSessionControlsFolderPolicy

from dataclasses import replace
from typing import cast

import pytest

from fortipam_mcp.secret_metadata_http_transport import (
    SecretSessionControlsProjectionInspection,
    secret_session_controls_event_filter_profile_digest,
)
from fortipam_mcp.rdp_event_filter_ssh_transport import RdpEventFilterReadback
from fortipam_mcp.secret_session_controls_ssh_transport import (
    FortiPamSecretSessionControlsSshTransport,
)
from fortipam_mcp.secret_session_controls_m4_runtime import (
    ProtectedSecretSessionControlsM4Runtime,
    SECRET_SESSION_CONTROLS_ACTION_ID,
    SECRET_SESSION_CONTROLS_ACTION_VERSION,
    SECRET_SESSION_CONTROLS_ADAPTER_REF,
    SecretSessionControlsBinding,
    SecretSessionControlsM4ExecutionBinding,
    SecretSessionControlsM4RuntimeError,
    SecretSessionControlsWriteTransport,
    secret_session_controls_binding_digest,
    secret_session_controls_parameters_digest,
    secret_session_controls_state_digest,
)
from test_v4_execution_kernel import NOW, _authorization, _plan
from v4_planning import (
    InMemoryM4ExecutionStateStore,
    M4AuthorizationDenied,
    M4AuthorizationVerifier,
    M4ExecutionResult,
    M4ExecutionPlan,
    M4Outcome,
    M4Verification,
    canonical_digest,
)


PRESERVED_DIGEST = "1" * 64
PREWRITE_EVENT_FILTER_PROFILE = "mcp-v4-rdp-event-filter-existing00"
EVENT_FILTER_PROFILE = "mcp-v4-rdp-event-filter-existing01"


def _binding() -> SecretSessionControlsBinding:
    return SecretSessionControlsBinding(
        secret_session_controls_object_ref="secret-controls-object-ref01",
        folder_ref="folder-object-ref000001",
        folder_path="Public/folder",
        secret_name="mcp-v4-secret-metadata-01",
        template_ref="template-object-ref0001",
        template_name="Windows Local Account",
        target_ref="target-object-ref0000001",
        target_name="MCP Windows Target",
        secret_id=42,
        rdp_event_filter_profile_ref="rdp-event-profile-ref01",
        rdp_event_filter_profile_name=EVENT_FILTER_PROFILE,
        prewrite_recording_enabled=True,
        prewrite_clipboard_blocking_enabled=False,
        prewrite_rdp_event_filter_enabled=False,
        prewrite_rdp_event_filter_profile_matches=False,
        prewrite_rdp_event_filter_profile_digest=(
            secret_session_controls_event_filter_profile_digest(
                PREWRITE_EVENT_FILTER_PROFILE
            )
        ),
        preserved_identity_relations_digest=PRESERVED_DIGEST,
    )


def _state_digest(
    *,
    recording_enabled: bool,
    clipboard_blocking_enabled: bool,
    rdp_event_filter_enabled: bool,
    rdp_event_filter_profile_matches: bool,
    preserved_digest: str = PRESERVED_DIGEST,
    rdp_event_filter_profile_digest: str | None = None,
) -> str:
    return secret_session_controls_state_digest(
        _binding(),
        preserved_identity_relations_digest=preserved_digest,
        rdp_event_filter_profile_digest=(
            _binding().prewrite_rdp_event_filter_profile_digest
            if rdp_event_filter_profile_digest is None
            else rdp_event_filter_profile_digest
        ),
        recording_enabled=recording_enabled,
        clipboard_blocking_enabled=clipboard_blocking_enabled,
        rdp_event_filter_enabled=rdp_event_filter_enabled,
        rdp_event_filter_profile_matches=rdp_event_filter_profile_matches,
        target_ref=_binding().secret_session_controls_object_ref,
    )


def _controls_plan() -> M4ExecutionPlan:
    base = _plan()
    content = dict(base.canonical_content())
    content.update(
        {
            "action_id": SECRET_SESSION_CONTROLS_ACTION_ID,
            "action_version": SECRET_SESSION_CONTROLS_ACTION_VERSION,
            "adapter_ref": SECRET_SESSION_CONTROLS_ADAPTER_REF,
            "target_ref": _binding().secret_session_controls_object_ref,
            "parameters_digest": secret_session_controls_parameters_digest(
                _binding()
            ),
            "expected_current_digest": _state_digest(
                recording_enabled=_binding().prewrite_recording_enabled,
                clipboard_blocking_enabled=(
                    _binding().prewrite_clipboard_blocking_enabled
                ),
                rdp_event_filter_enabled=(
                    _binding().prewrite_rdp_event_filter_enabled
                ),
                rdp_event_filter_profile_matches=(
                    _binding().prewrite_rdp_event_filter_profile_matches
                ),
            ),
            "expected_state_digest": _state_digest(
                recording_enabled=True,
                clipboard_blocking_enabled=True,
                rdp_event_filter_enabled=True,
                rdp_event_filter_profile_matches=True,
                rdp_event_filter_profile_digest=(
                    secret_session_controls_event_filter_profile_digest(
                        EVENT_FILTER_PROFILE
                    )
                ),
            ),
        }
    )
    return replace(
        base,
        action_id=SECRET_SESSION_CONTROLS_ACTION_ID,
        action_version=SECRET_SESSION_CONTROLS_ACTION_VERSION,
        adapter_ref=SECRET_SESSION_CONTROLS_ADAPTER_REF,
        target_ref=_binding().secret_session_controls_object_ref,
        parameters_digest=secret_session_controls_parameters_digest(_binding()),
        expected_current_digest=_state_digest(
            recording_enabled=_binding().prewrite_recording_enabled,
            clipboard_blocking_enabled=(
                _binding().prewrite_clipboard_blocking_enabled
            ),
            rdp_event_filter_enabled=_binding().prewrite_rdp_event_filter_enabled,
            rdp_event_filter_profile_matches=(
                _binding().prewrite_rdp_event_filter_profile_matches
            ),
        ),
        expected_state_digest=_state_digest(
            recording_enabled=True,
            clipboard_blocking_enabled=True,
            rdp_event_filter_enabled=True,
            rdp_event_filter_profile_matches=True,
            rdp_event_filter_profile_digest=(
                secret_session_controls_event_filter_profile_digest(
                    EVENT_FILTER_PROFILE
                )
            ),
        ),
        plan_digest=canonical_digest(content),
    )


class _Resolver:
    def __init__(self, binding: SecretSessionControlsM4ExecutionBinding) -> None:
        self.binding = binding

    def resolve_execution_binding(
        self, authorization_ref: str
    ) -> SecretSessionControlsM4ExecutionBinding:
        assert authorization_ref == self.binding.authorization.authorization_ref
        return self.binding


class _Verifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, plan: M4ExecutionPlan, authorization: object, *, now_epoch: int) -> None:
        del authorization
        assert now_epoch == NOW
        assert plan.action_id == SECRET_SESSION_CONTROLS_ACTION_ID
        self.calls += 1


class _RejectingVerifier:
    def verify(self, plan: M4ExecutionPlan, authorization: object, *, now_epoch: int) -> None:
        del plan, authorization, now_epoch
        raise M4AuthorizationDenied("missing authorization")


class _State:
    def __init__(self) -> None:
        self.recording_enabled = True
        self.clipboard_blocking_enabled = False
        self.rdp_event_filter_enabled = False
        self.current_event_filter_profile = PREWRITE_EVENT_FILTER_PROFILE
        self.proxy_enabled = True
        self.rdp_tcp_forwarding_disabled = True
        self.preserved_digest = PRESERVED_DIGEST
        self.write_calls: list[tuple[int, str]] = []
        self.read_calls = 0
        self.event_filter_read_calls = 0
        self.event_filter_verified = True

    def enable_controls(self, secret_id: int, profile_name: str) -> None:
        self.write_calls.append((secret_id, profile_name))
        self.recording_enabled = True
        self.clipboard_blocking_enabled = True
        self.rdp_event_filter_enabled = True
        self.current_event_filter_profile = EVENT_FILTER_PROFILE

    def readback(self, profile_name: str) -> RdpEventFilterReadback:
        assert profile_name == EVENT_FILTER_PROFILE
        self.event_filter_read_calls += 1
        return RdpEventFilterReadback(
            self.event_filter_verified,
            self.event_filter_verified,
            self.event_filter_verified,
            self.event_filter_verified,
        )

    def inspect_session_controls_projection(
        self,
        folder_path: str,
        secret_name: str,
        expected_template: str,
        expected_target: str,
        expected_rdp_event_filter_profile: str,
        *,
        expected_secret_id: int,
    ) -> SecretSessionControlsProjectionInspection:
        assert (
            folder_path,
            secret_name,
            expected_template,
            expected_target,
            expected_rdp_event_filter_profile,
            expected_secret_id,
        ) == (
            "Public/folder",
            "mcp-v4-secret-metadata-01",
            "Windows Local Account",
            "MCP Windows Target",
            EVENT_FILTER_PROFILE,
            42,
        )
        self.read_calls += 1
        return SecretSessionControlsProjectionInspection(
            original_name="mcp-v4-secret-metadata-01",
            original_template="Windows Local Account",
            folder_policy=SecretSessionControlsFolderPolicy(17, "folder", "mcp-v4-secret-policy-test", "not-set", "not-set", "not-set"),
            recording_enabled=self.recording_enabled,
            clipboard_blocking_enabled=self.clipboard_blocking_enabled,
            rdp_event_filter_enabled=self.rdp_event_filter_enabled,
            rdp_event_filter_profile_matches=(
                self.current_event_filter_profile == EVENT_FILTER_PROFILE
            ),
            proxy_enabled=self.proxy_enabled,
            rdp_tcp_forwarding_disabled=self.rdp_tcp_forwarding_disabled,
            inherit_permission_matches=True,
            preserved_identity_relations_digest=self.preserved_digest,
            rdp_event_filter_profile_digest=(
                secret_session_controls_event_filter_profile_digest(
                    self.current_event_filter_profile
                )
            ),
        )


class _SshStateTransport(FortiPamSecretSessionControlsSshTransport):
    """SSH-provenance test double; it does not replace composition coverage."""

    def __init__(self, state: _State) -> None:
        self._state = state

    def enable_controls(self, secret_id: int, profile_name: str, *, prewrite: SecretSessionControlsProjectionInspection) -> None:
        self._state.enable_controls(secret_id, profile_name)


def _runtime(
    state: _State,
    *,
    store: InMemoryM4ExecutionStateStore | None = None,
    verifier: M4AuthorizationVerifier | None = None,
    plan: M4ExecutionPlan | None = None,
    write_transport: SecretSessionControlsWriteTransport | None = None,
) -> tuple[ProtectedSecretSessionControlsM4Runtime, _Verifier]:
    exact_plan = _controls_plan() if plan is None else plan
    authorization = _authorization(exact_plan)
    exact_verifier = _Verifier() if verifier is None else verifier
    runtime = ProtectedSecretSessionControlsM4Runtime(
        _Resolver(
            SecretSessionControlsM4ExecutionBinding(
                exact_plan,
                authorization,
                _binding(),
            )
        ),
        exact_verifier,
        InMemoryM4ExecutionStateStore() if store is None else store,
        _SshStateTransport(state) if write_transport is None else write_transport,
        state,
        state,
        authenticated_requester_digest=exact_plan.requester_digest,
        clock=lambda: NOW,
    )
    return runtime, cast(_Verifier, exact_verifier)


def _execute(
    runtime: ProtectedSecretSessionControlsM4Runtime,
) -> M4ExecutionResult:
    return runtime.execute_bound(
        "execution-authorization-01",
        expected_session_controls_binding_digest=(
            secret_session_controls_binding_digest(_binding())
        ),
    )


def test_m4_session_controls_are_authorized_read_write_readback() -> None:
    state = _State()
    runtime, verifier = _runtime(state)

    result = _execute(runtime)

    assert result.outcome is M4Outcome.SUCCEEDED
    assert result.verification is M4Verification.VERIFIED
    assert verifier.calls == 1
    assert state.write_calls == [(42, EVENT_FILTER_PROFILE)]
    assert state.read_calls == 2
    assert state.event_filter_read_calls == 2


def test_m4_session_controls_safe_identity_drift_stops_before_write() -> None:
    state = _State()
    state.preserved_digest = "2" * 64
    runtime, verifier = _runtime(state)

    result = _execute(runtime)

    assert result.outcome is M4Outcome.PRECONDITION_FAILED
    assert verifier.calls == 1
    assert state.write_calls == []
    assert state.read_calls == 1


def test_m4_session_controls_changed_prewrite_control_stops_before_write() -> None:
    state = _State()
    state.clipboard_blocking_enabled = True
    runtime, verifier = _runtime(state)

    result = _execute(runtime)

    assert result.outcome is M4Outcome.PRECONDITION_FAILED
    assert verifier.calls == 1
    assert state.write_calls == []
    assert state.read_calls == 1


def test_m4_session_controls_prewrite_event_filter_profile_drift_stops_before_write() -> None:
    state = _State()
    state.current_event_filter_profile = "mcp-v4-rdp-event-filter-existing02"
    runtime, verifier = _runtime(state)

    result = _execute(runtime)

    assert result.outcome is M4Outcome.PRECONDITION_FAILED
    assert verifier.calls == 1
    assert state.write_calls == []
    assert state.read_calls == 1


def test_m4_session_controls_incompatible_rdp_evidence_never_reaches_write() -> None:
    state = _State()
    state.proxy_enabled = False
    runtime, verifier = _runtime(state)

    result = _execute(runtime)

    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert verifier.calls == 1
    assert state.write_calls == []
    assert state.read_calls == 1


def test_m4_session_controls_missing_rdp_event_filter_stops_before_write() -> None:
    state = _State()
    state.event_filter_verified = False
    runtime, verifier = _runtime(state)

    result = _execute(runtime)

    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert verifier.calls == 1
    assert state.write_calls == []
    assert state.read_calls == 1
    assert state.event_filter_read_calls == 1


def test_m4_session_controls_rejects_private_binding_mismatch_before_read() -> None:
    state = _State()
    runtime, verifier = _runtime(state)

    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(
            "execution-authorization-01",
            expected_session_controls_binding_digest="0" * 64,
        )

    assert verifier.calls == 0
    assert state.write_calls == []
    assert state.read_calls == 0


def test_m4_session_controls_rejects_arbitrary_expected_state_before_read() -> None:
    state = _State()
    plan = _controls_plan()
    content = dict(plan.canonical_content())
    content["expected_state_digest"] = "0" * 64
    tampered = replace(
        plan,
        expected_state_digest="0" * 64,
        plan_digest=canonical_digest(content),
    )
    runtime, verifier = _runtime(state, plan=tampered)

    with pytest.raises(M4AuthorizationDenied):
        _execute(runtime)

    assert verifier.calls == 0
    assert state.write_calls == []
    assert state.read_calls == 0


@pytest.mark.parametrize("old_adapter", [
    "fortipam-secret-session-controls-cli-191",
    "fortipam-secret-session-controls-rest-191",
    "fortipam-secret-session-controls-rest-policy-191-v2",
    "fortipam-secret-session-controls-rest-folder-191-v3",
    "fortipam-secret-session-controls-rest-template-191-v4",
    "fortipam-secret-session-controls-rest-identity-191-v5",
        "fortipam-secret-session-controls-ssh-preserving-191-v1",
        "fortipam-secret-session-controls-ssh-preserving-191-v2",
])
def test_m4_session_controls_rejects_old_adapter_plan_before_write(old_adapter: str) -> None:
    state = _State()
    plan = _controls_plan()
    content = dict(plan.canonical_content())
    content["adapter_ref"] = old_adapter
    old_cli_plan = replace(
        plan,
        adapter_ref=old_adapter,
        plan_digest=canonical_digest(content),
    )
    runtime, verifier = _runtime(state, plan=old_cli_plan)

    with pytest.raises(M4AuthorizationDenied):
        _execute(runtime)

    assert verifier.calls == 0
    assert state.write_calls == []
    assert state.read_calls == 0


def test_m4_session_controls_rejects_old_action_version_before_read() -> None:
    state = _State()
    plan = _controls_plan()
    content = dict(plan.canonical_content())
    content["action_version"] = "1.6.0"
    old_plan = replace(plan, action_version="1.6.0", plan_digest=canonical_digest(content))
    runtime, verifier = _runtime(state, plan=old_plan)
    with pytest.raises(M4AuthorizationDenied):
        _execute(runtime)
    assert verifier.calls == 0
    assert state.write_calls == []
    assert state.read_calls == 0


def test_m4_session_controls_rejects_nonssh_writer_at_construction() -> None:
    state = _State()

    with pytest.raises(SecretSessionControlsM4RuntimeError):
        _runtime(state, write_transport=state)  # type: ignore[arg-type]

    assert state.write_calls == []


def test_m4_session_controls_missing_authorization_stops_before_read_or_write() -> None:
    state = _State()
    runtime, _ = _runtime(state, verifier=_RejectingVerifier())

    with pytest.raises(M4AuthorizationDenied):
        _execute(runtime)

    assert state.write_calls == []
    assert state.read_calls == 0


def test_m4_session_controls_reuses_durable_store_without_redispatch() -> None:
    state = _State()
    store = InMemoryM4ExecutionStateStore()
    first_runtime, first_verifier = _runtime(state, store=store)
    first = _execute(first_runtime)
    restarted_runtime, second_verifier = _runtime(state, store=store)
    replay = _execute(restarted_runtime)

    assert first.outcome is M4Outcome.SUCCEEDED
    assert replay.outcome is M4Outcome.SUCCEEDED
    assert replay.idempotent_replay is True
    assert first_verifier.calls == 1
    assert second_verifier.calls == 0
    assert state.write_calls == [(42, EVENT_FILTER_PROFILE)]
    assert state.read_calls == 2


def test_policy_conflict_is_denied_before_dispatch() -> None:
    class ConflictingPolicy(_State):
        def inspect_session_controls_projection(self, *args, **kwargs):
            projection = super().inspect_session_controls_projection(*args, **kwargs)
            assert projection.folder_policy is not None
            return replace(projection, folder_policy=replace(
                projection.folder_policy, block_clipboard="disable",
            ))

    state = ConflictingPolicy()
    runtime, _ = _runtime(state)
    result = _execute(runtime)
    assert result.outcome is M4Outcome.DENIED
    assert result.verification is M4Verification.NOT_STARTED
    assert state.write_calls == []


def test_policy_drift_after_dispatch_cannot_report_verified_success() -> None:
    class ChangedPolicy(_State):
        def enable_controls(self, secret_id: int, profile_name: str) -> None:
            super().enable_controls(secret_id, profile_name)
            # Reader digest includes the exact Policy relation and states.
            self.preserved_digest = "3" * 64

    state = ChangedPolicy()
    runtime, _ = _runtime(state)
    result = _execute(runtime)
    assert result.outcome is not M4Outcome.SUCCEEDED
    assert result.verification is not M4Verification.VERIFIED
    assert state.write_calls == [(42, EVENT_FILTER_PROFILE)]
    assert state.read_calls == 2


def test_dispatch_requires_fresh_matching_read_and_consumes_its_cache() -> None:
    from fortipam_mcp.secret_session_controls_m4_runtime import _SecretSessionControlsM4Adapter
    from v4_planning.execution_kernel import M4AdapterDenied

    state = _State()
    plan = _controls_plan()
    adapter = _SecretSessionControlsM4Adapter(
        SecretSessionControlsM4ExecutionBinding(plan, _authorization(plan), _binding()),
        _SshStateTransport(state), state, state,
    )
    with pytest.raises(M4AdapterDenied):
        adapter.dispatch(plan)
    assert adapter.read_current(plan) == plan.expected_current_digest
    adapter.dispatch(plan)
    with pytest.raises(M4AdapterDenied):
        adapter.dispatch(plan)
    assert state.write_calls == [(42, EVENT_FILTER_PROFILE)]

    # A later mismatching read cannot reuse the first matching snapshot.
    state.rdp_event_filter_enabled = False
    assert adapter.read_current(plan) != plan.expected_current_digest
    with pytest.raises(M4AdapterDenied):
        adapter.dispatch(plan)
    assert state.write_calls == [(42, EVENT_FILTER_PROFILE)]


def test_original_template_mismatch_denied_even_with_claimed_preserved_digest() -> None:
    class ChangedTemplate(_State):
        def inspect_session_controls_projection(self, *args, **kwargs):
            projection = super().inspect_session_controls_projection(*args, **kwargs)
            return replace(projection, original_template="Different Template")
    state = ChangedTemplate()
    runtime, _ = _runtime(state)
    result = _execute(runtime)
    assert result.outcome is M4Outcome.DENIED
    assert state.write_calls == []


def test_original_name_mismatch_denied_even_with_claimed_preserved_digest() -> None:
    class ChangedName(_State):
        def inspect_session_controls_projection(self, *args, **kwargs):
            projection = super().inspect_session_controls_projection(*args, **kwargs)
            return replace(projection, original_name="mcp-v4-secret-metadata-02")

    state = ChangedName()
    runtime, _ = _runtime(state)
    result = _execute(runtime)

    assert result.outcome is M4Outcome.DENIED
    assert state.write_calls == []


@pytest.mark.parametrize("stale_reads", [1, 2, 3])
def test_postcondition_polls_only_complete_baseline_without_redispatch(stale_reads, monkeypatch):
    import fortipam_mcp.secret_session_controls_m4_runtime as module
    pauses = []
    monkeypatch.setattr(module.time, "sleep", pauses.append)

    class DelayedState(_State):
        baseline = None

        def inspect_session_controls_projection(self, *args, **kwargs):
            observed = super().inspect_session_controls_projection(*args, **kwargs)
            if self.read_calls == 1:
                self.baseline = observed
            if self.write_calls and self.read_calls <= 1 + stale_reads:
                return self.baseline
            return observed

    state = DelayedState()
    store = InMemoryM4ExecutionStateStore()
    runtime, _ = _runtime(state, store=store)
    result = _execute(runtime)
    assert state.write_calls == [(42, EVENT_FILTER_PROFILE)]
    assert state.read_calls == 1 + min(stale_reads + 1, 3)
    assert pauses == [5.0] * min(stale_reads, 2)
    assert len(store.audit_events) == 1
    assert result.outcome is (M4Outcome.SUCCEEDED if stale_reads < 3 else M4Outcome.VERIFICATION_FAILED)
    # The terminal invocation remains consumed, even if a later read would match.
    _execute(runtime)
    assert state.write_calls == [(42, EVENT_FILTER_PROFILE)]
    assert len(store.audit_events) == 1


@pytest.mark.parametrize("unexpected", ["intermediate", "read_error"])
def test_postcondition_does_not_poll_unexpected_state_or_read_error(unexpected, monkeypatch):
    import fortipam_mcp.secret_session_controls_m4_runtime as module
    pauses = []
    monkeypatch.setattr(module.time, "sleep", pauses.append)

    class UnexpectedState(_State):
        def inspect_session_controls_projection(self, *args, **kwargs):
            observed = super().inspect_session_controls_projection(*args, **kwargs)
            if self.write_calls:
                if unexpected == "read_error":
                    raise OSError("Synthetic read failure")
                return replace(observed, rdp_event_filter_enabled=False)
            return observed

    state = UnexpectedState()
    runtime, _ = _runtime(state)
    result = _execute(runtime)
    assert result.outcome is not M4Outcome.SUCCEEDED
    assert state.read_calls == 2
    assert pauses == []
    assert state.write_calls == [(42, EVENT_FILTER_PROFILE)]
