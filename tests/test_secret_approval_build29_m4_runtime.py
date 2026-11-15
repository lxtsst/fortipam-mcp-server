from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from v4_planning import (
    InMemoryM4ExecutionStateStore, M4AdapterDenied, M4AuthorizationDenied,
    M4ExecutionAuthorization, M4ExecutionPlan, M4Outcome, canonical_digest,
)
from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_approval_build29_contract import compile_secret_approval_build29_enable_body
from fortipam_mcp.secret_approval_build29_http_transport import (
    FortiPamSecretApprovalBuild29HttpTransport, SecretApprovalBuild29MutationBinding,
    SecretApprovalBuild29PrivateState, SecretApprovalBuild29Readback,
    SecretApprovalBuild29WebFieldsBinding, SecretApprovalBuild29LinuxFieldsBinding,
)
from fortipam_mcp.secret_approval_build29_m4_runtime import (
    ACTION_ID, ACTION_VERSION, ADAPTER_REF, RESTORE_ACTION_ID, SecretApprovalBuild29M4ExecutionBinding,
    assemble_secret_approval_build29_m4_runtime, secret_approval_build29_binding_digest,
    secret_approval_build29_parameters_digest,
    secret_approval_build29_restore_parameters_digest,
)
from fortipam_mcp.secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig,
)


_REQUESTER = "a" * 64
_NOW = 1000


class _Store(InMemoryM4ExecutionStateStore):
    def __init__(self) -> None:
        super().__init__()
        self.claim_calls = 0

    def claim(self, **kwargs: Any) -> Any:
        self.claim_calls += 1
        return super().claim(**kwargs)


class _Authorizer:
    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        assert authorization.plan_digest == plan.plan_digest and now_epoch == _NOW


class _Qualifier:
    """Simulated trusted proof only; not a production qualification provider."""

    def __init__(self, *, unavailable: str | None = None) -> None:
        self.unavailable = unavailable

    def verify(self, *, binding_digest: str, plan_digest: str, now_epoch: int) -> None:
        assert len(binding_digest) == len(plan_digest) == 64 and now_epoch == _NOW
        if self.unavailable is not None:
            raise M4AdapterDenied("Unqualified unit source.")


def _plan() -> M4ExecutionPlan:
    values: dict[str, Any] = {
        "plan_ref": "plan-build29-unit01", "revision": 1,
        "action_id": ACTION_ID, "action_version": ACTION_VERSION, "adapter_ref": ADAPTER_REF,
        "target_ref": "target-build29-unit01", "requester_digest": _REQUESTER,
        "summary_digest": "d" * 64, "confirmation_digest": "e" * 64,
        "approval_digest": "f" * 64, "parameters_digest": "0" * 64,
        "expected_current_digest": "b" * 64, "expected_state_digest": "c" * 64,
        "idempotency_digest": "1" * 64, "expires_at": 2000, "compensation_ref": None,
    }
    return M4ExecutionPlan(**values, plan_digest=canonical_digest(values))


def _authorization(plan: M4ExecutionPlan) -> M4ExecutionAuthorization:
    values: dict[str, Any] = {
        "authorization_ref": "authorization-build29-unit01", "plan_ref": plan.plan_ref,
        "plan_digest": plan.plan_digest, "requester_digest": plan.requester_digest,
        "confirmation_ref": "confirmation-build29-unit01", "confirmation_digest": plan.confirmation_digest,
        "approval_ref": "approval-build29-unit01", "approval_digest": plan.approval_digest,
        "approver_digest": "2" * 64, "issued_at": 900, "expires_at": 2000,
        "one_time": True, "execution_authorized": True,
    }
    return M4ExecutionAuthorization(**values, authorization_digest=canonical_digest(values))


def _schema() -> dict[str, object]:
    selected: dict[str, dict[str, object]] = {}
    for name in ("need-approval", "need-approval-job", "bypass-approval", "approval-profile"):
        field: dict[str, object] = {
            "name": name, "category": "unitary", "multiple_values": False,
            "type": "string" if name == "approval-profile" else "option",
            "default": "" if name == "approval-profile" else "disable", "help": "Unit source.",
        }
        if name != "bypass-approval":
            field["required"] = True
        if name == "approval-profile":
            field.update(size=79, datasource=["secret.approval-profile.name"])
        else:
            field["options"] = [{"name": value, "help": "Unit enum."} for value in ("enable", "disable")]
        selected[name] = field
    return {"version": "v7.0.0", "build": 29, "selected_schema": selected}


def _binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, bypass: str = "disable", web_fields: bool = True, linux: bool = False) -> tuple[SecretApprovalBuild29M4ExecutionBinding, dict[str, int]]:
    config = SecretMetadataHttpTransportConfig("https://unit.example.test", "unit-token", 15, None)
    owner = OwnerSessionMetadataTransport(
        config, owner_name="mcp-v4-owner-unit01", credentials=lambda: ("unit-owner", "unit-password"),
        folder_path="Public/mcp-v4-folder-unit01", secret_name="mcp-v4-secret-unit01",
        target_name="mcp-v4-target-unit01", witness=FortiPamSecretMetadataHttpTransport(config),
    )
    mutation = SecretApprovalBuild29MutationBinding(
        _schema(), "mcp-v4-approval-profile-unit01", lambda: "3" * 64,
        lambda _values: "4" * 64, tmp_path, lambda _status, _raw: True,
        SecretApprovalBuild29WebFieldsBinding("https://unit.example.test/", lambda: memoryview(bytearray(b"unit-account"))) if web_fields and not linux else None,
        SecretApprovalBuild29LinuxFieldsBinding("mcp-v4-target-unit01", "192.0.2.10", lambda: memoryview(bytearray(b"unit-account"))) if linux else None,
        expected_folder_acl_digest="d" * 64 if linux else None,
    )
    transport = FortiPamSecretApprovalBuild29HttpTransport(
        owner, expected_secret_id=24, expected_secret_name="mcp-v4-secret-unit01",
        expected_folder_id=17, folder_path="Public/mcp-v4-folder-unit01",
        expected_serial="FPAVUNIT01", mutation=mutation, execution_enabled=True,
        linux_target_name="mcp-v4-target-unit01" if linux else None,
    )
    before = SecretApprovalBuild29PrivateState(("disable", "disable", bypass, ""), "3" * 64, "4" * 64, "5" * 64, "b" * 64)
    after = replace(before, approval_values=("enable", "disable", bypass, mutation.approval_profile_name), state_digest="c" * 64)
    calls = {"read": 0, "write": 0}
    def read() -> SecretApprovalBuild29PrivateState:
        calls["read"] += 1
        return transport._ownership[1] if transport._ownership is not None else before
    def write(expected: SecretApprovalBuild29PrivateState, **kwargs: Any) -> SecretApprovalBuild29Readback:
        assert expected == before
        calls["write"] += 1
        transport._ownership = (before, after)
        return SecretApprovalBuild29Readback(True, True, True, True)
    monkeypatch.setattr(transport, "inspect_transition", read)
    monkeypatch.setattr(transport, "enable_and_readback", write)
    plan = _plan()
    provisional = SecretApprovalBuild29M4ExecutionBinding(plan, _authorization(plan), plan.target_ref, before, transport)
    parameters = secret_approval_build29_parameters_digest(secret_approval_build29_binding_digest(provisional))
    content = {**plan.canonical_content(), "parameters_digest": parameters}
    plan = replace(plan, parameters_digest=parameters, plan_digest=canonical_digest(content))
    return replace(provisional, plan=plan, authorization=_authorization(plan)), calls


def test_linux_binding_executes_once_and_binds_address(tmp_path, monkeypatch):
    binding, calls = _binding(tmp_path, monkeypatch, linux=True)
    store = _Store()
    runtime = assemble_secret_approval_build29_m4_runtime(
        binding, authorization_verifier=_Authorizer(), execution_store=store,
        authenticated_requester_digest=_REQUESTER, qualification_verifier=_Qualifier(),
        execution_enabled=True, clock=lambda: _NOW,
    )
    digest = runtime.inspect_binding_digest(binding.authorization.authorization_ref)
    result = runtime.execute_bound(binding.authorization.authorization_ref, expected_binding_digest=digest)
    assert result.outcome is M4Outcome.SUCCEEDED and calls == {"read": 2, "write": 1}
    mutation = binding.transport._mutation
    assert mutation is not None and mutation.linux_fields is not None
    binding.transport._mutation = replace(mutation, linux_fields=replace(
        mutation.linux_fields, target_ipv4_address="192.0.2.11"))
    assert secret_approval_build29_binding_digest(binding) != digest
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(binding.authorization.authorization_ref, expected_binding_digest=digest)
    assert calls == {"read": 2, "write": 1}


def test_linux_binding_without_independent_qualification_never_claims(tmp_path, monkeypatch):
    binding, calls = _binding(tmp_path, monkeypatch, linux=True)
    store = _Store()
    runtime = assemble_secret_approval_build29_m4_runtime(
        binding, authorization_verifier=_Authorizer(), execution_store=store,
        authenticated_requester_digest=_REQUESTER, execution_enabled=True, clock=lambda: _NOW,
    )
    with pytest.raises(M4AdapterDenied):
        runtime.execute_bound(binding.authorization.authorization_ref,
            expected_binding_digest=secret_approval_build29_binding_digest(binding))
    assert calls == {"read": 0, "write": 0} and store.claim_calls == 0


@pytest.mark.parametrize("missing", ["default_gate", "default_qualification", "ack", "native", "permission", "profile", "transport_gate", "web_fields"])
def test_actual_direct_composition_denies_unqualified_writes_before_read_or_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str,
) -> None:
    binding, calls = _binding(tmp_path, monkeypatch, web_fields=missing != "web_fields")
    store = _Store()
    qualifier = None if missing == "default_qualification" else _Qualifier(unavailable=missing if missing in {"ack", "native", "permission", "profile"} else None)
    if missing == "transport_gate":
        binding.transport._execution_enabled = False
    runtime = assemble_secret_approval_build29_m4_runtime(
        binding, authorization_verifier=_Authorizer(), execution_store=store,
        authenticated_requester_digest=_REQUESTER, qualification_verifier=qualifier,
        execution_enabled=missing != "default_gate", clock=lambda: _NOW,
    )
    digest = runtime.inspect_binding_digest(binding.authorization.authorization_ref)
    with pytest.raises(M4AdapterDenied):
        runtime.execute_bound(binding.authorization.authorization_ref, expected_binding_digest=digest)
    assert calls == {"read": 0, "write": 0} and store.claim_calls == 0


def test_simulated_qualified_adapter_uses_existing_kernel_once_and_replays_only_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding, calls = _binding(tmp_path, monkeypatch)
    runtime = assemble_secret_approval_build29_m4_runtime(
        binding, authorization_verifier=_Authorizer(), execution_store=_Store(),
        authenticated_requester_digest=_REQUESTER, qualification_verifier=_Qualifier(),
        execution_enabled=True, clock=lambda: _NOW,
    )
    digest = runtime.inspect_binding_digest(binding.authorization.authorization_ref)
    result = runtime.execute_bound(binding.authorization.authorization_ref, expected_binding_digest=digest)
    assert result.outcome is M4Outcome.SUCCEEDED and calls == {"read": 2, "write": 1}
    replay = runtime.execute_bound(binding.authorization.authorization_ref, expected_binding_digest=digest)
    assert replay.idempotent_replay and calls == {"read": 2, "write": 1}


def test_legacy_191_adapter_contract_cannot_be_relabelled_for_build29(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding, calls = _binding(tmp_path, monkeypatch)
    content = {**binding.plan.canonical_content(), "adapter_ref": "fortipam-secret-approval-cli-191"}
    plan = replace(binding.plan, adapter_ref="fortipam-secret-approval-cli-191", plan_digest=canonical_digest(content))
    with pytest.raises(M4AuthorizationDenied):
        assemble_secret_approval_build29_m4_runtime(
            replace(binding, plan=plan, authorization=_authorization(plan)),
            authorization_verifier=_Authorizer(), execution_store=_Store(),
            authenticated_requester_digest=_REQUESTER,
        )
    assert calls == {"read": 0, "write": 0}


def test_owner_identity_drift_denies_old_binding_before_read_or_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding, calls = _binding(tmp_path, monkeypatch)
    store = _Store()
    runtime = assemble_secret_approval_build29_m4_runtime(
        binding, authorization_verifier=_Authorizer(), execution_store=store,
        authenticated_requester_digest=_REQUESTER, qualification_verifier=_Qualifier(),
        execution_enabled=True, clock=lambda: _NOW,
    )
    digest = runtime.inspect_binding_digest(binding.authorization.authorization_ref)
    binding.transport._owner._owner_name = "mcp-v4-owner-unit02"
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(binding.authorization.authorization_ref, expected_binding_digest=digest)
    assert calls == {"read": 0, "write": 0} and store.claim_calls == 0


def test_fixed_web_routing_is_bound_without_acquiring_username(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binding, calls = _binding(tmp_path, monkeypatch)
    mutation = binding.transport._mutation
    assert mutation is not None and mutation.web_fields is not None
    original = secret_approval_build29_binding_digest(binding)
    binding.transport._mutation = replace(mutation, web_fields=replace(
        mutation.web_fields, username_span_provider=lambda: pytest.fail("material acquired for digest"),
    ))
    assert secret_approval_build29_binding_digest(binding) == original
    binding.transport._mutation = replace(mutation, web_fields=replace(mutation.web_fields, web_url="https://changed.example.test/"))
    assert secret_approval_build29_binding_digest(binding) != original and calls == {"read": 0, "write": 0}


def test_web_routing_drift_denies_old_m4_binding_before_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binding, calls = _binding(tmp_path, monkeypatch)
    store = _Store()
    runtime = assemble_secret_approval_build29_m4_runtime(
        binding, authorization_verifier=_Authorizer(), execution_store=store,
        authenticated_requester_digest=_REQUESTER, qualification_verifier=_Qualifier(),
        execution_enabled=True, clock=lambda: _NOW,
    )
    digest = runtime.inspect_binding_digest(binding.authorization.authorization_ref)
    mutation = binding.transport._mutation
    assert mutation is not None and mutation.web_fields is not None
    binding.transport._mutation = replace(mutation, web_fields=replace(mutation.web_fields, web_url="https://changed.example.test/"))
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(binding.authorization.authorization_ref, expected_binding_digest=digest)
    assert calls == {"read": 0, "write": 0} and store.claim_calls == 0


def test_enabled_bypass_is_preserved_and_old_disable_parameter_plan_is_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding, calls = _binding(tmp_path, monkeypatch, bypass="enable")
    transport = binding.transport
    assert transport._mutation is not None
    proposed = compile_secret_approval_build29_enable_body(
        transport._projection(binding.baseline.approval_values), schema=transport._schema,
        identity=transport._identity, approval_profile_name=transport._mutation.approval_profile_name,
    )
    assert proposed["bypass-approval"] == "enable"
    old_parameters = canonical_digest({
        "action_id": ACTION_ID, "action_version": ACTION_VERSION, "adapter_ref": ADAPTER_REF,
        "binding_digest": secret_approval_build29_binding_digest(binding),
        "need-approval": "enable", "need-approval-job": "disable",
        "bypass-approval": "disable", "approval_profile_attached": True,
    })
    content = {**binding.plan.canonical_content(), "parameters_digest": old_parameters}
    old_plan = replace(binding.plan, parameters_digest=old_parameters, plan_digest=canonical_digest(content))
    with pytest.raises(M4AuthorizationDenied):
        assemble_secret_approval_build29_m4_runtime(
            replace(binding, plan=old_plan, authorization=_authorization(old_plan)),
            authorization_verifier=_Authorizer(), execution_store=_Store(),
            authenticated_requester_digest=_REQUESTER,
        )
    assert calls == {"read": 0, "write": 0}
    runtime = assemble_secret_approval_build29_m4_runtime(
        binding, authorization_verifier=_Authorizer(), execution_store=_Store(),
        authenticated_requester_digest=_REQUESTER, qualification_verifier=_Qualifier(),
        execution_enabled=True, clock=lambda: _NOW,
    )
    assert runtime.execute_bound(
        binding.authorization.authorization_ref,
        expected_binding_digest=runtime.inspect_binding_digest(binding.authorization.authorization_ref),
    ).outcome is M4Outcome.SUCCEEDED
    assert transport._ownership is not None and transport._ownership[1].approval_values[2] == "enable"


@pytest.mark.parametrize("applied", [False, True])
def test_restore_composition_requires_same_transport_apply_ownership_and_independent_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, applied: bool,
) -> None:
    binding, calls = _binding(tmp_path, monkeypatch)
    store = _Store()
    enable = assemble_secret_approval_build29_m4_runtime(
        binding, authorization_verifier=_Authorizer(), execution_store=store,
        authenticated_requester_digest=_REQUESTER, qualification_verifier=_Qualifier(),
        execution_enabled=True, clock=lambda: _NOW,
    )
    if applied:
        assert enable.execute_bound(
            binding.authorization.authorization_ref,
            expected_binding_digest=enable.inspect_binding_digest(binding.authorization.authorization_ref),
        ).outcome is M4Outcome.SUCCEEDED
    digest = secret_approval_build29_binding_digest(binding)
    changes: dict[str, Any] = {
        "plan_ref": "plan-build29-restore-unit01", "action_id": RESTORE_ACTION_ID,
        "parameters_digest": secret_approval_build29_restore_parameters_digest(digest, binding.baseline.state_digest),
        "expected_current_digest": "c" * 64, "expected_state_digest": binding.baseline.state_digest,
        "idempotency_digest": "6" * 64,
    }
    content = {**binding.plan.canonical_content(), **changes}
    plan = replace(binding.plan, **changes, plan_digest=canonical_digest(content))
    authorization = _authorization(plan)
    ref = "authorization-build29-restore-unit01"
    authorization = replace(authorization, authorization_ref=ref, authorization_digest=canonical_digest(
        {**authorization.canonical_content(), "authorization_ref": ref}))
    restore = assemble_secret_approval_build29_m4_runtime(
        replace(binding, plan=plan, authorization=authorization, operation="restore"),
        authorization_verifier=_Authorizer(), execution_store=store,
        authenticated_requester_digest=_REQUESTER, qualification_verifier=_Qualifier(),
        execution_enabled=True, clock=lambda: _NOW,
    )
    def restore_write(expected: SecretApprovalBuild29PrivateState, **kwargs: Any) -> SecretApprovalBuild29Readback:
        assert binding.transport._ownership is not None
        assert expected == binding.transport._ownership[1]
        calls["write"] += 1
        binding.transport._ownership = None
        return SecretApprovalBuild29Readback(True, True, True, True)
    monkeypatch.setattr(binding.transport, "restore_and_readback", restore_write)
    if not applied:
        with pytest.raises(M4AdapterDenied):
            restore.execute_bound(ref, expected_binding_digest=digest)
        assert calls == {"read": 0, "write": 0} and store.claim_calls == 0
        return
    result = restore.execute_bound(ref, expected_binding_digest=digest)
    assert result.outcome is M4Outcome.SUCCEEDED
    assert calls == {"read": 4, "write": 2} and store.claim_calls == 2
    # Consumed ownership cannot grant another restore, even with the old intent.
    with pytest.raises(M4AdapterDenied):
        restore.execute_bound(ref, expected_binding_digest=digest)
    assert calls == {"read": 4, "write": 2} and store.claim_calls == 2


def test_linux_folder_acl_digest_is_bound(tmp_path, monkeypatch):
    binding, _ = _binding(tmp_path, monkeypatch, linux=True)
    original = secret_approval_build29_binding_digest(binding)
    mutation = binding.transport._mutation
    binding.transport._mutation = replace(mutation, expected_folder_acl_digest="e" * 64)
    assert secret_approval_build29_binding_digest(binding) != original
