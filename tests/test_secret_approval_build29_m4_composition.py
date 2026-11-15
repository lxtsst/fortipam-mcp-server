from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import fortipam_mcp.secret_approval_build29_m4_composition as composition
from fortipam_mcp.secret_approval_build29_http_transport import SecretApprovalBuild29Readback
from fortipam_mcp.secret_approval_build29_m4_composition import (
    SecretApprovalBuild29M4CompositionError, SecretApprovalBuild29M4RunnerFactory,
    SecretApprovalBuild29PrivateTransition,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_secret_approval_build29_m4_authorization import _inputs, _OverrideReader, _tampered
from test_secret_approval_build29_m4_runtime import _Store
from test_v4_planning import NOW, _approval_and_observe_draft
from v4_planning import AuthenticatedRequester, M4AdapterDenied, M4AuthorizationDenied, M4Outcome, canonical_digest


class _Producer:
    def __init__(self, values: dict[str, Any]) -> None:
        self.transition = SecretApprovalBuild29PrivateTransition(
            values["transport"], values["baseline"], values["expected_private_state"], values["expected_binding_digest"],
        )
        self.expected_binding = values["approval_binding"]
        self.calls = 0
        self.failure: str | None = None
        self.validated: list[bool] | None = None
        self.advance_clock: Any = None

    def produce(self, approval_binding: Any) -> Any:
        assert approval_binding == self.expected_binding
        if self.validated is not None:
            assert self.validated
        self.calls += 1
        if self.advance_clock is not None:
            self.advance_clock()
        if self.failure == "raise":
            raise ValueError("private-provider-unit-sentinel")
        if self.failure == "wrong_type":
            return object()
        if self.failure == "bad_state":
            return replace(self.transition, expected_private_state=replace(self.transition.expected_private_state, state_digest="f" * 64))
        return self.transition


class _Qualifier:
    """Test authority only; no real source qualification is issued here."""

    def verify(self, *, binding_digest: str, plan_digest: str, now_epoch: int) -> None:
        assert len(binding_digest) == len(plan_digest) == 64 and now_epoch >= NOW + 5


class _DenyQualifier:
    def verify(self, *, binding_digest: str, plan_digest: str, now_epoch: int) -> None:
        raise ValueError("private-qualification-unit-sentinel")


def _context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, old_source: bool = False) -> dict[str, Any]:
    values = _inputs(tmp_path, monkeypatch, old_source=old_source)
    principal = V4PlanningPrincipal(
        AuthenticatedRequester("operator-subject-0001", "operator", identity_authority_ref="identity-authority-ref01",
                               subject_namespace="workforce-namespace-v1"), "a" * 64,
    )
    values.update(plan=values["planning"].get_plan(values["source_plan_ref"]),
                  draft=_approval_and_observe_draft(), principal=principal,
                  producer=_Producer(values), store=_Store(), clock_value=[NOW + 5])
    return values


def _factory(values: dict[str, Any], **overrides: Any) -> SecretApprovalBuild29M4RunnerFactory:
    kwargs = {
        "planning": values["planning"], "receipt_authenticator": values["receipt_authenticator"],
        "producer": values["producer"], "execution_store": values["store"],
        "source_plan_ref": values["source_plan_ref"], "approval_receipt_ref": values["approval_receipt_ref"],
        "approver_authority_ref": values["approver_authority_ref"], "authorization_ref": values["authorization_ref"],
        "authorized_environment_ref": values["authorized_environment_ref"],
        "authorized_scope_ref": values["authorized_scope_ref"], "clock": lambda: values["clock_value"][0],
        "qualification_verifier": _Qualifier(), "execution_enabled": True,
    }
    return SecretApprovalBuild29M4RunnerFactory(**{**kwargs, **overrides})


def _bind(factory: SecretApprovalBuild29M4RunnerFactory, values: dict[str, Any], **overrides: Any) -> Any:
    kwargs = {"plan": values["plan"], "line_ref": values["plan"].lines[0].line_ref,
              "principal": values["principal"], "draft": values["draft"], "approval_binding": values["approval_binding"]}
    return factory.bind(**{**kwargs, **overrides})


def test_constructor_does_not_read_the_chain_or_produce_private_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    values = _context(tmp_path, monkeypatch)
    def forbidden(*_args: Any) -> Any:
        raise AssertionError("Unexpected construction read")
    for name in ("get_plan", "get_summary", "get_confirmation", "get_policy_decision", "get_approval_receipt", "get_approval_claim"):
        monkeypatch.setattr(values["planning"], name, forbidden)
    factory = _factory(values)
    assert values["producer"].calls == values["store"].claim_calls == 0
    assert values["approval_binding"].secret_name not in repr(factory)


def test_signed_validation_precedes_production_and_successful_rebind_keeps_one_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _context(tmp_path, monkeypatch)
    validated: list[bool] = []
    real_validate = composition.validate_build29_planning_chain
    def validate(*args: Any, **kwargs: Any) -> Any:
        chain = real_validate(*args, **kwargs)
        validated.append(True)
        return chain
    monkeypatch.setattr(composition, "validate_build29_planning_chain", validate)
    values["producer"].validated = validated
    factory = _factory(values)
    runner = _bind(factory, values)
    assert runner.line_ref == values["plan"].lines[0].line_ref and runner.depends_on == ()
    assert _bind(factory, values) is runner and values["producer"].calls == 1
    assert len(validated) == 2
    assert "PrivateTransition" in type(values["producer"].transition).__name__
    for item in (values["producer"].transition, runner):
        assert values["approval_binding"].secret_name not in repr(item)
        assert values["approval_binding"].approval_profile_name not in repr(item)
    assert values["store"].claim_calls == 0


@pytest.mark.parametrize("closed", ["gate", "qualification", "both"])
def test_default_closed_factory_refuses_before_private_production(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, closed: str,
) -> None:
    values = _context(tmp_path, monkeypatch)
    factory = _factory(values, execution_enabled=closed == "qualification",
                       qualification_verifier=_Qualifier() if closed == "gate" else None)
    with pytest.raises(SecretApprovalBuild29M4CompositionError):
        _bind(factory, values)
    assert values["producer"].calls == values["store"].claim_calls == 0


def test_non_none_qualifier_does_not_confer_execution_qualification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    values = _context(tmp_path, monkeypatch)
    calls = _allow_fixed_fake_execution(values, monkeypatch)
    runner = _bind(_factory(values, qualification_verifier=_DenyQualifier()), values)
    with pytest.raises(M4AdapterDenied) as failure:
        runner.execute_bound()
    assert "private-qualification-unit-sentinel" not in str(failure.value)
    assert values["producer"].calls == 1
    assert values["store"].claim_calls == calls["read"] == calls["write"] == 0


@pytest.mark.parametrize("change", [
    "principal", "source_plan", "line", "target", "draft_environment", "draft_scope", "draft_owner",
    "draft_audience", "draft_facts", "draft_risk", "draft_assumptions", "draft_desired", "binding_object",
])
def test_wrong_context_is_rejected_before_the_private_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    values = _context(tmp_path, monkeypatch)
    factory = _factory(values)
    overrides: dict[str, Any] = {}
    if change == "principal":
        overrides["principal"] = replace(values["principal"], requester=AuthenticatedRequester("another-subject-ref01", "operator"))
    elif change == "source_plan":
        source = values["plan"]
        overrides["plan"] = replace(source, plan_ref="another-source-plan-ref01",
                                    plan_digest=canonical_digest({**source.canonical_content(), "plan_ref": "another-source-plan-ref01"}))
    elif change == "line":
        overrides["line_ref"] = "another-line-ref01"
    elif change == "target":
        source = values["plan"]
        changed = replace(source.lines[0], target_ref="another-target-ref01")
        overrides["plan"] = replace(source, lines=(changed,), plan_digest=canonical_digest({**source.canonical_content(), "lines": [changed.as_dict()]}))
    elif change == "binding_object":
        overrides["approval_binding"] = replace(values["approval_binding"], secret_approval_object_ref="another-target-ref01")
    else:
        name, value = {
            "draft_environment": ("environment_ref", "another-environment-ref01"),
            "draft_scope": ("scope_ref", "another-scope-ref01"),
            "draft_owner": ("owner_ref", "another-owner-ref01"),
            "draft_audience": ("audience_ref", "another-audience-ref01"),
            "draft_facts": ("evidence_refs", ("another-evidence-ref01",)),
            "draft_risk": ("risk_class", "low"),
            "draft_assumptions": ("assumption_codes", ("another_assumption",)),
            "draft_desired": ("desired_objects", values["draft"].desired_objects[:1]),
        }[change]
        overrides["draft"] = replace(values["draft"], **{name: value})
    with pytest.raises(SecretApprovalBuild29M4CompositionError) as failure:
        _bind(factory, values, **overrides)
    assert values["producer"].calls == values["store"].claim_calls == 0
    assert failure.value.__cause__ is None


@pytest.mark.parametrize("changed", ["principal_namespace", "draft", "source", "line", "binding"])
def test_different_rebind_context_never_reproduces_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str,
) -> None:
    values = _context(tmp_path, monkeypatch)
    factory = _factory(values)
    runner = _bind(factory, values)
    overrides: dict[str, Any] = {}
    if changed == "principal_namespace":
        overrides["principal"] = replace(values["principal"], transport_namespace_digest="b" * 64)
    elif changed == "draft":
        # This value is not copied into the summary, but a rebind must still
        # preserve the complete original draft, including its requested TTL.
        overrides["draft"] = replace(values["draft"], summary_ttl_seconds=301)
    elif changed == "source":
        overrides["plan"] = _tampered(values["plan"], "revision", 2)
    elif changed == "line":
        overrides["line_ref"] = "another-line-ref01"
    else:
        overrides["approval_binding"] = replace(values["approval_binding"], secret_name="another-private-unit-name")
    with pytest.raises(SecretApprovalBuild29M4CompositionError):
        _bind(factory, values, **overrides)
    assert _bind(factory, values) is runner and values["producer"].calls == 1


@pytest.mark.parametrize("bad", ["old_source", "receipt", "claim", "expiry"])
def test_unqualified_signed_chain_never_reaches_private_production(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str,
) -> None:
    values = _context(tmp_path, monkeypatch, old_source=bad == "old_source")
    reader = values["planning"]
    if bad == "receipt":
        receipt = reader.get_approval_receipt(values["approval_receipt_ref"])
        values["planning"] = _OverrideReader(reader, "get_approval_receipt", _tampered(receipt, "receipt_mac", "f" * 64))
    elif bad == "claim":
        claim = reader.get_approval_claim(values["approval_receipt_ref"])
        values["planning"] = _OverrideReader(reader, "get_approval_claim", _tampered(claim, "execution_authorized", True))
    elif bad == "expiry":
        values["clock_value"][0] = NOW + 100
    with pytest.raises(SecretApprovalBuild29M4CompositionError):
        _bind(_factory(values), values)
    assert values["producer"].calls == values["store"].claim_calls == 0


@pytest.mark.parametrize("failure", ["raise", "wrong_type", "bad_state"])
def test_failed_private_production_is_value_free_and_cannot_be_repeated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    values = _context(tmp_path, monkeypatch)
    values["producer"].failure = failure
    factory = _factory(values)
    for _ in range(2):
        with pytest.raises(SecretApprovalBuild29M4CompositionError) as refusal:
            _bind(factory, values)
        assert "private-provider-unit-sentinel" not in str(refusal.value)
        assert refusal.value.__cause__ is None
    assert values["producer"].calls == 1 and values["store"].claim_calls == 0


def test_production_delay_cannot_extend_the_signed_chain_lifetime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    values = _context(tmp_path, monkeypatch)
    values["producer"].advance_clock = lambda: values["clock_value"].__setitem__(0, NOW + 100)
    with pytest.raises(SecretApprovalBuild29M4CompositionError):
        _bind(_factory(values), values)
    assert values["producer"].calls == 1 and values["store"].claim_calls == 0


def _allow_fixed_fake_execution(values: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    calls = {"read": 0, "write": 0}
    transport = values["transport"]
    def read() -> Any:
        calls["read"] += 1
        return transport._ownership[1] if transport._ownership is not None else values["baseline"]
    def write(expected: Any, **_kwargs: Any) -> SecretApprovalBuild29Readback:
        assert expected == values["baseline"]
        calls["write"] += 1
        transport._ownership = (values["baseline"], values["expected_private_state"])
        return SecretApprovalBuild29Readback(True, True, True, True)
    monkeypatch.setattr(transport, "inspect_transition", read)
    monkeypatch.setattr(transport, "enable_and_readback", write)
    return calls


def test_fixed_runner_executes_once_serializes_categories_and_keeps_restore_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _context(tmp_path, monkeypatch)
    calls = _allow_fixed_fake_execution(values, monkeypatch)
    factory = _factory(values, qualification_verifier=_Qualifier(), execution_enabled=True)
    runner = _bind(factory, values)
    result = runner.execute_bound()
    assert result["outcome"] == M4Outcome.SUCCEEDED.value
    assert calls["write"] == 1 and values["producer"].calls == 1
    assert _bind(factory, values) is runner
    runner.execute_bound()
    assert calls["write"] == 1 and values["producer"].calls == 1
    assert values["transport"]._ownership == (values["baseline"], values["expected_private_state"])
    assert values["approval_binding"].secret_name not in str(result)
    assert values["approval_binding"].approval_profile_name not in str(result)
    assert values["baseline"].native_digest not in str(result)


def test_execute_rechecks_expiry_before_claim_or_private_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    values = _context(tmp_path, monkeypatch)
    calls = _allow_fixed_fake_execution(values, monkeypatch)
    runner = _bind(_factory(values, qualification_verifier=_Qualifier(), execution_enabled=True), values)
    values["clock_value"][0] = NOW + 100
    with pytest.raises(M4AuthorizationDenied):
        runner.execute_bound()
    assert values["store"].claim_calls == calls["read"] == calls["write"] == 0


def test_execute_rechecks_signed_receipt_drift_before_private_read_and_preserves_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _context(tmp_path, monkeypatch)
    calls = _allow_fixed_fake_execution(values, monkeypatch)
    runner = _bind(_factory(values, qualification_verifier=_Qualifier(), execution_enabled=True), values)
    receipt = values["planning"].get_approval_receipt(values["approval_receipt_ref"])
    monkeypatch.setattr(values["planning"], "get_approval_receipt", lambda _ref: _tampered(receipt, "receipt_mac", "f" * 64))
    with pytest.raises(M4AuthorizationDenied):
        runner.execute_bound()
    assert values["store"].claim_calls == 1
    assert calls["read"] == calls["write"] == 0
