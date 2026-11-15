"""Synthetic categorical projection and owner-only build-29 binding cases."""

from dataclasses import asdict, replace
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

import fortipam_mcp.secret_approval_build29_projection_source as module
from fortipam_mcp.approval_and_observe_projection_source import (
    ApprovalAndObserveBinding, SOURCE_CONTRACT as OLD_SOURCE_CONTRACT,
    SOURCE_REF as OLD_SOURCE_REF, SOURCE_VERSION as OLD_SOURCE_VERSION,
)
from fortipam_mcp.secret_approval_build29_projection_source import (
    FortiPamSecretApprovalBuild29ProjectionSource,
    OwnerOnlySecretApprovalBuild29BindingResolver,
    SecretApprovalBuild29ProjectionSourceError,
    SecretApprovalBuild29ProfileInspection,
)
from fortipam_mcp.secret_metadata_http_transport import SecretApprovalProjectionInspection
from v4_planning import AuthenticatedRequester, DesiredObject, ObjectClass, SchemeDraft, SchemeId
from v4_planning.models import MaterialReferenceMetadata


_REQUESTER = AuthenticatedRequester("approval-requester-ref01", "operator")
_BINDING = ApprovalAndObserveBinding(
    "approval-profile-object-ref01", "approval-profile-reference01", "mcp-v4-approval-profile-unit01",
    "secret-approval-object-ref01", "Public/unit-folder", "mcp-v4-secret-unit01", 24,
)
_PROFILE = SecretApprovalBuild29ProfileInspection(True, True, True, True, True, True, True, True)
_SECRET = SecretApprovalProjectionInspection(True, False, False, True, False, True, False)


def _draft() -> SchemeDraft:
    return SchemeDraft(
        scheme_id=SchemeId.APPROVAL_AND_OBSERVE, scheme_version="1.0.0", registry_schema_version="1.1.0",
        blueprint_ref="FPA-BP-008", environment_ref="approval-environment-ref01", scope_ref="approval-scope-ref01",
        owner_ref="approval-owner-ref01", audience_ref="approval-audience-ref01",
        outcome_code="require_interactive_approval",
        desired_objects=(
            DesiredObject(_BINDING.approval_profile_object_ref, ObjectClass.APPROVAL_PROFILE_BINDING, True,
                          (("profile_mode", "single_tier"), ("profile_ref", _BINDING.approval_profile_ref))),
            DesiredObject(_BINDING.secret_approval_object_ref, ObjectClass.SECRET_APPROVAL_BINDING, True,
                          (("approval_profile_attached", True), ("interactive_approval_required", True),
                           ("job_approval_required", False), ("owner_bypass_allowed", False))),
        ),
        approval_class="independent_approval", separation_required=True, risk_class="high",
        external_effects=("interactive_approval_policy_change",), assumption_codes=("single_tier_profile_prevalidated",),
        excluded_scope_codes=("approval_request", "session_launch"), verification_codes=("secret_approval_relation_readback",),
        stop_codes=("current_state_drift", "projection_unavailable"), evidence_policy="redacted_contract_evidence",
        maintenance_class="none", reversibility_class="manual_reconciliation_only",
        evidence_refs=("approval-evidence-ref01",), unresolved_gap_codes=(),
        reconciliation_strategy="reconcile_or_manual", summary_ttl_seconds=300,
    )


class _Resolver:
    def resolve(self, draft: SchemeDraft, requester: AuthenticatedRequester) -> ApprovalAndObserveBinding:
        assert draft.environment_ref == _draft().environment_ref
        assert draft.scope_ref == _draft().scope_ref
        assert requester == _REQUESTER
        return _BINDING


class _ProfileTransport:
    def __init__(self, result: Any = _PROFILE) -> None:
        self.result = result
        self.calls = 0

    def readback(self, name: str) -> SecretApprovalBuild29ProfileInspection:
        self.calls += 1
        assert name == _BINDING.approval_profile_name
        return cast(SecretApprovalBuild29ProfileInspection, self.result)


class _SecretTransport:
    def __init__(self, result: Any = _SECRET) -> None:
        self.result = result
        self.calls = 0

    def inspect_approval_projection(
        self, folder_path: str, secret_name: str, approval_profile_name: str, *, expected_secret_id: int,
    ) -> SecretApprovalProjectionInspection:
        self.calls += 1
        assert (folder_path, secret_name, approval_profile_name, expected_secret_id) == (
            _BINDING.folder_path, _BINDING.secret_name, _BINDING.approval_profile_name, _BINDING.secret_id,
        )
        return cast(SecretApprovalProjectionInspection, self.result)


def _source(
    *, profile: Any = _PROFILE, secret: Any = _SECRET, resolver: Any = None,
    registered: bool = False,
) -> tuple[FortiPamSecretApprovalBuild29ProjectionSource, _ProfileTransport, _SecretTransport]:
    profile_transport, secret_transport = _ProfileTransport(profile), _SecretTransport(secret)
    source = FortiPamSecretApprovalBuild29ProjectionSource(
        secret_transport, profile_transport, _Resolver() if resolver is None else resolver,
        contract_registered=registered,
    )
    return source, profile_transport, secret_transport


def _payload() -> dict[str, object]:
    return {"contract": module.SOURCE_CONTRACT, "version": module.SOURCE_VERSION,
            "requester_digest": _REQUESTER.digest, "environment_ref": _draft().environment_ref,
            "scope_ref": _draft().scope_ref, **asdict(_BINDING)}


def _write(path: Path, payload: dict[str, object] | None = None) -> Path:
    path.write_text(json.dumps(_payload() if payload is None else payload))
    path.chmod(0o600)
    return path


def test_new_contract_categorical_projection_has_no_selectors_or_material() -> None:
    source, profile, secret = _source()
    projections = source.project(_draft(), _REQUESTER, now_epoch=1_800_000_000)
    assert source.contract_registered is False
    assert (profile.calls, secret.calls) == (1, 1)
    assert len(projections) == 2
    for projection in projections:
        assert projection.contract.contract_id == module.PROJECTION_CONTRACT
        assert projection.contract.version == "1.0.0"
        assert projection.contract.source_ref == module.SOURCE_REF
        assert projection.fresh_until - projection.observed_at == 300
        assert projection.contract.max_age_seconds == 300
        assert projection.c3_included is projection.raw_response_included is False
    assert projections[1].values == {"exists": True, "approval_profile_attached": False,
                                     "interactive_approval_required": False, "job_approval_required": False,
                                     "owner_bypass_allowed": True}
    public = json.dumps([projection.as_dict() for projection in projections])
    for private in (_BINDING.approval_profile_name, _BINDING.secret_name, _BINDING.folder_path):
        assert private not in public
    assert "field_values_attached" not in public
    assert module.SOURCE_REF != OLD_SOURCE_REF
    assert module.SOURCE_CONTRACT != OLD_SOURCE_CONTRACT
    assert (OLD_SOURCE_REF, OLD_SOURCE_CONTRACT, OLD_SOURCE_VERSION) == (
        "fortipam-191-approval-observe-projection", "fortipam-approval-observe-binding-v1", "1.1.0",
    )


def test_registration_is_explicit_read_only_and_binding_resolution_makes_no_reads() -> None:
    source, profile, secret = _source(registered=True)
    assert source.contract_registered is True
    assert source.resolve_private_binding(_draft(), _REQUESTER) == _BINDING
    assert (profile.calls, secret.calls) == (0, 0)
    assert not hasattr(source, "bind_request_observation")
    assert not hasattr(source, "inspect_transition")
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        _source(registered=cast(Any, 1))


def test_existing_same_profile_matches_is_supported() -> None:
    source, _, _ = _source(secret=replace(_SECRET, approval_profile_matches=True,
                                        approval_profile_unset=False, interactive_approval_required=True))
    projections = source.project(_draft(), _REQUESTER, now_epoch=0)
    assert projections[1].values["approval_profile_attached"] is True


@pytest.mark.parametrize("changes", [
    {"scheme_id": SchemeId.SECRET_ONBOARDING}, {"scheme_version": "2.0.0"},
    {"registry_schema_version": "1.0.0"}, {"blueprint_ref": "FPA-BP-006"},
    {"outcome_code": "observe_approval_request"},
    {"material_reference_metadata": MaterialReferenceMetadata("fortipam_managed_material", "jit_delivery", "available")},
    {"environment_ref": "different-environment-ref01"}, {"scope_ref": "different-scope-ref01"},
])
def test_invalid_scheme_or_bound_scope_stops_before_transport(changes: dict[str, Any]) -> None:
    source, profile, secret = _source()
    draft = replace(_draft(), **changes)
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        source.project(draft, _REQUESTER, now_epoch=1)
    assert (profile.calls, secret.calls) == (0, 0)
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        source.resolve_private_binding(draft, _REQUESTER)


@pytest.mark.parametrize("now", [True, -1, 1.5, "1"])
def test_invalid_freshness_stops_before_transport(now: Any) -> None:
    source, profile, secret = _source()
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        source.project(_draft(), _REQUESTER, now_epoch=now)
    assert (profile.calls, secret.calls) == (0, 0)


def test_wrong_requester_and_desired_field_type_stop_before_reads() -> None:
    source, profile, secret = _source()
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        source.project(_draft(), AuthenticatedRequester("other-requester-ref01", "operator"), now_epoch=1)
    objects = _draft().desired_objects
    mutated = replace(objects[1], desired_fields=(
        ("approval_profile_attached", 1), ("interactive_approval_required", True),
        ("job_approval_required", False), ("owner_bypass_allowed", False),
    ))
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        source.project(replace(_draft(), desired_objects=(objects[0], mutated)), _REQUESTER, now_epoch=1)
    assert (profile.calls, secret.calls) == (0, 0)


@pytest.mark.parametrize("secret", [
    None, {"secret_exists": True}, replace(_SECRET, secret_exists=False),
    replace(_SECRET, approval_profile_unset=False), replace(_SECRET, approval_profile_matches=True),
    replace(_SECRET, interactive_approval_required=cast(Any, 1)),
    replace(_SECRET, field_values_attached=cast(Any, None)),
])
def test_unknown_or_contradictory_secret_flags_are_denied(secret: Any) -> None:
    source, _, _ = _source(secret=secret)
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        source.project(_draft(), _REQUESTER, now_epoch=1)


@pytest.mark.parametrize("profile", [
    None, {"verified": True}, replace(_PROFILE, single_tier_enabled=False),
    replace(_PROFILE, profile_matches=cast(Any, 1)),
])
def test_unknown_profile_flags_fail_before_secret_read(profile: Any) -> None:
    source, _, secret = _source(profile=profile)
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        source.project(_draft(), _REQUESTER, now_epoch=1)
    assert secret.calls == 0


@pytest.mark.parametrize("category", [
    "profile_matches", "single_tier_enabled", "first_approval_count_one", "fixed_approver_present",
    "other_principals_disabled", "self_approval_disabled", "empty_custom_fields", "notifications_schedules_unset",
])
def test_each_actual_build29_profile_category_is_required(category: str) -> None:
    source, _, secret = _source(profile=replace(_PROFILE, **{category: False}))
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        source.project(_draft(), _REQUESTER, now_epoch=1)
    assert secret.calls == 0


def test_old_profile_readback_is_not_relabelled_as_build29_evidence() -> None:
    from fortipam_mcp.approval_profile_ssh_transport import ApprovalProfileReadback

    old = ApprovalProfileReadback(True, True, True, True, True, True, True, True, True)
    source, _, secret = _source(profile=old)
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        source.project(_draft(), _REQUESTER, now_epoch=1)
    assert secret.calls == 0


def test_owner_binding_contract_and_exact_request_scope(tmp_path: Path) -> None:
    path = _write(tmp_path / "binding.json")
    resolver = OwnerOnlySecretApprovalBuild29BindingResolver(path)
    assert resolver.resolve(_draft(), _REQUESTER) == _BINDING
    source, profile, secret = _source(resolver=resolver)
    source.project(_draft(), _REQUESTER, now_epoch=1)
    assert (profile.calls, secret.calls) == (1, 1)
    for draft, requester in (
        (replace(_draft(), environment_ref="other-environment-ref01"), _REQUESTER),
        (replace(_draft(), scope_ref="other-scope-ref01"), _REQUESTER),
        (_draft(), AuthenticatedRequester("other-requester-ref01", "operator")),
    ):
        with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
            resolver.resolve(draft, requester)


@pytest.mark.parametrize("name,value", [
    ("contract", OLD_SOURCE_CONTRACT), ("version", OLD_SOURCE_VERSION), ("contract", "unknown-binding-contract"),
    ("secret_id", True), ("secret_id", 0), ("secret_id", "24"),
    ("requester_digest", "0" * 64), ("unknown", "value"), ("secret_name", None),
])
def test_owner_binding_rejects_old_unknown_contract_or_types(tmp_path: Path, name: str, value: object) -> None:
    payload = _payload()
    payload[name] = value
    path = _write(tmp_path / "binding.json", payload)
    source, profile, secret = _source(resolver=OwnerOnlySecretApprovalBuild29BindingResolver(path))
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        source.project(_draft(), _REQUESTER, now_epoch=1)
    assert (profile.calls, secret.calls) == (0, 0)


@pytest.mark.parametrize("kind", ["duplicate", "missing", "oversize", "empty", "constant"])
def test_owner_binding_unique_bounded_complete_json(tmp_path: Path, kind: str) -> None:
    path = _write(tmp_path / "binding.json")
    if kind == "duplicate":
        content = json.dumps(_payload())[:-1] + ',"secret_id":24}'
    elif kind == "missing":
        payload = _payload()
        del payload["scope_ref"]
        content = json.dumps(payload)
    elif kind == "oversize":
        content = " " * (module._MAX_BINDING_BYTES + 1)
    elif kind == "constant":
        content = json.dumps(_payload())[:-1] + ',"unknown":NaN}'
    else:
        content = ""
    path.write_text(content)
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        OwnerOnlySecretApprovalBuild29BindingResolver(path).resolve(_draft(), _REQUESTER)


@pytest.mark.parametrize("mode", [0o400, 0o640, 0o644, 0o700])
def test_binding_requires_exact_owner_private_600(tmp_path: Path, mode: int) -> None:
    path = _write(tmp_path / "binding.json")
    path.chmod(mode)
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        OwnerOnlySecretApprovalBuild29BindingResolver(path).resolve(_draft(), _REQUESTER)


def test_binding_rejects_symlink_parent_symlink_nonfile_or_wrong_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write(tmp_path / "binding.json")
    link = tmp_path / "linked.json"
    link.symlink_to(path)
    parent = tmp_path / "linked-parent"
    parent.symlink_to(tmp_path, target_is_directory=True)
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo, 0o600)
    for candidate in (link, parent / path.name, tmp_path, fifo):
        with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
            OwnerOnlySecretApprovalBuild29BindingResolver(candidate).resolve(_draft(), _REQUESTER)
    monkeypatch.setattr(module.os, "getuid", lambda: path.stat().st_uid + 1)
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        OwnerOnlySecretApprovalBuild29BindingResolver(path).resolve(_draft(), _REQUESTER)


def test_source_failure_does_not_disclose_transport_error_values() -> None:
    class FailingProfile:
        def readback(self, name: str) -> SecretApprovalBuild29ProfileInspection:
            raise RuntimeError("Synthetic protected selector: " + name)

    source = FortiPamSecretApprovalBuild29ProjectionSource(_SecretTransport(), FailingProfile(), _Resolver())
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError) as caught:
        source.project(_draft(), _REQUESTER, now_epoch=1)
    assert str(caught.value) == module.SOURCE_UNAVAILABLE
    assert caught.value.__cause__ is None
