from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

import pytest

from fortipam_mcp.approval_and_observe_projection_source import (
    ApprovalAndObserveBinding,
    ApprovalAndObserveProjectionSourceError,
    FortiPamApprovalAndObserveProjectionSource,
    OwnerOnlyApprovalAndObserveBindingResolver,
    SOURCE_CONTRACT,
    SOURCE_VERSION,
)
from fortipam_mcp.approval_profile_ssh_transport import ApprovalProfileReadback
from fortipam_mcp.secret_metadata_http_transport import (
    SecretApprovalProjectionInspection,
)
from v4_planning import (
    AuthenticatedRequester,
    DesiredObject,
    ObjectClass,
    SchemeDraft,
    SchemeId,
)


def _desired(
    object_ref: str,
    object_class: ObjectClass,
    fields: dict[str, bool | str],
) -> DesiredObject:
    return DesiredObject(
        object_ref=object_ref,
        object_class=object_class,
        desired_exists=True,
        desired_fields=tuple(sorted(fields.items())),
    )


def _draft() -> SchemeDraft:
    return SchemeDraft(
        scheme_id=SchemeId.APPROVAL_AND_OBSERVE,
        scheme_version="1.0.0",
        registry_schema_version="1.1.0",
        blueprint_ref="FPA-BP-008",
        environment_ref="approval-environment-ref01",
        scope_ref="approval-scope-reference01",
        owner_ref="approval-owner-reference01",
        audience_ref="approval-audience-ref001",
        outcome_code="require_interactive_approval",
        desired_objects=(
            _desired(
                "approval-profile-object-ref01",
                ObjectClass.APPROVAL_PROFILE_BINDING,
                {
                    "profile_mode": "single_tier",
                    "profile_ref": "approval-profile-reference01",
                },
            ),
            _desired(
                "secret-approval-object-ref01",
                ObjectClass.SECRET_APPROVAL_BINDING,
                {
                    "approval_profile_attached": True,
                    "interactive_approval_required": True,
                    "job_approval_required": False,
                    "owner_bypass_allowed": False,
                },
            ),
        ),
        approval_class="independent_approval",
        separation_required=True,
        risk_class="high",
        external_effects=("interactive_approval_policy_change",),
        assumption_codes=("single_tier_profile_prevalidated",),
        excluded_scope_codes=("approval_request", "session_launch"),
        verification_codes=("secret_approval_relation_readback",),
        stop_codes=("current_state_drift", "projection_unavailable"),
        evidence_policy="redacted_contract_evidence",
        maintenance_class="none",
        reversibility_class="manual_reconciliation_only",
        evidence_refs=("approval-evidence-reference01",),
        unresolved_gap_codes=(),
        reconciliation_strategy="reconcile_or_manual",
        summary_ttl_seconds=300,
    )


def _binding() -> ApprovalAndObserveBinding:
    return ApprovalAndObserveBinding(
        approval_profile_object_ref="approval-profile-object-ref01",
        approval_profile_ref="approval-profile-reference01",
        approval_profile_name="mcp-v4-approval-profile-01",
        secret_approval_object_ref="secret-approval-object-ref01",
        folder_path="Public/folder",
        secret_name="mcp-v4-secret-metadata-01",
        secret_id=42,
    )


class _Resolver:
    def resolve(self, draft: SchemeDraft, requester: AuthenticatedRequester):
        assert draft == _draft()
        assert requester == AuthenticatedRequester("approval-requester-ref01", "operator")
        return _binding()


class _ProfileTransport:
    def readback(self, profile_name: str) -> ApprovalProfileReadback:
        assert profile_name == "mcp-v4-approval-profile-01"
        return ApprovalProfileReadback(True, True, True, True, True, True, True, True, True)


class _SecretTransport:
    def __init__(self, *, profile_matches: bool = False, profile_unset: bool = True):
        self._profile_matches = profile_matches
        self._profile_unset = profile_unset

    def inspect_approval_projection(
        self,
        folder_path: str,
        secret_name: str,
        approval_profile_name: str,
        *,
        expected_secret_id: int,
    ) -> SecretApprovalProjectionInspection:
        assert (folder_path, secret_name, approval_profile_name) == (
            "Public/folder",
            "mcp-v4-secret-metadata-01",
            "mcp-v4-approval-profile-01",
        )
        assert expected_secret_id == 42
        return SecretApprovalProjectionInspection(
            secret_exists=True,
            interactive_approval_required=self._profile_matches,
            job_approval_required=False,
            owner_bypass_allowed=False,
            approval_profile_matches=self._profile_matches,
            approval_profile_unset=self._profile_unset,
            field_values_attached=True,
        )


def test_source_projects_one_existing_profile_and_one_secret_update() -> None:
    source = FortiPamApprovalAndObserveProjectionSource(
        _SecretTransport(),
        _ProfileTransport(),
        _Resolver(),
    )

    projections = source.project(
        _draft(),
        AuthenticatedRequester("approval-requester-ref01", "operator"),
        now_epoch=1_800_000_000,
    )

    assert source.contract_registered is True
    assert [item.contract.object_class for item in projections] == [
        ObjectClass.APPROVAL_PROFILE_BINDING,
        ObjectClass.SECRET_APPROVAL_BINDING,
    ]
    assert projections[0].values["profile_mode"] == "single_tier"
    assert projections[1].values == {
        "approval_profile_attached": False,
        "exists": True,
        "interactive_approval_required": False,
        "job_approval_required": False,
        "owner_bypass_allowed": False,
    }
    serialized = json.dumps([item.as_dict() for item in projections])
    assert "mcp-v4-approval-profile-01" not in serialized
    assert "mcp-v4-secret-metadata-01" not in serialized
    assert "Public/folder" not in serialized


def test_source_rejects_a_different_attached_profile() -> None:
    source = FortiPamApprovalAndObserveProjectionSource(
        _SecretTransport(profile_unset=False),
        _ProfileTransport(),
        _Resolver(),
    )

    with pytest.raises(ApprovalAndObserveProjectionSourceError):
        source.project(
            _draft(),
            AuthenticatedRequester("approval-requester-ref01", "operator"),
            now_epoch=1_800_000_000,
        )


def test_source_binds_request_observation_to_the_same_private_secret() -> None:
    source = FortiPamApprovalAndObserveProjectionSource(
        _SecretTransport(),
        _ProfileTransport(),
        _Resolver(),
    )
    requester = AuthenticatedRequester("approval-requester-ref01", "operator")

    binding = source.bind_request_observation(
        _draft(),
        requester,
        request_ref="opaque-request-reference01",
        request_id=71,
    )

    assert binding.request_ref == "opaque-request-reference01"
    assert binding.request_id == 71
    assert binding.secret_id == _binding().secret_id
    assert binding.requester_digest == requester.digest
    assert binding.environment_ref == _draft().environment_ref
    assert binding.scope_ref == _draft().scope_ref


def test_private_binding_repr_does_not_disclose_selectors() -> None:
    rendered = repr(_binding())

    assert "Public/folder" not in rendered
    assert "mcp-v4-secret-metadata-01" not in rendered
    assert "mcp-v4-approval-profile-01" not in rendered


def test_owner_only_binding_is_requester_and_scope_bound(tmp_path: Path) -> None:
    draft = _draft()
    requester = AuthenticatedRequester("approval-requester-ref01", "operator")
    path = tmp_path / "approval-binding.json"
    path.write_text(
        json.dumps(
            {
                "contract": SOURCE_CONTRACT,
                "version": SOURCE_VERSION,
                "requester_digest": requester.digest,
                "environment_ref": draft.environment_ref,
                "scope_ref": draft.scope_ref,
                **asdict(_binding()),
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)

    assert OwnerOnlyApprovalAndObserveBindingResolver(path).resolve(
        draft,
        requester,
    ) == _binding()

    path.chmod(0o640)
    with pytest.raises(ApprovalAndObserveProjectionSourceError):
        OwnerOnlyApprovalAndObserveBindingResolver(path).resolve(draft, requester)
