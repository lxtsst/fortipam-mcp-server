from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path

import pytest

from fortipam_mcp.access_domain_projection_source import (
    AccessDomainFolderBinding,
    AccessDomainProjectionSourceError,
    BoundAclRelation,
    FortiPamAccessDomainProjectionSource,
    OwnerOnlyAccessDomainBindingResolver,
    SOURCE_CONTRACT,
    SOURCE_REF,
    SOURCE_VERSION,
)
from v4_planning import (
    AuthenticatedRequester,
    DesiredObject,
    ObjectClass,
    SchemeDraft,
    SchemeId,
)
from fortipam_mcp.v4_runtime_host import (
    V4PersistentReferenceAuthoritySettings,
    V4RuntimeHostError,
    V4SyntheticHostSettings,
    V4_SYNTHETIC_SCHEME_REF,
    access_domain_v4_plan_host_factory,
    issue_synthetic_reference_grants,
)
from fortipam_mcp.local_oauth import (
    LocalOAuthProvider,
    LocalOAuthSettings,
    hash_local_password,
)
from fortipam_mcp.v4_confirmation_http import V4ConfirmationSettings
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal


class FolderTransport:
    def __init__(self, records: list[dict[str, object]]) -> None:
        self.records = records

    def read_collection(self) -> Mapping[str, object]:
        return {"results": self.records}


class Resolver:
    def __init__(self, binding: AccessDomainFolderBinding) -> None:
        self.binding = binding

    def resolve(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> AccessDomainFolderBinding:
        del draft, requester
        return self.binding


def _draft() -> SchemeDraft:
    return SchemeDraft(
        scheme_id=SchemeId.ACCESS_DOMAIN,
        scheme_version="1.0.0",
        registry_schema_version="1.1.0",
        blueprint_ref="FPA-BP-004",
        environment_ref="projection-test-environment",
        scope_ref="projection-test-scope",
        owner_ref="projection-test-owner",
        audience_ref="projection-test-audience",
        outcome_code="establish_access_domain",
        desired_objects=(
            DesiredObject(
                object_ref="projection-folder-object",
                object_class=ObjectClass.PUBLIC_FOLDER,
                desired_exists=True,
                desired_fields=(("enabled", True), ("owner_ref", "projection-test-owner")),
            ),
            DesiredObject(
                object_ref="projection-grant-object1",
                object_class=ObjectClass.ACCESS_GRANT,
                desired_exists=True,
                desired_fields=(
                    ("permission", "use"),
                    ("subject_class", "group"),
                    ("subject_ref", "projection-group-ref01"),
                ),
            ),
        ),
        approval_class="independent_approval",
        separation_required=True,
        risk_class="high",
        external_effects=("access_scope_change",),
        assumption_codes=("bound_projection_only",),
        excluded_scope_codes=("credential_material",),
        verification_codes=("relation_readback",),
        stop_codes=("current_state_drift",),
        evidence_policy="redacted_contract_evidence",
        maintenance_class="none",
        reversibility_class="compensating_action_required",
        evidence_refs=("projection-test-evidence",),
        unresolved_gap_codes=(),
        reconciliation_strategy="reconcile_or_manual",
        summary_ttl_seconds=300,
    )


def _binding() -> AccessDomainFolderBinding:
    return AccessDomainFolderBinding(
        folder_object_ref="projection-folder-object",
        folder_name="private-product-folder",
        parent_folder_id=9,
        owner_ref="projection-test-owner",
        owner_principal_name="private-owner-name",
        owner_subject_class="user",
        acl_relations=(
            BoundAclRelation(
                object_ref="projection-grant-object1",
                subject_ref="projection-group-ref01",
                subject_class="group",
                principal_name="private-group-name",
                permission="use",
                folder_permission="view",
                secret_permission="view",
            ),
        ),
    )


def _folder(*, group_folder_permission: str = "View") -> dict[str, object]:
    groups: list[dict[str, object]] = []
    groups.append(
        {
            "group-name": [{"name": "private-group-name"}],
            "folder-permission": group_folder_permission,
            "secret-permission": "View",
        }
    )
    return {
        "id": 17,
        "name": "private-product-folder",
        "parent-folder": 9,
        "folder-type": "public",
        "user-permission": [
            {
                "user-name": [{"name": "private-owner-name"}],
                "folder-permission": "Owner",
                "secret-permission": "Owner",
            }
        ],
        "group-permission": groups,
        "sensitive-extra": "must-not-leave-source",
    }


def _parent_folder() -> dict[str, object]:
    return {"id": 9, "name": "private-parent-folder"}


def test_source_reduces_bound_folder_and_acl_without_product_selectors() -> None:
    source = FortiPamAccessDomainProjectionSource(
        FolderTransport([_parent_folder(), _folder()]), Resolver(_binding())
    )

    observations = source.observe(
        _draft(), AuthenticatedRequester("projection-requester01", "operator")
    )

    assert [item.object_class for item in observations] == [
        ObjectClass.PUBLIC_FOLDER,
        ObjectClass.ACCESS_GRANT,
    ]
    assert dict(observations[0].fields) == {
        "enabled": True,
        "exists": True,
        "owner_ref": "projection-test-owner",
    }
    assert dict(observations[1].fields) == {
        "exists": True,
        "permission": "use",
        "subject_class": "group",
        "subject_ref": "projection-group-ref01",
    }
    rendered = repr([item.as_dict() for item in observations])
    assert "private-product-folder" not in rendered
    assert "private-owner-name" not in rendered
    assert "private-group-name" not in rendered
    assert "sensitive-extra" not in rendered


def test_source_builds_fresh_safe_unregistered_authoritative_projections() -> None:
    source = FortiPamAccessDomainProjectionSource(
        FolderTransport([_parent_folder(), _folder()]), Resolver(_binding())
    )

    projections = source.project(
        _draft(),
        AuthenticatedRequester("projection-requester01", "operator"),
        now_epoch=1_800_000_000,
    )

    assert all(item.contract.contract_id == SOURCE_CONTRACT for item in projections)
    assert all(item.contract.source_ref == SOURCE_REF for item in projections)
    assert all(item.authoritative and item.complete for item in projections)
    assert all(not item.c3_included for item in projections)
    assert all(not item.raw_response_included for item in projections)
    assert all(item.fresh_until == 1_800_000_300 for item in projections)


def test_absent_bound_folder_produces_only_absence_observations() -> None:
    source = FortiPamAccessDomainProjectionSource(
        FolderTransport([_parent_folder()]), Resolver(_binding())
    )

    observations = source.observe(
        _draft(), AuthenticatedRequester("projection-requester01", "operator")
    )

    assert all(dict(item.fields) == {"exists": False} for item in observations)


def test_source_requires_the_bound_parent_and_scopes_duplicate_names_to_it() -> None:
    requester = AuthenticatedRequester("projection-requester01", "operator")
    with pytest.raises(AccessDomainProjectionSourceError):
        FortiPamAccessDomainProjectionSource(
            FolderTransport([_folder()]), Resolver(_binding())
        ).observe(_draft(), requester)

    other_parent = {**_folder(), "id": 18, "parent-folder": 10}
    observations = FortiPamAccessDomainProjectionSource(
        FolderTransport([_parent_folder(), other_parent, _folder()]),
        Resolver(_binding()),
    ).observe(_draft(), requester)
    assert dict(observations[0].fields)["exists"] is True


def test_ambiguous_or_unmapped_product_state_fails_closed() -> None:
    requester = AuthenticatedRequester("projection-requester01", "operator")
    with pytest.raises(AccessDomainProjectionSourceError):
        FortiPamAccessDomainProjectionSource(
            FolderTransport([_parent_folder(), _folder(), _folder()]), Resolver(_binding())
        ).observe(_draft(), requester)
    with pytest.raises(AccessDomainProjectionSourceError):
        FortiPamAccessDomainProjectionSource(
            FolderTransport([_parent_folder(), _folder(group_folder_permission="Edit")]),
            Resolver(_binding()),
        ).observe(_draft(), requester)


def test_source_backed_host_requires_a_real_reference_authority(
    tmp_path: Path,
) -> None:
    with pytest.raises(V4RuntimeHostError, match="requires a Reference Authority"):
        access_domain_v4_plan_host_factory(
            V4SyntheticHostSettings(
                tmp_path / "planning.sqlite3",
                tmp_path / "planning.hmac",
            ),
            folder_transport=FolderTransport([]),
            binding_resolver=Resolver(_binding()),
        )


def test_owner_only_binding_resolver_binds_requester_environment_and_scope(
    tmp_path: Path,
) -> None:
    requester = AuthenticatedRequester("projection-requester01", "operator")
    draft = _draft()
    binding_path = tmp_path / "access-domain-binding.json"
    binding_path.write_text(
        json.dumps(
            {
                "contract": SOURCE_CONTRACT,
                "version": SOURCE_VERSION,
                "requester_digest": requester.digest,
                "environment_ref": draft.environment_ref,
                "scope_ref": draft.scope_ref,
                "folder_object_ref": "projection-folder-object",
                "folder_name": "private-product-folder",
                "parent_folder_id": 9,
                "owner_ref": draft.owner_ref,
                "owner_principal_name": "private-owner-name",
                "owner_subject_class": "user",
                "acl_relations": [
                    {
                        "object_ref": "projection-grant-object1",
                        "subject_ref": "projection-group-ref01",
                        "subject_class": "group",
                        "principal_name": "private-group-name",
                        "permission": "use",
                        "folder_permission": "view",
                        "secret_permission": "view",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    binding_path.chmod(0o600)
    resolver = OwnerOnlyAccessDomainBindingResolver(binding_path)

    binding = resolver.resolve(draft, requester)

    assert binding.folder_object_ref == "projection-folder-object"
    assert binding.parent_folder_id == 9
    assert binding.acl_relations[0].subject_ref == "projection-group-ref01"
    with pytest.raises(AccessDomainProjectionSourceError):
        resolver.resolve(
            draft,
            AuthenticatedRequester("different-requester01", "operator"),
        )
    binding_path.chmod(0o644)
    with pytest.raises(AccessDomainProjectionSourceError):
        resolver.resolve(draft, requester)
    binding_path.chmod(0o600)
    symlink_path = tmp_path / "access-domain-binding-link.json"
    symlink_path.symlink_to(binding_path)
    with pytest.raises(AccessDomainProjectionSourceError):
        OwnerOnlyAccessDomainBindingResolver(symlink_path).resolve(draft, requester)


def test_source_backed_host_runs_a_sanitized_end_to_end_preview(
    tmp_path: Path,
) -> None:
    now = 1_800_000_000
    state = tmp_path / "state"
    oauth = tmp_path / "oauth"
    state.mkdir(mode=0o700)
    oauth.mkdir(mode=0o700)
    requester = AuthenticatedRequester("a" * 64, "operator")
    binding_path = state / "access-domain-binding.json"
    binding_path.write_text(
        json.dumps(
            {
                "contract": SOURCE_CONTRACT,
                "version": SOURCE_VERSION,
                "requester_digest": requester.digest,
                "environment_ref": "synthetic-lab-environment",
                "scope_ref": "synthetic-access-scope",
                "folder_object_ref": "synthetic-public-folder-reference",
                "folder_name": "private-product-folder",
                "parent_folder_id": 9,
                "owner_ref": "synthetic-owner-reference",
                "owner_principal_name": "private-owner-name",
                "owner_subject_class": "user",
                "acl_relations": [
                    {
                        "object_ref": "synthetic-access-grant-reference",
                        "subject_ref": "synthetic-group-reference",
                        "subject_class": "group",
                        "principal_name": "private-group-name",
                        "permission": "use",
                        "folder_permission": "view",
                        "secret_permission": "view",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    binding_path.chmod(0o600)

    def owner_file(name: str, value: bytes) -> Path:
        path = state / name
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    planning_key = owner_file("planning.hmac", b"p" * 32)
    reference_key = owner_file("reference.hmac", b"r" * 32)
    confirmation_key = owner_file("confirmation.hmac", b"c" * 32)
    receipt_key = owner_file("receipt.hmac", b"e" * 32)
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(
                "correct-horse-battery-staple",
                salt=b"0123456789abcdef",
            ),
        )
    )
    settings = V4SyntheticHostSettings(
        state / "planning.sqlite3",
        planning_key,
        reference_authority=V4PersistentReferenceAuthoritySettings(
            state / "reference.sqlite3",
            reference_key,
        ),
        host_mode="source-backed-access-domain",
        access_domain_binding_path=binding_path,
    )
    components = access_domain_v4_plan_host_factory(
        settings,
        folder_transport=FolderTransport([_parent_folder(), _folder()]),
        binding_resolver=OwnerOnlyAccessDomainBindingResolver(binding_path),
        clock=lambda: now,
    )(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            confirmation_key,
            receipt_key,
        ),
    )
    assert components.access_domain_projection_source is not None
    authority = components.reference_authority
    assert authority is not None
    issue_synthetic_reference_grants(
        authority,
        requester_digest=requester.digest,
        expires_at=now + 300,
        now_epoch=now,
    )
    authority.issue_many(
        ((SOURCE_REF, "projection_source"),),
        requester_digest=requester.digest,
        environment_ref="synthetic-lab-environment",
        scope_ref="synthetic-access-scope",
        expires_at=now + 300,
        now_epoch=now,
    )

    preview = components.plan_services.preview(
        V4_SYNTHETIC_SCHEME_REF,
        V4PlanningPrincipal(requester, "b" * 64),
    )

    assert preview["state"] == "awaiting_confirmation"
    assert preview["current_state_digest"]
    assert preview["proposed_changes_digest"]
    assert preview["expected_state_digest"]
    status = components.plan_services.status()
    assert status["projection_mode"] == "source_backed"
    assert status["projection_contract_registered"] is True
    assert status["device_access"] is True
    assert "live_projection_unbound" not in status["blocker_codes"]
    rendered = json.dumps(preview, sort_keys=True)
    assert "private-product-folder" not in rendered
    assert "private-owner-name" not in rendered
    assert "private-group-name" not in rendered
