from __future__ import annotations

import copy
from dataclasses import replace
import re

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from fortipam_mcp.access_domain_action_sequence import (
    AccessDomainFixedActionSequenceResolver,
)
from fortipam_mcp.access_domain_projection_source import (
    AccessDomainFolderBinding,
    BoundAclRelation,
    FortiPamAccessDomainProjectionSource,
    SOURCE_REF,
)
from fortipam_mcp.local_oauth import (
    LocalOAuthProvider,
    LocalOAuthSettings,
    hash_local_password,
)
from fortipam_mcp.folder_acl_live_workflow import FolderAclGrantLiveWorkflow
from fortipam_mcp.folder_acl_mcp_action import ProtectedFolderAclMcpAction
from fortipam_mcp.onboarding_action_coordinator import OnboardingActionCoordinator
from fortipam_mcp.onboarding_action_coordinator import OnboardingActionCoordinatorError
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.v4_confirmation_http import V4ConfirmationSettings
from fortipam_mcp.v4_runtime_host import (
    V4PersistentReferenceAuthoritySettings,
    V4PersistentSchemeDraftAuthoritySettings,
    V4SyntheticHostSettings,
    access_domain_v4_plan_host_factory,
)
from test_access_domain_projection_source import FolderTransport, Resolver, _draft, _folder, _parent_folder
from test_v4_m3 import _plan, _requester
from v4_planning import ChangeKind, DesiredObject, ObjectClass, canonical_digest


PLAN_REF = "prepared-plan-ref0001"
DRAFT_REF = "access-domain-draft-ref01"


def _relation(*, subject_class: str = "user") -> BoundAclRelation:
    return BoundAclRelation(
        object_ref="projection-grant-object1",
        subject_ref="projection-group-ref01",
        subject_class=subject_class,
        principal_name="private-requested-user",
        permission="use",
        folder_permission="view",
        secret_permission="view",
    )


def _binding(relation: BoundAclRelation) -> AccessDomainFolderBinding:
    return AccessDomainFolderBinding(
        folder_object_ref="projection-folder-object",
        folder_name="private-product-folder",
        parent_folder_id=9,
        owner_ref="projection-test-owner",
        owner_principal_name="private-owner-name",
        owner_subject_class="user",
        acl_relations=(relation,),
    )


def _context(relation: BoundAclRelation):
    requester = _requester()
    draft = _draft()
    desired = list(draft.desired_objects)
    desired[1] = replace(
        desired[1],
        desired_fields=(
            ("permission", relation.permission),
            ("subject_class", relation.subject_class),
            ("subject_ref", relation.subject_ref),
        ),
    )
    draft = replace(draft, desired_objects=tuple(desired))
    base = _plan(requester)
    line = replace(
        base.lines[0],
        target_ref=relation.object_ref,
        target_class=ObjectClass.ACCESS_GRANT,
        change_kind=ChangeKind.CREATE,
    )
    content = dict(base.canonical_content())
    content["lines"] = [line.as_dict()]
    plan = replace(base, lines=(line,), plan_digest=canonical_digest(content))
    return requester, draft, plan


def _new_folder_context(relation: BoundAclRelation):
    requester, draft, _existing_plan = _context(relation)
    base = _plan(requester)
    folder_line = replace(
        base.lines[0],
        line_ref="folder-create-line-ref01",
        target_ref="projection-folder-object",
        target_class=ObjectClass.PUBLIC_FOLDER,
        change_kind=ChangeKind.CREATE,
        depends_on=(),
    )
    acl_line = replace(
        base.lines[0],
        line_ref="folder-acl-line-ref0001",
        target_ref=relation.object_ref,
        target_class=ObjectClass.ACCESS_GRANT,
        change_kind=ChangeKind.CREATE,
        depends_on=(folder_line.line_ref,),
    )
    content = dict(base.canonical_content())
    content["lines"] = [folder_line.as_dict(), acl_line.as_dict()]
    plan = replace(
        base,
        lines=(folder_line, acl_line),
        plan_digest=canonical_digest(content),
    )
    return requester, draft, plan


class _Services:
    def __init__(self, relation: BoundAclRelation) -> None:
        self.requester, self.draft, self.plan = _context(relation)
        self.calls: list[str] = []

    def resolve_execution_context(self, plan_ref, draft_ref, principal):
        assert plan_ref == PLAN_REF
        assert draft_ref == DRAFT_REF
        assert principal.requester == self.requester
        self.calls.append("resolve")
        return self.plan, self.draft

    def evaluate_pre_write(self, plan_ref, draft_ref, principal):
        del plan_ref, draft_ref, principal
        self.calls.append("pre")
        return {"status": "match"}

    def evaluate_post_write(self, plan_ref, draft_ref, principal):
        del plan_ref, draft_ref, principal
        self.calls.append("post")
        return {"status": "expected_state_matches"}


class _NewFolderServices(_Services):
    def __init__(self, relation: BoundAclRelation) -> None:
        self.requester, self.draft, self.plan = _new_folder_context(relation)
        self.calls: list[str] = []


class _FullFolderTransport(FolderTransport):
    def __init__(self) -> None:
        super().__init__(
            [
                _parent_folder(),
                {
                    "id": 17,
                    "name": "private-product-folder",
                    "parent-folder": 9,
                    "folder-type": "public",
                    "secret-policy": "default",
                    "inherit-policy": "enable",
                    "inherit-permission": "disable",
                    "inherit-folder-ztna": "enable",
                    "ztna-ems-tag": [],
                    "ztna-tags-match-logic": "or",
                    "user-permission": [
                        {
                            "id": 7,
                            "user-name": [{"name": "private-owner-name"}],
                            "folder-permission": "owner",
                            "secret-permission": "owner",
                        }
                    ],
                    "group-permission": [
                        {
                            "id": 8,
                            "group-name": [{"name": "private-existing-group"}],
                            "folder-permission": "view",
                            "secret-permission": "view",
                        }
                    ],
                },
            ]
        )
        self.update_calls: list[dict[str, object]] = []

    def read_folder(self, folder_id: int) -> dict[str, object]:
        return copy.deepcopy(next(record for record in self.records if record["id"] == folder_id))

    def update_folder(
        self,
        folder_id: int,
        body: dict[str, object],
    ) -> dict[str, object]:
        rendered = copy.deepcopy(body)
        self.update_calls.append(rendered)
        index = next(
            index for index, record in enumerate(self.records) if record["id"] == folder_id
        )
        self.records[index] = rendered
        return {"ok": True}


class _SourceBackedServices:
    def __init__(self, requester, draft, plan, source) -> None:
        self.requester = requester
        self.draft = draft
        self.plan = plan
        self.source = source

    def resolve_execution_context(self, plan_ref, draft_ref, principal):
        assert plan_ref == PLAN_REF
        assert draft_ref == DRAFT_REF
        assert principal.requester == self.requester
        return self.plan, self.draft

    def evaluate_pre_write(self, plan_ref, draft_ref, principal):
        del plan_ref, draft_ref
        observations = self.source.observe(self.draft, principal.requester)
        assert [dict(item.fields)["exists"] for item in observations] == [
            True,
            False,
            False,
        ]
        return {"status": "match"}

    def evaluate_post_write(self, plan_ref, draft_ref, principal):
        del plan_ref, draft_ref
        observations = self.source.observe(self.draft, principal.requester)
        return {
            "status": (
                "expected_state_matches"
                if all(dict(item.fields)["exists"] is True for item in observations)
                else "mismatch"
            )
        }


def _relation_names(
    body: dict[str, object],
    relation_field: str,
    principal_field: str,
) -> set[str]:
    relations = body[relation_field]
    assert isinstance(relations, list)
    names: set[str] = set()
    for relation in relations:
        assert isinstance(relation, dict)
        principals = relation[principal_field]
        assert isinstance(principals, list)
        for principal in principals:
            assert isinstance(principal, dict)
            name = principal["name"]
            assert isinstance(name, str)
            names.add(name)
    return names


class _AclAction:
    def __init__(self, *, mismatch: bool = False) -> None:
        self.calls: list[str] = []
        self.mismatch = mismatch

    def preview(self, folder_id, username, folder_permission, secret_permission, principal):
        del principal
        self.calls.append("preview")
        rendered_username = "wrong-user" if self.mismatch else username
        return {
            "preview_ref": "folder-acl-preview-ref01",
            "device_write_executed": False,
            "Current State": {
                "selected_folder_id": folder_id,
                "requested_username": rendered_username,
                "requested_folder_permission": folder_permission,
                "requested_secret_permission": secret_permission,
                "folder_exists": True,
                "folder_scope": "public_child",
                "permission_inheritance": "disable",
                "requested_user_relation_present": False,
            },
            "Proposed Changes": {
                "operation": "grant_public_folder_user_acl",
                "folder_id": folder_id,
                "username": username,
                "folder_permission": folder_permission,
                "secret_permission": secret_permission,
                "permission_inheritance_after_change": "disable",
            },
            "Expected State": {
                "folder_exists": True,
                "folder_scope": "public_child",
                "permission_inheritance": "disable",
                "requested_username_relation_present": True,
                "requested_folder_permission_matches": True,
                "requested_secret_permission_matches": True,
                "effective_user_relations_preserved": True,
                "effective_group_relations_preserved": True,
            },
        }

    def confirm(self, preview_ref, principal):
        del principal
        assert preview_ref == "folder-acl-preview-ref01"
        self.calls.append("confirm")
        return {"authorization_ref": "folder-acl-authorization-ref01"}

    def execute(self, authorization_ref, principal):
        del principal
        assert authorization_ref == "folder-acl-authorization-ref01"
        self.calls.append("execute")
        return {"outcome": "succeeded", "verification": "verified"}


class _FolderAction:
    def __init__(self, transport: FolderTransport) -> None:
        self.transport = transport
        self.calls: list[str] = []

    def preview(self, folder_name, parent_folder_id, principal):
        del principal
        self.calls.append("preview")
        return {
            "preview_ref": "folder-create-preview-ref01",
            "device_write_executed": False,
            "Current State": {
                "selected_parent_folder_id": parent_folder_id,
                "requested_child_folder_name": folder_name,
                "parent_exists": True,
                "matching_child_exists": False,
            },
            "Proposed Changes": {
                "operation": "create_inherited_public_child_folder",
                "parent_folder_id": parent_folder_id,
                "folder_name": folder_name,
            },
            "Expected State": {
                "child_folder_name_matches": True,
                "matching_child_exists": True,
                "inherit_policy": "enable",
                "inherit_permission": "enable",
                "inherit_folder_ztna": "enable",
            },
        }

    def confirm(self, preview_ref, principal):
        del principal
        assert preview_ref == "folder-create-preview-ref01"
        self.calls.append("confirm")
        return {"authorization_ref": "folder-create-authorization-ref01"}

    def execute(self, authorization_ref, principal):
        del principal
        assert authorization_ref == "folder-create-authorization-ref01"
        self.calls.append("execute")
        self.transport.records.append(
            {
                "id": 17,
                "name": "private-product-folder",
                "parent-folder": 9,
                "folder-type": "public",
                "user-permission": [],
                "group-permission": [],
            }
        )
        return {"outcome": "succeeded", "verification": "verified"}


def _coordinator(relation: BoundAclRelation, action: _AclAction):
    services = _Services(relation)
    source = FortiPamAccessDomainProjectionSource(
        FolderTransport([_parent_folder(), _folder()]),
        Resolver(_binding(relation)),
    )
    resolver = AccessDomainFixedActionSequenceResolver(  # type: ignore[arg-type]
        services,
        source,
        action,
    )
    return services, OnboardingActionCoordinator(services, resolver)


def test_existing_access_domain_uses_scheme_confirmation_for_exact_acl_cpe() -> None:
    relation = _relation()
    action = _AclAction()
    services, coordinator = _coordinator(relation, action)
    result = coordinator.execute(
        PLAN_REF,
        DRAFT_REF,
        V4PlanningPrincipal(services.requester, "a" * 64),
    )

    assert result.outcome == "succeeded", result.as_dict()
    assert action.calls == ["preview", "confirm", "execute"]
    assert services.calls == ["pre", "resolve", "post"]


def test_action_preview_mismatch_stops_before_confirmation() -> None:
    relation = _relation()
    action = _AclAction(mismatch=True)
    services, coordinator = _coordinator(relation, action)
    result = coordinator.execute(
        PLAN_REF,
        DRAFT_REF,
        V4PlanningPrincipal(services.requester, "a" * 64),
    )

    assert result.outcome == "reconciliation_required"
    assert action.calls == ["preview"]
    assert services.calls == ["pre", "resolve"]


def test_group_grant_remains_unbound_instead_of_using_the_user_action() -> None:
    relation = _relation(subject_class="group")
    action = _AclAction()
    services, coordinator = _coordinator(relation, action)
    with pytest.raises(OnboardingActionCoordinatorError, match="unbound fixed action"):
        coordinator.execute(
            PLAN_REF,
            DRAFT_REF,
            V4PlanningPrincipal(services.requester, "a" * 64),
        )
    assert action.calls == []


def test_source_backed_group_grant_follows_scheme_dependency_and_preserves_acl() -> None:
    requester = _requester()
    user_relation = BoundAclRelation(
        object_ref="projection-user-grant01",
        subject_ref="projection-user-ref0001",
        subject_class="user",
        principal_name="private-requested-user",
        permission="use",
        folder_permission="view",
        secret_permission="view",
    )
    group_relation = BoundAclRelation(
        object_ref="projection-group-grant1",
        subject_ref="projection-group-ref01",
        subject_class="group",
        principal_name="private-requested-group",
        permission="use",
        folder_permission="view",
        secret_permission="view",
    )
    draft = replace(
        _draft(),
        desired_objects=(
            _draft().desired_objects[0],
            DesiredObject(
                object_ref=user_relation.object_ref,
                object_class=ObjectClass.ACCESS_GRANT,
                desired_exists=True,
                desired_fields=(
                    ("permission", user_relation.permission),
                    ("subject_class", user_relation.subject_class),
                    ("subject_ref", user_relation.subject_ref),
                ),
            ),
            DesiredObject(
                object_ref=group_relation.object_ref,
                object_class=ObjectClass.ACCESS_GRANT,
                desired_exists=True,
                desired_fields=(
                    ("permission", group_relation.permission),
                    ("subject_class", group_relation.subject_class),
                    ("subject_ref", group_relation.subject_ref),
                ),
            ),
        ),
    )
    binding = replace(
        _binding(user_relation),
        acl_relations=(user_relation, group_relation),
    )
    transport = _FullFolderTransport()
    source = FortiPamAccessDomainProjectionSource(transport, Resolver(binding))
    base = _plan(requester)
    user_line = replace(
        base.lines[0],
        line_ref="user-grant-line-ref0001",
        target_ref=user_relation.object_ref,
        target_class=ObjectClass.ACCESS_GRANT,
        change_kind=ChangeKind.CREATE,
        depends_on=(),
    )
    group_line = replace(
        base.lines[0],
        line_ref="group-grant-line-ref001",
        target_ref=group_relation.object_ref,
        target_class=ObjectClass.ACCESS_GRANT,
        change_kind=ChangeKind.CREATE,
        depends_on=(user_line.line_ref,),
    )
    content = dict(base.canonical_content())
    content["lines"] = [group_line.as_dict(), user_line.as_dict()]
    plan = replace(
        base,
        lines=(group_line, user_line),
        plan_digest=canonical_digest(content),
    )
    services = _SourceBackedServices(requester, draft, plan, source)
    action = ProtectedFolderAclMcpAction(FolderAclGrantLiveWorkflow(transport))
    resolver = AccessDomainFixedActionSequenceResolver(  # type: ignore[arg-type]
        services,
        source,
        action,
        group_acl_action=action,
    )

    result = OnboardingActionCoordinator(services, resolver).execute(
        PLAN_REF,
        DRAFT_REF,
        V4PlanningPrincipal(requester, "a" * 64),
    )

    assert result.outcome == "succeeded", result.as_dict()
    assert result.completed_line_refs == (user_line.line_ref, group_line.line_ref)
    assert len(transport.update_calls) == 2
    first_body, final_body = transport.update_calls
    assert _relation_names(first_body, "user-permission", "user-name") == {
        "private-owner-name",
        user_relation.principal_name,
    }
    assert _relation_names(first_body, "group-permission", "group-name") == {
        "private-existing-group"
    }
    assert _relation_names(final_body, "user-permission", "user-name") == {
        "private-owner-name",
        user_relation.principal_name,
    }
    assert _relation_names(final_body, "group-permission", "group-name") == {
        "private-existing-group",
        group_relation.principal_name,
    }
    assert {
        name: final_body[name]
        for name in (
            "inherit-folder-ztna",
            "ztna-ems-tag",
            "ztna-tags-match-logic",
        )
    } == {
        "inherit-folder-ztna": "enable",
        "ztna-ems-tag": [],
        "ztna-tags-match-logic": "or",
    }
    assert all(
        dict(item.fields)["exists"] is True
        for item in source.observe(draft, requester)
    )


def test_new_inherited_folder_runs_before_acl_materializes_owner_and_user() -> None:
    relation = _relation()
    services = _NewFolderServices(relation)
    transport = FolderTransport([_parent_folder()])
    source = FortiPamAccessDomainProjectionSource(
        transport,
        Resolver(_binding(relation)),
    )
    folder_action = _FolderAction(transport)
    acl_action = _MutatingAclAction(transport)
    resolver = AccessDomainFixedActionSequenceResolver(  # type: ignore[arg-type]
        services,
        source,
        acl_action,
        folder_action,
    )

    result = OnboardingActionCoordinator(services, resolver).execute(
        PLAN_REF,
        DRAFT_REF,
        V4PlanningPrincipal(services.requester, "a" * 64),
    )

    assert result.outcome == "succeeded"
    assert folder_action.calls == ["preview", "confirm", "execute"]
    assert acl_action.calls == [
        "preview",
        "confirm",
        "execute",
        "preview",
        "confirm",
        "execute",
    ]
    observations = source.observe(services.draft, services.requester)
    assert all(dict(item.fields)["exists"] is True for item in observations)


class _Clock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class _MutatingAclAction(_AclAction):
    def __init__(self, transport: FolderTransport) -> None:
        super().__init__()
        self.transport = transport
        self.pending: tuple[str, str, str] | None = None

    def preview(self, folder_id, username, folder_permission, secret_permission, principal):
        self.pending = (username, folder_permission, secret_permission)
        result = super().preview(
            folder_id,
            username,
            folder_permission,
            secret_permission,
            principal,
        )
        if username == "private-owner-name":
            current = result["Current State"]
            assert isinstance(current, dict)
            current["requested_user_relation_present"] = True
        return result

    def execute(self, authorization_ref, principal):
        result = super().execute(authorization_ref, principal)
        assert self.pending is not None
        username, folder_permission, secret_permission = self.pending
        folder = next(item for item in self.transport.records if item.get("id") == 17)
        users = folder["user-permission"]
        assert isinstance(users, list)
        users.append(
            {
                "user-name": [{"name": username}],
                "folder-permission": folder_permission.title(),
                "secret-permission": secret_permission.title(),
            }
        )
        return result


def test_persistent_host_runs_one_confirmation_through_folder_and_acl_readback(
    tmp_path,
) -> None:
    now = 1_900_000_000
    clock = _Clock(now)
    state = tmp_path / "state"
    oauth = tmp_path / "oauth"
    state.mkdir(mode=0o700)
    oauth.mkdir(mode=0o700)

    def owner_file(name: str, value: bytes):
        path = state / name
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    requester = _requester()
    relation = _relation()
    draft = _context(relation)[1]
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
    transport = FolderTransport([_parent_folder()])
    settings = V4SyntheticHostSettings(
        state / "planning.sqlite3",
        owner_file("planning.hmac", b"p" * 32),
        reference_authority=V4PersistentReferenceAuthoritySettings(
            state / "reference.sqlite3",
            owner_file("reference.hmac", b"r" * 32),
        ),
        scheme_draft_authority=V4PersistentSchemeDraftAuthoritySettings(
            state / "draft.sqlite3",
            owner_file("draft.hmac", b"d" * 32),
        ),
    )
    components = access_domain_v4_plan_host_factory(
        settings,
        folder_transport=transport,
        binding_resolver=Resolver(_binding(relation)),
        clock=clock,
    )(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            owner_file("confirmation.hmac", b"c" * 32),
            owner_file("receipt.hmac", b"e" * 32),
        ),
    )
    draft_authority = components.scheme_draft_authority
    reference_authority = components.reference_authority
    assert draft_authority is not None
    assert reference_authority is not None
    draft_ref = draft_authority.issue(
        draft,
        requester,
        expires_at=now + 300,
        now_epoch=now,
    )
    bindings = {
        (SOURCE_REF, "projection_source"),
        (draft.environment_ref, "environment"),
        (draft.scope_ref, "scope"),
        (draft.owner_ref, "owner"),
        (draft.audience_ref, "audience"),
        *((value, "evidence") for value in draft.evidence_refs),
    }
    object_kinds = {
        ObjectClass.PUBLIC_FOLDER: "public_folder",
        ObjectClass.ACCESS_GRANT: "access_grant",
    }
    for desired in draft.desired_objects:
        bindings.add((desired.object_ref, f"object_{object_kinds[desired.object_class]}"))
        bindings.update(
            (value, f"field_{name}")
            for name, value in desired.desired_fields
            if name.endswith("_ref") and isinstance(value, str)
        )
    reference_authority.issue_many(
        tuple(sorted(bindings)),
        requester_digest=requester.digest,
        environment_ref=draft.environment_ref,
        scope_ref=draft.scope_ref,
        expires_at=now + 300,
        now_epoch=now,
    )
    principal = V4PlanningPrincipal(requester, "b" * 64)
    preview = components.plan_services.preview(draft_ref, principal)
    confirmation_path = str(preview["confirmation_url"]).removeprefix(
        "https://mcp.example.com"
    )
    with TestClient(
        Starlette(routes=components.confirmation_service.routes()),
        base_url="https://mcp.example.com",
    ) as client:
        page = client.get(confirmation_path)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert csrf is not None
        clock.value = now + 1
        review = client.post(
            confirmation_path,
            data={
                "csrf_token": csrf.group(1),
                "username": "operator",
                "password": "correct-horse-battery-staple",
                "action": "review",
            },
            headers={"origin": "https://mcp.example.com"},
        )
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', review.text)
        assert csrf is not None
        clock.value = now + 2
        assert client.post(
            confirmation_path,
            data={"csrf_token": csrf.group(1), "action": "affirm"},
            headers={"origin": "https://mcp.example.com"},
        ).status_code == 200

    clock.value = now + 3
    confirmation = components.plan_services.confirm(
        str(preview["summary_ref"]),
        int(preview["revision"]),
        principal,
    )
    clock.value = now + 4
    plan = components.plan_services.prepare(
        str(preview["summary_ref"]),
        str(confirmation["confirmation_ref"]),
        principal,
    )
    coordinator = components.bind_access_domain_action_coordinator(
        _MutatingAclAction(transport),
        _FolderAction(transport),
    )
    clock.value = now + 5
    result = coordinator.execute(str(plan["plan_ref"]), draft_ref, principal)

    assert result.outcome == "succeeded", result.as_dict()
    assert result.pre_write_status == "match"
    assert result.post_write_status == "expected_state_matches"
