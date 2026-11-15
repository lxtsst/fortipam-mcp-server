"""Protected binding from one confirmed Access Domain Scheme to fixed ACL actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast, Mapping, Protocol

from v4_planning import (
    ChangeKind,
    ObjectClass,
    PlanLine,
    PreparedPlan,
    SchemeDraft,
    SchemeId,
)

from .access_domain_projection_source import (
    AccessDomainFolderBinding,
    BoundAclRelation,
    FortiPamAccessDomainProjectionSource,
)
from .onboarding_action_coordinator import (
    BoundFixedActionRunner,
    OnboardingActionCoordinatorError,
    ResolvedFixedActionSequence,
)
from .v4_plan_runtime import OAuthBoundV4PlanServices, V4PlanningPrincipal


class FixedFolderAclAction(Protocol):
    """Existing requester-bound fixed Folder ACL C/P/E action."""

    def preview(
        self,
        folder_id: int,
        username: str,
        folder_permission: str,
        secret_permission: str,
        principal: Any,
    ) -> dict[str, object]: ...

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]: ...

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]: ...


class FixedFolderGroupAclAction(Protocol):
    """Internal requester-bound group grant using the existing ACL state machine."""

    def preview_group(
        self,
        folder_id: int,
        group_name: str,
        folder_permission: str,
        secret_permission: str,
        principal: Any,
    ) -> dict[str, object]: ...

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]: ...

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]: ...


class FixedChildFolderAction(Protocol):
    """Existing requester-bound inherited child-Folder C/P/E action."""

    def preview(
        self,
        folder_name: str,
        parent_folder_id: int,
        principal: Any,
    ) -> dict[str, object]: ...

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]: ...

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class _BoundChildFolderRunner:
    line_ref: str
    depends_on: tuple[str, ...]
    binding: AccessDomainFolderBinding
    projection_source: FortiPamAccessDomainProjectionSource
    draft: SchemeDraft
    folder_action: FixedChildFolderAction
    acl_action: FixedFolderAclAction
    principal: V4PlanningPrincipal

    def execute_bound(self) -> Mapping[str, object]:
        preview = self.folder_action.preview(
            self.binding.folder_name,
            self.binding.parent_folder_id,
            self.principal,
        )
        _validate_folder_preview(
            preview,
            self.binding.folder_name,
            self.binding.parent_folder_id,
        )
        preview_ref = preview.get("preview_ref")
        if not isinstance(preview_ref, str) or not preview_ref:
            raise OnboardingActionCoordinatorError(
                "Fixed Folder preview did not return an opaque reference."
            )
        confirmation = self.folder_action.confirm(preview_ref, self.principal)
        authorization_ref = confirmation.get("authorization_ref")
        if not isinstance(authorization_ref, str) or not authorization_ref:
            raise OnboardingActionCoordinatorError(
                "Fixed Folder confirmation did not return an authorization reference."
            )
        created = self.folder_action.execute(authorization_ref, self.principal)
        if not _verified_success(created):
            return created
        folder_id = self.projection_source.resolve_existing_folder(
            self.draft,
            self.principal.requester,
        ).folder_id
        owner_relation = BoundAclRelation(
            object_ref=self.binding.folder_object_ref,
            subject_ref=self.binding.owner_ref,
            subject_class="user",
            principal_name=self.binding.owner_principal_name,
            permission="manage",
            folder_permission="owner",
            secret_permission="owner",
        )
        return _execute_acl_grant(
            self.acl_action,
            folder_id,
            owner_relation,
            self.principal,
            allow_existing=True,
        )


@dataclass(frozen=True, slots=True)
class _BoundAclRunner:
    line_ref: str
    depends_on: tuple[str, ...]
    relation: BoundAclRelation
    projection_source: FortiPamAccessDomainProjectionSource
    draft: SchemeDraft
    action: FixedFolderAclAction | FixedFolderGroupAclAction
    principal: V4PlanningPrincipal
    allow_existing: bool = False

    def execute_bound(self) -> Mapping[str, object]:
        folder_id = self.projection_source.resolve_existing_folder(
            self.draft,
            self.principal.requester,
        ).folder_id
        return _execute_acl_grant(
            self.action,
            folder_id,
            self.relation,
            self.principal,
            allow_existing=self.allow_existing,
        )


class AccessDomainFixedActionSequenceResolver:
    """Resolve an inherited child create and its missing direct ACL grants.

    The Folder action alone does not satisfy the ownership anchor. Its dependent
    ACL action must materialize the inherited effective owner relation while
    adding declared grants and disabling permission inheritance. Group grants
    require an explicitly injected internal action; Role grants remain unavailable.
    """

    def __init__(
        self,
        plan_services: OAuthBoundV4PlanServices,
        projection_source: FortiPamAccessDomainProjectionSource,
        acl_action: FixedFolderAclAction,
        folder_action: FixedChildFolderAction | None = None,
        group_acl_action: FixedFolderGroupAclAction | None = None,
    ) -> None:
        self._plan_services = plan_services
        self._projection_source = projection_source
        self._acl_action = acl_action
        self._folder_action = folder_action
        self._group_acl_action = group_acl_action

    def resolve(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> ResolvedFixedActionSequence:
        try:
            plan, draft = self._plan_services.resolve_execution_context(
                plan_ref,
                scheme_draft_ref,
                principal,
            )
            if plan.scheme_id is not SchemeId.ACCESS_DOMAIN:
                raise OnboardingActionCoordinatorError(
                    "The fixed action sequence is not an Access Domain Scheme."
                )
            runners = self.bind_prepared_runners(
                plan,
                draft,
                principal,
                plan.lines,
            )
        except OnboardingActionCoordinatorError:
            raise
        except Exception as exc:
            raise OnboardingActionCoordinatorError(
                "Access Domain fixed action sequence is unavailable."
            ) from exc
        return ResolvedFixedActionSequence(
            plan.plan_ref,
            plan.requester_digest,
            tuple(runners),
        )

    def bind_prepared_runners(
        self,
        plan: PreparedPlan,
        draft: SchemeDraft,
        principal: V4PlanningPrincipal,
        lines: tuple[PlanLine, ...],
    ) -> tuple[BoundFixedActionRunner, ...]:
        """Bind exact Folder/grant lines from an already confirmed parent plan."""

        try:
            resolved = self._projection_source.resolve_bound_folder(
                draft,
                principal.requester,
            )
            if (
                plan.requester_digest != principal.requester.digest
                or resolved.binding.owner_subject_class != "user"
            ):
                raise OnboardingActionCoordinatorError(
                    "Access Domain plan contains an unbound fixed action."
                )
            relations = {
                relation.object_ref: relation
                for relation in resolved.binding.acl_relations
            }
            desired = {item.object_ref: item for item in draft.desired_objects}
            runners: list[BoundFixedActionRunner] = []
            folder_line_ref: str | None = None
            for line in lines:
                target = desired.get(line.target_ref)
                if line.target_class is ObjectClass.PUBLIC_FOLDER:
                    if (
                        self._folder_action is None
                        or resolved.folder_id is not None
                        or folder_line_ref is not None
                        or line.target_ref != resolved.binding.folder_object_ref
                        or line.change_kind is not ChangeKind.CREATE
                        or line.depends_on
                        or target is None
                        or target.object_class is not ObjectClass.PUBLIC_FOLDER
                        or not target.desired_exists
                        or dict(target.desired_fields)
                        != {
                            "enabled": True,
                            "owner_ref": resolved.binding.owner_ref,
                        }
                    ):
                        raise OnboardingActionCoordinatorError(
                            "Access Domain plan contains an unbound fixed action."
                        )
                    folder_line_ref = line.line_ref
                    runners.append(
                        _BoundChildFolderRunner(
                            line.line_ref,
                            line.depends_on,
                            resolved.binding,
                            self._projection_source,
                            draft,
                            self._folder_action,
                            self._acl_action,
                            principal,
                        )
                    )
                    continue
                relation = relations.get(line.target_ref)
                if (
                    line.target_class is not ObjectClass.ACCESS_GRANT
                    or line.change_kind is not ChangeKind.CREATE
                    or relation is None
                    or relation.subject_class not in {"user", "group"}
                    or (
                        relation.subject_class == "group"
                        and self._group_acl_action is None
                    )
                    or target is None
                    or target.object_class is not ObjectClass.ACCESS_GRANT
                    or not target.desired_exists
                    or dict(target.desired_fields)
                    != {
                        "permission": relation.permission,
                        "subject_class": relation.subject_class,
                        "subject_ref": relation.subject_ref,
                    }
                ):
                    raise OnboardingActionCoordinatorError(
                        "Access Domain plan contains an unbound fixed action."
                    )
                action: FixedFolderAclAction | FixedFolderGroupAclAction = (
                    self._acl_action
                    if relation.subject_class == "user"
                    else cast(FixedFolderGroupAclAction, self._group_acl_action)
                )
                runners.append(
                    _BoundAclRunner(
                        line.line_ref,
                        line.depends_on,
                        relation,
                        self._projection_source,
                        draft,
                        action,
                        principal,
                        resolved.folder_id is None
                        and relation.subject_class == "user",
                    )
                )
            if resolved.folder_id is None:
                if folder_line_ref is None or len(runners) < 2 or any(
                    runner.line_ref != folder_line_ref
                    and runner.depends_on != (folder_line_ref,)
                    for runner in runners
                ):
                    raise OnboardingActionCoordinatorError(
                        "Access Domain plan contains an unbound fixed action."
                    )
            elif folder_line_ref is not None or any(
                dependency not in {item.line_ref for item in runners}
                for runner in runners
                for dependency in runner.depends_on
            ):
                raise OnboardingActionCoordinatorError(
                    "Access Domain plan contains an unbound fixed action."
                )
            return tuple(runners)
        except OnboardingActionCoordinatorError:
            raise
        except Exception as exc:
            raise OnboardingActionCoordinatorError(
                "Access Domain fixed action sequence is unavailable."
            ) from exc

    def bind_existing_grant_runners(
        self,
        plan: PreparedPlan,
        draft: SchemeDraft,
        principal: V4PlanningPrincipal,
        lines: tuple[PlanLine, ...],
    ) -> tuple[BoundFixedActionRunner, ...]:
        """Bind only missing grants for a source-verified existing Folder."""
        if any(line.depends_on for line in lines):
            raise OnboardingActionCoordinatorError(
                "Access Domain plan contains an unbound fixed action."
            )
        return self.bind_prepared_runners(plan, draft, principal, lines)


def _validate_folder_preview(
    preview: Mapping[str, object],
    folder_name: str,
    parent_folder_id: int,
) -> None:
    current = preview.get("Current State")
    proposed = preview.get("Proposed Changes")
    expected = preview.get("Expected State")
    if (
        preview.get("device_write_executed") is not False
        or not isinstance(current, Mapping)
        or not isinstance(proposed, Mapping)
        or not isinstance(expected, Mapping)
        or current.get("selected_parent_folder_id") != parent_folder_id
        or current.get("requested_child_folder_name") != folder_name
        or current.get("parent_exists") is not True
        or current.get("matching_child_exists") is not False
        or proposed.get("operation") != "create_inherited_public_child_folder"
        or proposed.get("parent_folder_id") != parent_folder_id
        or proposed.get("folder_name") != folder_name
        or expected.get("child_folder_name_matches") is not True
        or expected.get("matching_child_exists") is not True
        or expected.get("inherit_policy") != "enable"
        or expected.get("inherit_permission") != "enable"
        or expected.get("inherit_folder_ztna") != "enable"
    ):
        raise OnboardingActionCoordinatorError(
            "Fixed Folder preview does not match the protected Scheme placement."
        )


def _execute_acl_grant(
    action: FixedFolderAclAction | FixedFolderGroupAclAction,
    folder_id: int,
    relation: BoundAclRelation,
    principal: V4PlanningPrincipal,
    *,
    allow_existing: bool = False,
) -> Mapping[str, object]:
    if relation.subject_class == "user":
        preview = cast(FixedFolderAclAction, action).preview(
            folder_id,
            relation.principal_name,
            relation.folder_permission,
            relation.secret_permission,
            principal,
        )
    elif relation.subject_class == "group":
        preview = cast(FixedFolderGroupAclAction, action).preview_group(
            folder_id,
            relation.principal_name,
            relation.folder_permission,
            relation.secret_permission,
            principal,
        )
    else:
        raise OnboardingActionCoordinatorError(
            "Fixed ACL action supports only direct user or group grants."
        )
    _validate_acl_preview(
        preview,
        folder_id,
        relation,
        allow_existing=allow_existing,
    )
    preview_ref = preview.get("preview_ref")
    if not isinstance(preview_ref, str) or not preview_ref:
        raise OnboardingActionCoordinatorError(
            "Fixed ACL preview did not return an opaque reference."
        )
    confirmation = action.confirm(preview_ref, principal)
    authorization_ref = confirmation.get("authorization_ref")
    if not isinstance(authorization_ref, str) or not authorization_ref:
        raise OnboardingActionCoordinatorError(
            "Fixed ACL confirmation did not return an authorization reference."
        )
    return action.execute(authorization_ref, principal)


def _verified_success(result: Mapping[str, object]) -> bool:
    return result.get("outcome") == "succeeded" and result.get("verification") == "verified"


def _validate_acl_preview(
    preview: Mapping[str, object],
    folder_id: int,
    relation: BoundAclRelation,
    *,
    allow_existing: bool = False,
) -> None:
    current = preview.get("Current State")
    proposed = preview.get("Proposed Changes")
    expected = preview.get("Expected State")
    is_group = relation.subject_class == "group"
    subject_field = "requested_group_name" if is_group else "requested_username"
    relation_field = (
        "requested_group_relation_present"
        if is_group
        else "requested_user_relation_present"
    )
    operation = (
        "grant_public_folder_group_acl"
        if is_group
        else "grant_public_folder_user_acl"
    )
    proposed_subject_field = "group_name" if is_group else "username"
    if (
        preview.get("device_write_executed") is not False
        or not isinstance(current, Mapping)
        or not isinstance(proposed, Mapping)
        or not isinstance(expected, Mapping)
        or current.get("selected_folder_id") != folder_id
        or current.get(subject_field) != relation.principal_name
        or current.get("requested_folder_permission") != relation.folder_permission
        or current.get("requested_secret_permission") != relation.secret_permission
        or current.get("folder_exists") is not True
        or current.get("folder_scope") != "public_child"
        or type(current.get(relation_field)) is not bool
        or (
            not allow_existing
            and current.get(relation_field) is not False
        )
        or proposed.get("operation") != operation
        or proposed.get("folder_id") != folder_id
        or proposed.get(proposed_subject_field) != relation.principal_name
        or proposed.get("folder_permission") != relation.folder_permission
        or proposed.get("secret_permission") != relation.secret_permission
        or proposed.get("permission_inheritance_after_change") != "disable"
        or expected.get("folder_exists") is not True
        or expected.get("folder_scope") != "public_child"
        or expected.get("permission_inheritance") != "disable"
        or expected.get(
            "requested_group_relation_present"
            if is_group
            else "requested_username_relation_present"
        )
        is not True
        or expected.get("requested_folder_permission_matches") is not True
        or expected.get("requested_secret_permission_matches") is not True
        or expected.get("effective_user_relations_preserved") is not True
        or expected.get("effective_group_relations_preserved") is not True
    ):
        raise OnboardingActionCoordinatorError(
            "Fixed ACL preview does not match the protected Scheme line."
        )


__all__ = [
    "AccessDomainFixedActionSequenceResolver",
    "FixedChildFolderAction",
    "FixedFolderAclAction",
    "FixedFolderGroupAclAction",
]
