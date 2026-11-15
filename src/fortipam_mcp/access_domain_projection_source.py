"""Minimized source-backed observations for AccessDomainScheme planning.

This module bridges an owner-protected product binding to the existing fixed
Folder collection read. Product selectors and principal names never enter the
returned observation. It is not registered as an MCP projection provider and
has no write operation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
from typing import Protocol

from v4_planning import (
    AuthenticatedRequester,
    AuthoritativeProjection,
    FieldKind,
    FieldRule,
    ObjectClass,
    ProjectionContract,
    SchemeDraft,
    SchemeId,
)
from v4_planning.models import require_ref


SOURCE_CONTRACT = "fortipam-access-domain-folder-observation-v1"
SOURCE_VERSION = "1.1.0"
SOURCE_REF = "fortipam-191-access-domain-projection"
SOURCE_UNAVAILABLE = "FortiPAM Access Domain projection source is unavailable."
_MAX_FOLDER_ID = 2_147_483_647
_MAX_RECORDS = 512
_MAX_RELATIONS = 128
_MAX_NAMES = 64
_MAX_BINDING_BYTES = 32_768
_PRODUCT_PERMISSIONS = frozenset({"view", "edit", "owner", "add-secret"})


class AccessDomainProjectionSourceError(RuntimeError):
    """Stable, non-disclosing source failure."""


class FolderCollectionReadTransport(Protocol):
    """Existing fixed Folder collection read boundary."""

    def read_collection(self) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class BoundAclRelation:
    """Protected mapping from one Scheme relation to one product principal."""

    object_ref: str
    subject_ref: str
    subject_class: str
    principal_name: str
    permission: str
    folder_permission: str
    secret_permission: str

    def __post_init__(self) -> None:
        try:
            require_ref(self.object_ref, "ACL object_ref")
            require_ref(self.subject_ref, "ACL subject_ref")
        except ValueError as exc:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        if (
            self.subject_class not in {"user", "group", "role"}
            or self.permission not in {"use", "manage"}
            or self.folder_permission not in _PRODUCT_PERMISSIONS
            or self.secret_permission not in _PRODUCT_PERMISSIONS - {"add-secret"}
        ):
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        _bounded_name(self.principal_name)


@dataclass(frozen=True, slots=True)
class AccessDomainFolderBinding:
    """Owner-protected Folder selector and value-free Scheme mappings."""

    folder_object_ref: str
    folder_name: str
    parent_folder_id: int
    owner_ref: str
    owner_principal_name: str
    owner_subject_class: str
    acl_relations: tuple[BoundAclRelation, ...] = ()

    def __post_init__(self) -> None:
        try:
            require_ref(self.folder_object_ref, "Folder object_ref")
            require_ref(self.owner_ref, "Folder owner_ref")
        except ValueError as exc:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        _bounded_name(self.folder_name)
        _bounded_name(self.owner_principal_name)
        if (
            type(self.parent_folder_id) is not int
            or not 0 <= self.parent_folder_id <= _MAX_FOLDER_ID
            or self.owner_subject_class not in {"user", "group"}
        ):
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        relation_refs = [item.object_ref for item in self.acl_relations]
        if len(relation_refs) != len(set(relation_refs)) or len(relation_refs) > 16:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)


class AccessDomainBindingResolver(Protocol):
    """Resolve product selectors only inside a trusted host boundary."""

    def resolve(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> AccessDomainFolderBinding: ...


class OwnerOnlyAccessDomainBindingResolver:
    """Resolve one requester/scope-bound mapping from an owner-only JSON file."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        if not self._path.is_absolute():
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)

    def resolve(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> AccessDomainFolderBinding:
        payload = self._load()
        exact_keys = {
            "contract",
            "version",
            "requester_digest",
            "environment_ref",
            "scope_ref",
            "folder_object_ref",
            "folder_name",
            "parent_folder_id",
            "owner_ref",
            "owner_principal_name",
            "owner_subject_class",
            "acl_relations",
        }
        if (
            set(payload) != exact_keys
            or payload.get("contract") != SOURCE_CONTRACT
            or payload.get("version") != SOURCE_VERSION
            or payload.get("requester_digest") != requester.digest
            or payload.get("environment_ref") != draft.environment_ref
            or payload.get("scope_ref") != draft.scope_ref
            or payload.get("owner_ref") != draft.owner_ref
        ):
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        raw_relations = payload.get("acl_relations")
        if not isinstance(raw_relations, list) or len(raw_relations) > 16:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        relations = tuple(_bound_acl_relation(item) for item in raw_relations)
        try:
            return AccessDomainFolderBinding(
                folder_object_ref=_string(payload, "folder_object_ref"),
                folder_name=_string(payload, "folder_name"),
                parent_folder_id=_integer(payload, "parent_folder_id"),
                owner_ref=_string(payload, "owner_ref"),
                owner_principal_name=_string(payload, "owner_principal_name"),
                owner_subject_class=_string(payload, "owner_subject_class"),
                acl_relations=relations,
            )
        except (TypeError, ValueError) as exc:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE) from exc

    def _load(self) -> Mapping[str, object]:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self._path, flags)
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077
                    or info.st_size <= 0
                    or info.st_size > _MAX_BINDING_BYTES
                ):
                    raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
                content = os.read(descriptor, _MAX_BINDING_BYTES + 1)
            finally:
                os.close(descriptor)
            if len(content) > _MAX_BINDING_BYTES:
                raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
            value = json.loads(content)
        except AccessDomainProjectionSourceError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        if not isinstance(value, Mapping):
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        return {str(key): item for key, item in value.items()}


@dataclass(frozen=True, slots=True)
class AccessDomainStateObservation:
    """One value-free observation ready for a reviewed projection contract."""

    object_ref: str
    object_class: ObjectClass
    fields: tuple[tuple[str, bool | str], ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "object_ref": self.object_ref,
            "object_class": self.object_class.value,
            "fields": dict(self.fields),
        }


@dataclass(frozen=True, slots=True)
class ExistingAccessDomainFolderBinding:
    """Private fixed-action inputs resolved from the same bounded source."""

    folder_id: int
    binding: AccessDomainFolderBinding


@dataclass(frozen=True, slots=True)
class ResolvedAccessDomainFolderBinding:
    """Private binding plus an optional exact child ID for action sequencing."""

    folder_id: int | None
    binding: AccessDomainFolderBinding


class FortiPamAccessDomainProjectionSource:
    """Read one bound Folder and reduce it to Access Domain semantics."""

    mode = "source_backed"
    contract_registered = True

    def __init__(
        self,
        transport: FolderCollectionReadTransport,
        resolver: AccessDomainBindingResolver,
    ) -> None:
        self._transport = transport
        self._resolver = resolver

    def observe(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> tuple[AccessDomainStateObservation, ...]:
        if draft.scheme_id is not SchemeId.ACCESS_DOMAIN:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        binding = self._resolve(draft, requester)
        desired = {item.object_ref: item for item in draft.desired_objects}
        if (
            len(desired) != len(draft.desired_objects)
            or binding.folder_object_ref not in desired
            or desired[binding.folder_object_ref].object_class
            is not ObjectClass.PUBLIC_FOLDER
            or any(
                item.object_class
                not in {ObjectClass.PUBLIC_FOLDER, ObjectClass.ACCESS_GRANT}
                for item in draft.desired_objects
            )
            or {item.object_ref for item in binding.acl_relations}
            != {
                item.object_ref
                for item in draft.desired_objects
                if item.object_class is ObjectClass.ACCESS_GRANT
            }
        ):
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)

        folder = self._read_bound_folder(binding)
        if folder is None:
            return tuple(
                AccessDomainStateObservation(
                    object_ref=item.object_ref,
                    object_class=item.object_class,
                    fields=(("exists", False),),
                )
                for item in draft.desired_objects
            )

        folder_id = folder.get("id")
        if (
            folder.get("folder-type") != "public"
            or type(folder_id) is not int
            or not 0 < folder_id <= _MAX_FOLDER_ID
        ):
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        user_relations = _relations(folder.get("user-permission"), "user-name")
        group_relations = _relations(folder.get("group-permission"), "group-name")
        relation_sets = {"user": user_relations, "group": group_relations}
        owner = _find_relation(
            relation_sets[binding.owner_subject_class], binding.owner_principal_name
        )
        if owner is None or owner[1:] != ("owner", "owner"):
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)

        observations = [
            AccessDomainStateObservation(
                object_ref=binding.folder_object_ref,
                object_class=ObjectClass.PUBLIC_FOLDER,
                fields=(
                    ("enabled", True),
                    ("exists", True),
                    ("owner_ref", binding.owner_ref),
                ),
            )
        ]
        for relation in binding.acl_relations:
            if relation.subject_class == "role":
                raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
            product_relation = _find_relation(
                relation_sets[relation.subject_class], relation.principal_name
            )
            if product_relation is None:
                fields: dict[str, bool | str] = {"exists": False}
            else:
                if product_relation[1:] != (
                    relation.folder_permission,
                    relation.secret_permission,
                ):
                    raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
                fields = {
                    "exists": True,
                    "permission": relation.permission,
                    "subject_class": relation.subject_class,
                    "subject_ref": relation.subject_ref,
                }
            observations.append(
                AccessDomainStateObservation(
                    object_ref=relation.object_ref,
                    object_class=ObjectClass.ACCESS_GRANT,
                    fields=tuple(sorted(fields.items())),
                )
            )
        order = {item.object_ref: index for index, item in enumerate(draft.desired_objects)}
        return tuple(sorted(observations, key=lambda item: order[item.object_ref]))

    def resolve_existing_folder(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> ExistingAccessDomainFolderBinding:
        """Resolve private fixed-action inputs only for one existing bound Folder."""

        resolved = self.resolve_bound_folder(draft, requester)
        if resolved.folder_id is None:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        return ExistingAccessDomainFolderBinding(
            resolved.folder_id,
            resolved.binding,
        )

    def resolve_bound_folder(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> ResolvedAccessDomainFolderBinding:
        """Resolve protected placement and distinguish exact absence from failure."""

        binding = self._resolve(draft, requester)
        folder = self._read_bound_folder(binding)
        folder_id = folder.get("id") if folder is not None else None
        if folder_id is not None and (
            type(folder_id) is not int or not 0 < folder_id <= _MAX_FOLDER_ID
        ):
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        return ResolvedAccessDomainFolderBinding(folder_id, binding)

    def _read_bound_folder(
        self,
        binding: AccessDomainFolderBinding,
    ) -> Mapping[str, object] | None:
        records = _folder_records(self._read_collection())
        matches = [
            record
            for record in records
            if record.get("name") == binding.folder_name
            and record.get("parent-folder") == binding.parent_folder_id
        ]
        if len(matches) > 1:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        if binding.parent_folder_id == 0:
            # FortiPAM represents an existing top-level Public Folder with a
            # root sentinel rather than a record that can be used as parent.
            # Never turn that sentinel into a root-create plan.
            if len(matches) != 1:
                raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
            return matches[0]
        parent_matches = [
            record for record in records if record.get("id") == binding.parent_folder_id
        ]
        if len(parent_matches) != 1:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        return matches[0] if matches else None

    def project(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> tuple[AuthoritativeProjection, ...]:
        """Bind minimized observations to the registered read-only contract."""

        if type(now_epoch) is not int:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        try:
            return tuple(
                AuthoritativeProjection.from_mapping(
                    contract=access_domain_projection_contract(item.object_class),
                    object_ref=item.object_ref,
                    observed_at=now_epoch,
                    fresh_until=now_epoch + 300,
                    fields=dict(item.fields),
                )
                for item in self.observe(draft, requester)
            )
        except (TypeError, ValueError) as exc:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE) from exc

    def _resolve(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> AccessDomainFolderBinding:
        try:
            binding = self._resolver.resolve(draft, requester)
        except Exception as exc:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        if not isinstance(binding, AccessDomainFolderBinding):
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        return binding

    def _read_collection(self) -> Mapping[str, object]:
        try:
            value = self._transport.read_collection()
        except Exception as exc:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        if not isinstance(value, Mapping):
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        return value


def _bounded_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
    return value


def _string(value: Mapping[str, object], field: str) -> str:
    result = value.get(field)
    if not isinstance(result, str):
        raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
    return result


def _integer(value: Mapping[str, object], field: str) -> int:
    result = value.get(field)
    if type(result) is not int:
        raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
    return result


def _bound_acl_relation(value: object) -> BoundAclRelation:
    fields = {
        "object_ref",
        "subject_ref",
        "subject_class",
        "principal_name",
        "permission",
        "folder_permission",
        "secret_permission",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
    return BoundAclRelation(
        object_ref=_string(value, "object_ref"),
        subject_ref=_string(value, "subject_ref"),
        subject_class=_string(value, "subject_class"),
        principal_name=_string(value, "principal_name"),
        permission=_string(value, "permission"),
        folder_permission=_string(value, "folder_permission"),
        secret_permission=_string(value, "secret_permission"),
    )


def access_domain_projection_contract(
    object_class: ObjectClass,
) -> ProjectionContract:
    """Return the fixed registered read-only product projection contract."""

    rules: tuple[FieldRule, ...]
    if object_class is ObjectClass.PUBLIC_FOLDER:
        rules = (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("owner_ref", FieldKind.REFERENCE),
            FieldRule("enabled", FieldKind.BOOLEAN),
        )
    elif object_class is ObjectClass.ACCESS_GRANT:
        rules = (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("subject_ref", FieldKind.REFERENCE),
            FieldRule("subject_class", FieldKind.ENUM, ("user", "group", "role")),
            FieldRule("permission", FieldKind.ENUM, ("use", "manage")),
        )
    else:
        raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
    return ProjectionContract(
        contract_id=SOURCE_CONTRACT,
        version=SOURCE_VERSION,
        source_ref=SOURCE_REF,
        object_class=object_class,
        field_rules=rules,
        max_age_seconds=300,
    )


def _folder_records(value: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
    candidates: Sequence[object] | None = None
    if isinstance(value.get("results"), list):
        candidates = value["results"]  # type: ignore[assignment]
    elif isinstance(value.get("data"), list):
        candidates = value["data"]  # type: ignore[assignment]
    if candidates is None or len(candidates) > _MAX_RECORDS:
        raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
    records = tuple(item for item in candidates if isinstance(item, Mapping))
    if len(records) != len(candidates):
        raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
    return records


def _relations(
    value: object,
    principal_key: str,
) -> tuple[tuple[str, str, str], ...]:
    if not isinstance(value, list) or len(value) > _MAX_RELATIONS:
        raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
    result: list[tuple[str, str, str]] = []
    for relation in value:
        if not isinstance(relation, Mapping):
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        names = relation.get(principal_key)
        if not isinstance(names, list) or not names or len(names) > _MAX_NAMES:
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        folder_permission = relation.get("folder-permission")
        secret_permission = relation.get("secret-permission")
        if (
            not isinstance(folder_permission, str)
            or not isinstance(secret_permission, str)
        ):
            raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
        for item in names:
            name = item.get("name") if isinstance(item, Mapping) else item
            result.append(
                (
                    _bounded_name(name),
                    folder_permission.lower(),
                    secret_permission.lower(),
                )
            )
    if len({item[0] for item in result}) != len(result):
        raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
    return tuple(result)


def _find_relation(
    relations: tuple[tuple[str, str, str], ...],
    principal_name: str,
) -> tuple[str, str, str] | None:
    matches = [item for item in relations if item[0] == principal_name]
    if len(matches) > 1:
        raise AccessDomainProjectionSourceError(SOURCE_UNAVAILABLE)
    return matches[0] if matches else None


__all__ = [
    "AccessDomainBindingResolver",
    "AccessDomainFolderBinding",
    "AccessDomainProjectionSourceError",
    "AccessDomainStateObservation",
    "BoundAclRelation",
    "FolderCollectionReadTransport",
    "FortiPamAccessDomainProjectionSource",
    "ExistingAccessDomainFolderBinding",
    "OwnerOnlyAccessDomainBindingResolver",
    "ResolvedAccessDomainFolderBinding",
    "SOURCE_CONTRACT",
    "SOURCE_REF",
    "SOURCE_VERSION",
    "access_domain_projection_contract",
]
