"""Value-free permission readiness for the bounded Folder action family.

This module models the FortiPAM 1.9.1 Role controls documented for Secret
Folder and Root Folder.  It does not load credentials, contact a device, or
authorize an action.  A future private adapter must supply trusted role
evidence and still pass the independent V4 confirmation and execution gates.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from .least_privilege import (
    ACCESS_CATEGORY_FIELDS,
    CUSTOM_PERMISSION_FIELDS,
    SAFE_PROFILE_CONTROLS,
)


class FolderActionReadinessError(ValueError):
    """Raised when permission evidence is malformed or incomplete."""


class FolderScope(StrEnum):
    ROOT = "root"
    CHILD = "child"


class PermissionLevel(StrEnum):
    NONE = "none"
    READ = "read"
    READ_WRITE = "read_write"


@dataclass(frozen=True, slots=True)
class FolderRoleEvidence:
    """Minimized Role projection required for Folder reads and creates."""

    secret_folder: PermissionLevel
    root_folder: PermissionLevel
    source: str

    def __post_init__(self) -> None:
        if self.source not in {"trusted_api", "trusted_cli", "owner_gui_readback"}:
            raise FolderActionReadinessError("Role evidence source is not trusted.")


@dataclass(frozen=True, slots=True)
class FolderPermissionDecision:
    scope: FolderScope
    collection_read_allowed: bool
    create_allowed: bool
    blockers: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "blockers": list(self.blockers),
            "collection_read_allowed": self.collection_read_allowed,
            "create_allowed": self.create_allowed,
            "scope": self.scope.value,
        }


def assess_folder_permissions(
    scope: FolderScope,
    evidence: FolderRoleEvidence,
) -> FolderPermissionDecision:
    """Evaluate only documented Role permission prerequisites.

    Secret Folder at Read or Read/Write permits Folder visibility.  Creating a
    Folder requires Secret Folder Read/Write; creating directly under Root also
    requires Root Folder Read/Write.  Passing this decision is necessary but
    never sufficient to authorize a write.
    """

    blockers: list[str] = []
    read_allowed = evidence.secret_folder in {
        PermissionLevel.READ,
        PermissionLevel.READ_WRITE,
    }
    if not read_allowed:
        blockers.append("secret_folder_read_required")
    if evidence.secret_folder is not PermissionLevel.READ_WRITE:
        blockers.append("secret_folder_read_write_required")
    if scope is FolderScope.ROOT and evidence.root_folder is not PermissionLevel.READ_WRITE:
        blockers.append("root_folder_read_write_required")
    return FolderPermissionDecision(
        scope=scope,
        collection_read_allowed=read_allowed,
        create_allowed=not blockers,
        blockers=tuple(blockers),
    )


def desired_child_folder_action_profile() -> dict[str, object]:
    """Return the exact child-Folder-only Role permission projection.

    The FortiPAM 1.9.1 CLI contract names the GUI ``Secret Folder`` control as
    ``secretgrp-permission.folder-table`` and the GUI ``Root Folder`` control
    as ``secretgrp-permission.create-root-folder``.  The first V4 product
    action needs the former at read/write and keeps the latter, every sibling
    Secret permission, and every other top-level category at none.

    This is a pure desired-state projection.  It neither creates a Role nor
    authorizes a Folder write.
    """

    profile: dict[str, object] = {
        category: "custom" if category == "secretgrp" else "none"
        for category in ACCESS_CATEGORY_FIELDS
    }
    profile.update(SAFE_PROFILE_CONTROLS)
    for category, fields in CUSTOM_PERMISSION_FIELDS.items():
        profile[f"{category}-permission"] = {
            field: (
                "read-write"
                if category == "secretgrp" and field == "folder-table"
                else "none"
            )
            for field in fields
        }
    return profile


def evaluate_child_folder_action_profile(profile: object) -> dict[str, object]:
    """Evaluate exact Role shape without returning permission field values."""

    expected = desired_child_folder_action_profile()
    if not isinstance(profile, Mapping):
        return _invalid_child_profile("PROFILE_DEFINITION_NOT_AN_OBJECT")

    top_level_mismatch_count = sum(
        profile.get(field) != expected_value
        for field, expected_value in expected.items()
        if field in ACCESS_CATEGORY_FIELDS or field in SAFE_PROFILE_CONTROLS
    )
    subpermission_mismatch_count = 0
    unexpected_subpermission_access_count = 0
    for category, fields in CUSTOM_PERMISSION_FIELDS.items():
        field_name = f"{category}-permission"
        actual = profile.get(field_name)
        required = expected[field_name]
        assert isinstance(required, dict)
        if not isinstance(actual, Mapping):
            subpermission_mismatch_count += len(fields)
            continue
        for field in fields:
            actual_value = actual.get(field)
            expected_value = required[field]
            if actual_value != expected_value:
                subpermission_mismatch_count += 1
            if field != "folder-table" and actual_value not in {None, "none"}:
                unexpected_subpermission_access_count += 1
        unexpected_subpermission_access_count += sum(
            field not in fields and value not in {None, "none"}
            for field, value in actual.items()
        )
    known_permission_maps = {
        f"{category}-permission" for category in CUSTOM_PERMISSION_FIELDS
    }
    for field_name, permissions in profile.items():
        if not isinstance(field_name, str) or not field_name.endswith("-permission"):
            continue
        if field_name in known_permission_maps:
            continue
        if not isinstance(permissions, Mapping):
            unexpected_subpermission_access_count += 1
            continue
        unexpected_subpermission_access_count += sum(
            value not in {None, "none"} for value in permissions.values()
        )

    reason_codes: list[str] = []
    if top_level_mismatch_count:
        reason_codes.append("TOP_LEVEL_PERMISSION_SHAPE_MISMATCH")
    if subpermission_mismatch_count:
        reason_codes.append("FOLDER_SUBPERMISSION_SHAPE_MISMATCH")
    if unexpected_subpermission_access_count:
        reason_codes.append("UNEXPECTED_SUBPERMISSION_ACCESS_PRESENT")
    return {
        "candidate_profile_shape_confirmed": not reason_codes,
        "expected_custom_category_count": 1,
        "expected_read_write_subpermission_count": 1,
        "root_folder_write_expected": False,
        "subpermission_mismatch_count": subpermission_mismatch_count,
        "top_level_mismatch_count": top_level_mismatch_count,
        "unexpected_subpermission_access_count": (
            unexpected_subpermission_access_count
        ),
        "reason_codes": reason_codes,
        "permission_category_names_returned": False,
        "permission_field_names_returned": False,
        "profile_name_returned": False,
        "raw_response_returned": False,
        "product_write_authorized": False,
    }


def _invalid_child_profile(reason_code: str) -> dict[str, object]:
    return {
        "candidate_profile_shape_confirmed": False,
        "expected_custom_category_count": 1,
        "expected_read_write_subpermission_count": 1,
        "root_folder_write_expected": False,
        "subpermission_mismatch_count": sum(
            len(fields) for fields in CUSTOM_PERMISSION_FIELDS.values()
        ),
        "top_level_mismatch_count": (
            len(ACCESS_CATEGORY_FIELDS) + len(SAFE_PROFILE_CONTROLS)
        ),
        "unexpected_subpermission_access_count": 0,
        "reason_codes": [reason_code],
        "permission_category_names_returned": False,
        "permission_field_names_returned": False,
        "profile_name_returned": False,
        "raw_response_returned": False,
        "product_write_authorized": False,
    }


__all__ = [
    "FolderActionReadinessError",
    "FolderPermissionDecision",
    "FolderRoleEvidence",
    "FolderScope",
    "PermissionLevel",
    "assess_folder_permissions",
    "desired_child_folder_action_profile",
    "evaluate_child_folder_action_profile",
]
