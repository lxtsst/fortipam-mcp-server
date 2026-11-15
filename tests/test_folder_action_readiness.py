from __future__ import annotations

import pytest

from fortipam_mcp.folder_action_readiness import (
    FolderActionReadinessError,
    FolderRoleEvidence,
    FolderScope,
    PermissionLevel,
    assess_folder_permissions,
    desired_child_folder_action_profile,
    evaluate_child_folder_action_profile,
)


def _evidence(secret: PermissionLevel, root: PermissionLevel) -> FolderRoleEvidence:
    return FolderRoleEvidence(secret, root, "trusted_cli")


def test_read_only_secret_folder_can_read_but_cannot_create() -> None:
    decision = assess_folder_permissions(
        FolderScope.CHILD,
        _evidence(PermissionLevel.READ, PermissionLevel.NONE),
    )

    assert decision.collection_read_allowed is True
    assert decision.create_allowed is False
    assert decision.blockers == ("secret_folder_read_write_required",)


def test_child_create_does_not_require_root_folder_permission() -> None:
    decision = assess_folder_permissions(
        FolderScope.CHILD,
        _evidence(PermissionLevel.READ_WRITE, PermissionLevel.NONE),
    )

    assert decision.create_allowed is True
    assert decision.blockers == ()


def test_root_create_requires_both_documented_permissions() -> None:
    missing_root = assess_folder_permissions(
        FolderScope.ROOT,
        _evidence(PermissionLevel.READ_WRITE, PermissionLevel.NONE),
    )
    ready = assess_folder_permissions(
        FolderScope.ROOT,
        _evidence(PermissionLevel.READ_WRITE, PermissionLevel.READ_WRITE),
    )

    assert missing_root.create_allowed is False
    assert missing_root.blockers == ("root_folder_read_write_required",)
    assert ready.create_allowed is True


def test_none_permission_fails_read_and_create() -> None:
    decision = assess_folder_permissions(
        FolderScope.ROOT,
        _evidence(PermissionLevel.NONE, PermissionLevel.NONE),
    )

    assert decision.as_dict() == {
        "blockers": [
            "secret_folder_read_required",
            "secret_folder_read_write_required",
            "root_folder_read_write_required",
        ],
        "collection_read_allowed": False,
        "create_allowed": False,
        "scope": "root",
    }


def test_untrusted_evidence_source_is_rejected() -> None:
    with pytest.raises(FolderActionReadinessError, match="source"):
        FolderRoleEvidence(
            PermissionLevel.READ_WRITE,
            PermissionLevel.READ_WRITE,
            "model_text",
        )


def test_child_folder_action_profile_is_exactly_one_write_subpermission() -> None:
    profile = desired_child_folder_action_profile()

    assert profile["secretgrp"] == "custom"
    assert profile["sysgrp"] == "none"
    permissions = profile["secretgrp-permission"]
    assert isinstance(permissions, dict)
    assert permissions["folder-table"] == "read-write"
    assert permissions["create-root-folder"] == "none"
    assert sum(value == "read-write" for value in permissions.values()) == 1
    assert evaluate_child_folder_action_profile(profile) == {
        "candidate_profile_shape_confirmed": True,
        "expected_custom_category_count": 1,
        "expected_read_write_subpermission_count": 1,
        "root_folder_write_expected": False,
        "subpermission_mismatch_count": 0,
        "top_level_mismatch_count": 0,
        "unexpected_subpermission_access_count": 0,
        "reason_codes": [],
        "permission_category_names_returned": False,
        "permission_field_names_returned": False,
        "profile_name_returned": False,
        "raw_response_returned": False,
        "product_write_authorized": False,
    }


def test_child_folder_action_profile_rejects_root_or_sibling_access() -> None:
    profile = desired_child_folder_action_profile()
    permissions = profile["secretgrp-permission"]
    assert isinstance(permissions, dict)
    permissions["create-root-folder"] = "read-write"
    permissions["target"] = "read"

    result = evaluate_child_folder_action_profile(profile)

    assert result["candidate_profile_shape_confirmed"] is False
    assert result["subpermission_mismatch_count"] == 2
    assert result["unexpected_subpermission_access_count"] == 2
    assert result["reason_codes"] == [
        "FOLDER_SUBPERMISSION_SHAPE_MISMATCH",
        "UNEXPECTED_SUBPERMISSION_ACCESS_PRESENT",
    ]


def test_child_folder_action_profile_rejects_broad_top_level_access() -> None:
    profile = desired_child_folder_action_profile()
    profile["secretgrp"] = "read-write"

    result = evaluate_child_folder_action_profile(profile)

    assert result["candidate_profile_shape_confirmed"] is False
    assert result["top_level_mismatch_count"] == 1
    assert result["reason_codes"] == ["TOP_LEVEL_PERMISSION_SHAPE_MISMATCH"]


def test_child_folder_action_profile_rejects_access_in_live_extra_permission_map() -> None:
    profile = desired_child_folder_action_profile()
    profile["authgrp-permission"] = {
        "auth-rule": "none",
        "group": "read",
    }

    result = evaluate_child_folder_action_profile(profile)

    assert result["candidate_profile_shape_confirmed"] is False
    assert result["unexpected_subpermission_access_count"] == 1
    assert result["reason_codes"] == ["UNEXPECTED_SUBPERMISSION_ACCESS_PRESENT"]


def test_child_folder_action_profile_rejects_non_object() -> None:
    result = evaluate_child_folder_action_profile([])

    assert result["candidate_profile_shape_confirmed"] is False
    assert result["reason_codes"] == ["PROFILE_DEFINITION_NOT_AN_OBJECT"]
    assert result["product_write_authorized"] is False
