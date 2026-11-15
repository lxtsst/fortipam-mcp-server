from __future__ import annotations

import pytest

from fortipam_mcp.folder_create_contract import (
    CREATE_METHOD,
    CREATE_PATH,
    DELETE_PATH,
    DETAIL_READ_PATH,
    FolderCreateContractError,
    FolderCreateReadinessError,
    FolderCreateRequest,
    FolderPermissionEvidenceError,
    MockFolderReadTransport,
    REQUEST_FIELDS,
    RootOwnerGrant,
    RootPermissionEncodingEvidence,
    project_folder_response,
)


def _response() -> dict[str, object]:
    return {
        "id": 42,
        "name": "Contractor-Secrets",
        "inherit-policy": "disable",
        "inherit-permission": "disable",
        "inherit-folder-ztna": "disable",
        "folder-type": "public",
        "secret-policy": "default",
        "parent-folder": 0,
        "user-permission": [{"private-readback-owner-entry": "opaque"}],
        "group-permission": [],
    }


def _root_permission_evidence() -> RootPermissionEncodingEvidence:
    return RootPermissionEncodingEvidence(
        adapter_ref="private-fpam-191-folder-adapter-v1",
        evidence_ref="isolated-lab-root-folder-acl-encoding-2026-08-24",
        request_schema_ref="private-root-folder-permission-v1",
        fortipam_version="1.9.1",
        exact_schema_verified=True,
        owner_grant=RootOwnerGrant(),
        user_permission=({"private-encoded-owner-entry": "opaque"},),
    )


def test_child_request_builds_documented_inherited_body() -> None:
    request = FolderCreateRequest.child("Contractor-Secrets", 101)
    body = request.body()
    assert tuple(body) == REQUEST_FIELDS
    assert body == {
        "id": 0,
        "name": "Contractor-Secrets",
        "inherit-policy": "enable",
        "inherit-permission": "enable",
        "inherit-folder-ztna": "enable",
        "parent-folder": 101,
        "user-permission": [],
        "group-permission": [],
    }
    assert (CREATE_METHOD, CREATE_PATH) == ("POST", "/api/v2/cmdb/secret/folder")
    assert DETAIL_READ_PATH.endswith("/{id}")
    assert DELETE_PATH.endswith("/{id}")


def test_root_request_is_explicit_and_fails_closed_without_permission_evidence() -> None:
    request = FolderCreateRequest.root("Contractor-Secrets")
    readiness = request.readiness()
    assert readiness.placement == "root"
    assert readiness.body_projection_ready is False
    assert readiness.permission_encoding_required is True
    assert readiness.blockers == ("exact-root-permission-array-schema-unverified",)
    with pytest.raises(FolderCreateReadinessError, match="permission-array-schema-unverified"):
        request.body()


def test_root_request_uses_disabled_inheritance_and_never_emits_empty_arrays() -> None:
    request = FolderCreateRequest.root("Contractor-Secrets")
    body = request.body(_root_permission_evidence())
    assert body == {
        "id": 0,
        "name": "Contractor-Secrets",
        "inherit-policy": "disable",
        "inherit-permission": "disable",
        "inherit-folder-ztna": "disable",
        "parent-folder": 0,
        "user-permission": [{"private-encoded-owner-entry": "opaque"}],
    }
    assert all(value != [] for value in body.values())
    assert "group-permission" not in body


def test_root_permission_evidence_cannot_be_applied_to_child() -> None:
    request = FolderCreateRequest.child("Contractor-Secrets", 101)
    readiness = request.readiness(_root_permission_evidence())
    assert readiness.body_projection_ready is False
    assert readiness.blockers == ("root-permission-evidence-on-child",)
    with pytest.raises(FolderCreateReadinessError, match="root-permission-evidence-on-child"):
        request.body(_root_permission_evidence())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "bad/name", "placement": "root"},
        {"name": "bad\\name", "placement": "root"},
        {"name": "", "placement": "root"},
        {"name": "x" * 65, "placement": "root"},
        {"name": "valid", "placement": "child", "parent_folder_id": "101"},
        {"name": "valid", "placement": "child", "parent_folder_id": True},
        {"name": "valid", "placement": "child", "parent_folder_id": 0},
        {"name": "valid", "placement": "child", "parent_folder_id": -1},
        {"name": "valid", "placement": "child", "parent_folder_id": 2_147_483_648},
        {"name": "valid", "placement": "child"},
        {"name": "valid", "placement": "root", "parent_folder_id": 101},
    ],
)
def test_request_rejects_unbounded_ambiguous_or_path_like_values(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(FolderCreateContractError):
        FolderCreateRequest(**kwargs)  # type: ignore[arg-type]


def test_request_rejects_unknown_fields() -> None:
    with pytest.raises(TypeError):
        FolderCreateRequest.root("valid", unexpected="x")  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "overrides",
    [
        {"fortipam_version": "1.9.0"},
        {"exact_schema_verified": False},
        {"owner_grant": RootOwnerGrant(principal_name="ops")},  # type: ignore[arg-type]
        {"user_permission": ()},
        {"user_permission": ({},)},
        {"user_permission": ({"encoded": "one"}, {"encoded": "two"})},
        {"group_permission": ({"encoded-group": "unexpected"},)},
    ],
)
def test_root_permission_evidence_fails_closed_on_unverified_or_drifted_input(
    overrides: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "adapter_ref": "private-fpam-191-folder-adapter-v1",
        "evidence_ref": "isolated-lab-root-folder-acl-encoding-2026-08-24",
        "request_schema_ref": "private-root-folder-permission-v1",
        "fortipam_version": "1.9.1",
        "exact_schema_verified": True,
        "owner_grant": RootOwnerGrant(),
        "user_permission": ({"private-encoded-owner-entry": "opaque"},),
        "group_permission": (),
    }
    values.update(overrides)
    with pytest.raises(FolderPermissionEvidenceError):
        RootPermissionEncodingEvidence(**values)  # type: ignore[arg-type]


def test_response_projector_returns_fixed_value_free_projection() -> None:
    projection = project_folder_response(_response())
    assert projection.as_dict() == {
        "exists": True,
        "id": 42,
        "name": "Contractor-Secrets",
        "parent-folder-id": 0,
        "folder-type": "public",
        "inherit-policy": "disable",
        "inherit-permission": "disable",
        "inherit-folder-ztna": "disable",
        "secret-policy": "default",
        "user-permission-count": 1,
        "group-permission-count": 0,
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update({"unexpected": True}),
        lambda value: value.pop("secret-policy"),
        lambda value: value.update({"inherit-policy": "maybe"}),
        lambda value: value.update({"user-permission": [object()] * 65}),
        lambda value: value.update({"user-permission": []}),
        lambda value: value.update({"parent-folder": "0"}),
        lambda value: value.update({"folder-type": "private"}),
        lambda value: value.update({"inherit-folder-ztna": "enable"}),
        lambda value: value.update({"id": "42"}),
    ],
)
def test_response_projector_fails_closed_on_shape_or_bound_drift(mutate: object) -> None:
    response = _response()
    assert callable(mutate)
    mutate(response)  # type: ignore[operator]
    with pytest.raises(FolderCreateContractError):
        project_folder_response(response)


def test_mock_transport_is_the_only_transport_implemented() -> None:
    transport = MockFolderReadTransport(_response())
    assert project_folder_response(transport.read_folder(42)).object_id == 42
