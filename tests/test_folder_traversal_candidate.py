from copy import deepcopy

import pytest

from fortipam_mcp.folder_acl_live_workflow import FolderAclLiveWorkflowError
from fortipam_mcp.folder_traversal_candidate import prepare_folder_traversal


def record():
    return {
        "id": 12, "name": "synthetic", "parent-folder": 0,
        "folder-type": "public", "secret-policy": "default",
        "inherit-policy": "disable", "inherit-permission": "disable",
        "inherit-folder-ztna": "disable", "ztna-ems-tag": [],
        "ztna-tags-match-logic": "or",
        "user-permission": [{"id": 3, "user-name": [{"name": "owner"}],
            "folder-permission": "owner", "secret-permission": "owner",
            "allowed-launcher-type": "all"}],
        "group-permission": [],
    }


def prepare(value, **overrides):
    args = dict(folder_id=12, parent_id=0, username="gui-user",
                version="7.0.0", build=29)
    args.update(overrides)
    return prepare_folder_traversal(value, **args)


def test_root_candidate_preserves_every_existing_relation_and_control():
    current = record()
    original = deepcopy(current)
    candidate = prepare(current)
    assert current == original
    proposed = deepcopy(candidate.body)
    added = proposed["user-permission"].pop()
    assert added == {"id": 0, "user-name": [{"name": "gui-user"}],
                     "folder-permission": "view", "secret-permission": "none"}
    assert proposed == original
    assert candidate.current_digest != candidate.proposed_digest
    current["user-permission"][0]["allowed-launcher-type"] = "custom"
    assert prepare(current).current_digest != candidate.current_digest


@pytest.mark.parametrize("change", [
    {"parent-folder": True}, {"parent-folder": 1},
    {"inherit-permission": "enable"}, {"folder-type": "private"},
])
def test_rejects_unbound_or_inherited_folder(change):
    current = record()
    current.update(change)
    with pytest.raises(FolderAclLiveWorkflowError):
        prepare(current)


@pytest.mark.parametrize("overrides", [{"version": "1.9.1"}, {"build": 30},
                                      {"build": True}, {"parent_id": True}])
def test_rejects_wrong_firmware_or_binding(overrides):
    with pytest.raises(FolderAclLiveWorkflowError):
        prepare(record(), **overrides)


def test_does_not_replace_existing_principal_permissions():
    with pytest.raises(FolderAclLiveWorkflowError):
        prepare(record(), username="owner")
