"""Private, read-only preparation of the pinned 7.0 Folder traversal candidate.

This module does not register a tool or authorize a device write. Existing
public-child workflows retain their positive-parent requirement.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass

from v4_planning import canonical_digest
from .folder_acl_live_workflow import (
    FolderAclLiveWorkflowError,
    WORKFLOW_UNAVAILABLE,
    _FolderAclRequest,
    _UPDATE_FIELDS,
    _nonempty_text,
    _positive_int,
    _relations,
    _ztna_control_semantics,
)


@dataclass(frozen=True, slots=True, repr=False)
class FolderTraversalCandidate:
    """Private payload and drift binding; never return the body through MCP."""

    current_digest: str
    proposed_digest: str
    body: dict[str, object]


def prepare_folder_traversal(
    record: Mapping[str, object], *, folder_id: int, parent_id: int,
    username: str, version: str, build: int,
) -> FolderTraversalCandidate:
    """Append exactly one view/none relation, preserving existing ACL fields."""
    def deny() -> None:
        raise FolderAclLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    if version != "7.0.0" or type(build) is not int or build != 29:
        deny()
    _FolderAclRequest.create(folder_id=folder_id, username=username,
                             folder_permission="view", secret_permission="none")
    if type(parent_id) is not int or parent_id < 0 or parent_id > 2_147_483_647:
        deny()
    if set(_UPDATE_FIELDS) - set(record):
        deny()
    if (_positive_int(record.get("id")) != folder_id
        or type(record.get("parent-folder")) is not int
        or record.get("parent-folder") != parent_id
        or record.get("folder-type") != "public"
        or record.get("inherit-permission") != "disable"):
        deny()
    for field in ("name", "secret-policy"):
        _nonempty_text(record.get(field), maximum=128)
    if record.get("inherit-policy") not in {"enable", "disable"}:
        deny()
    _ztna_control_semantics(record)
    users = _relations(record, principal_key="user-name")
    _relations(record, principal_key="group-name")
    if len(users) >= 128 or any(username in relation.names for relation in users):
        deny()
    current = deepcopy({field: record[field] for field in _UPDATE_FIELDS})
    body = deepcopy(current)
    relations = body["user-permission"]
    assert isinstance(relations, list)
    relations.append({"id": 0, "user-name": [{"name": username}],
                      "folder-permission": "view", "secret-permission": "none"})
    return FolderTraversalCandidate(canonical_digest(current), canonical_digest(body), body)
