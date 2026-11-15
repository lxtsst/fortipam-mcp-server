"""Fixed candidate for one additive ancestor ACL change on FortiPAM 7.0."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Protocol

from v4_planning import M4AdapterAmbiguous, M4AdapterDenied, M4AdapterFailure, M4ExecutionPlan, canonical_digest
from .folder_acl_live_workflow import _relations
from .folder_traversal_candidate import prepare_folder_traversal

ACTION_ID = "folder-acl-grant"
ACTION_VERSION = "1.0.0"
ADAPTER_REF = "fortipam-700-build29-folder-traversal-candidate"
_UNAVAILABLE = "The Folder traversal candidate is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class FolderTraversalBinding:
    folder_id: int
    parent_id: int
    username: str
    current_digest: str
    expected_digest: str

    def __post_init__(self) -> None:
        from .folder_acl_live_workflow import _FolderAclRequest
        _FolderAclRequest.create(folder_id=self.folder_id, username=self.username,
                                folder_permission="view", secret_permission="none")
        if type(self.parent_id) is not int or not 0 <= self.parent_id <= 2_147_483_647:
            raise ValueError(_UNAVAILABLE)
        for digest in (self.current_digest, self.expected_digest):
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError(_UNAVAILABLE)

    @property
    def parameters_digest(self) -> str:
        return canonical_digest({"contract": ADAPTER_REF, "folder": self.folder_id,
            "parent": self.parent_id, "username": self.username,
            "current": self.current_digest, "expected": self.expected_digest})


class FolderTraversalTransport(Protocol):
    def read_product_version_and_build(self) -> tuple[str, int]: ...
    def owner_is_available(self, owner_name: str) -> bool: ...
    def read_folder(self, folder_id: int) -> Mapping[str, object]: ...
    def update_traversal(self, binding: FolderTraversalBinding) -> None: ...


class FolderTraversalM4Adapter:
    def __init__(self, plan: M4ExecutionPlan, binding: FolderTraversalBinding,
                 transport: FolderTraversalTransport) -> None:
        self._plan, self._binding, self._transport = plan, binding, transport
        self._dispatched = False
        self._validate(plan)

    def _validate(self, plan: M4ExecutionPlan) -> None:
        b = self._binding
        if (plan != self._plan or plan.action_id != ACTION_ID or plan.action_version != ACTION_VERSION
            or plan.adapter_ref != ADAPTER_REF or plan.parameters_digest != b.parameters_digest
            or plan.expected_current_digest != b.current_digest
            or plan.expected_state_digest != b.expected_digest):
            raise M4AdapterDenied(_UNAVAILABLE)

    def _version(self) -> None:
        version, build = self._transport.read_product_version_and_build()
        if version != "7.0.0" or type(build) is not int or build != 29:
            raise ValueError(_UNAVAILABLE)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self._validate(plan)
        b, t = self._binding, self._transport
        try:
            self._version()
            if t.owner_is_available(b.username) is not True:
                raise ValueError
            candidate = prepare_folder_traversal(t.read_folder(b.folder_id),
                folder_id=b.folder_id, parent_id=b.parent_id, username=b.username,
                version="7.0.0", build=29)
            if (candidate.current_digest != b.current_digest or candidate.proposed_digest != b.expected_digest):
                raise ValueError
            return b.current_digest
        except Exception:
            raise M4AdapterDenied(_UNAVAILABLE) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        self._validate(plan)
        if self._dispatched:
            raise M4AdapterDenied(_UNAVAILABLE)
        self.read_current(plan)
        self._dispatched = True
        try:
            self._transport.update_traversal(self._binding)
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self._validate(plan)
        b, t = self._binding, self._transport
        try:
            self._version()
            if not self._dispatched or t.owner_is_available(b.username) is not True:
                raise ValueError
            record = deepcopy(dict(t.read_folder(b.folder_id)))
            relations = _relations(record, principal_key="user-name")
            indices = [i for i, relation in enumerate(relations) if b.username in relation.names]
            if len(indices) != 1:
                raise ValueError
            relation = relations[indices[0]]
            if (relation.relation_id <= 0 or relation.names != (b.username,)
                or relation.folder_permission != "view" or relation.secret_permission != "none"):
                raise ValueError
            users = record["user-permission"]
            if not isinstance(users, list):
                raise ValueError
            users.pop(indices[0])
            candidate = prepare_folder_traversal(record, folder_id=b.folder_id,
                parent_id=b.parent_id, username=b.username, version="7.0.0", build=29)
            if candidate.current_digest != b.current_digest or candidate.proposed_digest != b.expected_digest:
                raise ValueError
            return b.expected_digest
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None
