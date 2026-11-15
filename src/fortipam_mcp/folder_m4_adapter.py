"""Unregistered M4 adapter contract for one inherited child Folder create.

The adapter resolves only a previously prepared private action, compares a
minimized logical current-state digest, dispatches one fixed child-Folder body,
and reads the same collection again.  It has no credential loader, URL, MCP
registration, or default runtime binding.  Root Folder creation, updates,
deletes, permission arrays, and Secret values are outside this contract.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from v4_planning import (
    M4AdapterAmbiguous,
    M4AdapterDenied,
    M4AdapterFailure,
    M4AdapterTimeout,
    M4ExecutionPlan,
    canonical_digest,
)

from .folder_create_contract import FolderCreateRequest


ACTION_ID = "folder-create"
ACTION_VERSION = "3.2.0"
ADAPTER_REF = "fortipam-folder-child-create-adapter-v1"


class FolderM4AdapterContractError(ValueError):
    """Raised when a private prepared action or product projection is invalid."""


@dataclass(frozen=True, slots=True)
class ChildFolderLogicalState:
    """Minimized state used for pre-write and post-write digest comparison."""

    exists: bool
    name: str
    parent_folder_id: int
    inherit_policy: str | None
    inherit_permission: str | None
    inherit_folder_ztna: str | None
    user_permission_count: int | None
    group_permission_count: int | None

    @classmethod
    def absent(cls, request: FolderCreateRequest) -> ChildFolderLogicalState:
        _require_child_request(request)
        assert request.parent_folder_id is not None
        return cls(
            False,
            request.name,
            request.parent_folder_id,
            None,
            None,
            None,
            None,
            None,
        )

    @classmethod
    def expected(cls, request: FolderCreateRequest) -> ChildFolderLogicalState:
        _require_child_request(request)
        assert request.parent_folder_id is not None
        return cls(
            True,
            request.name,
            request.parent_folder_id,
            "enable",
            "enable",
            "enable",
            None,
            None,
        )

    def digest(self) -> str:
        return canonical_digest(
            {
                "contract": "fortipam-child-folder-logical-state-v1",
                "exists": self.exists,
                "group_permission_count": self.group_permission_count,
                "inherit_folder_ztna": self.inherit_folder_ztna,
                "inherit_permission": self.inherit_permission,
                "inherit_policy": self.inherit_policy,
                "name": self.name,
                "parent_folder_id": self.parent_folder_id,
                "user_permission_count": self.user_permission_count,
            }
        )


@dataclass(frozen=True, slots=True)
class PreparedChildFolderCreate:
    """Private prepared action resolved by opaque plan references only."""

    plan_ref: str
    target_ref: str
    request: FolderCreateRequest
    parameters_digest: str
    expected_current_digest: str
    expected_state_digest: str

    @classmethod
    def build(
        cls,
        *,
        plan_ref: str,
        target_ref: str,
        request: FolderCreateRequest,
    ) -> PreparedChildFolderCreate:
        body = _require_child_request(request).body()
        return cls(
            plan_ref=plan_ref,
            target_ref=target_ref,
            request=request,
            parameters_digest=canonical_digest(body),
            expected_current_digest=ChildFolderLogicalState.absent(request).digest(),
            expected_state_digest=ChildFolderLogicalState.expected(request).digest(),
        )

    def __post_init__(self) -> None:
        body = _require_child_request(self.request).body()
        if self.parameters_digest != canonical_digest(body):
            raise FolderM4AdapterContractError("Prepared parameters digest is invalid.")
        if self.expected_current_digest != ChildFolderLogicalState.absent(self.request).digest():
            raise FolderM4AdapterContractError("Prepared current-state digest is invalid.")
        if self.expected_state_digest != ChildFolderLogicalState.expected(self.request).digest():
            raise FolderM4AdapterContractError("Prepared expected-state digest is invalid.")


class PreparedFolderActionResolver(Protocol):
    """Private store boundary; caller JSON can never construct an action body."""

    def resolve(self, plan: M4ExecutionPlan) -> PreparedChildFolderCreate: ...


class ChildFolderMutationTransport(Protocol):
    """Exact product transport implemented outside the M4 kernel."""

    def read_collection(self) -> Mapping[str, object]: ...

    def create_child(self, body: Mapping[str, object]) -> Mapping[str, object]: ...


class InMemoryPreparedFolderActionResolver:
    """Deterministic test resolver; production must use a protected store."""

    def __init__(self, prepared: PreparedChildFolderCreate) -> None:
        self._prepared = prepared

    def resolve(self, plan: M4ExecutionPlan) -> PreparedChildFolderCreate:
        prepared = self._prepared
        if (
            plan.plan_ref != prepared.plan_ref
            or plan.target_ref != prepared.target_ref
            or plan.parameters_digest != prepared.parameters_digest
            or plan.expected_current_digest != prepared.expected_current_digest
            or plan.expected_state_digest != prepared.expected_state_digest
        ):
            raise M4AdapterDenied("Prepared Folder action binding is unavailable.")
        return prepared


class ChildFolderCreateM4Adapter:
    """One-object read -> create -> readback adapter, not registered by default."""

    def __init__(
        self,
        resolver: PreparedFolderActionResolver,
        transport: ChildFolderMutationTransport,
    ) -> None:
        self._resolver = resolver
        self._transport = transport

    def read_current(self, plan: M4ExecutionPlan) -> str:
        prepared = self._resolve(plan)
        try:
            payload = self._transport.read_collection()
        except (
            M4AdapterDenied,
            M4AdapterTimeout,
            M4AdapterAmbiguous,
            M4AdapterFailure,
        ):
            raise
        except RuntimeError as exc:
            raise M4AdapterFailure("FortiPAM Folder collection read failed.") from exc
        return self._state(prepared, payload).digest()

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        prepared = self._resolve(plan)
        try:
            response = self._transport.create_child(prepared.request.body())
        except (
            M4AdapterDenied,
            M4AdapterTimeout,
            M4AdapterAmbiguous,
            M4AdapterFailure,
        ):
            raise
        except RuntimeError as exc:
            # A POST transport error cannot prove whether FortiPAM committed the
            # object, so it is never downgraded to a declared pre-write failure.
            raise M4AdapterAmbiguous(
                "FortiPAM child Folder create result is unknown."
            ) from exc
        if response.get("http_status") != 200:
            raise M4AdapterFailure("FortiPAM child Folder create failed.")
        mkey = response.get("mkey")
        if isinstance(mkey, float) and mkey.is_integer():
            mkey = int(mkey)
        if type(mkey) is not int or mkey <= 0:
            raise M4AdapterAmbiguous("FortiPAM create response omitted a valid object id.")

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        prepared = self._resolve(plan)
        try:
            payload = self._transport.read_collection()
        except (
            M4AdapterDenied,
            M4AdapterTimeout,
            M4AdapterAmbiguous,
            M4AdapterFailure,
        ):
            raise
        except RuntimeError as exc:
            raise M4AdapterAmbiguous(
                "FortiPAM Folder postcondition read result is unknown."
            ) from exc
        return self._state(prepared, payload).digest()

    def _resolve(self, plan: M4ExecutionPlan) -> PreparedChildFolderCreate:
        if (
            plan.action_id != ACTION_ID
            or plan.action_version != ACTION_VERSION
            or plan.adapter_ref != ADAPTER_REF
        ):
            raise M4AdapterDenied("M4 plan is outside the child Folder adapter contract.")
        return self._resolver.resolve(plan)

    @staticmethod
    def _state(
        prepared: PreparedChildFolderCreate,
        payload: Mapping[str, object],
    ) -> ChildFolderLogicalState:
        request = prepared.request
        if payload.get("http_status") != 200:
            raise M4AdapterFailure("FortiPAM Folder collection read failed.")
        raw_results = payload.get("results")
        if not isinstance(raw_results, Sequence) or isinstance(
            raw_results,
            (str, bytes, bytearray),
        ):
            raise M4AdapterFailure("FortiPAM Folder collection shape is invalid.")
        matches: list[Mapping[str, object]] = []
        for item in raw_results:
            if not isinstance(item, Mapping):
                raise M4AdapterFailure("FortiPAM Folder collection item is invalid.")
            if (
                item.get("name") == request.name
                and item.get("parent-folder") == request.parent_folder_id
            ):
                matches.append(item)
        if not matches:
            return ChildFolderLogicalState.absent(request)
        if len(matches) != 1:
            raise M4AdapterAmbiguous("Folder identity is not unique under the parent.")
        return _project_existing(request, matches[0])


def _project_existing(
    request: FolderCreateRequest,
    item: Mapping[str, object],
) -> ChildFolderLogicalState:
    _require_child_request(request)
    inherit_values: dict[str, str] = {}
    for field in ("inherit-policy", "inherit-permission", "inherit-folder-ztna"):
        value = item.get(field)
        if value not in {"enable", "disable"}:
            raise M4AdapterFailure("FortiPAM Folder inheritance projection is invalid.")
        assert isinstance(value, str)
        inherit_values[field] = value
    counts: dict[str, int | None] = {}
    for field in ("user-permission", "group-permission"):
        value = item.get(field)
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise M4AdapterFailure("FortiPAM Folder permission projection is invalid.")
        if len(value) > 64:
            raise M4AdapterFailure("FortiPAM Folder permission projection exceeds the bound.")
        # FortiPAM expands inherited parent ACL entries into the child readback
        # even though the create request is required to submit empty arrays.
        # Their dynamic count therefore cannot be part of the action's stable
        # postcondition when permission inheritance is enabled.  The adapter
        # still validates the response container and its bounded size.
        counts[field] = (
            None if inherit_values["inherit-permission"] == "enable" else len(value)
        )
    assert request.parent_folder_id is not None
    return ChildFolderLogicalState(
        True,
        request.name,
        request.parent_folder_id,
        inherit_values["inherit-policy"],
        inherit_values["inherit-permission"],
        inherit_values["inherit-folder-ztna"],
        counts["user-permission"],
        counts["group-permission"],
    )


def _require_child_request(request: FolderCreateRequest) -> FolderCreateRequest:
    if not isinstance(request, FolderCreateRequest) or request.placement != "child":
        raise FolderM4AdapterContractError("Only inherited child Folder create is supported.")
    return request


__all__ = [
    "ACTION_ID",
    "ACTION_VERSION",
    "ADAPTER_REF",
    "ChildFolderCreateM4Adapter",
    "ChildFolderLogicalState",
    "ChildFolderMutationTransport",
    "FolderM4AdapterContractError",
    "InMemoryPreparedFolderActionResolver",
    "PreparedChildFolderCreate",
    "PreparedFolderActionResolver",
]
