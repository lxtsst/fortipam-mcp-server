from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from fortipam_mcp.folder_create_contract import FolderCreateRequest
from fortipam_mcp.folder_m4_adapter import (
    ACTION_ID,
    ACTION_VERSION,
    ADAPTER_REF,
    ChildFolderCreateM4Adapter,
    FolderM4AdapterContractError,
    InMemoryPreparedFolderActionResolver,
    PreparedChildFolderCreate,
)
from v4_planning import (
    M4AdapterAmbiguous,
    M4AdapterDenied,
    M4AdapterFailure,
    M4ExecutionPlan,
    canonical_digest,
)


NOW = 1_000
DIGESTS = {
    "requester_digest": "a" * 64,
    "summary_digest": "b" * 64,
    "confirmation_digest": "c" * 64,
    "approval_digest": "d" * 64,
    "idempotency_digest": "e" * 64,
}


class _Transport:
    def __init__(self, request: FolderCreateRequest) -> None:
        self.request = request
        self.exists = False
        self.duplicate = False
        self.calls: list[str] = []
        self.create_response: dict[str, object] = {"http_status": 200, "mkey": 77}
        self.user_permissions: list[dict[str, object]] = []
        self.group_permissions: list[dict[str, object]] = []

    def read_collection(self) -> dict[str, object]:
        self.calls.append("read")
        results: list[dict[str, object]] = []
        if self.exists:
            item = {
                "id": 77,
                "name": self.request.name,
                "parent-folder": self.request.parent_folder_id,
                "inherit-policy": "enable",
                "inherit-permission": "enable",
                "inherit-folder-ztna": "enable",
                "user-permission": list(self.user_permissions),
                "group-permission": list(self.group_permissions),
                "ignored-product-field": "never-projected",
            }
            results.append(item)
            if self.duplicate:
                results.append(dict(item, id=78))
        return {"http_status": 200, "results": results}

    def create_child(self, body: object) -> dict[str, object]:
        self.calls.append("create")
        assert body == self.request.body()
        self.exists = True
        return dict(self.create_response)


def _prepared() -> PreparedChildFolderCreate:
    return PreparedChildFolderCreate.build(
        plan_ref="folder-plan-reference-01",
        target_ref="folder-target-reference-01",
        request=FolderCreateRequest.child("V4-Demo", 17),
    )


def _plan(prepared: PreparedChildFolderCreate) -> M4ExecutionPlan:
    values = {
        "action_id": ACTION_ID,
        "action_version": ACTION_VERSION,
        "adapter_ref": ADAPTER_REF,
        "approval_digest": DIGESTS["approval_digest"],
        "compensation_ref": None,
        "confirmation_digest": DIGESTS["confirmation_digest"],
        "expected_current_digest": prepared.expected_current_digest,
        "expected_state_digest": prepared.expected_state_digest,
        "expires_at": NOW + 300,
        "idempotency_digest": DIGESTS["idempotency_digest"],
        "parameters_digest": prepared.parameters_digest,
        "plan_ref": prepared.plan_ref,
        "requester_digest": DIGESTS["requester_digest"],
        "revision": 1,
        "summary_digest": DIGESTS["summary_digest"],
        "target_ref": prepared.target_ref,
    }
    return M4ExecutionPlan(
        plan_ref=prepared.plan_ref,
        revision=1,
        action_id=ACTION_ID,
        action_version=ACTION_VERSION,
        adapter_ref=ADAPTER_REF,
        target_ref=prepared.target_ref,
        requester_digest=DIGESTS["requester_digest"],
        summary_digest=DIGESTS["summary_digest"],
        confirmation_digest=DIGESTS["confirmation_digest"],
        approval_digest=DIGESTS["approval_digest"],
        parameters_digest=prepared.parameters_digest,
        expected_current_digest=prepared.expected_current_digest,
        expected_state_digest=prepared.expected_state_digest,
        idempotency_digest=DIGESTS["idempotency_digest"],
        expires_at=NOW + 300,
        compensation_ref=None,
        plan_digest=canonical_digest(values),
    )


def test_adapter_is_exact_read_create_readback_contract() -> None:
    prepared = _prepared()
    transport = _Transport(prepared.request)
    adapter = ChildFolderCreateM4Adapter(
        InMemoryPreparedFolderActionResolver(prepared),
        transport,
    )
    plan = _plan(prepared)

    assert adapter.read_current(plan) == prepared.expected_current_digest
    adapter.dispatch(plan)
    assert adapter.read_postcondition(plan) == prepared.expected_state_digest
    assert transport.calls == ["read", "create", "read"]


def test_inherited_acl_expansion_is_not_part_of_the_stable_postcondition() -> None:
    prepared = _prepared()
    transport = _Transport(prepared.request)
    transport.exists = True
    transport.user_permissions = [{"name": "owner"}, {"name": "api-user"}]
    transport.group_permissions = [
        {"name": "admins"},
        {"name": "users"},
        {"name": "remote-users"},
    ]
    adapter = ChildFolderCreateM4Adapter(
        InMemoryPreparedFolderActionResolver(prepared),
        transport,
    )

    assert adapter.read_postcondition(_plan(prepared)) == prepared.expected_state_digest


def test_existing_folder_produces_drift_digest() -> None:
    prepared = _prepared()
    transport = _Transport(prepared.request)
    transport.exists = True
    adapter = ChildFolderCreateM4Adapter(InMemoryPreparedFolderActionResolver(prepared), transport)

    assert adapter.read_current(_plan(prepared)) != prepared.expected_current_digest
    assert transport.calls == ["read"]


def test_duplicate_folder_identity_is_ambiguous() -> None:
    prepared = _prepared()
    transport = _Transport(prepared.request)
    transport.exists = True
    transport.duplicate = True
    adapter = ChildFolderCreateM4Adapter(InMemoryPreparedFolderActionResolver(prepared), transport)

    with pytest.raises(M4AdapterAmbiguous):
        adapter.read_current(_plan(prepared))


@pytest.mark.parametrize(
    "response,error",
    [
        ({"http_status": 403}, M4AdapterFailure),
        ({"http_status": 200}, M4AdapterAmbiguous),
        ({"http_status": 200, "mkey": 0}, M4AdapterAmbiguous),
    ],
)
def test_dispatch_response_fails_closed(
    response: dict[str, object],
    error: type[Exception],
) -> None:
    prepared = _prepared()
    transport = _Transport(prepared.request)
    transport.create_response = response
    adapter = ChildFolderCreateM4Adapter(InMemoryPreparedFolderActionResolver(prepared), transport)

    with pytest.raises(error):
        adapter.dispatch(_plan(prepared))


def test_plan_or_private_binding_drift_is_denied() -> None:
    prepared = _prepared()
    transport = _Transport(prepared.request)
    adapter = ChildFolderCreateM4Adapter(InMemoryPreparedFolderActionResolver(prepared), transport)
    plan = _plan(prepared)
    changed_values = dict(plan.canonical_content())
    changed_values["adapter_ref"] = "another-fixed-adapter-ref"
    changed = replace(
        plan,
        adapter_ref="another-fixed-adapter-ref",
        plan_digest=canonical_digest(changed_values),
    )

    with pytest.raises(M4AdapterDenied):
        adapter.read_current(changed)
    assert transport.calls == []


def test_prepared_action_rejects_root_or_digest_drift() -> None:
    with pytest.raises(FolderM4AdapterContractError):
        PreparedChildFolderCreate.build(
            plan_ref="folder-plan-reference-01",
            target_ref="folder-target-reference-01",
            request=FolderCreateRequest.root("V4-Demo"),
        )
    prepared = _prepared()
    with pytest.raises(FolderM4AdapterContractError, match="parameters"):
        replace(prepared, parameters_digest="f" * 64)


def test_adapter_source_has_no_transport_implementation_or_mcp_registration() -> None:
    source = (
        Path(__file__).parents[1]
        / "src"
        / "fortipam_mcp"
        / "folder_m4_adapter.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "import httpx",
        "import requests",
        "from mcp",
        "@mcp.tool",
        "Authorization",
        "/api/v2/",
    ):
        assert forbidden not in source
