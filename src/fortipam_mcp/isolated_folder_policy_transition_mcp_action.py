"""Explicit-only MCP candidate for one fixed isolated Folder Policy transition."""
from __future__ import annotations

import asyncio
import re
from typing import Any, Callable, Literal

from .isolated_folder_policy_transition_live_workflow import (
    CONTRACT, IsolatedFolderPolicyTransitionLiveWorkflow,
)
from .v4_plan_runtime import V4PlanningPrincipal

Operation = Literal["assign", "restore"]
UNAVAILABLE = "FortiPAM fixed isolated Folder Policy transition action is unavailable."
ASSIGN_TOOLS = frozenset({"preview_v4_isolated_folder_policy_transition_700",
    "confirm_v4_isolated_folder_policy_transition_700",
    "execute_confirmed_v4_isolated_folder_policy_transition_700"})
RESTORE_TOOLS = frozenset({"preview_v4_isolated_folder_policy_transition_restore_700",
    "confirm_v4_isolated_folder_policy_transition_restore_700",
    "execute_confirmed_v4_isolated_folder_policy_transition_restore_700"})
TOOLS = ASSIGN_TOOLS | RESTORE_TOOLS


class IsolatedFolderPolicyTransitionMcpActionError(RuntimeError):
    """Categorical boundary refusal without protected upstream details."""


def valid_isolated_folder_policy_transition_ref(value: object, operation: Operation, kind: str) -> bool:
    return (operation in {"assign", "restore"} and kind in {"preview", "authorized"}
        and type(value) is str and len(value) <= 128 and re.fullmatch(
            rf"isolated-folder-policy-{operation}-{kind}-[A-Za-z0-9_-]+", value,
        ) is not None)


def _exact(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(actual, dict)
        return set(actual) == set(expected) and all(_exact(actual[key], value) for key, value in expected.items())
    return bool(actual == expected)


def validate_isolated_folder_policy_transition_preview(value: Any, operation: Operation) -> dict[str, object]:
    if (type(value) is not dict or set(value) != {"contract", "preview_ref", "expires_at",
            "Current State", "Proposed Changes", "Expected State", "device_write_executed"}
        or not valid_isolated_folder_policy_transition_ref(value.get("preview_ref"), operation, "preview")
        or type(value.get("expires_at")) is not int or value["expires_at"] <= 0
        or not _exact(value, {"contract": CONTRACT, "preview_ref": value["preview_ref"],
            "expires_at": value["expires_at"],
            "Current State": {"creation_ownership_bound": True, "single_secret_verified": True,
                "no_child_folders_verified": True, "policy_inheritance_enabled": operation == "assign"},
            "Proposed Changes": {"operation": operation, "other_fields_preserved": True},
            "Expected State": {"policy_inheritance_enabled": operation == "restore",
                "fixed_policy_relation_enabled": operation == "assign", "single_secret_scope_preserved": True,
                "owner_only_preserved": True}, "device_write_executed": False})):
        raise IsolatedFolderPolicyTransitionMcpActionError(UNAVAILABLE)
    return dict(value)


def validate_isolated_folder_policy_transition_confirmation(
    value: Any, operation: Operation, preview_ref: str,
) -> dict[str, object]:
    if (not valid_isolated_folder_policy_transition_ref(preview_ref, operation, "preview")
        or type(value) is not dict or set(value) != {"contract", "preview_ref", "authorization_ref",
            "confirmation", "execution", "expires_at", "device_write_executed"}
        or not valid_isolated_folder_policy_transition_ref(value.get("authorization_ref"), operation, "authorized")
        or type(value.get("expires_at")) is not int or value["expires_at"] <= 0
        or not _exact(value, {"contract": CONTRACT, "preview_ref": preview_ref,
            "authorization_ref": value["authorization_ref"], "confirmation": "recorded",
            "execution": "authorized_once", "expires_at": value["expires_at"], "device_write_executed": False})):
        raise IsolatedFolderPolicyTransitionMcpActionError(UNAVAILABLE)
    return dict(value)


def validate_isolated_folder_policy_transition_result(
    value: Any, operation: Operation, *, require_success: bool = False,
) -> dict[str, object]:
    if (operation not in {"assign", "restore"} or type(value) is not dict
        or set(value) != {"contract", "operation", "outcome", "verification", "idempotent_replay",
            "device_write_may_have_occurred", "private_snapshot_returned", "folder_or_secret_ids_returned",
            "raw_api_response_returned"}
        or type(value.get("outcome")) is not str
        or value.get("outcome") not in {"succeeded", "not_executed", "reconciliation_required"}
        or type(value.get("idempotent_replay")) is not bool
        or not _exact(value, {"contract": CONTRACT, "operation": operation, "outcome": value["outcome"],
            "verification": "verified" if value["outcome"] == "succeeded" else "unknown",
            "idempotent_replay": value["idempotent_replay"],
            "device_write_may_have_occurred": value["outcome"] != "not_executed",
            "private_snapshot_returned": False, "folder_or_secret_ids_returned": False,
            "raw_api_response_returned": False})
        or (require_success and (value["outcome"] != "succeeded" or value["idempotent_replay"] is not False))):
        raise IsolatedFolderPolicyTransitionMcpActionError(UNAVAILABLE)
    return dict(value)


def _requester(principal: Any) -> str:
    if not isinstance(principal, V4PlanningPrincipal):
        raise IsolatedFolderPolicyTransitionMcpActionError(UNAVAILABLE)
    digest = principal.requester.digest
    if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise IsolatedFolderPolicyTransitionMcpActionError(UNAVAILABLE)
    return digest


class IsolatedFolderPolicyTransitionMcpAction:
    """No loader: only the caller's explicit private same-instance workflow."""

    def __init__(self, workflow: IsolatedFolderPolicyTransitionLiveWorkflow, *, execution_enabled: bool = False) -> None:
        if type(workflow) is not IsolatedFolderPolicyTransitionLiveWorkflow or type(execution_enabled) is not bool:
            raise IsolatedFolderPolicyTransitionMcpActionError(UNAVAILABLE)
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview_transition(self, principal: Any) -> dict[str, object]:
        return self._preview("assign", principal)

    def preview_restore(self, principal: Any) -> dict[str, object]:
        return self._preview("restore", principal)

    def _preview(self, operation: Operation, principal: Any) -> dict[str, object]:
        try:
            self._workflow.check_bound_principal(principal)
            method = self._workflow.preview_transition if operation == "assign" else self._workflow.preview_restore
            return validate_isolated_folder_policy_transition_preview(method(requester_digest=_requester(principal)), operation)
        except Exception:
            raise IsolatedFolderPolicyTransitionMcpActionError(UNAVAILABLE) from None

    def confirm_transition(self, preview_ref: str, principal: Any) -> dict[str, object]:
        return self._confirm("assign", preview_ref, principal)

    def confirm_restore(self, preview_ref: str, principal: Any) -> dict[str, object]:
        return self._confirm("restore", preview_ref, principal)

    def _confirm(self, operation: Operation, preview_ref: str, principal: Any) -> dict[str, object]:
        try:
            self._workflow.check_bound_principal(principal)
            if not valid_isolated_folder_policy_transition_ref(preview_ref, operation, "preview"):
                raise ValueError
            result = self._workflow.confirm(preview_ref, requester_digest=_requester(principal))
            return validate_isolated_folder_policy_transition_confirmation(result, operation, preview_ref)
        except Exception:
            raise IsolatedFolderPolicyTransitionMcpActionError(UNAVAILABLE) from None

    def execute_transition(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        return self._execute("assign", authorization_ref, principal)

    def execute_restore(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        return self._execute("restore", authorization_ref, principal)

    def _execute(self, operation: Operation, authorization_ref: str, principal: Any) -> dict[str, object]:
        try:
            self._workflow.check_bound_principal(principal)
            if not self._execution_enabled or not valid_isolated_folder_policy_transition_ref(authorization_ref, operation, "authorized"):
                raise ValueError
            result = self._workflow.execute(authorization_ref, requester_digest=_requester(principal))
            return validate_isolated_folder_policy_transition_result(result, operation)
        except Exception:
            raise IsolatedFolderPolicyTransitionMcpActionError(UNAVAILABLE) from None


def register_isolated_folder_policy_transition_candidate_tools(
    server: Any, action: IsolatedFolderPolicyTransitionMcpAction,
) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS

    if type(action) is not IsolatedFolderPolicyTransitionMcpAction:
        raise IsolatedFolderPolicyTransitionMcpActionError(UNAVAILABLE)

    async def invoke(method: Callable[..., dict[str, object]], *args: str, preview: bool = False) -> dict[str, object]:
        try:
            principal = server._v4_planning_principal() if preview else server._v4_folder_action_principal()
            return await asyncio.to_thread(lambda: method(*args, principal))
        except Exception:
            raise IsolatedFolderPolicyTransitionMcpActionError(UNAVAILABLE) from None

    @server.mcp.tool(description="Preview the fixed privately bound isolated Folder Policy assignment; no write.",
                     annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_isolated_folder_policy_transition_700() -> dict[str, object]:
        return await invoke(action.preview_transition, preview=True)

    @server.mcp.tool(description="Confirm one unchanged fixed isolated Folder Policy assignment preview; no write.",
                     annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_isolated_folder_policy_transition_700(preview_ref: str) -> dict[str, object]:
        return await invoke(action.confirm_transition, preview_ref)

    @server.mcp.tool(description="Execute one confirmed fixed isolated Folder Policy assignment and categorical readback.",
                     annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_isolated_folder_policy_transition_700(authorization_ref: str) -> dict[str, object]:
        return await invoke(action.execute_transition, authorization_ref)

    @server.mcp.tool(description="Preview separate same-creator owned restoration of the fixed isolated Folder Policy baseline; no write.",
                     annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_isolated_folder_policy_transition_restore_700() -> dict[str, object]:
        return await invoke(action.preview_restore, preview=True)

    @server.mcp.tool(description="Confirm one unchanged separately previewed owned isolated Folder Policy restoration; no write.",
                     annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_isolated_folder_policy_transition_restore_700(preview_ref: str) -> dict[str, object]:
        return await invoke(action.confirm_restore, preview_ref)

    @server.mcp.tool(description="Execute one separately confirmed owned isolated Folder Policy baseline restoration and readback.",
                     annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_isolated_folder_policy_transition_restore_700(authorization_ref: str) -> dict[str, object]:
        return await invoke(action.execute_restore, authorization_ref)

    # Explicit candidates can be registered after the host's hardening pass.
    # The existing host wrapper sanitizes validation errors without values.
    try:
        for name in TOOLS:
            tool = server.mcp._tool_manager.get_tool(name)
            model = tool.fn_metadata.arg_model
            model.model_config["extra"] = "forbid"
            model.model_rebuild(force=True)
            schema = model.model_json_schema()
            if schema.get("additionalProperties") is not False:
                raise ValueError
            tool.parameters = schema
    except Exception:
        raise IsolatedFolderPolicyTransitionMcpActionError(UNAVAILABLE) from None
