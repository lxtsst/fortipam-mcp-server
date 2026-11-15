"""Explicit-only MCP candidate for fixed Secret DLP association and owned restore."""
from __future__ import annotations

import asyncio
import re
from typing import Any, Literal

from .secret_dlp_association_live_workflow import CONTRACT, SecretDlpAssociationLiveWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

Operation = Literal["associate", "restore"]
UNAVAILABLE = "FortiPAM fixed Secret DLP association action is unavailable."
ASSOCIATION_TOOLS = frozenset({"preview_v4_secret_dlp_association_700",
    "confirm_v4_secret_dlp_association_700", "execute_confirmed_v4_secret_dlp_association_700"})
RESTORE_TOOLS = frozenset({"preview_v4_secret_dlp_association_restore_700",
    "confirm_v4_secret_dlp_association_restore_700", "execute_confirmed_v4_secret_dlp_association_restore_700"})


class SecretDlpAssociationMcpActionError(RuntimeError):
    """Categorical boundary failure without protected upstream details."""


def valid_secret_dlp_ref(value: object, operation: Operation, kind: str) -> bool:
    return type(value) is str and len(value) <= 128 and re.fullmatch(
        rf"secret-dlp-{operation}-{kind}-[A-Za-z0-9_-]+", value,
    ) is not None


def _exact(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(actual, dict)
        return set(actual) == set(expected) and all(_exact(actual[key], value) for key, value in expected.items())
    return bool(actual == expected)


def validate_secret_dlp_preview(value: Any, operation: Operation) -> dict[str, object]:
    if (type(value) is not dict or set(value) != {"contract", "preview_ref", "expires_at",
            "Current State", "Proposed Changes", "Expected State", "device_write_executed"}
        or not valid_secret_dlp_ref(value.get("preview_ref"), operation, "preview")
        or type(value.get("expires_at")) is not int or value["expires_at"] <= 0
        or not _exact(value, {"contract": CONTRACT, "preview_ref": value["preview_ref"],
            "expires_at": value["expires_at"],
            "Current State": {"dlp": "disabled_without_sensor" if operation == "associate" else "enabled_with_owned_sensor",
                "secret_prerequisites": "matched", "sensor_native_profile": "matched",
                "preservation_baseline": "bound", "opaque_fields": "privately_witnessed"},
            "Proposed Changes": {"operation": operation, "other_secret_fields": "preserve"},
            "Expected State": {"dlp": "enabled_with_fixed_log_only_sensor" if operation == "associate" else "disabled_without_sensor",
                "metadata_and_opaque_fields": "unchanged", "file_audit_effect": "unproven"},
            "device_write_executed": False})):
        raise SecretDlpAssociationMcpActionError(UNAVAILABLE)
    return dict(value)


def validate_secret_dlp_confirmation(value: Any, operation: Operation, preview_ref: str) -> dict[str, object]:
    if (not valid_secret_dlp_ref(preview_ref, operation, "preview") or type(value) is not dict
        or set(value) != {"contract", "preview_ref", "authorization_ref", "confirmation",
                         "execution", "expires_at", "device_write_executed"}
        or not valid_secret_dlp_ref(value.get("authorization_ref"), operation, "authorized")
        or type(value.get("expires_at")) is not int or value["expires_at"] <= 0
        or not _exact(value, {"contract": CONTRACT, "preview_ref": preview_ref,
            "authorization_ref": value["authorization_ref"], "confirmation": "recorded",
            "execution": "authorized_once", "expires_at": value["expires_at"], "device_write_executed": False})):
        raise SecretDlpAssociationMcpActionError(UNAVAILABLE)
    return dict(value)


def validate_secret_dlp_result(value: Any, operation: Operation, *, require_success: bool = False) -> dict[str, object]:
    if (type(value) is not dict or set(value) != {"contract", "operation", "outcome", "verification",
            "idempotent_replay", "device_write_may_have_occurred", "credential_values_returned",
            "raw_api_response_returned", "file_audit_effect"}
        or type(value.get("outcome")) is not str
        or value.get("outcome") not in {"succeeded", "not_executed", "reconciliation_required"}
        or type(value.get("idempotent_replay")) is not bool
        or type(value.get("device_write_may_have_occurred")) is not bool
        or not _exact(value, {"contract": CONTRACT, "operation": operation, "outcome": value["outcome"],
            "verification": "verified" if value["outcome"] == "succeeded" else "unknown",
            "idempotent_replay": value["idempotent_replay"],
            "device_write_may_have_occurred": value["device_write_may_have_occurred"],
            "credential_values_returned": False, "raw_api_response_returned": False,
            "file_audit_effect": "unproven"})
        or (require_success and (value["outcome"] != "succeeded" or value["idempotent_replay"] is not False
                                 or value["device_write_may_have_occurred"] is not True))):
        raise SecretDlpAssociationMcpActionError(UNAVAILABLE)
    return dict(value)


def _requester(principal: Any) -> str:
    if not isinstance(principal, V4PlanningPrincipal):
        raise SecretDlpAssociationMcpActionError(UNAVAILABLE)
    digest = principal.requester.digest
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise SecretDlpAssociationMcpActionError(UNAVAILABLE)
    return digest


class SecretDlpAssociationMcpAction:
    """No loader: only the caller's explicit, private same-instance workflow."""
    def __init__(self, workflow: SecretDlpAssociationLiveWorkflow, *, execution_enabled: bool = False) -> None:
        if type(workflow) is not SecretDlpAssociationLiveWorkflow or type(execution_enabled) is not bool:
            raise SecretDlpAssociationMcpActionError(UNAVAILABLE)
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview_association(self, principal: Any) -> dict[str, object]:
        return self._preview("associate", principal)

    def preview_restore(self, principal: Any) -> dict[str, object]:
        return self._preview("restore", principal)

    def _preview(self, operation: Operation, principal: Any) -> dict[str, object]:
        try:
            method = self._workflow.preview_association if operation == "associate" else self._workflow.preview_restore
            return validate_secret_dlp_preview(method(requester_digest=_requester(principal)), operation)
        except Exception:
            raise SecretDlpAssociationMcpActionError(UNAVAILABLE) from None

    def confirm_association(self, preview_ref: str, principal: Any) -> dict[str, object]:
        return self._confirm("associate", preview_ref, principal)

    def confirm_restore(self, preview_ref: str, principal: Any) -> dict[str, object]:
        return self._confirm("restore", preview_ref, principal)

    def _confirm(self, operation: Operation, preview_ref: str, principal: Any) -> dict[str, object]:
        try:
            if not valid_secret_dlp_ref(preview_ref, operation, "preview"):
                raise ValueError
            result = self._workflow.confirm(preview_ref, requester_digest=_requester(principal))
            return validate_secret_dlp_confirmation(result, operation, preview_ref)
        except Exception:
            raise SecretDlpAssociationMcpActionError(UNAVAILABLE) from None

    def execute_association(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        return self._execute("associate", authorization_ref, principal)

    def execute_restore(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        return self._execute("restore", authorization_ref, principal)

    def _execute(self, operation: Operation, authorization_ref: str, principal: Any) -> dict[str, object]:
        try:
            if not self._execution_enabled or not valid_secret_dlp_ref(authorization_ref, operation, "authorized"):
                raise ValueError
            result = self._workflow.execute(authorization_ref, requester_digest=_requester(principal))
            return validate_secret_dlp_result(result, operation)
        except Exception:
            raise SecretDlpAssociationMcpActionError(UNAVAILABLE) from None


def register_secret_dlp_association_candidate_tools(server: Any, action: SecretDlpAssociationMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS

    @server.mcp.tool(description="Preview the fixed private-bound Secret log-only DLP association; no write.",
                     annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_secret_dlp_association_700() -> dict[str, object]:
        return await asyncio.to_thread(action.preview_association, server._v4_planning_principal())

    @server.mcp.tool(description="Confirm one unchanged fixed Secret DLP association preview; no write.",
                     annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_secret_dlp_association_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.confirm_association, preview_ref, server._v4_secret_metadata_action_principal())

    @server.mcp.tool(description="Execute one confirmed fixed Secret DLP association and categorical readback.",
                     annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_secret_dlp_association_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.execute_association, authorization_ref, server._v4_secret_metadata_action_principal())

    @server.mcp.tool(description="Preview separate same-creator owned restoration of the fixed Secret DLP baseline; no write.",
                     annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_secret_dlp_association_restore_700() -> dict[str, object]:
        return await asyncio.to_thread(action.preview_restore, server._v4_planning_principal())

    @server.mcp.tool(description="Confirm one unchanged separately previewed owned Secret DLP restoration; no write.",
                     annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_secret_dlp_association_restore_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.confirm_restore, preview_ref, server._v4_secret_metadata_action_principal())

    @server.mcp.tool(description="Execute one separately confirmed owned Secret DLP baseline restoration and readback.",
                     annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_secret_dlp_association_restore_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.execute_restore, authorization_ref, server._v4_secret_metadata_action_principal())
