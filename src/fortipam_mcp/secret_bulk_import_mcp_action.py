"""Opaque-reference MCP entry for one original, fixed Text import batch."""

from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from .secret_bulk_import_text_batch_owner import _OriginalTextBatchOwner
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = "FortiPAM Text import action is unavailable."


class SecretBulkImportMcpAction(_OpaqueC3Object):
    def __init__(self, workflow: _OriginalTextBatchOwner) -> None:
        if type(workflow) is not _OriginalTextBatchOwner:
            raise ValueError(_ERROR)
        self._workflow = workflow

    def call(self, operation: str, principal: V4PlanningPrincipal,
             reference: str | None = None) -> dict[str, object]:
        try:
            if type(principal) is not V4PlanningPrincipal:
                raise ValueError
            identity = dict(requester_digest=principal.requester.digest,
                            transport_digest=principal.transport_namespace_digest)
            if operation == "preview" and reference is None:
                return self._workflow.preview(**identity)
            if operation == "authorize" and type(reference) is str:
                return self._workflow.authorize(reference, **identity)
            if operation == "execute" and type(reference) is str:
                return self._workflow.execute_once(reference, **identity)
            raise ValueError
        except Exception:
            raise RuntimeError(_ERROR) from None


def register_secret_bulk_import_candidate_tools(
    server: Any, action: SecretBulkImportMcpAction,
) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    if type(action) is not SecretBulkImportMcpAction:
        raise ValueError(_ERROR)

    async def preview() -> dict[str, object]:
        return await asyncio.to_thread(
            action.call, "preview", server._v4_planning_principal())

    async def authorize(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(
            action.call, "authorize", server._v4_secret_metadata_action_principal(), preview_ref)

    async def execute(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(
            action.call, "execute", server._v4_secret_metadata_action_principal(), authorization_ref)

    server.mcp.tool(
        name="preview_v4_secret_bulk_import_text_700",
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
        description="Preview one retained Text import batch and its fixed native preservation checks.",
    )(preview)
    server.mcp.tool(
        name="authorize_v4_secret_bulk_import_text_700",
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Authorize the original Text rows under the fixed lab policy and independent row permissions.",
    )(authorize)
    server.mcp.tool(
        name="execute_v4_secret_bulk_import_text_700",
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        description="Execute the original Text batch once with per-row M4, material release and native readback.",
    )(execute)
