"""Opaque-reference OAuth/MCP surface for one native encrypted backup creation."""
from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object
from .backup_export_workflow import BackupExportWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = "FortiPAM encrypted backup action is unavailable."


class BackupExportMcpAction(_OpaqueC3Object):
    def __init__(self, workflow: BackupExportWorkflow) -> None:
        if type(workflow) is not BackupExportWorkflow:
            raise ValueError(_ERROR)
        self._workflow = workflow

    def call(self, phase: str, operation: str, principal: V4PlanningPrincipal,
             reference: str | None = None) -> dict[str, object]:
        try:
            if type(principal) is not V4PlanningPrincipal:
                raise ValueError
            identity = dict(requester_digest=principal.requester.digest,
                            transport_digest=principal.transport_namespace_digest)
            if operation == "preview" and reference is None:
                return self._workflow.preview(phase, **identity)
            if operation == "authorize" and type(reference) is str:
                return self._workflow.authorize(phase, reference, **identity)
            if operation == "execute" and type(reference) is str:
                return self._workflow.execute(phase, reference, **identity)
            raise ValueError
        except Exception:
            raise RuntimeError(_ERROR) from None


def register_backup_export_candidate_tools(server: Any, action: BackupExportMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS

    if type(action) is not BackupExportMcpAction:
        raise ValueError(_ERROR)

    def register(phase: str) -> None:
        async def preview() -> dict[str, object]:
            return await asyncio.to_thread(action.call, phase, "preview", server._v4_planning_principal())

        async def authorize(preview_ref: str) -> dict[str, object]:
            return await asyncio.to_thread(action.call, phase, "authorize",
                server._v4_secret_metadata_action_principal(), preview_ref)

        async def execute(authorization_ref: str) -> dict[str, object]:
            return await asyncio.to_thread(action.call, phase, "execute",
                server._v4_secret_metadata_action_principal(), authorization_ref)

        server.mcp.tool(name=f"preview_v4_backup_export_{phase}_700", annotations=READ_ONLY_TOOL_ANNOTATIONS,
            description="Preview one fixed connected encrypted backup phase and native preservation checks.")(preview)
        server.mcp.tool(name=f"authorize_v4_backup_export_{phase}_700", annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
            description="Authorize one fixed encrypted backup phase under the authenticated operator's standing lab policy.")(authorize)
        server.mcp.tool(name=f"execute_v4_backup_export_{phase}_700", annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
            description="Execute one encrypted backup phase with durable M4 and categorical artifact integrity readback.")(execute)

    register("create")
