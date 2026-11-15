"""Explicit private MCP composition for the local-only system-email workflow.

The HTTP app factory accepts an explicitly supplied candidate. Default startup
does not bind it; this registrar supplies no native backend or qualification.
"""
from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from .runtime_profile import RuntimeProfile
from .system_email_local_workflow import Phase,SystemEmailLocalWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR="The private local system-email action is unavailable."


class SystemEmailLocalMcpAction(_OpaqueC3Object):
    def __init__(self,workflow: SystemEmailLocalWorkflow) -> None:
        if type(workflow) is not SystemEmailLocalWorkflow:raise ValueError(_ERROR)
        self._workflow=workflow

    @staticmethod
    def _identity(principal: V4PlanningPrincipal) -> dict[str,str]:
        if type(principal) is not V4PlanningPrincipal:raise ValueError(_ERROR)
        return dict(requester_digest=principal.requester.digest,
            transport_digest=principal.transport_namespace_digest)

    def preview(self,phase: Phase,principal: V4PlanningPrincipal) -> dict[str,object]:
        try:return self._workflow.preview(phase,**self._identity(principal))
        except Exception:raise RuntimeError(_ERROR)from None

    def authorize(self,phase: Phase,preview_ref: str,principal: V4PlanningPrincipal) -> dict[str,object]:
        try:return self._workflow.authorize(phase,preview_ref,**self._identity(principal))
        except Exception:raise RuntimeError(_ERROR)from None

    def execute(self,phase: Phase,authorization_ref: str,principal: V4PlanningPrincipal) -> dict[str,object]:
        try:return self._workflow.execute(phase,authorization_ref,**self._identity(principal))
        except Exception:raise RuntimeError(_ERROR)from None

    def outcome(self,principal: V4PlanningPrincipal) -> dict[str,object]:
        try:return self._workflow.outcome(**self._identity(principal))
        except Exception:raise RuntimeError(_ERROR)from None


def register_system_email_local_candidate_tools(server: Any,action: SystemEmailLocalMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,LOCAL_STATE_TOOL_ANNOTATIONS,READ_ONLY_TOOL_ANNOTATIONS

    if (type(action) is not SystemEmailLocalMcpAction
            or getattr(server,"_runtime_profile",None)is not RuntimeProfile.V4_CONTROLLED):
        raise ValueError(_ERROR)

    def register(phase: Phase) -> None:
        suffix=phase.replace('-','_')
        async def preview() -> dict[str,object]:
            return await asyncio.to_thread(action.preview,phase,server._v4_planning_principal())

        async def authorize(preview_ref: str) -> dict[str,object]:
            return await asyncio.to_thread(action.authorize,phase,preview_ref,
                server._v4_secret_metadata_action_principal())

        async def execute(authorization_ref: str) -> dict[str,object]:
            return await asyncio.to_thread(action.execute,phase,authorization_ref,
                server._v4_secret_metadata_action_principal())

        server.mcp.tool(name=f"preview_v4_system_email_local_{suffix}_700",
            description="Preview the private local-only system-email protocol, without native backend qualification.",
            annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview)
        server.mcp.tool(name=f"authorize_v4_system_email_local_{suffix}_700",
            description="Request independent authorization for the local-only candidate protocol.",
            annotations=LOCAL_STATE_TOOL_ANNOTATIONS)(authorize)
        server.mcp.tool(name=f"execute_v4_system_email_local_{suffix}_700",
            description="Exercise one local candidate phase; this registrar supplies no native SMTP backend.",
            annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)(execute)

    register("update");register("restore")
    if action._workflow.has_delivery:register("test-delivery")

    async def outcome() -> dict[str,object]:
        return await asyncio.to_thread(action.outcome,server._v4_planning_principal())
    server.mcp.tool(name="get_v4_system_email_local_outcome_700",
        description="Read local owned phase outcomes without native delivery qualification or redispatch.",
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(outcome)
