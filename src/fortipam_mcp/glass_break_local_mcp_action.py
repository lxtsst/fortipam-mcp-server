"""Optional controlled-OAuth tools for fixed local activation/independent exit."""
from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object
from .glass_break_local_workflow import GlassBreakLocalWorkflow,Phase
from .runtime_profile import RuntimeProfile
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = 'The private glass-breaking local action is unavailable.'


class GlassBreakLocalMcpAction(_OpaqueC3Object):
    def __init__(self, workflow: GlassBreakLocalWorkflow) -> None:
        if type(workflow) is not GlassBreakLocalWorkflow: raise ValueError(_ERROR)
        self._workflow=workflow

    @staticmethod
    def _identity(principal: V4PlanningPrincipal) -> dict[str,str]:
        if type(principal) is not V4PlanningPrincipal: raise ValueError(_ERROR)
        return dict(requester_digest=principal.requester.digest,transport_digest=principal.transport_namespace_digest)

    def preview(self, phase: Phase, principal: V4PlanningPrincipal) -> dict[str,object]:
        try: return self._workflow.preview(phase,**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def authorize(self, reference: str, principal: V4PlanningPrincipal) -> dict[str,object]:
        try: return self._workflow.authorize(reference,**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def execute(self, reference: str, principal: V4PlanningPrincipal) -> dict[str,object]:
        try: return self._workflow.execute(reference,**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def outcome(self, principal: V4PlanningPrincipal) -> dict[str,object]:
        try: return self._workflow.outcome(**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None


def register_glass_break_local_candidate_tools(server: Any, action: GlassBreakLocalMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,LOCAL_STATE_TOOL_ANNOTATIONS,READ_ONLY_TOOL_ANNOTATIONS
    if type(action) is not GlassBreakLocalMcpAction or getattr(server,'_runtime_profile',None) is not RuntimeProfile.V4_CONTROLLED:
        raise ValueError(_ERROR)
    async def preview(phase: Phase) -> dict[str,object]:
        return await asyncio.to_thread(action.preview,phase,server._v4_planning_principal())
    async def authorize(preview_ref: str) -> dict[str,object]:
        return await asyncio.to_thread(action.authorize,preview_ref,server._v4_secret_metadata_action_principal())
    async def execute(authorization_ref: str) -> dict[str,object]:
        return await asyncio.to_thread(action.execute,authorization_ref,server._v4_secret_metadata_action_principal())
    async def outcome() -> dict[str,object]:
        return await asyncio.to_thread(action.outcome,server._v4_planning_principal())
    server.mcp.tool(name='preview_v4_glass_break_step_local_700',description='Preview fixed local activation or independent exit; no reason, actor or credential input.',
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview)
    server.mcp.tool(name='authorize_v4_glass_break_step_local_700',description='Request separate protected lab authorization for one owned preview; cannot issue grants or native qualification.',
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS)(authorize)
    server.mcp.tool(name='execute_v4_glass_break_step_local_700',description='Execute one exact owned authorization; native scope and qualification remain pending, and late exit does not verify duration.',
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)(execute)
    server.mcp.tool(name='get_v4_glass_break_local_outcome_700',description='Read owned local outcomes/timing without actor reads, grants, login/logout or redispatch.',
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(outcome)
