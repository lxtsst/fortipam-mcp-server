"""Explicit controlled-OAuth factory injection for a fixed local JIT workflow."""
from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object
from .runtime_profile import RuntimeProfile
from .v4_plan_runtime import V4PlanningPrincipal
from .windows_jit_local_workflow import PHASES, Phase, WindowsJitLocalWorkflow

_ERROR = 'The private Windows JIT local action is unavailable.'


class WindowsJitLocalMcpAction(_OpaqueC3Object):
    def __init__(self, workflow: WindowsJitLocalWorkflow) -> None:
        if type(workflow) is not WindowsJitLocalWorkflow: raise ValueError(_ERROR)
        self._workflow = workflow

    @staticmethod
    def _identity(principal: V4PlanningPrincipal) -> dict[str,str]:
        if type(principal) is not V4PlanningPrincipal: raise ValueError(_ERROR)
        return dict(requester_digest=principal.requester.digest,transport_digest=principal.transport_namespace_digest)

    def preview(self, phase: Phase, principal: V4PlanningPrincipal) -> dict[str,object]:
        try: return self._workflow.preview(phase,**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def authorize(self, phase: Phase, reference: str, principal: V4PlanningPrincipal) -> dict[str,object]:
        try: return self._workflow.authorize(phase,reference,**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def execute(self, phase: Phase, reference: str, principal: V4PlanningPrincipal) -> dict[str,object]:
        try: return self._workflow.execute(phase,reference,**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def outcome(self, principal: V4PlanningPrincipal) -> dict[str,object]:
        try: return self._workflow.outcome(**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None


def register_windows_jit_local_candidate_tools(server: Any, action: WindowsJitLocalMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS
    if type(action) is not WindowsJitLocalMcpAction or getattr(server,'_runtime_profile',None) is not RuntimeProfile.V4_CONTROLLED:
        raise ValueError(_ERROR)

    def register(phase: Phase) -> None:
        async def preview() -> dict[str,object]:
            return await asyncio.to_thread(action.preview,phase,server._v4_planning_principal())
        async def authorize(preview_ref: str) -> dict[str,object]:
            return await asyncio.to_thread(action.authorize,phase,preview_ref,server._v4_secret_metadata_action_principal())
        async def execute(authorization_ref: str) -> dict[str,object]:
            return await asyncio.to_thread(action.execute,phase,authorization_ref,server._v4_secret_metadata_action_principal())
        server.mcp.tool(name=f'preview_v4_windows_jit_local_{phase}_700',
            description='Preview one fixed local JIT definition/configuration phase; no privilege qualification.',
            annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview)
        server.mcp.tool(name=f'authorize_v4_windows_jit_local_{phase}_700',
            description='Request independent protected lab authorization for one fixed local JIT phase.',
            annotations=LOCAL_STATE_TOOL_ANNOTATIONS)(authorize)
        server.mcp.tool(name=f'execute_v4_windows_jit_local_{phase}_700',
            description='Execute one fixed local JIT phase; native and effective-privilege qualification remain pending.',
            annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)(execute)
    for phase in PHASES: register(phase)

    async def outcome() -> dict[str,object]:
        return await asyncio.to_thread(action.outcome,server._v4_planning_principal())
    server.mcp.tool(name='get_v4_windows_jit_local_outcome_700',description='Read owned local JIT outcomes without redispatch.',
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(outcome)
