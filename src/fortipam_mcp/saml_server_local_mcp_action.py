"""Explicit factory-only MCP access to one private inert SAML workflow."""
from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from .runtime_profile import RuntimeProfile
from .saml_server_local_workflow import Phase, SamlLocalWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = 'The private local SAML action is unavailable.'


class SamlLocalMcpAction(_OpaqueC3Object):
    def __init__(self, workflow: SamlLocalWorkflow) -> None:
        if type(workflow) is not SamlLocalWorkflow: raise ValueError(_ERROR)
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


def register_saml_local_candidate_tools(server: Any, action: SamlLocalMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS
    if type(action) is not SamlLocalMcpAction or getattr(server,'_runtime_profile',None) is not RuntimeProfile.V4_CONTROLLED:
        raise ValueError(_ERROR)

    def register(phase: Phase) -> None:
        async def preview() -> dict[str,object]:
            return await asyncio.to_thread(action.preview,phase,server._v4_planning_principal())
        async def authorize(preview_ref: str) -> dict[str,object]:
            return await asyncio.to_thread(action.authorize,phase,preview_ref,server._v4_secret_metadata_action_principal())
        async def execute(authorization_ref: str) -> dict[str,object]:
            return await asyncio.to_thread(action.execute,phase,authorization_ref,server._v4_secret_metadata_action_principal())
        server.mcp.tool(name=f'preview_v4_saml_local_{phase}_700',
            description='Preview one fixed local inert SAML fixture candidate.',annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview)
        server.mcp.tool(name=f'authorize_v4_saml_local_{phase}_700',
            description='Request protected lab authorization for one local inert SAML fixture phase.',annotations=LOCAL_STATE_TOOL_ANNOTATIONS)(authorize)
        server.mcp.tool(name=f'execute_v4_saml_local_{phase}_700',
            description='Execute one local inert SAML fixture phase; native isolation and login remain unqualified.',
            annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)(execute)
    register('create'); register('remove')

    async def outcome() -> dict[str,object]:
        return await asyncio.to_thread(action.outcome,server._v4_planning_principal())
    server.mcp.tool(name='get_v4_saml_local_outcome_700',description='Read owned local SAML results without redispatch.',
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(outcome)
