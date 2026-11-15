"""Fixed OAuth/MCP DNS lifecycle; inputs are opaque technical references only."""
from __future__ import annotations

import asyncio
from typing import Any
from v4_planning.material_provider import _OpaqueC3Object
from .dns_timeout_live_workflow import DnsTimeoutLiveWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = 'FortiPAM DNS timeout action is unavailable.'


class DnsTimeoutMcpAction(_OpaqueC3Object):
    def __init__(self, workflow: DnsTimeoutLiveWorkflow) -> None:
        if type(workflow) is not DnsTimeoutLiveWorkflow:
            raise ValueError(_ERROR)
        self._workflow = workflow

    @staticmethod
    def _identity(principal: V4PlanningPrincipal) -> dict[str, str]:
        if type(principal) is not V4PlanningPrincipal:
            raise ValueError(_ERROR)
        return dict(requester_digest=principal.requester.digest,
                    transport_digest=principal.transport_namespace_digest)

    def preview(self, phase: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            return self._workflow.preview(phase, **self._identity(principal))
        except Exception:
            raise RuntimeError(_ERROR) from None

    def authorize(self, phase: str, preview_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            return self._workflow.authorize(phase, preview_ref, **self._identity(principal))
        except Exception:
            raise RuntimeError(_ERROR) from None

    def execute(self, phase: str, authorization_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            return self._workflow.execute(phase, authorization_ref, **self._identity(principal))
        except Exception:
            raise RuntimeError(_ERROR) from None


def register_dns_timeout_candidate_tools(server: Any, action: DnsTimeoutMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS

    def register(phase: str) -> None:
        async def preview() -> dict[str, object]:
            return await asyncio.to_thread(action.preview, phase, server._v4_planning_principal())

        async def authorize(preview_ref: str) -> dict[str, object]:
            return await asyncio.to_thread(action.authorize, phase, preview_ref,
                                           server._v4_secret_metadata_action_principal())

        async def execute(authorization_ref: str) -> dict[str, object]:
            return await asyncio.to_thread(action.execute, phase, authorization_ref,
                                           server._v4_secret_metadata_action_principal())

        server.mcp.tool(name=f'preview_v4_dns_timeout_{phase}_700', annotations=READ_ONLY_TOOL_ANNOTATIONS,
            description='Preview the fixed DNS timeout phase and complete preservation checks.')(preview)
        server.mcp.tool(name=f'authorize_v4_dns_timeout_{phase}_700', annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
            description='Authorize the fixed DNS timeout phase under standing lab policy for the authenticated operator.')(authorize)
        server.mcp.tool(name=f'execute_v4_dns_timeout_{phase}_700', annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
            description='Execute one fixed DNS timeout phase and return categorical complete-configuration readback.')(execute)

    if type(action) is not DnsTimeoutMcpAction:
        raise ValueError(_ERROR)
    register('update')
    register('recover')
