"""Explicit controlled-OAuth injection; four typed fixed-alert workflow Tools."""
from __future__ import annotations

import asyncio
from typing import Any
from pydantic import StrictBool

from v4_planning.material_provider import _OpaqueC3Object
from .email_alert_compound_contract import Step
from .email_alert_local_workflow import EmailAlertLocalWorkflow
from .runtime_profile import RuntimeProfile
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = 'The private email-alert local action is unavailable.'


class EmailAlertLocalMcpAction(_OpaqueC3Object):
    def __init__(self, workflow: EmailAlertLocalWorkflow) -> None:
        if type(workflow) is not EmailAlertLocalWorkflow: raise ValueError(_ERROR)
        self._workflow=workflow

    @staticmethod
    def _identity(principal: V4PlanningPrincipal) -> dict[str,str]:
        if type(principal) is not V4PlanningPrincipal: raise ValueError(_ERROR)
        return dict(requester_digest=principal.requester.digest,transport_digest=principal.transport_namespace_digest)

    def preview(self, step: Step, restore: bool, principal: V4PlanningPrincipal) -> dict[str,object]:
        try: return self._workflow.preview(step,restore=restore,**self._identity(principal))
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


def register_email_alert_local_candidate_tools(server: Any, action: EmailAlertLocalMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,LOCAL_STATE_TOOL_ANNOTATIONS,READ_ONLY_TOOL_ANNOTATIONS
    if type(action) is not EmailAlertLocalMcpAction or getattr(server,'_runtime_profile',None) is not RuntimeProfile.V4_CONTROLLED:
        raise ValueError(_ERROR)
    async def preview(step: Step, restore: StrictBool = False) -> dict[str,object]:
        return await asyncio.to_thread(action.preview,step,restore,server._v4_planning_principal())
    async def authorize(preview_ref: str) -> dict[str,object]:
        return await asyncio.to_thread(action.authorize,preview_ref,server._v4_secret_metadata_action_principal())
    async def execute(authorization_ref: str) -> dict[str,object]:
        return await asyncio.to_thread(action.execute,authorization_ref,server._v4_secret_metadata_action_principal())
    async def outcome() -> dict[str,object]:
        return await asyncio.to_thread(action.outcome,server._v4_planning_principal())
    server.mcp.tool(name='preview_v4_email_alert_step_local_700',
        description='Preview one of eight fixed alert objects or its original-receipt restore; no mail identity or arbitrary body.',
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(preview)
    server.mcp.tool(name='authorize_v4_email_alert_step_local_700',
        description='Request separate protected lab authorization for one exact owned alert preview reference.',
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS)(authorize)
    server.mcp.tool(name='execute_v4_email_alert_step_local_700',
        description='Execute one exact owned alert authorization reference; native and delivery qualification remain pending.',
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)(execute)
    server.mcp.tool(name='get_v4_email_alert_local_outcome_700',
        description='Read owned local alert outcomes without device access, grants or redispatch.',
        annotations=READ_ONLY_TOOL_ANNOTATIONS)(outcome)
