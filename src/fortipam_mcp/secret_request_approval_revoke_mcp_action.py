"""Default-closed, privately composed original-reviewer withdrawal candidate."""
import asyncio
from typing import Any

from .secret_request_approval_revoke_live_workflow import SecretRequestApprovalRevokeLiveWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

_UNAVAILABLE = "FortiPAM Request approval withdrawal is unavailable."


class SecretRequestApprovalRevokeMcpAction:
    """No caller-selected device, request, path, key or reviewer mapping."""

    def __init__(self, workflow: SecretRequestApprovalRevokeLiveWorkflow, *, execution_enabled: bool = False):
        if (not isinstance(workflow, SecretRequestApprovalRevokeLiveWorkflow)
                or type(execution_enabled) is not bool):
            raise ValueError(_UNAVAILABLE)
        self._workflow, self._enabled = workflow, execution_enabled

    @staticmethod
    def _identity(principal: V4PlanningPrincipal) -> dict[str, str]:
        if type(principal) is not V4PlanningPrincipal:
            raise ValueError(_UNAVAILABLE)
        return {"requester_digest": principal.requester.digest,
                "transport_digest": principal.transport_namespace_digest}

    def preview(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            return self._workflow.preview(**self._identity(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def authorize(self, preview_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            return self._workflow.authorize(preview_ref, **self._identity(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        if not self._enabled:
            raise RuntimeError(_UNAVAILABLE)
        try:
            return self._workflow.execute(authorization_ref, **self._identity(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None


def register_secret_request_approval_revoke_tools(server: Any, action: SecretRequestApprovalRevokeMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS
    if type(action) is not SecretRequestApprovalRevokeMcpAction:
        raise ValueError(_UNAVAILABLE)

    @server.mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS,
        description="Preview withdrawal of the original reviewer's fixed active Request approval; no device write.")
    async def preview_v4_secret_request_approval_revoke_700() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    @server.mcp.tool(annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Bind one short-lived technical authorization to an unchanged withdrawal preview and authenticated operator.")
    async def authorize_v4_secret_request_approval_revoke_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.authorize, preview_ref, server._v4_secret_metadata_action_principal())

    @server.mcp.tool(annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        description="Withdraw the original reviewer's fixed approval once; return categorical readback without raw source values.")
    async def execute_v4_secret_request_approval_revoke_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.execute, authorization_ref, server._v4_secret_metadata_action_principal())
