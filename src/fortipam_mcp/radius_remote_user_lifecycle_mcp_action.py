"""Reference-only controlled OAuth/MCP boundary for the fixed associated parent."""
from __future__ import annotations

import asyncio
from typing import Any
from v4_planning.material_provider import _OpaqueC3Object
from .v4_plan_runtime import V4PlanningPrincipal
from .radius_remote_user_lifecycle_workflow import RadiusRemoteUserLifecycleWorkflow

_ERROR = "FortiPAM RADIUS User lifecycle is unavailable."


class RadiusRemoteUserLifecycleMcpAction(_OpaqueC3Object):
    __slots__ = ("_workflow", "_enabled")
    _workflow: RadiusRemoteUserLifecycleWorkflow
    _enabled: bool

    def __init__(self, workflow: RadiusRemoteUserLifecycleWorkflow, *, execution_enabled: bool = False) -> None:
        if type(workflow) is not RadiusRemoteUserLifecycleWorkflow or type(execution_enabled) is not bool:
            raise ValueError(_ERROR)
        object.__setattr__(self, "_workflow", workflow); object.__setattr__(self, "_enabled", execution_enabled)

    def __setattr__(self, name: str, value: object) -> None: raise ValueError(_ERROR)
    def __delattr__(self, name: str) -> None: raise ValueError(_ERROR)

    @staticmethod
    def _identity(principal: V4PlanningPrincipal) -> dict[str, str]:
        if type(principal) is not V4PlanningPrincipal: raise ValueError
        return {"requester_digest": principal.requester.digest, "transport_digest": principal.transport_namespace_digest}

    def preview(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try: return self._workflow.preview(**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def authorize(self, preview_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if not self._enabled: raise ValueError
            return self._workflow.authorize(preview_ref, **self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def execute(self, authorization_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if not self._enabled: raise ValueError
            return self._workflow.execute(authorization_ref, **self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def close(self) -> None: self._workflow.close()


def register_radius_remote_user_lifecycle_tools(server: Any, action: RadiusRemoteUserLifecycleMcpAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS
    if type(action) is not RadiusRemoteUserLifecycleMcpAction: raise ValueError(_ERROR)

    async def preview_v4_radius_user_lifecycle_700() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    async def authorize_v4_radius_user_lifecycle_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.authorize, preview_ref, server._v4_secret_metadata_action_principal())

    async def execute_v4_radius_user_lifecycle_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.execute, authorization_ref, server._v4_secret_metadata_action_principal())

    server.mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS,
        description="Preview one fixed pair and disabled Standard User lifecycle; no device write.")(preview_v4_radius_user_lifecycle_700)
    server.mcp.tool(annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Bind the exact associated lifecycle summary to a short-lived lab authorization.")(authorize_v4_radius_user_lifecycle_700)
    server.mcp.tool(annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        description="Run six original child M4s once, recover User before pair and close Gates; login/failover unqualified.")(execute_v4_radius_user_lifecycle_700)


def wrap_radius_remote_user_lifecycle_shutdown(app: Any, action: RadiusRemoteUserLifecycleMcpAction) -> Any:
    async def bounded(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "lifespan":
            await app(scope, receive, send)
            return
        closed = False
        async def closing_send(message: Any) -> None:
            nonlocal closed
            if message["type"] in {"lifespan.shutdown.complete", "lifespan.startup.failed", "lifespan.shutdown.failed"}:
                await asyncio.to_thread(action.close)
                closed = True
            await send(message)
        try:
            await app(scope, receive, closing_send)
        finally:
            if not closed: await asyncio.to_thread(action.close)
    return bounded
