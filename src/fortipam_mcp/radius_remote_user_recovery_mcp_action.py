"""Original User recovery and separately guarded associated pair recovery."""
from __future__ import annotations

import asyncio
from typing import Any
from v4_planning.material_provider import _OpaqueC3Object
from .v4_plan_runtime import V4PlanningPrincipal
from .radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow
from .radius_server_pair_recovery_workflow import RadiusServerPairRecoveryWorkflow
from .radius_remote_user_absence_guard import RadiusRemoteUserAbsenceGuard
from .radius_remote_user_preparation_reader import RadiusRemoteUserPreparationReader

_ERROR = "FortiPAM RADIUS User recovery is unavailable."


class RadiusRemoteUserRecoveryMcpAction(_OpaqueC3Object):
    __slots__ = ("_workflow", "_enabled", "_pair")
    _workflow: RadiusRemoteUserLiveWorkflow | RadiusRemoteUserPreparationReader
    _enabled: bool
    _pair: RadiusServerPairRecoveryWorkflow | None

    def __init__(self, workflow: RadiusRemoteUserLiveWorkflow | RadiusRemoteUserPreparationReader, *, execution_enabled: bool = False,
            pair_recovery: RadiusServerPairRecoveryWorkflow | None = None) -> None:
        if (type(workflow) not in {RadiusRemoteUserLiveWorkflow, RadiusRemoteUserPreparationReader}
                or isinstance(workflow, RadiusRemoteUserLiveWorkflow) and workflow._operation != "remove"
                or not workflow._target._recovery_only or type(execution_enabled) is not bool):
            raise ValueError(_ERROR)
        if pair_recovery is not None:
            if (type(pair_recovery) is not RadiusServerPairRecoveryWorkflow
                    or type(pair_recovery._user_absence) is not RadiusRemoteUserAbsenceGuard):
                raise ValueError(_ERROR)
            if (pair_recovery._user_absence._reader._binding is not workflow._binding
                    or pair_recovery._user_absence._reader._store is not workflow._store): raise ValueError(_ERROR)
        object.__setattr__(self, "_workflow", workflow)
        object.__setattr__(self, "_enabled", execution_enabled)
        object.__setattr__(self, "_pair", pair_recovery)

    def __setattr__(self, name: str, value: object) -> None: raise ValueError(_ERROR)
    def __delattr__(self, name: str) -> None: raise ValueError(_ERROR)

    @staticmethod
    def _identity(principal: V4PlanningPrincipal) -> dict[str, str]:
        if type(principal) is not V4PlanningPrincipal: raise ValueError
        return {"requester_digest": principal.requester.digest, "transport_digest": principal.transport_namespace_digest}

    def preview(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if not isinstance(self._workflow, RadiusRemoteUserLiveWorkflow): raise ValueError
            return self._workflow.preview(**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def authorize(self, preview_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if not self._enabled or not isinstance(self._workflow, RadiusRemoteUserLiveWorkflow): raise ValueError
            return self._workflow.authorize(preview_ref, **self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def execute(self, authorization_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if not self._enabled or not isinstance(self._workflow, RadiusRemoteUserLiveWorkflow): raise ValueError
            return self._workflow.execute(authorization_ref, **self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def reconcile(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if not isinstance(self._workflow, RadiusRemoteUserLiveWorkflow): raise ValueError
            return self._workflow.reconcile(**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def inspect_cleanup(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try: return self._workflow.inspect_cleanup_state(**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def preview_pair(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if self._pair is None: raise ValueError
            return self._pair.preview(**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def authorize_pair(self, preview_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if not self._enabled or self._pair is None: raise ValueError
            return self._pair.authorize(preview_ref, **self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def execute_pair(self, authorization_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if not self._enabled or self._pair is None: raise ValueError
            return self._pair.execute(authorization_ref, **self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def reconcile_pair(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if self._pair is None: raise ValueError
            return self._pair.reconcile(**self._identity(principal))
        except Exception: raise RuntimeError(_ERROR) from None

    def close(self) -> None:
        self._workflow.revoke()
        if self._pair is not None: self._pair.revoke()
        self._workflow.close()
        if self._pair is not None: self._pair.close()


def register_radius_remote_user_recovery_tools(server: Any, action: RadiusRemoteUserRecoveryMcpAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS
    if type(action) is not RadiusRemoteUserRecoveryMcpAction: raise ValueError(_ERROR)

    async def preview_v4_radius_user_recovery_700() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    async def authorize_v4_radius_user_recovery_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.authorize, preview_ref, server._v4_secret_metadata_action_principal())

    async def execute_v4_radius_user_recovery_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.execute, authorization_ref, server._v4_secret_metadata_action_principal())

    async def reconcile_v4_radius_user_recovery_700() -> dict[str, object]:
        return await asyncio.to_thread(action.reconcile, server._v4_planning_principal())

    async def inspect_v4_radius_user_cleanup_700() -> dict[str, object]:
        return await asyncio.to_thread(action.inspect_cleanup, server._v4_planning_principal())

    if isinstance(action._workflow, RadiusRemoteUserLiveWorkflow):
        server.mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS,
            description="Preview removal of one original owned disabled User; no pair cleanup.")(preview_v4_radius_user_recovery_700)
        server.mcp.tool(annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
            description="Authorize fresh original-ACK User recovery through its separate original M4.")(authorize_v4_radius_user_recovery_700)
        server.mcp.tool(annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
            description="Remove the original owned unchanged User once; no material acquisition or pair deletion.")(execute_v4_radius_user_recovery_700)
        server.mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS,
            description="Observe dual absence after a consumed User DELETE; prior M4 outcome stays unchanged.")(reconcile_v4_radius_user_recovery_700)
    server.mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS,
        description="Observe original unattempted/consumed User cleanup state; no adoption, User DELETE authority or replay.")(inspect_v4_radius_user_cleanup_700)

    if action._pair is not None:
        async def preview_v4_radius_associated_pair_recovery_700() -> dict[str, object]:
            return await asyncio.to_thread(action.preview_pair, server._v4_planning_principal())

        async def authorize_v4_radius_associated_pair_recovery_700(preview_ref: str) -> dict[str, object]:
            return await asyncio.to_thread(action.authorize_pair, preview_ref, server._v4_secret_metadata_action_principal())

        async def execute_v4_radius_associated_pair_recovery_700(authorization_ref: str) -> dict[str, object]:
            return await asyncio.to_thread(action.execute_pair, authorization_ref, server._v4_secret_metadata_action_principal())

        async def reconcile_v4_radius_associated_pair_recovery_700() -> dict[str, object]:
            return await asyncio.to_thread(action.reconcile_pair, server._v4_planning_principal())

        server.mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS,
            description="Preview original pair recovery after fresh owned User dual absence.")(preview_v4_radius_associated_pair_recovery_700)
        server.mcp.tool(annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
            description="Authorize separate original pair recovery M4 with a bound User absence dependency.")(authorize_v4_radius_associated_pair_recovery_700)
        server.mcp.tool(annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
            description="Remove the original unchanged pair once; recheck User absence through final before-send.")(execute_v4_radius_associated_pair_recovery_700)
        server.mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS,
            description="Observe User and pair dual absence after consumed pair DELETE; never retry or promote UNKNOWN.")(reconcile_v4_radius_associated_pair_recovery_700)


def wrap_radius_remote_user_recovery_shutdown(app: Any, action: RadiusRemoteUserRecoveryMcpAction) -> Any:
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
