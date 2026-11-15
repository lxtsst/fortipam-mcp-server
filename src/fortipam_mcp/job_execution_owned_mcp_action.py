"""Reference-only ordinary OAuth/MCP entry for fixed Job execution."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
import threading
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .job_execution_owned_workflow import CONTRACT, JobExecutionOwnedWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = "The owned Job execution is unavailable."


class JobExecutionOwnedMcpAction(_OpaqueC3Object):
    def __init__(self, factory: Callable[[], JobExecutionOwnedWorkflow], *, phase: str,
            requester_digest: str, transport_digest: str, execution_enabled: bool = False):
        if not callable(factory) or phase not in {"activate", "observe", "cleanup"} or type(execution_enabled) is not bool:
            raise ValueError(_ERROR)
        require_digest(requester_digest, "job_requester");require_digest(transport_digest, "job_transport")
        self._factory, self._phase = factory, phase
        self._requester, self._transport, self._enabled = requester_digest, transport_digest, execution_enabled
        self._workflow: JobExecutionOwnedWorkflow | None = None
        self._closed = False
        self._lock = threading.Lock()

    def _identity(self, principal: V4PlanningPrincipal) -> dict[str, str]:
        if (type(principal) is not V4PlanningPrincipal or principal.requester.digest != self._requester
                or principal.transport_namespace_digest != self._transport or self._closed):
            raise RuntimeError(_ERROR)
        return {"requester_digest":self._requester, "transport_digest":self._transport}

    def observe(self, principal: V4PlanningPrincipal) -> dict[str, Any]:
        with self._lock:
            identity=self._identity(principal)
            try:
                if self._phase != "observe":raise ValueError
                if self._workflow is None:
                    self._workflow=self._factory()
                    if type(self._workflow) is not JobExecutionOwnedWorkflow:raise ValueError
                return self._workflow.observe(**identity)
            except Exception:
                self._close();raise RuntimeError(_ERROR) from None

    def preview(self, principal: V4PlanningPrincipal) -> dict[str, Any]:
        with self._lock:
            identity = self._identity(principal)
            try:
                if self._workflow is None:
                    self._workflow = self._factory()
                    if type(self._workflow) is not JobExecutionOwnedWorkflow or self._workflow.phase != self._phase:
                        raise ValueError
                return self._workflow.preview(**identity)
            except Exception:
                self._close()
                raise RuntimeError(_ERROR) from None

    def authorize(self, preview_ref: str, principal: V4PlanningPrincipal) -> dict[str, Any]:
        with self._lock:
            identity = self._identity(principal)
            try:
                if not self._enabled or self._workflow is None or type(preview_ref) is not str:
                    raise ValueError
                return self._workflow.authorize(preview_ref, **identity)
            except Exception:
                self._close()
                raise RuntimeError(_ERROR) from None

    def execute(self, authorization_ref: str, principal: V4PlanningPrincipal) -> dict[str, Any]:
        with self._lock:
            identity = self._identity(principal)
            try:
                if not self._enabled or self._workflow is None or type(authorization_ref) is not str:
                    raise ValueError
                return self._workflow.execute(authorization_ref, **identity)
            except Exception:
                raise RuntimeError(_ERROR) from None
            finally:
                self._close()

    def _close(self) -> None:
        self._enabled, self._closed = False, True
        if self._workflow is not None:self._workflow.close()

    def close(self) -> None:
        with self._lock:self._close()


def register_job_execution_owned_tools(server: Any, action: JobExecutionOwnedMcpAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS
    if type(action) is not JobExecutionOwnedMcpAction:raise ValueError(_ERROR)

    async def observe_v4_owned_job_execution_700() -> dict[str, Any]:
        return await asyncio.to_thread(action.observe, server._v4_secret_metadata_action_principal())

    server.mcp.tool(annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Observe the fixed owned Job result and retain a categorical local final-state seal; no device write.")(observe_v4_owned_job_execution_700)

    async def preview_v4_owned_job_execution_700() -> dict[str, Any]:
        return await asyncio.to_thread(action.preview, server._v4_secret_metadata_action_principal())

    async def authorize_v4_owned_job_execution_700(preview_ref: str) -> dict[str, Any]:
        return await asyncio.to_thread(action.authorize, preview_ref, server._v4_secret_metadata_action_principal())

    async def execute_v4_owned_job_execution_700(authorization_ref: str) -> dict[str, Any]:
        return await asyncio.to_thread(action.execute, authorization_ref, server._v4_secret_metadata_action_principal())

    server.mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS,
        description="Preview one configured owned Job activation or completed-state cleanup; no selectors or writes.")(preview_v4_owned_job_execution_700)
    server.mcp.tool(annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Authorize the fresh fixed scheduled Job preview under the configured standing lab policy.")(authorize_v4_owned_job_execution_700)
    server.mcp.tool(annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        description="Dispatch one exact original M4 scheduled-Job operation, verify scheduled full state or completed-state absence and close Gates.")(execute_v4_owned_job_execution_700)
    for verb in ("preview", "authorize", "execute", "observe"):
        tool = server.mcp._tool_manager.get_tool(verb+"_v4_owned_job_execution_700")
        if tool is None:raise ValueError(_ERROR)
        tool.fn_metadata.arg_model.model_config["extra"] = "forbid"
        tool.fn_metadata.arg_model.model_rebuild(force=True)
        tool.parameters = tool.fn_metadata.arg_model.model_json_schema()
        if tool.parameters.get("additionalProperties") is not False:raise ValueError(_ERROR)


def wrap_job_execution_owned_shutdown(app: Any, action: JobExecutionOwnedMcpAction) -> Any:
    async def bounded(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "lifespan":
            await app(scope, receive, send);return
        try:await app(scope, receive, send)
        finally:await asyncio.to_thread(action.close)
    return bounded
