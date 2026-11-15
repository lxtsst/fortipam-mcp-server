"""Strict reference-only OAuth/MCP boundary for one manual JWT rotation graph."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
import threading
import time
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from .jwt_manual_key_contract import _require_digest
from .jwt_rotation_workflow import JwtRotationWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = "FortiPAM manual JWT rotation is unavailable."


class JwtRotationMcpAction(_OpaqueC3Object):
    def __init__(self, factory: Callable[[],JwtRotationWorkflow], *, requester_digest: str,
            transport_digest: str, execution_enabled: bool = False) -> None:
        if not callable(factory) or type(execution_enabled) is not bool:
            raise ValueError(_ERROR)
        _require_digest(requester_digest); _require_digest(transport_digest)
        self._factory,self._requester,self._transport = factory,requester_digest,transport_digest
        self._enabled,self._closed = execution_enabled,False
        self._workflow: JwtRotationWorkflow | None = None
        self._lock = threading.Lock()

    def _identity(self, principal: V4PlanningPrincipal) -> dict[str,str]:
        if (type(principal) is not V4PlanningPrincipal or self._closed
                or principal.requester.digest != self._requester or principal.transport_namespace_digest != self._transport):
            raise RuntimeError(_ERROR)
        return {"requester_digest":self._requester,"transport_digest":self._transport}

    def call(self, operation: str, principal: V4PlanningPrincipal, reference: str | None = None,
            *, authorization_deadline: int) -> dict[str,Any]:
        with self._lock:
            identity = self._identity(principal)
            if type(authorization_deadline) is not int or authorization_deadline<=int(time.time()):
                raise RuntimeError(_ERROR)
            try:
                if operation == "preview":
                    if reference is not None:
                        raise ValueError
                    if self._workflow is None:
                        self._workflow = self._factory()
                        if type(self._workflow) is not JwtRotationWorkflow:
                            raise ValueError
                    return self._workflow.preview(**identity)
                if self._workflow is None or not self._enabled or type(reference) is not str:
                    raise ValueError
                if operation == "authorize":
                    return self._workflow.authorize(reference,**identity)
                if operation == "execute":
                    return self._workflow.execute(reference,**identity,authorization_deadline=authorization_deadline)
                raise ValueError
            except Exception:
                try:
                    self._close()
                finally:
                    raise RuntimeError(_ERROR) from None
            finally:
                if operation == "execute":
                    self._enabled = False; self._closed = True

    def _close(self) -> None:
        self._enabled = False; self._closed = True
        if self._workflow is not None:
            self._workflow.close()

    def close(self) -> None:
        with self._lock:
            self._close()


def register_jwt_rotation_tools(server: Any, action: JwtRotationMcpAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS
    if type(action) is not JwtRotationMcpAction:
        raise ValueError(_ERROR)

    def caller() -> tuple[V4PlanningPrincipal,int]:
        principal = server._v4_secret_metadata_action_principal()
        deadline = getattr(server._access_token(),"expires_at",None)
        if type(principal) is not V4PlanningPrincipal or type(deadline) is not int or deadline<=int(time.time()):
            raise RuntimeError(_ERROR)
        return principal,deadline

    async def preview_v4_jwt_manual_rotation_700() -> dict[str,Any]:
        principal,deadline = caller()
        return await asyncio.to_thread(action.call,"preview",principal,authorization_deadline=deadline)

    async def authorize_v4_jwt_manual_rotation_700(preview_ref: str) -> dict[str,Any]:
        principal,deadline = caller()
        return await asyncio.to_thread(action.call,"authorize",principal,preview_ref,authorization_deadline=deadline)

    async def execute_v4_jwt_manual_rotation_700(authorization_ref: str) -> dict[str,Any]:
        principal,deadline = caller()
        return await asyncio.to_thread(action.call,"execute",principal,authorization_ref,authorization_deadline=deadline)

    server.mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS,
        description="Preview the configured original-owned manual JWT rotation graph; no token/key inputs or device write.")(preview_v4_jwt_manual_rotation_700)
    server.mcp.tool(annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Bind one complete JWT rotation summary to the configured standing lab authorization.")(authorize_v4_jwt_manual_rotation_700)
    server.mcp.tool(annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        description="Run six independent JWT User/initialization/overlap/cutover/restore/removal M4s and protected identity/lease probes once.")(execute_v4_jwt_manual_rotation_700)
    for operation in ("preview","authorize","execute"):
        tool = server.mcp._tool_manager.get_tool(operation+"_v4_jwt_manual_rotation_700")
        if tool is None:
            raise ValueError(_ERROR)
        model = tool.fn_metadata.arg_model; model.model_config["extra"] = "forbid"; model.model_rebuild(force=True)
        tool.parameters = model.model_json_schema()
        if tool.parameters.get("additionalProperties") is not False:
            raise ValueError(_ERROR)


def wrap_jwt_rotation_shutdown(app: Any, action: JwtRotationMcpAction) -> Any:
    async def bounded(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "lifespan":
            await app(scope,receive,send); return
        try:
            await app(scope,receive,send)
        finally:
            await asyncio.to_thread(action.close)
    return bounded
