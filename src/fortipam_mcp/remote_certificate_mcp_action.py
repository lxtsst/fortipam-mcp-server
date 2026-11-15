"""Opaque-reference OAuth/MCP surface for one native remote certificate import/recovery."""
from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object
from .remote_certificate_workflow import NativeRemoteCertificateWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = "FortiPAM remote certificate action is unavailable."


class NativeRemoteCertificateMcpAction(_OpaqueC3Object):
    def __init__(self, workflow: NativeRemoteCertificateWorkflow) -> None:
        if type(workflow) is not NativeRemoteCertificateWorkflow:
            raise ValueError(_ERROR)
        self._workflow = workflow

    def call(self, phase: str, operation: str, principal: V4PlanningPrincipal,
             reference: str | None = None) -> dict[str, object]:
        try:
            if type(principal) is not V4PlanningPrincipal:
                raise ValueError
            identity = dict(requester_digest=principal.requester.digest,
                            transport_digest=principal.transport_namespace_digest)
            if operation == "preview" and reference is None:
                return self._workflow.preview(phase, **identity)
            if operation == "authorize" and type(reference) is str:
                return self._workflow.authorize(phase, reference, **identity)
            if operation == "execute" and type(reference) is str:
                return self._workflow.execute(phase, reference, **identity)
            raise ValueError
        except Exception:
            raise RuntimeError(_ERROR) from None


def register_remote_certificate_candidate_tools(server: Any, action: NativeRemoteCertificateMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS

    if type(action) is not NativeRemoteCertificateMcpAction:
        raise ValueError(_ERROR)

    def register(phase: str) -> None:
        async def preview() -> dict[str, object]:
            return await asyncio.to_thread(action.call, phase, "preview", server._v4_planning_principal())

        async def authorize(preview_ref: str) -> dict[str, object]:
            return await asyncio.to_thread(action.call, phase, "authorize",
                server._v4_secret_metadata_action_principal(), preview_ref)

        async def execute(authorization_ref: str) -> dict[str, object]:
            return await asyncio.to_thread(action.call, phase, "execute",
                server._v4_secret_metadata_action_principal(), authorization_ref)

        server.mcp.tool(name=f"preview_v4_remote_certificate_{phase}_700", annotations=READ_ONLY_TOOL_ANNOTATIONS,
            description="Preview one fixed public remote certificate phase and native preservation checks.")(preview)
        server.mcp.tool(name=f"authorize_v4_remote_certificate_{phase}_700", annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
            description="Authorize one fixed remote certificate phase under the authenticated operator's standing lab policy.")(authorize)
        server.mcp.tool(name=f"execute_v4_remote_certificate_{phase}_700", annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
            description="Execute one remote certificate phase with durable M4 and categorical original-owned readback.")(execute)

    register("import")
    register("recover")
