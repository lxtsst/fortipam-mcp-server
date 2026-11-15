"""Reference-only OAuth MCP boundary for a separately governed quota incident."""
from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from .instruction_quota_recovery_runtime import InstructionQuotaRecoveryRuntime
from .v4_plan_runtime import V4PlanningPrincipal

_ERROR = "FortiPAM Instruction quota incident correction is unavailable."


class InstructionQuotaRecoveryMcpAction(_OpaqueC3Object):
    """Keep protected original/new custody and policy outside MCP arguments."""

    __slots__ = ("_runtime", "_enabled")
    _runtime: InstructionQuotaRecoveryRuntime
    _enabled: bool

    def __init__(self, runtime: InstructionQuotaRecoveryRuntime, *, execution_enabled: bool = False) -> None:
        if type(runtime) is not InstructionQuotaRecoveryRuntime or type(execution_enabled) is not bool:
            raise ValueError(_ERROR)
        object.__setattr__(self, "_runtime", runtime)
        object.__setattr__(self, "_enabled", execution_enabled)

    def __setattr__(self, name: str, value: object) -> None:
        raise ValueError(_ERROR)

    def __delattr__(self, name: str) -> None:
        raise ValueError(_ERROR)

    @staticmethod
    def _identity(principal: V4PlanningPrincipal) -> dict[str, str]:
        if type(principal) is not V4PlanningPrincipal:
            raise ValueError(_ERROR)
        return {"requester_digest": principal.requester.digest,
            "transport_digest": principal.transport_namespace_digest}

    def preview(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            return self._runtime.preview(**self._identity(principal))
        except Exception:
            raise RuntimeError(_ERROR) from None

    def authorize(self, preview_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if self._enabled is not True:
                raise ValueError
            return self._runtime.authorize(preview_ref, **self._identity(principal))
        except Exception:
            raise RuntimeError(_ERROR) from None

    def execute(self, authorization_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if self._enabled is not True:
                raise ValueError
            return self._runtime.execute(authorization_ref, **self._identity(principal))
        except Exception:
            raise RuntimeError(_ERROR) from None


def register_instruction_quota_recovery_candidate_tools(server: Any, action: InstructionQuotaRecoveryMcpAction) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS
    if type(action) is not InstructionQuotaRecoveryMcpAction:
        raise ValueError(_ERROR)

    async def preview() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    async def authorize(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.authorize, preview_ref, server._v4_secret_metadata_action_principal())

    async def execute(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.execute, authorization_ref, server._v4_secret_metadata_action_principal())

    server.mcp.tool(name="preview_v4_instruction_quota_incident_correction_700", annotations=READ_ONLY_TOOL_ANNOTATIONS,
        description="Preview the privately fixed original-baseline quota correction; preserve the unresolved original restore.")(preview)
    server.mcp.tool(name="authorize_v4_instruction_quota_incident_correction_700", annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Bind one short-lived correction authorization to the authenticated operator and exact owner incident policy.")(authorize)
    server.mcp.tool(name="execute_v4_instruction_quota_incident_correction_700", annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        description="Execute the separately governed quota correction once; baseline readback does not close the original incident.")(execute)


__all__ = ["InstructionQuotaRecoveryMcpAction", "register_instruction_quota_recovery_candidate_tools"]
