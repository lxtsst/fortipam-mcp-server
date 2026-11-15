"""Default-closed MCP boundary for one fixed Instruction quota create or delete phase."""

from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from .instruction_quota_live_workflow import InstructionQuotaLiveWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

_UNAVAILABLE = "FortiPAM Instruction quota is unavailable."


class InstructionQuotaMcpAction(_OpaqueC3Object):
    """Keep phase, object binding, and native body outside MCP arguments."""

    __slots__ = ("_workflow", "_enabled", "_phase")
    _display_name = "InstructionQuotaMcpAction"
    _workflow: InstructionQuotaLiveWorkflow
    _enabled: bool
    _phase: str

    def __init__(
        self, workflow: InstructionQuotaLiveWorkflow, *, execution_enabled: bool = False,
    ) -> None:
        if (type(workflow) is not InstructionQuotaLiveWorkflow
                or type(execution_enabled) is not bool
                or workflow.phase not in {"allocate", "restore"}):
            raise ValueError(_UNAVAILABLE)
        object.__setattr__(self, "_workflow", workflow)
        object.__setattr__(self, "_enabled", execution_enabled)
        object.__setattr__(self, "_phase", workflow.phase)

    def __setattr__(self, name: str, value: object) -> None:
        raise ValueError(_UNAVAILABLE)

    def __delattr__(self, name: str) -> None:
        raise ValueError(_UNAVAILABLE)

    @property
    def phase(self) -> str:
        return self._phase

    @staticmethod
    def _identity(principal: V4PlanningPrincipal) -> dict[str, str]:
        if type(principal) is not V4PlanningPrincipal:
            raise ValueError(_UNAVAILABLE)
        return {
            "requester_digest": principal.requester.digest,
            "transport_digest": principal.transport_namespace_digest,
        }

    def preview(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            return self._workflow.preview(**self._identity(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def authorize(self, preview_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        if not self._enabled:
            raise RuntimeError(_UNAVAILABLE)
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


def register_instruction_quota_candidate_tools(server: Any, action: InstructionQuotaMcpAction) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    if type(action) is not InstructionQuotaMcpAction:
        raise ValueError(_UNAVAILABLE)
    phase = action.phase

    async def preview() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    async def authorize(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(
            action.authorize, preview_ref, server._v4_secret_metadata_action_principal(),
        )

    async def execute(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(
            action.execute, authorization_ref, server._v4_secret_metadata_action_principal(),
        )

    server.mcp.tool(
        name=f"preview_v4_instruction_quota_{phase}_700",
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
        description="Preview the privately fixed Instruction quota phase with current and expected state; no device write.",
    )(preview)
    server.mcp.tool(
        name=f"authorize_v4_instruction_quota_{phase}_700",
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Bind one short-lived authorization to the fixed Instruction quota phase and authenticated operator.",
    )(authorize)
    server.mcp.tool(
        name=f"execute_v4_instruction_quota_{phase}_700",
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        description="Execute the privately fixed Instruction quota phase once and return categorical readback without native values.",
    )(execute)



__all__ = ["InstructionQuotaMcpAction", "register_instruction_quota_candidate_tools"]
