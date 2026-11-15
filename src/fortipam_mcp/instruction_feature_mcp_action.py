"""Default-closed MCP boundary for one fixed Instruction feature create or delete phase."""

from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from .instruction_feature_live_workflow import InstructionFeatureLiveWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

_UNAVAILABLE = "FortiPAM Instruction feature is unavailable."


class InstructionFeatureMcpAction(_OpaqueC3Object):
    """Keep phase, object binding, and native body outside MCP arguments."""

    __slots__ = ("_workflow", "_enabled", "_phase")
    _display_name = "InstructionFeatureMcpAction"
    _workflow: InstructionFeatureLiveWorkflow
    _enabled: bool
    _phase: str

    def __init__(
        self, workflow: InstructionFeatureLiveWorkflow, *, execution_enabled: bool = False,
    ) -> None:
        if (type(workflow) is not InstructionFeatureLiveWorkflow
                or type(execution_enabled) is not bool
                or workflow.phase not in {"enable", "restore"}):
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

    def reconcile_restore(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            return self._workflow.reconcile_restore(**self._identity(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def preview_reconciled_restore(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            return self._workflow.preview_reconciled_restore(**self._identity(principal))
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


def register_instruction_feature_candidate_tools(server: Any, action: InstructionFeatureMcpAction) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    if type(action) is not InstructionFeatureMcpAction:
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
        name=f"preview_v4_instruction_feature_{phase}_700",
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
        description="Preview the privately fixed Instruction feature phase with current and expected state; no device write.",
    )(preview)
    server.mcp.tool(
        name=f"authorize_v4_instruction_feature_{phase}_700",
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Bind one short-lived authorization to the fixed Instruction feature phase and authenticated operator.",
    )(authorize)
    server.mcp.tool(
        name=f"execute_v4_instruction_feature_{phase}_700",
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        description="Execute the privately fixed Instruction feature phase once and return categorical readback without native values.",
    )(execute)

    if phase == "restore":
        async def reconcile() -> dict[str, object]:
            return await asyncio.to_thread(action.reconcile_restore, server._v4_planning_principal())

        server.mcp.tool(
            name="reconcile_v4_instruction_feature_restore_700",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
            description="Observe an unapplied pre-write restore failure; retain all claims and grant no execution authority.",
        )(reconcile)

        async def preview_reconciled() -> dict[str, object]:
            return await asyncio.to_thread(action.preview_reconciled_restore, server._v4_planning_principal())

        server.mcp.tool(
            name="preview_v4_instruction_feature_reconciled_restore_700",
            annotations=READ_ONLY_TOOL_ANNOTATIONS,
            description="Prepare a fresh restore plan after renewed complete pre-write reconciliation; no old dispatch is replayed.",
        )(preview_reconciled)


__all__ = ["InstructionFeatureMcpAction", "register_instruction_feature_candidate_tools"]
