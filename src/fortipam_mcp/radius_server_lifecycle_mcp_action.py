"""Default-closed MCP boundary for one privately bound RADIUS lifecycle candidate."""

from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from .radius_server_lifecycle_workflow import RadiusServerLifecycleWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

_UNAVAILABLE = "FortiPAM RADIUS lifecycle is unavailable."


class RadiusServerLifecycleMcpAction(_OpaqueC3Object):
    """Keep private bindings and material outside caller-selected arguments."""

    __slots__ = ("_workflow", "_enabled", "_persistent")
    _display_name = "RadiusServerLifecycleMcpAction"
    _workflow: RadiusServerLifecycleWorkflow
    _enabled: bool
    _persistent: bool

    def __init__(
        self, workflow: RadiusServerLifecycleWorkflow, *, execution_enabled: bool = False,
        persistent_primary: bool = False,
    ) -> None:
        if (type(workflow) is not RadiusServerLifecycleWorkflow or type(execution_enabled) is not bool
                or type(persistent_primary) is not bool
                or persistent_primary != getattr(workflow, "_retain_on_success", False)):
            raise ValueError(_UNAVAILABLE)
        object.__setattr__(self, "_workflow", workflow)
        object.__setattr__(self, "_enabled", execution_enabled)
        object.__setattr__(self, "_persistent", persistent_primary)

    def __setattr__(self, name: str, value: object) -> None:
        raise ValueError(_UNAVAILABLE)

    def __delattr__(self, name: str) -> None:
        raise ValueError(_UNAVAILABLE)

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

    def close(self) -> None:
        self._workflow.close()

    def preview_removal(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if not self._persistent:
                raise ValueError
            return self._workflow.preview_removal(**self._identity(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def authorize_removal(self, preview_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if not self._persistent:
                raise ValueError
            return self._workflow.authorize_removal(preview_ref, **self._identity(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def execute_removal(self, authorization_ref: str, principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if not self._persistent or not self._enabled:
                raise ValueError
            return self._workflow.execute_removal(authorization_ref, **self._identity(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None


def register_radius_server_lifecycle_candidate_tools(server: Any, action: RadiusServerLifecycleMcpAction) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    if type(action) is not RadiusServerLifecycleMcpAction:
        raise ValueError(_UNAVAILABLE)

    async def preview_v4_radius_primary_lifecycle_700() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    async def authorize_v4_radius_primary_lifecycle_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(
            action.authorize, preview_ref, server._v4_secret_metadata_action_principal(),
        )

    async def execute_v4_radius_primary_lifecycle_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(
            action.execute, authorization_ref, server._v4_secret_metadata_action_principal(),
        )

    server.mcp.tool(
        name="preview_v4_radius_primary_configure_700" if action._persistent
            else "preview_v4_radius_primary_lifecycle_700",
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
        description="Preview one privately bound RADIUS lifecycle with fixed current and expected state; no device write.",
    )(preview_v4_radius_primary_lifecycle_700)
    server.mcp.tool(
        name="authorize_v4_radius_primary_configure_700" if action._persistent
            else "authorize_v4_radius_primary_lifecycle_700",
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Bind one short-lived technical authorization to an unchanged RADIUS lifecycle preview and authenticated operator.",
    )(authorize_v4_radius_primary_lifecycle_700)
    server.mcp.tool(
        name="execute_v4_radius_primary_configure_700" if action._persistent
            else "execute_v4_radius_primary_lifecycle_700",
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        description=("Create and test one privately bound primary once; retain the verified entry on success, "
            "recover the original ACK on failure, and close Gates. User authentication is unqualified."
            if action._persistent else "Run one privately bound create/connect/original-ACK recovery sequence once; "
            "return categorical readback without material or raw response values."),
    )(execute_v4_radius_primary_lifecycle_700)

    if action._persistent:
        async def preview_v4_radius_primary_remove_700() -> dict[str, object]:
            return await asyncio.to_thread(action.preview_removal, server._v4_planning_principal())

        async def authorize_v4_radius_primary_remove_700(preview_ref: str) -> dict[str, object]:
            return await asyncio.to_thread(action.authorize_removal, preview_ref,
                server._v4_secret_metadata_action_principal())

        async def execute_v4_radius_primary_remove_700(authorization_ref: str) -> dict[str, object]:
            return await asyncio.to_thread(action.execute_removal, authorization_ref,
                server._v4_secret_metadata_action_principal())

        server.mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS,
            description="Preview removal of the unchanged zero-reference primary owned by the original ACK; no material acquisition.",
        )(preview_v4_radius_primary_remove_700)
        server.mcp.tool(annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
            description="Bind a fresh independent removal authorization to the original-owned primary preview.",
        )(authorize_v4_radius_primary_remove_700)
        server.mcp.tool(annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
            description="Remove only the unchanged zero-reference original-owned primary once and verify dual absence; close Gates.",
        )(execute_v4_radius_primary_remove_700)


__all__ = ["RadiusServerLifecycleMcpAction", "register_radius_server_lifecycle_candidate_tools"]


def wrap_radius_server_lifecycle_shutdown(app: Any, action: RadiusServerLifecycleMcpAction) -> Any:
    """Close the fixed candidate before acknowledging ASGI lifespan termination."""
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
            if not closed:
                await asyncio.to_thread(action.close)
    return bounded
