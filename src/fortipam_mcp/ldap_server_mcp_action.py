"""Default-closed MCP boundary for one privately bound LDAP create candidate."""

from __future__ import annotations

import asyncio
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from .ldap_server_live_workflow import LdapServerLiveWorkflow
from .v4_plan_runtime import V4PlanningPrincipal

_UNAVAILABLE = "FortiPAM LDAP server creation is unavailable."


class LdapServerMcpAction(_OpaqueC3Object):
    """Keep private bindings and material outside caller-selected arguments."""

    __slots__ = ("_workflow", "_enabled")
    _display_name = "LdapServerMcpAction"
    _workflow: LdapServerLiveWorkflow
    _enabled: bool

    def __init__(
        self, workflow: LdapServerLiveWorkflow, *, execution_enabled: bool = False,
    ) -> None:
        if type(workflow) is not LdapServerLiveWorkflow or type(execution_enabled) is not bool:
            raise ValueError(_UNAVAILABLE)
        object.__setattr__(self, "_workflow", workflow)
        object.__setattr__(self, "_enabled", execution_enabled)

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


def register_ldap_server_candidate_tools(server: Any, action: LdapServerMcpAction) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    if type(action) is not LdapServerMcpAction:
        raise ValueError(_UNAVAILABLE)

    async def preview_v4_ldap_server_create_700() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    async def authorize_v4_ldap_server_create_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(
            action.authorize, preview_ref, server._v4_secret_metadata_action_principal(),
        )

    async def execute_v4_ldap_server_create_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(
            action.execute, authorization_ref, server._v4_secret_metadata_action_principal(),
        )

    server.mcp.tool(
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
        description="Preview one privately bound LDAP server creation with fixed current and expected state; no device write.",
    )(preview_v4_ldap_server_create_700)
    server.mcp.tool(
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
        description="Bind one short-lived technical authorization to an unchanged LDAP preview and authenticated operator.",
    )(authorize_v4_ldap_server_create_700)
    server.mcp.tool(
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        description="Create one privately bound LDAP server once and return categorical readback without credential or raw response values.",
    )(execute_v4_ldap_server_create_700)


__all__ = ["LdapServerMcpAction", "register_ldap_server_candidate_tools"]
