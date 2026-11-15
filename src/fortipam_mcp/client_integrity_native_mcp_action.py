"""Default-off build-29 native Client Integrity OAuth/MCP candidate."""
from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .client_integrity_http_transport import (
    FortiPamNativeClientIntegrityHttpTransport, load_native_client_integrity_binding,
    load_native_hash_client_integrity_binding,
)
from .client_integrity_native_workflow import NativeClientIntegrityWorkflow
from .password_changer_mcp_action import _requester
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config

PREFIX = "FORTIPAM_MCP_V4_CLIENT_INTEGRITY_NATIVE_700_"
HASH_PREFIX = "FORTIPAM_MCP_V4_CLIENT_INTEGRITY_NATIVE_HASH_700_"
_UNAVAILABLE = "The native Client Integrity action is unavailable."


class NativeClientIntegrityMcpAction:
    def __init__(self, workflow: NativeClientIntegrityWorkflow, *, execution_enabled: bool = False) -> None:
        if type(execution_enabled) is not bool:
            raise ValueError(_UNAVAILABLE)
        self._workflow, self._enabled = workflow, execution_enabled

    def preview(self, principal: Any) -> dict[str, object]:
        try:
            return self._workflow.preview(requester_digest=_requester(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        try:
            return self._workflow.confirm(preview_ref, requester_digest=_requester(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        try:
            if not self._enabled:
                raise ValueError
            return self._workflow.execute(authorization_ref, requester_digest=_requester(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None


@dataclass(frozen=True, slots=True)
class NativeClientIntegrityActions:
    create: NativeClientIntegrityMcpAction
    recovery: NativeClientIntegrityMcpAction


def build_native_client_integrity_candidate(environment: Mapping[str, str]) -> NativeClientIntegrityActions | None:
    """Select one explicit private profile; never infer it from binding contents."""
    try:
        profiles = {
            prefix: [environment.get(prefix + key, "false") for key in
                     ("ENABLED", "EXECUTION_ENABLED", "RECOVERY_EXECUTION_ENABLED")]
            for prefix in (PREFIX, HASH_PREFIX)
        }
        if any(any(v not in {"true", "false"} for v in flags)
               or flags[0] == "false" and "true" in flags[1:] for flags in profiles.values()):
            raise ValueError
        selected = [prefix for prefix, flags in profiles.items() if flags[0] == "true"]
        if len(selected) > 1:
            raise ValueError
        if not selected:
            return None
        prefix = selected[0]
        flags = profiles[prefix]
        paths = {key: Path(environment[prefix + key]) for key in
                 ("BINDING_FILE", "STATE_DIRECTORY", "AUTHORIZATION_KEY_FILE")}
        if any(not p.is_absolute() for p in paths.values()):
            raise ValueError
        transport = FortiPamNativeClientIntegrityHttpTransport(
            load_secret_metadata_http_transport_config(environment),
            (load_native_hash_client_integrity_binding(paths["BINDING_FILE"]) if prefix == HASH_PREFIX
             else load_native_client_integrity_binding(paths["BINDING_FILE"])),
            paths["STATE_DIRECTORY"], paths["AUTHORIZATION_KEY_FILE"],
            create_enabled=flags[1] == "true", recovery_enabled=flags[2] == "true",
        )
        return NativeClientIntegrityActions(
            NativeClientIntegrityMcpAction(NativeClientIntegrityWorkflow(transport), execution_enabled=flags[1] == "true"),
            NativeClientIntegrityMcpAction(NativeClientIntegrityWorkflow(transport, recovery=True), execution_enabled=flags[2] == "true"),
        )
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def register_native_client_integrity_tools(server: Any, actions: NativeClientIntegrityActions) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS

    @server.mcp.tool(description="Preview one privately bound native Client Software precondition; no package values.",
                     annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_client_integrity_native_700() -> dict[str, object]:
        return await asyncio.to_thread(actions.create.preview, server._v4_planning_principal())

    @server.mcp.tool(description="Bind the unchanged native Client Software preview to this authorized requester once.",
                     annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_client_integrity_native_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(actions.create.confirm, preview_ref, server._v4_password_policy_action_principal())

    @server.mcp.tool(description="Create only the fixed native Client Software precondition once; never download or launch.",
                     annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_client_integrity_native_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(actions.create.execute, authorization_ref, server._v4_password_policy_action_principal())

    @server.mcp.tool(description="Preview removal only of this binding's verified, unchanged native software with empty reported usage.",
                     annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_client_integrity_native_recovery_700() -> dict[str, object]:
        return await asyncio.to_thread(actions.recovery.preview, server._v4_planning_principal())

    @server.mcp.tool(description="Bind unchanged verified-owned native Client Software recovery to this requester once.",
                     annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_client_integrity_native_recovery_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(actions.recovery.confirm, preview_ref, server._v4_password_policy_action_principal())

    @server.mcp.tool(description="Delete only the bound verified native Client Software once and verify absence and preservation.",
                     annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_client_integrity_native_recovery_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(actions.recovery.execute, authorization_ref, server._v4_password_policy_action_principal())
