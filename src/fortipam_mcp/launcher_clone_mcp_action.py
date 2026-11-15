"""Default-off controlled OAuth tools for fixed Launcher clone and recovery."""
from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .launcher_clone_http_transport import (
    FortiPamLauncherCloneHttpTransport, load_launcher_clone_binding, load_putty_launcher_clone_binding,
    load_putty_launcher_copy_binding, load_putty_launcher_windows_binding,
    LauncherCloneBinding, PuttyLauncherCloneBinding, PuttyLauncherCopyBinding, PuttyLauncherWindowsBinding,
)
from .launcher_clone_live_workflow import LauncherCloneLiveWorkflow
from .password_changer_mcp_action import _requester
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config

PREFIX = 'FORTIPAM_MCP_V4_LAUNCHER_CLONE_700_'
PUTTY_PREFIX = 'FORTIPAM_MCP_V4_PUTTY_LAUNCHER_CLONE_700_'
COPY_PREFIX = 'FORTIPAM_MCP_V4_PUTTY_LAUNCHER_COPY_700_'
WINDOWS_PREFIX = 'FORTIPAM_MCP_V4_PUTTY_LAUNCHER_WINDOWS_700_'
_UNAVAILABLE = 'FortiPAM Launcher clone action is unavailable.'


class LauncherCloneMcpAction:
    def __init__(self, workflow: LauncherCloneLiveWorkflow, *, execution_enabled: bool = False) -> None:
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
class LauncherCloneActions:
    clone: LauncherCloneMcpAction
    recovery: LauncherCloneMcpAction


def build_launcher_clone_candidate(environment: Mapping[str, str]) -> LauncherCloneActions | None:
    try:
        profiles = {prefix: [environment.get(prefix + key, 'false') for key in
                            ('ENABLED', 'EXECUTION_ENABLED', 'RECOVERY_EXECUTION_ENABLED')]
                    for prefix in (PREFIX, PUTTY_PREFIX, COPY_PREFIX, WINDOWS_PREFIX)}
        if any(any(v not in {'true', 'false'} for v in flags)
               or flags[0] == 'false' and 'true' in flags[1:] for flags in profiles.values()):
            raise ValueError
        selected = [prefix for prefix, flags in profiles.items() if flags[0] == 'true']
        if len(selected) > 1:
            raise ValueError
        if not selected:
            return None
        prefix = selected[0]; flags = profiles[prefix]
        path = Path(environment[prefix + 'BINDING_FILE'])
        binding: LauncherCloneBinding | PuttyLauncherCloneBinding | PuttyLauncherCopyBinding | PuttyLauncherWindowsBinding
        if prefix == WINDOWS_PREFIX:
            binding = load_putty_launcher_windows_binding(path)
        elif prefix == COPY_PREFIX:
            binding = load_putty_launcher_copy_binding(path)
        elif prefix == PUTTY_PREFIX:
            binding = load_putty_launcher_clone_binding(path)
        else:
            binding = load_launcher_clone_binding(path)
        transport = FortiPamLauncherCloneHttpTransport(
            load_secret_metadata_http_transport_config(environment), binding,
            Path(environment[prefix + 'STATE_DIRECTORY']),
            clone_enabled=flags[1] == 'true', recovery_enabled=flags[2] == 'true',
        )
        return LauncherCloneActions(
            LauncherCloneMcpAction(LauncherCloneLiveWorkflow(transport), execution_enabled=flags[1] == 'true'),
            LauncherCloneMcpAction(LauncherCloneLiveWorkflow(transport, recovery=True), execution_enabled=flags[2] == 'true'),
        )
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def register_launcher_clone_tools(server: Any, actions: LauncherCloneActions) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS

    @server.mcp.tool(description='Preview one privately bound, unattached native Launcher clone without parameters.',
                     annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_launcher_clone_700() -> dict[str, object]:
        return await asyncio.to_thread(actions.clone.preview, server._v4_planning_principal())

    @server.mcp.tool(description='Bind the unchanged Launcher clone preview to this authorized requester once.',
                     annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_launcher_clone_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(actions.clone.confirm, preview_ref, server._v4_password_policy_action_principal())

    @server.mcp.tool(description='Create only the fixed native Launcher definition once using its bound profile and verify full expected state; never launch.',
                     annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_launcher_clone_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(actions.clone.execute, authorization_ref, server._v4_password_policy_action_principal())

    @server.mcp.tool(description='Preview deletion only of this binding\'s verified, unchanged, zero-reference clone.',
                     annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_launcher_clone_recovery_700() -> dict[str, object]:
        return await asyncio.to_thread(actions.recovery.preview, server._v4_planning_principal())

    @server.mcp.tool(description='Bind the unchanged owned-clone recovery to this authorized requester once.',
                     annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_launcher_clone_recovery_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(actions.recovery.confirm, preview_ref, server._v4_password_policy_action_principal())

    @server.mcp.tool(description='Delete only the bound verified clone once and verify absence and source preservation.',
                     annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_launcher_clone_recovery_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(actions.recovery.execute, authorization_ref, server._v4_password_policy_action_principal())
