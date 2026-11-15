"""Default-off controlled OAuth/MCP association of two verified-owned fixtures."""
from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .client_integrity_http_transport import FortiPamNativeClientIntegrityHttpTransport, load_native_hash_client_integrity_binding
from .launcher_clone_http_transport import FortiPamLauncherCloneHttpTransport, load_putty_launcher_windows_binding
from .password_changer_mcp_action import _requester
from .putty_integrity_association_http_transport import (
    PuttyIntegrityAssociationHttpTransport, load_putty_integrity_association_binding,
)
from .putty_integrity_association_live_workflow import PuttyIntegrityAssociationWorkflow
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config

PREFIX = "FORTIPAM_MCP_V4_PUTTY_INTEGRITY_ASSOCIATION_700_"
_UNAVAILABLE = "The fixed Windows Client Integrity association action is unavailable."


class PuttyIntegrityAssociationMcpAction:
    def __init__(self, workflow: PuttyIntegrityAssociationWorkflow, *, execution_enabled: bool = False) -> None:
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
            return self._workflow.confirm(preview_ref,requester_digest=_requester(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        try:
            if not self._enabled:
                raise ValueError
            return self._workflow.execute(authorization_ref,requester_digest=_requester(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None


@dataclass(frozen=True, slots=True)
class PuttyIntegrityAssociationActions:
    association: PuttyIntegrityAssociationMcpAction
    restore: PuttyIntegrityAssociationMcpAction


def build_putty_integrity_association_candidate(environment: Mapping[str, str]) -> PuttyIntegrityAssociationActions | None:
    try:
        flags = [environment.get(PREFIX + key,"false") for key in
                 ("ENABLED","EXECUTION_ENABLED","RESTORE_EXECUTION_ENABLED")]
        if any(v not in {"true","false"} for v in flags) or flags[0] == "false" and "true" in flags[1:]:
            raise ValueError
        if flags[0] == "false":
            return None
        paths = {key:Path(environment[PREFIX + key]) for key in (
            "BINDING_FILE","STATE_DIRECTORY","AUTHORIZATION_KEY_FILE",
            "LAUNCHER_BINDING_FILE","LAUNCHER_STATE_DIRECTORY",
            "SOFTWARE_BINDING_FILE","SOFTWARE_STATE_DIRECTORY","SOFTWARE_AUTHORIZATION_KEY_FILE",
        )}
        if any(not path.is_absolute() for path in paths.values()):
            raise ValueError
        config = load_secret_metadata_http_transport_config(environment)
        # Existing state/bindings are read-only prerequisites. These providers
        # always have both mutation gates false, independently of environment flags.
        launcher = FortiPamLauncherCloneHttpTransport(config,
            load_putty_launcher_windows_binding(paths["LAUNCHER_BINDING_FILE"]),paths["LAUNCHER_STATE_DIRECTORY"])
        software = FortiPamNativeClientIntegrityHttpTransport(config,
            load_native_hash_client_integrity_binding(paths["SOFTWARE_BINDING_FILE"]),paths["SOFTWARE_STATE_DIRECTORY"],
            paths["SOFTWARE_AUTHORIZATION_KEY_FILE"])
        transport = PuttyIntegrityAssociationHttpTransport(launcher,software,
            load_putty_integrity_association_binding(paths["BINDING_FILE"]),paths["STATE_DIRECTORY"],
            paths["AUTHORIZATION_KEY_FILE"],association_enabled=flags[1] == "true",restore_enabled=flags[2] == "true")
        return PuttyIntegrityAssociationActions(
            PuttyIntegrityAssociationMcpAction(PuttyIntegrityAssociationWorkflow(transport),execution_enabled=flags[1] == "true"),
            PuttyIntegrityAssociationMcpAction(PuttyIntegrityAssociationWorkflow(transport,recovery=True),execution_enabled=flags[2] == "true"),
        )
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def register_putty_integrity_association_tools(server: Any, actions: PuttyIntegrityAssociationActions) -> None:
    from .server import LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, READ_ONLY_TOOL_ANNOTATIONS

    @server.mcp.tool(description="Preview one software-hash reference change between fixed verified-owned Windows fixtures.",
                     annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_putty_integrity_association_700() -> dict[str, object]:
        return await asyncio.to_thread(actions.association.preview,server._v4_planning_principal())

    @server.mcp.tool(description="Bind the unchanged Windows integrity association to this authorized requester once.",
                     annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_putty_integrity_association_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(actions.association.confirm,preview_ref,server._v4_password_policy_action_principal())

    @server.mcp.tool(description="Change only the fixed Windows software reference once and verify both complete objects; never launch.",
                     annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_putty_integrity_association_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(actions.association.execute,authorization_ref,server._v4_password_policy_action_principal())

    @server.mcp.tool(description="Preview restoration only of this binding's verified, unchanged software association.",
                     annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_putty_integrity_association_restore_700() -> dict[str, object]:
        return await asyncio.to_thread(actions.restore.preview,server._v4_planning_principal())

    @server.mcp.tool(description="Bind unchanged verified software-reference restoration to this requester once.",
                     annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_putty_integrity_association_restore_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(actions.restore.confirm,preview_ref,server._v4_password_policy_action_principal())

    @server.mcp.tool(description="Restore only the bound verified software reference once; preserve executable and all other fields.",
                     annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_putty_integrity_association_restore_700(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(actions.restore.execute,authorization_ref,server._v4_password_policy_action_principal())
