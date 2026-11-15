"""Explicit candidate-only MCP entry for a private-bound Folder traversal."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import stat
from collections.abc import Mapping
from typing import Any

from .folder_mcp_action import ProtectedChildFolderMcpAction
from .folder_traversal_live_workflow import FolderTraversalLiveWorkflow
from .folder_traversal_m4_adapter import FolderTraversalBinding
from .folder_traversal_http_transport import FolderTraversalHttpTransport
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config

PREFIX = "FORTIPAM_MCP_V4_FOLDER_TRAVERSAL_"
CONTRACT = "fortipam-700-build29-folder-traversal-candidate-v1"
_UNAVAILABLE = "The Folder traversal candidate configuration is unavailable."


class FolderTraversalMcpAction:
    def __init__(self, workflow: FolderTraversalLiveWorkflow, binding: FolderTraversalBinding, *, execution_enabled: bool = False) -> None:
        self._action = ProtectedChildFolderMcpAction(workflow, execution_enabled=execution_enabled)
        self._binding = binding

    def preview(self, principal: Any) -> dict[str, object]:
        return self._action.preview("folder-traversal", self._binding.folder_id, principal)

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        return self._action.confirm(preview_ref, principal)

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        return self._action.execute(authorization_ref, principal)


def _private_binding(path: Path) -> tuple[FolderTraversalBinding, str]:
    try:
        if not path.is_absolute():
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077 or not 0 < info.st_size <= 16384):
                raise ValueError
            content = os.read(descriptor, 16385)
        finally:
            os.close(descriptor)
        value = json.loads(content)
        if (len(content) > 16384 or not isinstance(value, dict) or set(value) != {
            "contract", "folder_id", "parent_id", "username", "current_digest", "expected_digest", "parent_path"
        } or value["contract"] != CONTRACT or not isinstance(value["parent_path"], str)):
            raise ValueError
        return FolderTraversalBinding(value["folder_id"], value["parent_id"], value["username"], value["current_digest"], value["expected_digest"]), value["parent_path"]
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def build_folder_traversal_candidate(environment: Mapping[str, str]) -> FolderTraversalMcpAction | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    gate = environment.get(PREFIX + "EXECUTION_ENABLED", "false")
    if enabled not in {"true", "false"} or gate not in {"true", "false"} or enabled == "false" and gate == "true":
        raise ValueError(_UNAVAILABLE)
    if enabled == "false":
        return None
    try:
        def path(suffix: str) -> Path:
            value = Path(environment[PREFIX + suffix])
            if not value.is_absolute():
                raise ValueError
            return value
        binding, parent_path = _private_binding(path("BINDING_FILE"))
        transport = FolderTraversalHttpTransport(load_secret_metadata_http_transport_config(environment), parent_path=parent_path)
        workflow = FolderTraversalLiveWorkflow(path("AUTHORIZATION_DB"), path("AUTHORIZATION_HMAC_KEY_FILE"),
            transport, binding=binding)
        return FolderTraversalMcpAction(workflow, binding, execution_enabled=gate == "true")
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def register_folder_traversal_tools(server: Any, action: FolderTraversalMcpAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS

    @server.mcp.tool(description="Preview the one private-bound 7.0 candidate Folder traversal; no device write.", annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_folder_traversal_grant() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    @server.mcp.tool(description="Confirm an unchanged Folder traversal preview using operation authority.", annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_folder_traversal_grant(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.confirm, preview_ref, server._v4_folder_action_principal())

    @server.mcp.tool(description="Execute one confirmed Folder traversal candidate once, with fixed readback and an independent execution Gate.", annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_folder_traversal(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.execute, authorization_ref, server._v4_folder_action_principal())
