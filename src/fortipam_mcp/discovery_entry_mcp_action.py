"""Default-off OAuth/MCP candidate for one 7.0 Unix Discovery source."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
import json
import os
from pathlib import Path
import stat
from typing import Any

from .discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from .discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from .discovery_entry_live_workflow import UnixDiscoveryCreateLiveWorkflow
from .password_changer_mcp_action import _requester
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config


PREFIX = "FORTIPAM_MCP_V4_DISCOVERY_UNIX_700_"
BINDING_CONTRACT = "fortipam_v4_unix_discovery_700_private_binding_v1"
_UNAVAILABLE = "FortiPAM V4 Unix Discovery action is unavailable."


class UnixDiscoveryMcpAction:
    def __init__(self, workflow: UnixDiscoveryCreateLiveWorkflow, *, execution_enabled: bool) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

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
        if not self._execution_enabled:
            raise RuntimeError(_UNAVAILABLE)
        try:
            return self._workflow.execute(
                authorization_ref, requester_digest=_requester(principal),
            )
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None


def build_unix_discovery_candidate(environment: Mapping[str, str]) -> UnixDiscoveryMcpAction | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    gate = environment.get(PREFIX + "EXECUTION_ENABLED", "false")
    if enabled not in {"true", "false"} or gate not in {"true", "false"}:
        raise ValueError(_UNAVAILABLE)
    if enabled == "false":
        if gate == "true":
            raise ValueError(_UNAVAILABLE)
        return None
    try:
        request = _load_binding(_path(environment, "BINDING_FILE"))
        transport = FortiPamDiscoveryEntryCreateHttpTransport(
            load_secret_metadata_http_transport_config(environment),
        )
        workflow = UnixDiscoveryCreateLiveWorkflow(
            transport, request, _path(environment, "CLAIM_FILE"),
        )
        return UnixDiscoveryMcpAction(workflow, execution_enabled=gate == "true")
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def _path(environment: Mapping[str, str], suffix: str) -> Path:
    value = Path(environment[PREFIX + suffix])
    if not value.is_absolute():
        raise ValueError(_UNAVAILABLE)
    return value


def _load_binding(path: Path) -> DisabledUnixDiscoveryCreateInput:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= 4096):
            raise ValueError(_UNAVAILABLE)
        content = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    if len(content) > 4096:
        raise ValueError(_UNAVAILABLE)
    value = json.loads(content)
    if (not isinstance(value, dict)
            or set(value) != {"contract", "source_name", "discovery_secret_id"}
            or value["contract"] != BINDING_CONTRACT):
        raise ValueError(_UNAVAILABLE)
    return DisabledUnixDiscoveryCreateInput(
        value["source_name"], value["discovery_secret_id"],
    )


def register_unix_discovery_candidate_tools(server: Any, action: UnixDiscoveryMcpAction) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    @server.mcp.tool(
        description="Preview one privately bound disabled-scan Unix Discovery source on FortiPAM 7.0.",
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
    )
    async def preview_v4_unix_discovery_create_700() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    @server.mcp.tool(
        description="Record requester-bound authorization for the unchanged Unix Discovery preview.",
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
    )
    async def confirm_v4_unix_discovery_create_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(
            action.confirm, preview_ref, server._v4_password_policy_action_principal(),
        )

    @server.mcp.tool(
        description="Create the exact bound disabled-scan Unix Discovery source once and verify its detail.",
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
    )
    async def execute_confirmed_v4_unix_discovery_create_700(
        authorization_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.execute, authorization_ref,
            server._v4_password_policy_action_principal(),
        )


__all__ = [
    "UnixDiscoveryMcpAction",
    "build_unix_discovery_candidate",
    "register_unix_discovery_candidate_tools",
]
