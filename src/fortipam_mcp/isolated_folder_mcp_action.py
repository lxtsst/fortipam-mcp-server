"""Explicit candidate-only MCP entry for a private-bound isolated Folder."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
import stat
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from .folder_mcp_action import ProtectedChildFolderMcpAction
from .folder_namespace_candidate import build_folder_namespace_observer
from .isolated_folder_live_workflow import IsolatedFolderLiveWorkflow
from .isolated_folder_m4_adapter import InitialRdpPolicyBinding, IsolatedFolderBinding
from .isolated_folder_http_transport import IsolatedFolderHttpTransport
from .owner_collector_runtime import PREFIX as OWNER_LOGIN_PREFIX, owner_login_provider
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config

PREFIX = "FORTIPAM_MCP_V4_ISOLATED_FOLDER_"
CONTRACT = "fortipam-700-build29-isolated-folder-candidate-v1"
RDP_POLICY_CONTRACT = "fortipam-700-build29-initial-rdp-policy-folder-candidate-v1"
_UNAVAILABLE = "The isolated Folder candidate configuration is unavailable."


class IsolatedFolderMcpAction:
    def __init__(self, workflow: IsolatedFolderLiveWorkflow, binding: IsolatedFolderBinding, *, execution_enabled: bool = False) -> None:
        self._workflow = workflow
        self._action = ProtectedChildFolderMcpAction(workflow, execution_enabled=execution_enabled)
        self._binding = binding

    def preview(self, principal: Any) -> dict[str, object]:
        return self._action.preview(self._binding.name, self._binding.parent_folder_id, principal)

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        return self._action.confirm(preview_ref, principal)

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        return self._action.execute(authorization_ref, principal)


def _private_binding(path: Path) -> tuple[IsolatedFolderBinding, str]:
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
        fields = {"contract", "name", "parent_folder_id", "owner_name", "parent_digest", "parent_path"}
        if (len(content) > 16384 or not isinstance(value, dict)
            or value.get("contract") not in {CONTRACT, RDP_POLICY_CONTRACT}
            or set(value) != fields | ({"initial_rdp_policy"} if value["contract"] == RDP_POLICY_CONTRACT else set())
            or not isinstance(value["parent_path"], str)):
            raise ValueError
        policy = None
        if value["contract"] == RDP_POLICY_CONTRACT:
            if type(value["initial_rdp_policy"]) is not dict or set(value["initial_rdp_policy"]) != {
                    "name", "configuration_digest", "serial_digest"}:
                raise ValueError
            policy = InitialRdpPolicyBinding(**value["initial_rdp_policy"])
        return IsolatedFolderBinding(value["name"], value["parent_folder_id"], value["owner_name"],
            value["parent_digest"], initial_rdp_policy=policy), value["parent_path"]
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def build_isolated_folder_candidate(environment: Mapping[str, str]) -> IsolatedFolderMcpAction | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    gate = environment.get(PREFIX + "EXECUTION_ENABLED", "false")
    namespace_enabled = environment.get(PREFIX + "NAMESPACE_ENABLED", "false")
    empty_policy = environment.get(PREFIX + "EMPTY_INACTIVE_POLICY_ENABLED", "false")
    initial_policy = environment.get(PREFIX + "INITIAL_RDP_POLICY_ENABLED", "false")
    ownership_serial = environment.get(PREFIX + "OWNERSHIP_EXPECTED_SERIAL")
    if (enabled not in {"true", "false"} or gate not in {"true", "false"}
        or namespace_enabled not in {"true", "false"}
        or empty_policy not in {"true", "false"}
        or initial_policy not in {"true", "false"}
        or initial_policy == "true" and empty_policy == "true"
        or ownership_serial is not None and (type(ownership_serial) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", ownership_serial) is None)
        or enabled == "false" and (gate == "true" or namespace_enabled == "true"
                                  or ownership_serial is not None or empty_policy == "true" or initial_policy == "true")):
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
        owner_enabled = environment.get(PREFIX + "OWNER_READBACK_ENABLED", "false")
        if owner_enabled not in {"true", "false"}:
            raise ValueError(_UNAVAILABLE)
        if (binding.initial_rdp_policy is not None) != (initial_policy == "true"):
            raise ValueError(_UNAVAILABLE)
        if initial_policy == "true" and (owner_enabled != "true" or namespace_enabled != "true"
            or binding.initial_rdp_policy is None or ownership_serial is None
            or hashlib.sha256(ownership_serial.encode("ascii")).hexdigest()
                != binding.initial_rdp_policy.serial_digest):
            raise ValueError(_UNAVAILABLE)
        if ownership_serial is not None and (owner_enabled != "true" or namespace_enabled != "true"):
            raise ValueError(_UNAVAILABLE)
        if empty_policy == "true":
            if owner_enabled != "true" or namespace_enabled != "true" or ownership_serial is None:
                raise ValueError(_UNAVAILABLE)
            binding = replace(binding, empty_inactive_policy=True)
        provider = None
        if owner_enabled == "true":
            login = {OWNER_LOGIN_PREFIX + "SESSION_ENABLED": "true"}
            for suffix in ("LOGIN_ENV_FILE", "USERNAME_VARIABLE", "PASSWORD_VARIABLE"):
                login[OWNER_LOGIN_PREFIX + suffix] = environment[PREFIX + "OWNER_" + suffix]
            provider = owner_login_provider(login)
            if provider is None:
                raise ValueError(_UNAVAILABLE)
        config = load_secret_metadata_http_transport_config(environment)
        namespace_options = {}
        if namespace_enabled == "true":
            if provider is None:
                raise ValueError(_UNAVAILABLE)
            namespace_options["namespace_observer"] = build_folder_namespace_observer(
                config, binding=binding, parent_path=parent_path, credentials=provider,
                ssh_host=environment[PREFIX + "SSH_HOST"],
                ssh_port=int(environment.get(PREFIX + "SSH_PORT", "22")),
                ssh_known_hosts_file=path("SSH_KNOWN_HOSTS_FILE"),
                witness_folder_id=int(environment[PREFIX + "NAMESPACE_WITNESS_FOLDER_ID"]),
            )
        transport = IsolatedFolderHttpTransport(
            config, parent_path=parent_path,
            child_name=binding.name if provider is not None else None,
            owner_name=binding.owner_name if provider is not None else None,
            owner_credentials=provider, **namespace_options,
        )
        workflow = IsolatedFolderLiveWorkflow(path("AUTHORIZATION_DB"), path("AUTHORIZATION_HMAC_KEY_FILE"),
            transport, binding=binding, ownership_expected_serial=ownership_serial)
        return IsolatedFolderMcpAction(workflow, binding, execution_enabled=gate == "true")
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def register_isolated_folder_tools(server: Any, action: IsolatedFolderMcpAction) -> None:
    from .server import READ_ONLY_TOOL_ANNOTATIONS, LOCAL_STATE_TOOL_ANNOTATIONS, LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS

    @server.mcp.tool(description="Preview the one private-bound 7.0 candidate isolated Folder; no device write.", annotations=READ_ONLY_TOOL_ANNOTATIONS)
    async def preview_v4_isolated_folder_create() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    @server.mcp.tool(description="Confirm an unchanged isolated Folder preview using operation authority.", annotations=LOCAL_STATE_TOOL_ANNOTATIONS)
    async def confirm_v4_isolated_folder_create(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.confirm, preview_ref, server._v4_folder_action_principal())

    @server.mcp.tool(description="Execute one confirmed isolated Folder candidate once, with fixed readback and an independent execution Gate.", annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS)
    async def execute_confirmed_v4_isolated_folder(authorization_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(action.execute, authorization_ref, server._v4_folder_action_principal())
