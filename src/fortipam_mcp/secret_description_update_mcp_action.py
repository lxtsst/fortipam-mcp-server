"""Default-off OAuth/MCP candidate for one private-bound Unix Secret."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
import json
import os
from pathlib import Path
import stat
from typing import Any

from .secret_description_update_http_transport import (
    FortiPamSecretDescriptionUpdateHttpTransport,
    SecretDescriptionBinding,
)
from .secret_description_update_live_workflow import SecretDescriptionUpdateLiveWorkflow
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config
from .v4_plan_runtime import V4PlanningPrincipal
from .owner_collector_runtime import owner_login_provider, PREFIX as OWNER_PREFIX


PREFIX = "FORTIPAM_MCP_V4_SECRET_DESCRIPTION_UPDATE_700_"
BINDING_CONTRACT = "fortipam_v4_secret_description_update_700_private_binding_v1"
_UNAVAILABLE = "FortiPAM V4 Secret description update action is unavailable."


class SecretDescriptionUpdateMcpAction:
    def __init__(
        self, workflow: SecretDescriptionUpdateLiveWorkflow, *, execution_enabled: bool,
    ) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(self, principal: Any) -> dict[str, object]:
        try:
            return self._workflow.preview(requester_digest=_requester(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        try:
            return self._workflow.confirm(
                preview_ref, requester_digest=_requester(principal),
            )
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


def build_secret_description_update_candidate(
    environment: Mapping[str, str],
) -> SecretDescriptionUpdateMcpAction | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    gate = environment.get(PREFIX + "EXECUTION_ENABLED", "false")
    if enabled not in {"true", "false"} or gate not in {"true", "false"}:
        raise ValueError(_UNAVAILABLE)
    if enabled == "false":
        if gate == "true":
            raise ValueError(_UNAVAILABLE)
        return None
    try:
        binding, description, account = _load_binding(_path(environment, "BINDING_FILE"))
        owner_settings = {OWNER_PREFIX + "SESSION_ENABLED": "true",
            OWNER_PREFIX + "LOGIN_ENV_FILE": environment[PREFIX + "LOGIN_ENV_FILE"],
            OWNER_PREFIX + "USERNAME_VARIABLE": environment[PREFIX + "OWNER_USERNAME_VARIABLE"],
            OWNER_PREFIX + "PASSWORD_VARIABLE": environment[PREFIX + "OWNER_PASSWORD_VARIABLE"]}
        credentials = owner_login_provider(owner_settings)
        if credentials is None:
            raise ValueError
        transport = FortiPamSecretDescriptionUpdateHttpTransport(
            load_secret_metadata_http_transport_config(environment), binding, credentials,
            description=description, claim_path=_path(environment, "CLAIM_FILE"),
            retained_account=lambda: account,
        )
        workflow = SecretDescriptionUpdateLiveWorkflow(
            _path(environment, "AUTHORIZATION_DB"),
            _path(environment, "AUTHORIZATION_HMAC_KEY_FILE"),
            transport, binding, description=description,
        )
        return SecretDescriptionUpdateMcpAction(
            workflow, execution_enabled=gate == "true",
        )
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def _path(environment: Mapping[str, str], name: str) -> Path:
    value = Path(environment[PREFIX + name])
    if not value.is_absolute():
        raise ValueError(_UNAVAILABLE)
    return value


def _load_binding(path: Path) -> tuple[SecretDescriptionBinding, str, str]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or not 0 < info.st_size <= 4096
        ):
            raise ValueError(_UNAVAILABLE)
        content = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    if len(content) > 4096:
        raise ValueError(_UNAVAILABLE)
    value = json.loads(content)
    fields = {
        "contract", "folder_path", "owner_name", "secret_name", "template_name",
        "target_name", "target_address", "account_name", "description",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(_UNAVAILABLE)
    if value["contract"] != BINDING_CONTRACT:
        raise ValueError(_UNAVAILABLE)
    for key in fields - {"contract", "description"}:
        if (not isinstance(value[key], str) or not value[key]
                or len(value[key].encode("utf-8")) > 255
                or any(ord(char) < 32 or ord(char) == 127 for char in value[key])):
            raise ValueError(_UNAVAILABLE)
    from ipaddress import IPv4Address
    if str(IPv4Address(value["target_address"])) != value["target_address"]:
        raise ValueError(_UNAVAILABLE)
    if value["template_name"] != "Unix Account (SSH Password)":
        raise ValueError(_UNAVAILABLE)
    return SecretDescriptionBinding(
        folder_path=value["folder_path"],
        owner_name=value["owner_name"],
        template_name=value["template_name"],
        secret_name=value["secret_name"],
        target_name=value["target_name"],
        target_address=value["target_address"],
    ), value["description"], value["account_name"]


def _requester(principal: Any) -> str:
    if not isinstance(principal, V4PlanningPrincipal):
        raise RuntimeError(_UNAVAILABLE)
    return principal.requester.digest


def register_secret_description_update_candidate_tools(
    server: Any, action: SecretDescriptionUpdateMcpAction,
) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    @server.mcp.tool(
        description=(
            "Preview the fixed FortiPAM 7.0 Unix Secret description delta "
            "using credential-redacted state; no device write."
        ),
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
    )
    async def preview_v4_secret_description_update_700() -> dict[str, object]:
        return await asyncio.to_thread(
            action.preview, server._v4_planning_principal(),
        )

    @server.mcp.tool(
        description=(
            "Record one requester-bound authorization for the unchanged fixed "
            "Unix Secret description preview; no device write."
        ),
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
    )
    async def confirm_v4_secret_description_update_700(
        preview_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.confirm, preview_ref, server._v4_secret_metadata_action_principal(),
        )

    @server.mcp.tool(
        description=(
            "Apply the confirmed private-bound Unix description update once "
            "through FortiPAM 7.0 and return credential-free categorical readback."
        ),
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
    )
    async def execute_confirmed_v4_secret_description_update_700(
        authorization_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.execute, authorization_ref,
            server._v4_secret_metadata_action_principal(),
        )


__all__ = [
    "SecretDescriptionUpdateMcpAction",
    "build_secret_description_update_candidate",
    "register_secret_description_update_candidate_tools",
]
