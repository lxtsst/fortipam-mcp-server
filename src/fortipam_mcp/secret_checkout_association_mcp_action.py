"""Default-off OAuth/MCP candidate for one private-bound Unix Secret."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
import json
import os
from pathlib import Path
import stat
from typing import Any

from .secret_checkout_association_http_transport import (
    SecretCheckoutAssociationHttpTransport,
    SecretCheckoutBinding,
)
from .secret_checkout_association_live_workflow import SecretCheckoutAssociationLiveWorkflow
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config
from .v4_plan_runtime import V4PlanningPrincipal
from .owner_collector_runtime import owner_login_provider, PREFIX as OWNER_PREFIX


PREFIX = "FORTIPAM_MCP_V4_SECRET_CHECKOUT_ASSOCIATION_700_"
BINDING_CONTRACT = "fortipam_v4_secret_checkout_association_700_private_binding_v5"
_UNAVAILABLE = "FortiPAM V4 Secret checkout association action is unavailable."


class SecretCheckoutAssociationMcpAction:
    def __init__(
        self, workflow: SecretCheckoutAssociationLiveWorkflow, *, execution_enabled: bool,
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


def build_secret_checkout_association_candidate(
    environment: Mapping[str, str],
) -> SecretCheckoutAssociationMcpAction | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    gate = environment.get(PREFIX + "EXECUTION_ENABLED", "false")
    if enabled not in {"true", "false"} or gate not in {"true", "false"}:
        raise ValueError(_UNAVAILABLE)
    if enabled == "false":
        if gate == "true":
            raise ValueError(_UNAVAILABLE)
        return None
    try:
        binding, restore, account = _load_binding(_path(environment, "BINDING_FILE"))
        owner_settings = {OWNER_PREFIX + "SESSION_ENABLED": "true",
            OWNER_PREFIX + "LOGIN_ENV_FILE": environment[PREFIX + "LOGIN_ENV_FILE"],
            OWNER_PREFIX + "USERNAME_VARIABLE": environment[PREFIX + "OWNER_USERNAME_VARIABLE"],
            OWNER_PREFIX + "PASSWORD_VARIABLE": environment[PREFIX + "OWNER_PASSWORD_VARIABLE"]}
        credentials = owner_login_provider(owner_settings)
        if credentials is None:
            raise ValueError
        transport = SecretCheckoutAssociationHttpTransport(
            load_secret_metadata_http_transport_config(environment), binding, credentials,
            restore=restore, claim_path=_path(environment, "CLAIM_FILE"),
            retained_account=lambda: account,
        )
        workflow = SecretCheckoutAssociationLiveWorkflow(
            _path(environment, "AUTHORIZATION_DB"),
            _path(environment, "AUTHORIZATION_HMAC_KEY_FILE"),
            transport, binding, restore=restore,
        )
        return SecretCheckoutAssociationMcpAction(
            workflow, execution_enabled=gate == "true",
        )
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def _path(environment: Mapping[str, str], name: str) -> Path:
    value = Path(environment[PREFIX + name])
    if not value.is_absolute():
        raise ValueError(_UNAVAILABLE)
    return value


def _load_binding(path: Path) -> tuple[SecretCheckoutBinding, bool, str]:
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
        "target_name", "target_address", "account_name", "checkout_script", "checkin_script",
        "baseline_controls", "force_checkout_idle_time", "restore", "execution_secret_name",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(_UNAVAILABLE)
    if value["contract"] != BINDING_CONTRACT:
        raise ValueError(_UNAVAILABLE)
    for key in fields - {"contract", "baseline_controls", "force_checkout_idle_time", "restore"}:
        if (not isinstance(value[key], str)
                or (not value[key] and key not in {"checkout_script", "checkin_script"})
                or len(value[key].encode("utf-8")) > 255
                or any(ord(char) < 32 or ord(char) == 127 for char in value[key])):
            raise ValueError(_UNAVAILABLE)
    from ipaddress import IPv4Address
    if str(IPv4Address(value["target_address"])) != value["target_address"]:
        raise ValueError(_UNAVAILABLE)
    if value["template_name"] != "Unix Account (SSH Password)":
        raise ValueError(_UNAVAILABLE)
    from .secret_checkout_association_contract import CONTROLS
    controls = value["baseline_controls"]
    if type(value["force_checkout_idle_time"]) is not int or not 0 <= value["force_checkout_idle_time"] <= 30:
        raise ValueError(_UNAVAILABLE)
    if type(value["restore"]) is not bool or not isinstance(controls, dict) or set(controls) != CONTROLS:
        raise ValueError(_UNAVAILABLE)
    if any(type(controls.get(key)) is not str or controls[key] != expected for key, expected in {
        "checkout": "disable", "checkout-script": "", "checkin-script": "",
        "checkout-duration-renew": "disable", "checkin-pwd-change": "disable",
    }.items()) or type(controls["checkout-duration"]) is not int or not 3 <= controls["checkout-duration"] <= 1440 \
            or type(controls["checkout-renew-times"]) is not int or not 1 <= controls["checkout-renew-times"] <= 5:
        raise ValueError(_UNAVAILABLE)
    import re
    match = re.fullmatch(r"MCPV4Checkout([0-9]{8}R[1-9][0-9]{0,2})", value["checkout_script"])
    if ((not (value["checkout_script"] == value["checkin_script"] == "")
         and (match is None or value["checkin_script"] != "MCPV4Checkin" + match.group(1)))
            or re.fullmatch(r"mcp-v4-bp008-(?:denial|checkout)-[0-9]{8}-r[1-9][0-9]*", value["secret_name"]) is None):
        raise ValueError(_UNAVAILABLE)
    return SecretCheckoutBinding(
        folder_path=value["folder_path"],
        owner_name=value["owner_name"],
        template_name=value["template_name"],
        secret_name=value["secret_name"],
        target_name=value["target_name"],
        target_address=value["target_address"],
        execution_secret_name=value["execution_secret_name"],
        checkout_script=value["checkout_script"],
        checkin_script=value["checkin_script"],
        baseline_controls=tuple(sorted(controls.items())),
        force_checkout_idle_time=value["force_checkout_idle_time"],
    ), value["restore"], value["account_name"]


def _requester(principal: Any) -> str:
    if not isinstance(principal, V4PlanningPrincipal):
        raise RuntimeError(_UNAVAILABLE)
    return principal.requester.digest


def register_secret_checkout_association_candidate_tools(
    server: Any, action: SecretCheckoutAssociationMcpAction,
) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    @server.mcp.tool(
        description=(
            "Preview the fixed FortiPAM 7.0 Unix Secret checkout Script association configuration delta "
            "using credential-redacted state; no device write."
        ),
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
    )
    async def preview_v4_secret_checkout_association_700() -> dict[str, object]:
        return await asyncio.to_thread(
            action.preview, server._v4_planning_principal(),
        )

    @server.mcp.tool(
        description=(
            "Record one requester-bound authorization for the unchanged fixed "
            "Unix Secret checkout Script association preview; no device write."
        ),
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
    )
    async def confirm_v4_secret_checkout_association_700(
        preview_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.confirm, preview_ref, server._v4_secret_metadata_action_principal(),
        )

    @server.mcp.tool(
        description=(
            "Apply the confirmed private-bound Unix checkout Script association once "
            "through FortiPAM 7.0 and return credential-free categorical readback."
        ),
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
    )
    async def execute_confirmed_v4_secret_checkout_association_700(
        authorization_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.execute, authorization_ref,
            server._v4_secret_metadata_action_principal(),
        )


__all__ = [
    "SecretCheckoutAssociationMcpAction",
    "build_secret_checkout_association_candidate",
    "register_secret_checkout_association_candidate_tools",
]
