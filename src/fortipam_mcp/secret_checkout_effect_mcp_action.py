"""Default-off OAuth/MCP candidate for one private-bound Unix Secret."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from .secret_checkout_association_mcp_action import _load_binding
from .secret_checkout_effect_contract import Operation
from .secret_checkout_effect_http_transport import SecretCheckoutEffectHttpTransport
from .secret_checkout_effect_live_workflow import SecretCheckoutEffectLiveWorkflow
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config
from .v4_plan_runtime import V4PlanningPrincipal
from .owner_collector_runtime import owner_login_provider, PREFIX as OWNER_PREFIX


PREFIX = "FORTIPAM_MCP_V4_SECRET_CHECKOUT_EFFECT_700_"
_UNAVAILABLE = "FortiPAM V4 Secret checkout effect action is unavailable."


class SecretCheckoutEffectMcpAction:
    def __init__(
        self, workflow: SecretCheckoutEffectLiveWorkflow, *, execution_enabled: bool,
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


def build_secret_checkout_effect_candidate(
    environment: Mapping[str, str],
) -> SecretCheckoutEffectMcpAction | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    gate = environment.get(PREFIX + "EXECUTION_ENABLED", "false")
    if enabled not in {"true", "false"} or gate not in {"true", "false"}:
        raise ValueError(_UNAVAILABLE)
    if enabled == "false":
        if gate == "true":
            raise ValueError(_UNAVAILABLE)
        return None
    try:
        binding, restore, _account = _load_binding(_path(environment, "BINDING_FILE"))
        operation = environment[PREFIX + "OPERATION"]
        if restore or binding.checkout_script or binding.checkin_script or operation not in {"checkout", "checkin"}:
            raise ValueError
        operation = "checkout" if operation == "checkout" else "checkin"
        owner_settings = {OWNER_PREFIX + "SESSION_ENABLED": "true",
            OWNER_PREFIX + "LOGIN_ENV_FILE": environment[PREFIX + "LOGIN_ENV_FILE"],
            OWNER_PREFIX + "USERNAME_VARIABLE": environment[PREFIX + "OWNER_USERNAME_VARIABLE"],
            OWNER_PREFIX + "PASSWORD_VARIABLE": environment[PREFIX + "OWNER_PASSWORD_VARIABLE"]}
        credentials = owner_login_provider(owner_settings)
        if credentials is None:
            raise ValueError
        transport = SecretCheckoutEffectHttpTransport(
            load_secret_metadata_http_transport_config(environment), binding, credentials,
            operation=cast(Operation, operation), claim_path=_path(environment, "CLAIM_FILE"),
            execution_enabled=gate == "true",
        )
        workflow = SecretCheckoutEffectLiveWorkflow(
            _path(environment, "AUTHORIZATION_DB"),
            _path(environment, "AUTHORIZATION_HMAC_KEY_FILE"),
            transport, binding, operation=cast(Operation, operation),
        )
        return SecretCheckoutEffectMcpAction(
            workflow, execution_enabled=gate == "true",
        )
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def _path(environment: Mapping[str, str], name: str) -> Path:
    value = Path(environment[PREFIX + name])
    if not value.is_absolute():
        raise ValueError(_UNAVAILABLE)
    return value


def _requester(principal: Any) -> str:
    if not isinstance(principal, V4PlanningPrincipal):
        raise RuntimeError(_UNAVAILABLE)
    return principal.requester.digest


def register_secret_checkout_effect_candidate_tools(
    server: Any, action: SecretCheckoutEffectMcpAction,
) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    @server.mcp.tool(
        description=(
            "Preview the fixed FortiPAM 7.0 same-owner Unix Secret Checkout or Check-in effect "
            "using credential-redacted state; no device write."
        ),
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
    )
    async def preview_v4_secret_checkout_effect_700() -> dict[str, object]:
        return await asyncio.to_thread(
            action.preview, server._v4_planning_principal(),
        )

    @server.mcp.tool(
        description=(
            "Record one requester-bound authorization for the unchanged fixed "
            "Unix Secret native effect preview; no device write."
        ),
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
    )
    async def confirm_v4_secret_checkout_effect_700(
        preview_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.confirm, preview_ref, server._v4_secret_metadata_action_principal(),
        )

    @server.mcp.tool(
        description=(
            "Dispatch the confirmed fixed same-owner Unix Checkout or Check-in once "
            "through FortiPAM 7.0 and return credential-free categorical readback."
        ),
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
    )
    async def execute_confirmed_v4_secret_checkout_effect_700(
        authorization_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.execute, authorization_ref,
            server._v4_secret_metadata_action_principal(),
        )


__all__ = [
    "SecretCheckoutEffectMcpAction",
    "build_secret_checkout_effect_candidate",
    "register_secret_checkout_effect_candidate_tools",
]
