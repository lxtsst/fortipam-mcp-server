"""Default-off OAuth/MCP recovery candidate for one FortiPAM 7.0 Unix clone."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .password_changer_delete_http_transport import FortiPamUnixPasswordChangerDeleteHttpTransport
from .password_changer_delete_live_workflow import PasswordChangerDeleteLiveWorkflow
from .password_changer_mcp_action import _load_binding, _requester
from .password_changer_reference_ssh_transport import FortiPamPasswordChangerReferenceSshTransport
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config
from .template_ssh_transport import load_template_ssh_transport_config


PREFIX = "FORTIPAM_MCP_V4_PASSWORD_CHANGER_DELETE_700_"
_UNAVAILABLE = "FortiPAM V4 Unix Password Changer recovery is unavailable."


class PasswordChangerDeleteMcpAction:
    def __init__(
        self, workflow: PasswordChangerDeleteLiveWorkflow, *, execution_enabled: bool,
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


def build_password_changer_delete_candidate(
    environment: Mapping[str, str],
) -> PasswordChangerDeleteMcpAction | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    gate = environment.get(PREFIX + "EXECUTION_ENABLED", "false")
    if enabled not in {"true", "false"} or gate not in {"true", "false"}:
        raise ValueError(_UNAVAILABLE)
    if enabled == "false":
        if gate == "true":
            raise ValueError(_UNAVAILABLE)
        return None
    try:
        binding = _load_binding(_path(environment, "BINDING_FILE"))
        references = FortiPamPasswordChangerReferenceSshTransport(
            load_template_ssh_transport_config(environment),
        )
        transport = FortiPamUnixPasswordChangerDeleteHttpTransport(
            load_secret_metadata_http_transport_config(environment), binding,
            references,
        )
        workflow = PasswordChangerDeleteLiveWorkflow(
            transport, _path(environment, "CLAIM_FILE"),
        )
        return PasswordChangerDeleteMcpAction(workflow, execution_enabled=gate == "true")
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def _path(environment: Mapping[str, str], suffix: str) -> Path:
    value = Path(environment[PREFIX + suffix])
    if not value.is_absolute():
        raise ValueError(_UNAVAILABLE)
    return value


def register_password_changer_delete_candidate_tools(
    server: Any, action: PasswordChangerDeleteMcpAction,
) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    @server.mcp.tool(
        description=(
            "Preview deletion of one privately bound, exact, unreferenced "
            "FortiPAM 7.0 Unix Password Changer clone."
        ),
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
    )
    async def preview_v4_password_changer_delete_700() -> dict[str, object]:
        return await asyncio.to_thread(action.preview, server._v4_planning_principal())

    @server.mcp.tool(
        description=(
            "Record one requester-bound authorization for the unchanged "
            "Password Changer recovery preview; no device write."
        ),
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
    )
    async def confirm_v4_password_changer_delete_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(
            action.confirm, preview_ref, server._v4_password_policy_action_principal(),
        )

    @server.mcp.tool(
        description=(
            "Dispatch one fixed DELETE for the confirmed unreferenced Unix "
            "clone and return categorical absence and source-preservation readback."
        ),
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
    )
    async def execute_confirmed_v4_password_changer_delete_700(
        authorization_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.execute, authorization_ref,
            server._v4_password_policy_action_principal(),
        )


__all__ = [
    "PasswordChangerDeleteMcpAction",
    "build_password_changer_delete_candidate",
    "register_password_changer_delete_candidate_tools",
]
