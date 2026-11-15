"""Default-off OAuth/MCP candidate for one fixed FortiPAM 7.0 Job run."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .job_activation_live_workflow import JobActivationLiveWorkflow
from .job_definition_http_transport import FortiPamDisabledJobHttpTransport
from .job_definition_mcp_action import _load_binding, _requester
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config


PREFIX = "FORTIPAM_MCP_V4_FIXED_JOB_ACTIVATION_700_"
_UNAVAILABLE = "The fixed Job activation action is unavailable."


class JobActivationMcpAction:
    def __init__(
        self, workflow: JobActivationLiveWorkflow, *, execution_enabled: bool,
    ) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def observe(self, principal: Any) -> dict[str, object]:
        try:
            return self._workflow.observe(requester_digest=_requester(principal))
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

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


def build_fixed_job_activation_candidate(
    environment: Mapping[str, str],
) -> JobActivationMcpAction | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    gate = environment.get(PREFIX + "EXECUTION_ENABLED", "false")
    if enabled not in {"true", "false"} or gate not in {"true", "false"}:
        raise ValueError(_UNAVAILABLE)
    if enabled == "false":
        if gate == "true":
            raise ValueError(_UNAVAILABLE)
        return None
    try:
        binding_path = Path(environment[PREFIX + "BINDING_FILE"])
        claim_path = Path(environment[PREFIX + "CLAIM_FILE"])
        if not binding_path.is_absolute() or not claim_path.is_absolute():
            raise ValueError
        binding = _load_binding(binding_path)
        transport = FortiPamDisabledJobHttpTransport(
            load_secret_metadata_http_transport_config(environment),
            target_name=binding["target_name"],
            target_requester=binding["target_requester"],
            expected_secret_id=binding["expected_secret_id"],
        )
        return JobActivationMcpAction(
            JobActivationLiveWorkflow(transport, claim_path),
            execution_enabled=gate == "true",
        )
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def register_fixed_job_activation_candidate_tools(
    server: Any, action: JobActivationMcpAction,
) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    @server.mcp.tool(
        description=(
            "Observe categorical execution timing for one privately bound "
            "FortiPAM 7.0 Job without returning script output."
        ),
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
    )
    async def observe_v4_fixed_job_activation_700() -> dict[str, object]:
        return await asyncio.to_thread(
            action.observe, server._v4_planning_principal(),
        )

    @server.mcp.tool(
        description=(
            "Preview one future activation of the privately bound harmless "
            "one-shot Job without a device write."
        ),
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
    )
    async def preview_v4_fixed_job_activation_700() -> dict[str, object]:
        return await asyncio.to_thread(
            action.preview, server._v4_planning_principal(),
        )

    @server.mcp.tool(
        description="Record one requester-bound technical confirmation; no device write.",
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
    )
    async def confirm_v4_fixed_job_activation_700(
        preview_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.confirm, preview_ref, server._v4_password_policy_action_principal(),
        )

    @server.mcp.tool(
        description=(
            "Activate the confirmed fixed Job once and verify it became enabled; "
            "actual script execution requires later observation."
        ),
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
    )
    async def execute_confirmed_v4_fixed_job_activation_700(
        authorization_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.execute, authorization_ref,
            server._v4_password_policy_action_principal(),
        )
