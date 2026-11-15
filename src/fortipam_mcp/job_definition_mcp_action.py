"""Default-off OAuth/MCP candidate for one disabled FortiPAM 7.0 Job."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from .job_definition_http_transport import FortiPamDisabledJobHttpTransport
from .job_definition_live_workflow import JobDefinitionCreateLiveWorkflow
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config
from .v4_plan_runtime import V4PlanningPrincipal


PREFIX = "FORTIPAM_MCP_V4_DISABLED_JOB_700_"
BINDING_CONTRACT = "fortipam_v4_disabled_job_700_private_binding_v1"
_UNAVAILABLE = "The fixed disabled Job action is unavailable."
_JOB_NAME = re.compile(r"mcp-v4-bp008-job-[0-9]{8}-r[1-9][0-9]*\Z")
_REQUESTER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,63}\Z")


class JobDefinitionMcpAction:
    def __init__(
        self, workflow: JobDefinitionCreateLiveWorkflow, *, execution_enabled: bool,
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


def build_disabled_job_candidate(
    environment: Mapping[str, str],
) -> JobDefinitionMcpAction | None:
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
        transport = FortiPamDisabledJobHttpTransport(
            load_secret_metadata_http_transport_config(environment),
            target_name=binding["target_name"],
            target_requester=binding["target_requester"],
            expected_secret_id=binding["expected_secret_id"],
        )
        workflow = JobDefinitionCreateLiveWorkflow(
            transport, _path(environment, "CLAIM_FILE"),
        )
        return JobDefinitionMcpAction(workflow, execution_enabled=gate == "true")
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def _path(environment: Mapping[str, str], suffix: str) -> Path:
    value = Path(environment[PREFIX + suffix])
    if not value.is_absolute():
        raise ValueError(_UNAVAILABLE)
    return value


def _load_binding(path: Path) -> dict[str, Any]:
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
    if (
        not isinstance(value, dict)
        or set(value) != {
            "contract", "target_name", "target_requester", "expected_secret_id",
        }
        or value["contract"] != BINDING_CONTRACT
        or not isinstance(value["target_name"], str)
        or _JOB_NAME.fullmatch(value["target_name"]) is None
        or not isinstance(value["target_requester"], str)
        or _REQUESTER_NAME.fullmatch(value["target_requester"]) is None
        or type(value["expected_secret_id"]) is not int
        or value["expected_secret_id"] <= 0
    ):
        raise ValueError(_UNAVAILABLE)
    return value


def _requester(principal: Any) -> str:
    if not isinstance(principal, V4PlanningPrincipal):
        raise RuntimeError(_UNAVAILABLE)
    return principal.requester.digest


def register_disabled_job_candidate_tools(server: Any, action: JobDefinitionMcpAction) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    @server.mcp.tool(
        description=(
            "Observe the privately bound FortiPAM 7.0 Job definition after a "
            "consumed dispatch; return only categorical state, without execution."
        ),
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
    )
    async def observe_v4_disabled_job_create_700() -> dict[str, object]:
        return await asyncio.to_thread(
            action.observe, server._v4_planning_principal(),
        )

    @server.mcp.tool(
        description=(
            "Preview one privately bound disabled one-shot FortiPAM 7.0 Job "
            "definition without returning its Secret or script."
        ),
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
    )
    async def preview_v4_disabled_job_create_700() -> dict[str, object]:
        return await asyncio.to_thread(
            action.preview, server._v4_planning_principal(),
        )

    @server.mcp.tool(
        description=(
            "Record one requester-bound technical authorization for the "
            "unchanged disabled Job preview; no device write."
        ),
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
    )
    async def confirm_v4_disabled_job_create_700(preview_ref: str) -> dict[str, object]:
        return await asyncio.to_thread(
            action.confirm, preview_ref, server._v4_password_policy_action_principal(),
        )

    @server.mcp.tool(
        description=(
            "Dispatch the confirmed privately bound disabled Job definition "
            "once and return categorical collection readback; do not execute it."
        ),
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
    )
    async def execute_confirmed_v4_disabled_job_create_700(
        authorization_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.execute, authorization_ref,
            server._v4_password_policy_action_principal(),
        )


__all__ = [
    "JobDefinitionMcpAction", "build_disabled_job_candidate",
    "register_disabled_job_candidate_tools",
]
