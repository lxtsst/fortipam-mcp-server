"""Default-off OAuth/MCP candidate for one private-bound Job Request."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
import json
import os
from pathlib import Path
import stat
from typing import Any

from .job_request_deny_http_transport import (
    FortiPamJobRequestDenyHttpTransport,
    JobRequestDenyBinding,
)
from .job_request_deny_live_workflow import JobRequestDenyLiveWorkflow
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config
from .v4_plan_runtime import V4PlanningPrincipal
from .owner_collector_runtime import owner_login_provider, PREFIX as OWNER_PREFIX


PREFIX = "FORTIPAM_MCP_V4_JOB_REQUEST_DENY_700_"
BINDING_CONTRACT = "fortipam_v4_job_request_deny_700_private_binding_v1"
_UNAVAILABLE = "FortiPAM V4 Job Request denial action is unavailable."


class JobRequestDenyMcpAction:
    def __init__(
        self, workflow: JobRequestDenyLiveWorkflow, *, execution_enabled: bool,
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


def build_job_request_deny_candidate(
    environment: Mapping[str, str],
) -> JobRequestDenyMcpAction | None:
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
        login_settings = {OWNER_PREFIX + "SESSION_ENABLED": "true",
            OWNER_PREFIX + "LOGIN_ENV_FILE": environment[PREFIX + "LOGIN_ENV_FILE"],
            OWNER_PREFIX + "USERNAME_VARIABLE": environment[PREFIX + "REVIEWER_USERNAME_VARIABLE"],
            OWNER_PREFIX + "PASSWORD_VARIABLE": environment[PREFIX + "REVIEWER_PASSWORD_VARIABLE"]}
        credentials = owner_login_provider(login_settings)
        if credentials is None:
            raise ValueError
        transport = FortiPamJobRequestDenyHttpTransport(
            load_secret_metadata_http_transport_config(environment), binding, credentials,
            claim_path=_path(environment, "CLAIM_FILE"),
        )
        workflow = JobRequestDenyLiveWorkflow(
            _path(environment, "AUTHORIZATION_DB"),
            _path(environment, "AUTHORIZATION_HMAC_KEY_FILE"), transport, binding,
        )
        return JobRequestDenyMcpAction(
            workflow, execution_enabled=gate == "true",
        )
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def _path(environment: Mapping[str, str], name: str) -> Path:
    value = Path(environment[PREFIX + name])
    if not value.is_absolute():
        raise ValueError(_UNAVAILABLE)
    return value


def _load_binding(path: Path) -> JobRequestDenyBinding:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096):
            raise ValueError(_UNAVAILABLE)
        content = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    if len(content) > 4096:
        raise ValueError(_UNAVAILABLE)
    value = json.loads(content)
    fields = {"contract", "request_id", "secret_id", "job_name", "requester", "reviewer"}
    if not isinstance(value, dict) or set(value) != fields or value["contract"] != BINDING_CONTRACT:
        raise ValueError(_UNAVAILABLE)
    return JobRequestDenyBinding(**{k: value[k] for k in fields - {"contract"}})


def _requester(principal: Any) -> str:
    if not isinstance(principal, V4PlanningPrincipal):
        raise RuntimeError(_UNAVAILABLE)
    return principal.requester.digest


def register_job_request_deny_candidate_tools(
    server: Any, action: JobRequestDenyMcpAction,
) -> None:
    from .server import (
        LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
        LOCAL_STATE_TOOL_ANNOTATIONS,
        READ_ONLY_TOOL_ANNOTATIONS,
    )

    @server.mcp.tool(
        description=(
            "Preview one fixed FortiPAM 7.0 Job Request denial under an "
            "independently authenticated reviewer; no device write."
        ),
        annotations=READ_ONLY_TOOL_ANNOTATIONS,
    )
    async def preview_v4_job_request_deny_700() -> dict[str, object]:
        return await asyncio.to_thread(
            action.preview, server._v4_planning_principal(),
        )

    @server.mcp.tool(
        description=(
            "Record one MCP caller-bound authorization for the unchanged "
            "fixed Job Request denial preview; no device write."
        ),
        annotations=LOCAL_STATE_TOOL_ANNOTATIONS,
    )
    async def confirm_v4_job_request_deny_700(
        preview_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.confirm, preview_ref, server._v4_secret_metadata_action_principal(),
        )

    @server.mcp.tool(
        description=(
            "Deny the confirmed private-bound Job Request once through FortiPAM "
            "7.0 and return categorical denial and schedule readback."
        ),
        annotations=LAB_ADMIN_EXECUTE_TOOL_ANNOTATIONS,
    )
    async def execute_confirmed_v4_job_request_deny_700(
        authorization_ref: str,
    ) -> dict[str, object]:
        return await asyncio.to_thread(
            action.execute, authorization_ref,
            server._v4_secret_metadata_action_principal(),
        )


__all__ = [
    "JobRequestDenyMcpAction",
    "build_job_request_deny_candidate",
    "register_job_request_deny_candidate_tools",
]
