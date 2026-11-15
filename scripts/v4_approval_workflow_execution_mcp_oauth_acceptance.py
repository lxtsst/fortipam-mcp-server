#!/usr/bin/env python3
"""Execute one pre-authorized BP008 plan through HTTPS OAuth/MCP exactly once."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
for import_root in (str(SOURCE_ROOT), str(PROJECT_ROOT)):
    while import_root in sys.path:
        sys.path.remove(import_root)
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(SOURCE_ROOT))

from mcp import ClientSession

from fortipam_mcp.approval_and_observe_execution_mcp_action import (
    V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL,
)
from fortipam_mcp.env import EnvironmentFileError
from fortipam_mcp.secret_request_create_mcp_action import (
    V4_SECRET_REQUEST_CREATE_TOOL,
)
from scripts import v4_address_mcp_oauth_surface_acceptance as oauth
from v4_planning.models import PlanningContractError, require_ref


TOOLS = frozenset(
    {
        "get_server_info",
        "get_v4_plan_status",
        V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL,
    }
)
REQUEST_CREATE_TOOLS = frozenset(
    {
        "get_server_info",
        "get_v4_plan_status",
        V4_SECRET_REQUEST_CREATE_TOOL,
    }
)
_MAX_BINDING_BYTES = 2_048
_DISPATCH_CONTRACT = "fortipam_v4_bp008_execution_dispatch_record_v1"


class ApprovalWorkflowExecutionMcpOAuthAcceptanceError(RuntimeError):
    """Stable non-disclosing failure for one BP008 execution acceptance."""


async def run_approval_workflow_execution_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    execution_binding_file: Path | None,
    dispatch_state_file: Path,
    *,
    ca_file: Path | None = None,
    request_intent_ref_file: Path | None = None,
    allow_insecure_private_ip_lab: bool = False,
    lab_connect_host: str | None = None,
    lab_connect_port: int | None = None,
    allow_loopback_tunnel: bool = False,
    mcp_read_timeout_seconds: int = 30,
) -> dict[str, object]:
    """Execute BP008 and/or submit one exact same-requester Request once."""

    execution_requested = execution_binding_file is not None
    if not execution_requested and request_intent_ref_file is None:
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 execution or Request intent is required."
        )
    plan_ref, scheme_draft_ref = (
        (None, None)
        if execution_binding_file is None
        else _read_execution_binding(execution_binding_file)
    )
    intent_ref = (
        None
        if request_intent_ref_file is None
        else _read_request_intent_ref(request_intent_ref_file)
    )
    _validate_new_dispatch_state_path(dispatch_state_file)
    execution_result: dict[str, object] | None = None
    request_result: dict[str, object] | None = None

    async def callback(session: ClientSession) -> None:
        nonlocal execution_result, request_result
        server_info = _structured(
            await session.call_tool("get_server_info", {}),
            "server status",
        )
        _validate_server_info(
            server_info,
            approval_execution=execution_requested,
            request_create=intent_ref is not None,
        )
        plan_status = _structured(
            await session.call_tool("get_v4_plan_status", {}),
            "plan status",
        )
        _validate_plan_status(plan_status, approval_execution=execution_requested)
        _create_dispatch_record(dispatch_state_file)
        if execution_requested:
            assert plan_ref is not None and scheme_draft_ref is not None
            execution_result = _structured(
                await session.call_tool(
                    V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL,
                    {
                        "plan_ref": plan_ref,
                        "scheme_draft_ref": scheme_draft_ref,
                    },
                ),
                "execution",
            )
            _validate_execution(execution_result)
        if intent_ref is not None:
            request_result = _structured(
                await session.call_tool(
                    V4_SECRET_REQUEST_CREATE_TOOL,
                    {"intent_ref": intent_ref},
                ),
                "Request creation",
            )
            _validate_request_create(request_result)

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(
            url,
            login_file,
            client_state_file,
            ca_file=ca_file,
            tool_session_callback=callback,
            required_tools=(
                TOOLS
                if execution_requested and intent_ref is None
                else (
                    TOOLS | {V4_SECRET_REQUEST_CREATE_TOOL}
                    if execution_requested
                    else REQUEST_CREATE_TOOLS
                )
            ),
            allow_insecure_private_ip_lab=allow_insecure_private_ip_lab,
            lab_connect_host=lab_connect_host,
            lab_connect_port=lab_connect_port,
            allow_loopback_tunnel=allow_loopback_tunnel,
            mcp_read_timeout_seconds=mcp_read_timeout_seconds,
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
                "BP008 OAuth/MCP execution acceptance failed."
            ) from None
        raise
    if (
        common.get("oauth_metadata_verified") is not True
        or common.get("mcp_initialized") is not True
        or common.get("token_revoked") is not True
        or common.get("credential_values_returned") is not False
        or (execution_requested and execution_result is None)
        or (intent_ref is not None and request_result is None)
    ):
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 OAuth/MCP execution acceptance is incomplete."
        )
    completed = (
        []
        if execution_result is None
        else execution_result["completed_line_refs"]
    )
    assert isinstance(completed, list)
    return {
        "contract": "fortipam_v4_bp008_execution_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": True,
        "mcp_initialized": True,
        "required_tool_surface_complete": True,
        "source_backed_status_verified": True,
        "independent_approval_binding_verified": execution_requested,
        "dispatch_attempted_once": True,
        "completed_action_count": len(completed),
        "post_write_expected_state_verified": execution_requested,
        "approval_policy_action_attempted": execution_requested,
        "request_create_attempted": intent_ref is not None,
        "request_bound": intent_ref is not None,
        "request_identifiers_returned": False,
        "device_write_executed": execution_requested or intent_ref is not None,
        "reconciliation_required": False,
        "token_revoked": True,
        "credential_values_returned": False,
        "selector_values_returned": False,
        "plan_or_draft_refs_returned": False,
        "approval_receipt_returned": False,
        "client_id_returned": False,
        "token_returned": False,
    }


def _validate_server_info(
    value: dict[str, object],
    *,
    approval_execution: bool,
    request_create: bool,
) -> None:
    if (
        value.get("runtime_profile") != "v4-controlled"
        or value.get("v4_host_services_bound") is not True
        or (
            approval_execution
            and (
                value.get("v4_approval_and_observe_execution_bound") is not True
                or value.get("v4_approval_and_observe_execution_tool_count") != 1
            )
        )
        or (
            request_create
            and (
                value.get("v4_secret_request_create_bound") is not True
                or value.get("v4_secret_request_create_tool_count") != 1
            )
        )
    ):
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 execution Tool binding is unavailable."
        )


def _validate_request_create(value: dict[str, object]) -> None:
    if (
        set(value)
        != {
            "contract",
            "outcome",
            "raw_values_returned",
            "reconciliation_required",
            "request_bound",
            "request_identifiers_returned",
            "request_intent_returned",
        }
        or value.get("contract")
        != "fortipam-v4-secret-request-create-result-v1"
        or value.get("outcome") != "bound"
        or value.get("request_bound") is not True
        or value.get("reconciliation_required") is not False
        or value.get("raw_values_returned") is not False
        or value.get("request_identifiers_returned") is not False
        or value.get("request_intent_returned") is not False
    ):
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 Request creation or readback was not accepted."
        )


def _validate_plan_status(
    value: dict[str, object],
    *,
    approval_execution: bool,
) -> None:
    if (
        value.get("host_services_bound") is not True
        or value.get("projection_mode") != "source_backed"
        or value.get("confirmation_transport_bound") is not True
        or value.get("scheme_draft_issuance_protocol_bound") is not True
        or value.get("reference_authorization_protocol_bound") is not True
        or (
            approval_execution
            and (
                value.get("approval_receipt_authenticator_protocol_bound")
                is not True
                or value.get("approver_authorization_protocol_bound") is not True
            )
        )
        or "synthetic_scheme_draft_refs" in value
    ):
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 trusted Host status is unavailable."
        )


def _validate_execution(value: dict[str, object]) -> None:
    completed = value.get("completed_line_refs")
    if (
        set(value)
        != {
            "authorization_scope",
            "completed_line_refs",
            "outcome",
            "policy_mode",
            "post_write_status",
            "pre_write_status",
            "reconciliation_required",
            "stopped_line_ref",
        }
        or value.get("outcome") != "succeeded"
        or value.get("pre_write_status") != "match"
        or value.get("post_write_status") != "expected_state_matches"
        or value.get("reconciliation_required") is not False
        or value.get("stopped_line_ref") is not None
        or value.get("authorization_scope")
        != "source_bound_approval_workflow"
        or value.get("policy_mode") != "independent_approval"
        or not isinstance(completed, list)
        or len(completed) != 1
        or any(not isinstance(item, str) for item in completed)
    ):
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 execution or final readback was not accepted."
        )


def _structured(result: Any, stage: str) -> dict[str, object]:
    value = getattr(result, "structured_content", None)
    if getattr(result, "is_error", True) or not isinstance(value, dict):
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            f"BP008 {stage} Tool call failed."
        )
    return dict(value)


def _read_execution_binding(path: Path) -> tuple[str, str]:
    value = _read_owner_only_json(path, _MAX_BINDING_BYTES)
    plan_ref = value.get("plan_ref")
    scheme_draft_ref = value.get("scheme_draft_ref")
    if (
        set(value) != {"plan_ref", "scheme_draft_ref"}
        or not isinstance(plan_ref, str)
        or not isinstance(scheme_draft_ref, str)
    ):
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 execution binding file is invalid."
        )
    try:
        return (
            require_ref(plan_ref, "plan_ref"),
            require_ref(scheme_draft_ref, "scheme_draft_ref"),
        )
    except PlanningContractError:
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 execution binding file is invalid."
        ) from None


def _read_request_intent_ref(path: Path) -> str:
    value = _read_owner_only_json(path, _MAX_BINDING_BYTES)
    intent_ref = value.get("intent_ref")
    if set(value) != {"intent_ref"} or not isinstance(intent_ref, str):
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 Request intent reference file is invalid."
        )
    try:
        return require_ref(intent_ref, "intent_ref")
    except PlanningContractError:
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 Request intent reference file is invalid."
        ) from None


def _read_owner_only_json(path: Path, maximum_bytes: int) -> dict[str, object]:
    if not path.is_absolute():
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 state path is invalid."
        )
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or not 0 < metadata.st_size <= maximum_bytes
        ):
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            content = os.read(descriptor, maximum_bytes + 1)
        finally:
            os.close(descriptor)
        value = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 state file is unavailable."
        ) from None
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 state file is invalid."
        )
    return value


def _validate_new_dispatch_state_path(path: Path) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 dispatch state file is unavailable."
        )
    try:
        parent = path.parent.lstat()
    except OSError:
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 dispatch state directory is unavailable."
        ) from None
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 dispatch state directory must be owner-only."
        )


def _create_dispatch_record(path: Path) -> None:
    content = json.dumps(
        {
            "contract": _DISPATCH_CONTRACT,
            "dispatch_attempted": True,
            "retry_allowed": False,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"
    try:
        descriptor = os.open(
            path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            written = 0
            while written < len(content):
                count = os.write(descriptor, content[written:])
                if count <= 0:
                    raise OSError
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise ApprovalWorkflowExecutionMcpOAuthAcceptanceError(
            "BP008 dispatch state file is unavailable."
        ) from None


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(
        isinstance(
            item,
            (
                ApprovalWorkflowExecutionMcpOAuthAcceptanceError,
                oauth.AddressMcpOAuthSurfaceAcceptanceError,
            ),
        )
        or (isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item))
        for item in error.exceptions
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--execution-binding-file", type=Path)
    parser.add_argument("--dispatch-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--request-intent-ref-file", type=Path)
    parser.add_argument(
        "--allow-insecure-private-ip-lab",
        action="store_true",
        help="Allow HTTP only for the explicit private-IP laboratory exception.",
    )
    parser.add_argument("--lab-connect-host")
    parser.add_argument("--lab-connect-port", type=int)
    parser.add_argument("--allow-loopback-tunnel", action="store_true")
    parser.add_argument("--mcp-read-timeout-seconds", type=int, default=30)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_approval_workflow_execution_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                args.execution_binding_file,
                args.dispatch_state_file,
                ca_file=args.ca_file,
                request_intent_ref_file=args.request_intent_ref_file,
                allow_insecure_private_ip_lab=(
                    args.allow_insecure_private_ip_lab
                ),
                lab_connect_host=args.lab_connect_host,
                lab_connect_port=args.lab_connect_port,
                allow_loopback_tunnel=args.allow_loopback_tunnel,
                mcp_read_timeout_seconds=args.mcp_read_timeout_seconds,
            )
        )
    except (
        EnvironmentFileError,
        ApprovalWorkflowExecutionMcpOAuthAcceptanceError,
        ValueError,
    ) as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
