#!/usr/bin/env python3
"""Verify one source-backed BP008 plan through HTTPS OAuth/MCP without writes."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import stat
from typing import Any
from urllib.parse import urlunsplit

import httpx2
from mcp import ClientSession

from fortipam_mcp.env import EnvironmentFileError
from scripts import v4_address_mcp_oauth_surface_acceptance as oauth
from scripts.local_oauth_http_acceptance import LOGIN_PASSWORD, LOGIN_USERNAME
from scripts.v4_https_oauth_acceptance import (
    V4HttpsOAuthAcceptanceError,
    _affirm_browser_confirmation,
    _confirmation_url,
    _revision,
    _validate_https_mcp_url,
    _validate_plan,
    _validate_preview,
)
from v4_planning.models import PlanningContractError, require_ref


TOOLS = frozenset(
    {
        "get_v4_plan_status",
        "preview_v4_administrative_intent",
        "confirm_v4_administrative_intent",
        "prepare_v4_non_executable_plan",
    }
)
REQUEST_OBSERVATION_TOOL = "observe_v4_bound_secret_request"
_MAX_REF_FILE_BYTES = 1_024


class ApprovalWorkflowMcpOAuthAcceptanceError(RuntimeError):
    """Stable non-disclosing failure for one BP008 plan acceptance."""


async def run_approval_workflow_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    scheme_draft_ref_file: Path,
    *,
    ca_file: Path | None = None,
    request_ref_file: Path | None = None,
    execution_binding_output_file: Path | None = None,
) -> dict[str, object]:
    """Preview, confirm, and prepare one pre-issued BP008 Draft without dispatch."""

    parsed = _validate_https_mcp_url(url)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    verify: str | bool = str(ca_file) if ca_file is not None else True
    scheme_draft_ref = _read_scheme_draft_ref(scheme_draft_ref_file)
    request_ref = (
        _read_owner_only_ref(request_ref_file, "request_ref")
        if request_ref_file is not None
        else None
    )
    if execution_binding_output_file is not None:
        _validate_new_owner_only_output_path(execution_binding_output_file)
    preview_verified = False
    confirmation_consumed = False
    plan_prepared = False
    request_observation_verified = False
    execution_binding_staged = False

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, confirmation_consumed, plan_prepared
        nonlocal request_observation_verified, execution_binding_staged

        status = _structured(
            await session.call_tool("get_v4_plan_status", {}),
            "status",
        )
        _validate_source_backed_status(status)
        preview = _structured(
            await session.call_tool(
                "preview_v4_administrative_intent",
                {"scheme_draft_ref": scheme_draft_ref},
            ),
            "preview",
        )
        _validate_preview(preview)
        _validate_bp008_preview(preview)
        preview_verified = True

        username = os.environ.get(LOGIN_USERNAME)
        password = os.environ.get(LOGIN_PASSWORD)
        if not username or not password:
            raise ApprovalWorkflowMcpOAuthAcceptanceError(
                "OAuth confirmation identity is unavailable."
            )
        async with httpx2.AsyncClient(
            timeout=30.0,
            follow_redirects=False,
            trust_env=False,
            verify=verify,
            headers={"User-Agent": "fortipam-mcp-v4-bp008-plan-acceptance/1"},
        ) as browser:
            await _affirm_browser_confirmation(
                browser,
                _confirmation_url(preview, origin),
                origin=origin,
                username=username,
                password=password,
            )

        summary_ref = str(preview["summary_ref"])
        confirmation = _structured(
            await session.call_tool(
                "confirm_v4_administrative_intent",
                {
                    "summary_ref": summary_ref,
                    "summary_revision": _revision(preview),
                },
            ),
            "confirmation",
        )
        confirmation_ref = confirmation.get("confirmation_ref")
        if not isinstance(confirmation_ref, str):
            raise ApprovalWorkflowMcpOAuthAcceptanceError(
                "BP008 confirmation consumption failed."
            )
        confirmation_consumed = True
        plan = _structured(
            await session.call_tool(
                "prepare_v4_non_executable_plan",
                {
                    "summary_ref": summary_ref,
                    "confirmation_ref": confirmation_ref,
                },
            ),
            "plan",
        )
        _validate_plan(plan)
        _validate_bp008_plan(plan)
        plan_ref = plan.get("plan_ref")
        if not isinstance(plan_ref, str):
            raise ApprovalWorkflowMcpOAuthAcceptanceError(
                "BP008 prepared Plan is unavailable."
            )
        plan_prepared = True
        if execution_binding_output_file is not None:
            _write_execution_binding(
                execution_binding_output_file,
                plan_ref,
                scheme_draft_ref,
            )
            execution_binding_staged = True
        if request_ref is not None:
            observation = _structured(
                await session.call_tool(
                    REQUEST_OBSERVATION_TOOL,
                    {"request_ref": request_ref},
                ),
                "request observation",
            )
            _validate_request_observation(observation)
            request_observation_verified = True

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(
            url,
            login_file,
            client_state_file,
            ca_file=ca_file,
            tool_session_callback=callback,
            required_tools=(
                TOOLS | {REQUEST_OBSERVATION_TOOL}
                if request_ref is not None
                else TOOLS
            ),
            requested_scope=oauth.PLAN_ONLY_SCOPE,
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise ApprovalWorkflowMcpOAuthAcceptanceError(str(exc)) from None
    except V4HttpsOAuthAcceptanceError as exc:
        raise ApprovalWorkflowMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise ApprovalWorkflowMcpOAuthAcceptanceError(
                "BP008 OAuth/MCP plan acceptance failed."
            ) from None
        raise
    _validate_common_acceptance(common)
    if not (preview_verified and confirmation_consumed and plan_prepared):
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 OAuth/MCP plan acceptance is incomplete."
        )
    return {
        "contract": "fortipam_v4_bp008_plan_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "required_tool_surface_complete": True,
        "source_backed_status_verified": True,
        "preview_verified": True,
        "browser_confirmation_completed": True,
        "confirmation_consumed": True,
        "non_executable_plan_prepared": True,
        "execution_binding_staged": execution_binding_staged,
        "request_observation_verified": request_observation_verified,
        "device_read_performed": True,
        "device_write_executed": False,
        "request_created": False,
        "approval_decision_executed": False,
        "session_launched": False,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": False,
        "selector_values_returned": False,
        "scheme_draft_ref_returned": False,
        "plan_or_line_refs_returned": False,
        "client_id_returned": False,
        "token_returned": False,
    }


def _validate_common_acceptance(result: dict[str, object]) -> None:
    if (
        result.get("oauth_metadata_verified") is not True
        or result.get("mcp_initialized") is not True
        or result.get("token_revoked") is not True
        or result.get("credential_values_returned") is not False
    ):
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 OAuth/MCP transport acceptance failed."
        )


def _validate_source_backed_status(status: dict[str, object]) -> None:
    if (
        status.get("runtime_profile") != "v4-plan-only"
        or status.get("host_services_bound") is not True
        or status.get("confirmation_transport_bound") is not True
        or status.get("projection_mode") != "source_backed"
        or status.get("scheme_draft_issuance_protocol_bound") is not True
        or status.get("reference_authorization_protocol_bound") is not True
        or "synthetic_scheme_draft_refs" in status
    ):
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 source-backed Host status is unavailable."
        )


def _validate_bp008_preview(preview: dict[str, object]) -> None:
    changes = preview.get("object_changes")
    if (
        preview.get("scheme_id") != "ApprovalAndObserveScheme"
        or preview.get("blueprint_ref") != "FPA-BP-008"
        or not isinstance(changes, list)
        or len(changes) != 2
        or any(not isinstance(item, dict) for item in changes)
    ):
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 intent preview is invalid."
        )
    classes = [item.get("object_class") for item in changes]
    if classes != [
        "ApprovalProfileBinding",
        "SecretApprovalBinding",
    ]:
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 intent preview is invalid."
        )


def _validate_bp008_plan(plan: dict[str, object]) -> None:
    if (
        plan.get("dispatchable") is not False
        or plan.get("adapter_registry_bound") is not False
        or plan.get("executor_runtime_packaged") is not False
        or plan.get("executor_mcp_exposed") is not False
        or plan.get("planner_mcp_exposed") is not True
        or not isinstance(plan.get("plan_ref"), str)
    ):
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 prepared Plan is not safely non-executable."
        )


def _validate_request_observation(observation: dict[str, object]) -> None:
    expected_keys = {
        "contract",
        "request_exists",
        "request_type",
        "lifecycle_state",
        "approval_progress",
        "action_status",
        "raw_values_returned",
    }
    if (
        set(observation) != expected_keys
        or observation.get("contract")
        != "fortipam-v4-secret-request-observation-v1"
        or type(observation.get("request_exists")) is not bool
        or observation.get("request_type") not in {"launcher", "job"}
        or observation.get("lifecycle_state")
        not in {
            "not_found",
            "pending",
            "approved_available",
            "approved_not_yet_available",
            "approved_availability_unknown",
            "denied",
            "expired",
            "unrecognized",
        }
        or observation.get("approval_progress")
        not in {"tier1", "tier2", "tier3", "complete", "unknown"}
        or observation.get("action_status")
        not in {"none", "needed", "complete", "unknown"}
        or observation.get("raw_values_returned") is not False
    ):
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 request observation is invalid."
        )


def _structured(result: Any, stage: str) -> dict[str, object]:
    value = getattr(result, "structured_content", None)
    if getattr(result, "is_error", True) or not isinstance(value, dict):
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            f"BP008 {stage} Tool call failed."
        )
    return dict(value)


def _read_scheme_draft_ref(path: Path) -> str:
    return _read_owner_only_ref(path, "scheme_draft_ref")


def _read_owner_only_ref(path: Path, key: str) -> str:
    if not path.is_absolute():
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 reference file is invalid."
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or not 0 < metadata.st_size <= _MAX_REF_FILE_BYTES
            ):
                raise OSError
            content = os.read(descriptor, _MAX_REF_FILE_BYTES + 1)
        finally:
            os.close(descriptor)
        value = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 reference file is unavailable."
        ) from None
    ref = value.get(key) if type(value) is dict else None
    if (
        type(value) is not dict
        or set(value) != {key}
        or not isinstance(ref, str)
    ):
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 reference file is invalid."
        )
    try:
        return require_ref(ref, key)
    except PlanningContractError:
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 reference file is invalid."
        ) from None


def _validate_new_owner_only_output_path(path: Path) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 execution binding output is unavailable."
        )
    try:
        parent = path.parent.lstat()
    except OSError:
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 execution binding directory is unavailable."
        ) from None
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 execution binding directory must be owner-only."
        )


def _write_execution_binding(
    path: Path,
    plan_ref: str,
    scheme_draft_ref: str,
) -> None:
    try:
        content = json.dumps(
            {
                "plan_ref": require_ref(plan_ref, "plan_ref"),
                "scheme_draft_ref": require_ref(
                    scheme_draft_ref,
                    "scheme_draft_ref",
                ),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii") + b"\n"
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
    except (OSError, PlanningContractError, UnicodeError):
        raise ApprovalWorkflowMcpOAuthAcceptanceError(
            "BP008 execution binding output is unavailable."
        ) from None


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(
        isinstance(
            item,
            (
                ApprovalWorkflowMcpOAuthAcceptanceError,
                V4HttpsOAuthAcceptanceError,
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
    parser.add_argument("--scheme-draft-ref-file", type=Path, required=True)
    parser.add_argument("--request-ref-file", type=Path)
    parser.add_argument("--execution-binding-output-file", type=Path)
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_approval_workflow_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                args.scheme_draft_ref_file,
                ca_file=args.ca_file,
                request_ref_file=args.request_ref_file,
                execution_binding_output_file=(
                    args.execution_binding_output_file
                ),
            )
        )
    except (
        EnvironmentFileError,
        ApprovalWorkflowMcpOAuthAcceptanceError,
        ValueError,
    ) as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
