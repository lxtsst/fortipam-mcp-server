#!/usr/bin/env python3
"""Accept the fixed retained-Target recovery OAuth/MCP flow."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

from mcp import ClientSession

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import v4_address_mcp_oauth_surface_acceptance as oauth


TOOLS = frozenset(
    {
        "preview_v4_ssh_target_create",
        "confirm_v4_ssh_target_create",
        "execute_confirmed_v4_ssh_target",
        "preview_v4_ssh_target_delete",
        "confirm_v4_ssh_target_delete",
        "execute_confirmed_v4_ssh_target_delete",
    }
)
WORKFLOW = "fortipam_v4_target_delete_api_workflow_v1"
EXECUTION = "fortipam_v4_target_delete_api_execution_v1"
PREVIEW_PREFIX = "target-delete-preview-"
AUTHORIZATION_PREFIX = "target-delete-authorized-"
EXPECTED_TOOL_COUNT = 298


class TargetDeleteMcpOAuthAcceptanceError(RuntimeError):
    """Raised when fixed Target recovery acceptance fails."""


async def run_target_delete_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
    execute_authorized_once: bool = False,
) -> dict[str, object]:
    """Verify the fixed surface, save a preview, or run one authorized chain."""

    if preview_state_file is not None and execute_preview_state_file is not None:
        raise TargetDeleteMcpOAuthAcceptanceError(
            "Target delete preview and execution cannot be combined."
        )
    if type(execute_authorized_once) is not bool or (
        execute_authorized_once
        and (preview_state_file is not None or execute_preview_state_file is not None)
    ):
        raise TargetDeleteMcpOAuthAcceptanceError(
            "Target delete authorization mode is invalid."
        )
    preview_verified = False
    execution_verified = False
    observed_tool_count = 0
    phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase, observed_tool_count
        names = {tool.name for tool in (await session.list_tools()).tools}
        observed_tool_count = len(names)
        if not TOOLS <= names or observed_tool_count != EXPECTED_TOOL_COUNT:
            raise TargetDeleteMcpOAuthAcceptanceError(
                "Target delete MCP Tool surface is incomplete."
            )
        authorized_preview_ref: str | None = None
        if preview_state_file is not None or execute_authorized_once:
            phase = "preview"
            preview = await session.call_tool("preview_v4_ssh_target_delete", {})
            _validate_preview(preview.structured_content, preview.is_error)
            projection = preview.structured_content
            assert isinstance(projection, dict)
            preview_ref = projection["preview_ref"]
            assert isinstance(preview_ref, str)
            if preview_state_file is not None:
                _write_preview_state(preview_state_file, preview_ref)
            else:
                authorized_preview_ref = preview_ref
            preview_verified = True
        if execute_preview_state_file is not None or authorized_preview_ref is not None:
            phase = "confirmation"
            if authorized_preview_ref is not None:
                preview_ref = authorized_preview_ref
            else:
                assert execute_preview_state_file is not None
                preview_ref = _read_preview_ref(execute_preview_state_file)
            confirmation = await session.call_tool(
                "confirm_v4_ssh_target_delete",
                {"preview_ref": preview_ref},
            )
            body = confirmation.structured_content
            authorization_ref = (
                body.get("authorization_ref") if isinstance(body, dict) else None
            )
            if (
                confirmation.is_error
                or not isinstance(body, dict)
                or not isinstance(authorization_ref, str)
                or not authorization_ref.startswith(AUTHORIZATION_PREFIX)
                or body.get("contract") != WORKFLOW
                or body.get("confirmation") != "recorded"
                or body.get("execution") != "authorized_once"
                or body.get("device_write_executed") is not False
            ):
                raise TargetDeleteMcpOAuthAcceptanceError(
                    "Target delete MCP confirmation failed."
                )
            phase = "execution readback"
            execution = await session.call_tool(
                "execute_confirmed_v4_ssh_target_delete",
                {"authorization_ref": authorization_ref},
            )
            _validate_execution(execution.structured_content, execution.is_error)
            if execute_preview_state_file is not None:
                execute_preview_state_file.unlink()
            execution_verified = True

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(
            url,
            login_file,
            client_state_file,
            ca_file=ca_file,
            tool_session_callback=callback,
            required_tools=TOOLS,
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise TargetDeleteMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise TargetDeleteMcpOAuthAcceptanceError(
                f"Target delete MCP {phase} failed."
            ) from None
        raise

    return {
        "contract": "fortipam_v4_target_delete_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "tool_count": observed_tool_count,
        "target_delete_tool_surface_complete": True,
        "target_delete_preview_verified": preview_verified,
        "target_delete_execution_verified": execution_verified,
        "authorized_once_chain_completed": (
            execute_authorized_once and preview_verified and execution_verified
        ),
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(projection: Any, is_error: bool) -> None:
    owner_state = {}
    if isinstance(projection, dict) and isinstance(projection.get("Current State"), dict):
        if projection["Current State"].get("delete_authentication") == "owner_session":
            owner_state = {"delete_authentication": "owner_session", "exact_owner_actor_and_relation_verified": True}
    if (
        is_error
        or not isinstance(projection, dict)
        or projection.get("contract") != WORKFLOW
        or projection.get("device_write_executed") is not False
        or projection.get("Current State")
        != {
            "accepted_target_exists": True,
            "complete_api_record_digest_matches": True,
            "target_class_is_other": True,
            "accepted_classification_tag_absent": True,
            "target_reference_count": 0,
            "selectors_returned": False,
            "read_transports": ["rest_api", "ssh_cli"],
            **owner_state,
        }
        or projection.get("Proposed Changes")
        != {
            "operation": "delete_exact_unreferenced_target_via_api",
            "target_count_affected": 1,
            "irreversible_after_execution": True,
            "classification_tag_secret_or_session_change": False,
        }
        or projection.get("Expected State")
        != {
            "target_absent": True,
            "accepted_classification_tag_absent": True,
            "target_reference_count": 0,
            "readback_transports": ["rest_api", "ssh_cli"],
        }
        or not isinstance(projection.get("preview_ref"), str)
        or not str(projection["preview_ref"]).startswith(PREVIEW_PREFIX)
        or "mcp-v4-target" in repr(projection)
        or "mcp-v4-classification-tag" in repr(projection)
    ):
        raise TargetDeleteMcpOAuthAcceptanceError(
            "Target delete C/P/E projection was invalid."
        )


def _validate_execution(result: Any, is_error: bool) -> None:
    if (
        is_error
        or not isinstance(result, dict)
        or result.get("contract") != EXECUTION
        or result.get("outcome") != "succeeded"
        or result.get("verification") != "verified"
        or result.get("idempotent_replay") is not False
        or result.get("compensation") != "separate_target_create_action_required"
        or result.get("target_name_or_configuration_returned") is not False
        or result.get("classification_tag_name_returned") is not False
        or result.get("raw_api_or_cli_response_returned") is not False
    ):
        raise TargetDeleteMcpOAuthAcceptanceError(
            "Target delete MCP execution readback failed."
        )


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(
        isinstance(item, TargetDeleteMcpOAuthAcceptanceError)
        or (isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item))
        for item in error.exceptions
    )


def _write_preview_state(path: Path, preview_ref: str) -> None:
    if (
        path.parent.is_symlink()
        or not path.parent.is_dir()
        or stat.S_IMODE(path.parent.stat().st_mode) & 0o077
        or path.exists()
        or path.is_symlink()
        or not preview_ref.startswith(PREVIEW_PREFIX)
    ):
        raise TargetDeleteMcpOAuthAcceptanceError("Preview state reference is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(
            descriptor,
            json.dumps({"preview_ref": preview_ref}, separators=(",", ":")).encode(),
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise TargetDeleteMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TargetDeleteMcpOAuthAcceptanceError(
            "Preview state file is invalid."
        ) from exc
    preview_ref = stored.get("preview_ref") if isinstance(stored, dict) else None
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREVIEW_PREFIX):
        raise TargetDeleteMcpOAuthAcceptanceError("Preview state file is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument("--execute-authorized-once", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_target_delete_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
                execute_authorized_once=args.execute_authorized_once,
            )
        )
    except TargetDeleteMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
