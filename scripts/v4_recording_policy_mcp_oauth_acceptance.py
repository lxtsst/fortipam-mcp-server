#!/usr/bin/env python3
"""Accept one bounded V4 Session Recording OAuth/MCP C/P/E flow."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import stat
from typing import Any

from mcp import ClientSession

from scripts import v4_address_mcp_oauth_surface_acceptance as oauth

TOOLS = frozenset({"preview_v4_recording_policy_enable", "confirm_v4_recording_policy_enable", "execute_confirmed_v4_recording_policy_enable"})
WORKFLOW = "fortipam_v4_recording_policy_enable_api_workflow_v1"
EXECUTION = "fortipam_v4_recording_policy_enable_api_execution_v1"
PREFIX = "recording-policy-preview-"


class RecordingPolicyMcpOAuthAcceptanceError(RuntimeError):
    """Raised for a non-disclosing Session Recording acceptance failure."""


async def run_recording_policy_mcp_oauth_acceptance(
    url: str, login_file: Path, client_state_file: Path, *, policy_name: str | None = None,
    preview_state_file: Path | None = None, execute_preview_state_file: Path | None = None,
    ca_file: Path | None = None,
) -> dict[str, object]:
    """Verify or execute one exact existing Policy recording transition."""
    preview_requested = policy_name is not None or preview_state_file is not None
    if preview_requested == (execute_preview_state_file is not None):
        raise RecordingPolicyMcpOAuthAcceptanceError("Recording Policy phase inputs are invalid.")
    if preview_requested and (policy_name is None or preview_state_file is None):
        raise RecordingPolicyMcpOAuthAcceptanceError("Recording Policy preview inputs are incomplete.")
    preview_verified = execution_verified = False

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}:
            raise RecordingPolicyMcpOAuthAcceptanceError("Recording Policy MCP Tool surface is incomplete.")
        if preview_requested:
            assert policy_name is not None and preview_state_file is not None
            reply = await session.call_tool("preview_v4_recording_policy_enable", {"policy_name": policy_name})
            _validate_preview(reply.structured_content, policy_name, reply.is_error)
            assert isinstance(reply.structured_content, dict)
            _write_preview_state(preview_state_file, str(reply.structured_content["preview_ref"]))
            preview_verified = True
        if execute_preview_state_file is not None:
            confirmation = await session.call_tool("confirm_v4_recording_policy_enable", {"preview_ref": _read_preview_ref(execute_preview_state_file)})
            body = confirmation.structured_content
            auth = body.get("authorization_ref") if isinstance(body, dict) else None
            if confirmation.is_error or not isinstance(body, dict) or not isinstance(auth, str) or not auth.startswith("recording-policy-authorized-") or body.get("contract") != WORKFLOW or body.get("confirmation") != "recorded" or body.get("execution") != "authorized_once" or body.get("device_write_executed") is not False:
                raise RecordingPolicyMcpOAuthAcceptanceError("Recording Policy MCP confirmation failed.")
            reply = await session.call_tool("execute_confirmed_v4_recording_policy_enable", {"authorization_ref": auth})
            _validate_execution(reply.structured_content, reply.is_error)
            execute_preview_state_file.unlink()
            execution_verified = True

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(url, login_file, client_state_file, ca_file=ca_file, tool_session_callback=callback, required_tools=TOOLS)
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise RecordingPolicyMcpOAuthAcceptanceError(str(exc)) from None
    return {"contract": "fortipam_v4_recording_policy_mcp_oauth_acceptance_v1", "oauth_metadata_verified": common["oauth_metadata_verified"], "mcp_initialized": common["mcp_initialized"], "recording_policy_tool_surface_complete": True, "recording_policy_preview_verified": preview_verified, "recording_policy_execution_verified": execution_verified, "device_tool_invoked": preview_verified or execution_verified, "device_write_executed": execution_verified, "token_revoked": common["token_revoked"], "credential_values_returned": common["credential_values_returned"], "token_returned": False, "client_id_returned": False}


def _validate_preview(value: Any, policy_name: str, is_error: bool) -> None:
    current = value.get("Current State") if isinstance(value, dict) else None; proposed = value.get("Proposed Changes") if isinstance(value, dict) else None; expected = value.get("Expected State") if isinstance(value, dict) else None; ref = value.get("preview_ref") if isinstance(value, dict) else None
    if is_error or not isinstance(current, dict) or not isinstance(proposed, dict) or not isinstance(expected, dict) or not isinstance(ref, str) or not ref.startswith(PREFIX) or value.get("contract") != WORKFLOW or value.get("device_write_executed") is not False or current.get("secret_policy_name") != policy_name or current.get("secret_policy_exists") is not True or current.get("recording_enabled") is not False or current.get("write_transport") != "rest_api" or proposed.get("operation") != "enable_session_recording_on_existing_secret_policy_via_api" or proposed.get("recording") != "enable" or proposed.get("other_policy_fields_modified") is not False or proposed.get("folder_or_secret_association_changes") is not False or expected.get("recording_enabled") is not True or expected.get("other_policy_fields_modified") is not False or expected.get("folder_or_secret_association_changes") is not False or expected.get("readback_transport") != "rest_api":
        raise RecordingPolicyMcpOAuthAcceptanceError("Recording Policy C/P/E projection was invalid.")


def _validate_execution(value: Any, is_error: bool) -> None:
    if is_error or not isinstance(value, dict) or value.get("contract") != EXECUTION or value.get("outcome") != "succeeded" or value.get("verification") != "verified" or value.get("idempotent_replay") is not False or value.get("compensation") != "separate_confirmed_secret_policy_reconciliation_required" or value.get("policy_name_returned") is not False or value.get("raw_api_returned") is not False:
        raise RecordingPolicyMcpOAuthAcceptanceError("Recording Policy MCP execution readback failed.")


def _write_preview_state(path: Path, preview_ref: str) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) & 0o077 or path.exists() or path.is_symlink() or not preview_ref.startswith(PREFIX):
        raise RecordingPolicyMcpOAuthAcceptanceError("Preview state reference is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, json.dumps({"preview_ref": preview_ref}).encode("utf-8")); os.fsync(descriptor)
    finally: os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RecordingPolicyMcpOAuthAcceptanceError("Preview state file is invalid.")
    try: ref = json.loads(path.read_text(encoding="utf-8")).get("preview_ref")
    except (OSError, json.JSONDecodeError, AttributeError) as exc: raise RecordingPolicyMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    if not isinstance(ref, str) or not ref.startswith(PREFIX): raise RecordingPolicyMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return ref
