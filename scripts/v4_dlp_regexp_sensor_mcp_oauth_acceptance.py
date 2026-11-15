#!/usr/bin/env python3
"""Accept the bounded V4 fixed-Regexp DLP Sensor OAuth/MCP C/P/E flow."""

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
        "preview_v4_dlp_sensor_create",
        "confirm_v4_dlp_sensor_create",
        "execute_confirmed_v4_dlp_sensor_create",
    }
)
WORKFLOW = "fortipam_v4_dlp_regexp_sensor_create_workflow_v1"
EXECUTION = "fortipam_v4_dlp_regexp_sensor_create_execution_v1"
PREFIX = "dlp-regexp-sensor-preview-"
AUTHORIZATION_PREFIX = "dlp-regexp-sensor-authorized-"
PROFILE = "regexp_sentinel"
TRANSPORT_PROFILE = "single_http_get_file_regexp_block_v1"


class DlpRegexpSensorMcpOAuthAcceptanceError(RuntimeError):
    """Raised when bounded fixed-Regexp DLP Sensor acceptance fails."""


async def run_dlp_regexp_sensor_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    preview_sensor_name: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
) -> dict[str, object]:
    """Verify the Tool surface, or save/execute one fixed-Regexp Sensor C/P/E."""

    preview_inputs = (preview_sensor_name, preview_state_file)
    preview_requested = any(value is not None for value in preview_inputs)
    if preview_requested and execute_preview_state_file is not None:
        raise DlpRegexpSensorMcpOAuthAcceptanceError(
            "Regexp DLP Sensor preview and execution inputs cannot be combined."
        )
    if preview_requested and any(value is None for value in preview_inputs):
        raise DlpRegexpSensorMcpOAuthAcceptanceError(
            "Regexp DLP Sensor preview inputs are incomplete."
        )

    preview_verified = False
    execution_verified = False
    callback_phase = "Tool-surface discovery"

    async def callback(session: ClientSession) -> None:
        nonlocal callback_phase, preview_verified, execution_verified
        names = {tool.name for tool in (await session.list_tools()).tools}
        if not TOOLS <= names:
            raise DlpRegexpSensorMcpOAuthAcceptanceError(
                "Regexp DLP Sensor MCP Tool surface is incomplete."
            )
        if preview_requested:
            assert preview_sensor_name is not None
            assert preview_state_file is not None
            callback_phase = "preview"
            preview = await session.call_tool(
                "preview_v4_dlp_sensor_create",
                {
                    "sensor_name": preview_sensor_name,
                    "configuration_profile": PROFILE,
                },
            )
            projection = preview.structured_content
            _validate_preview(projection, preview_sensor_name, preview.is_error)
            assert isinstance(projection, dict)
            preview_ref = projection["preview_ref"]
            assert isinstance(preview_ref, str)
            _write_preview_state(preview_state_file, preview_ref)
            preview_verified = True
        if execute_preview_state_file is not None:
            callback_phase = "confirmation"
            preview_ref = _read_preview_ref(execute_preview_state_file)
            confirmation = await session.call_tool(
                "confirm_v4_dlp_sensor_create", {"preview_ref": preview_ref}
            )
            confirmed = confirmation.structured_content
            authorization_ref = (
                confirmed.get("authorization_ref") if isinstance(confirmed, dict) else None
            )
            if (
                confirmation.is_error
                or not isinstance(confirmed, dict)
                or not isinstance(authorization_ref, str)
                or not authorization_ref.startswith(AUTHORIZATION_PREFIX)
                or confirmed.get("contract") != WORKFLOW
                or confirmed.get("confirmation") != "recorded"
                or confirmed.get("execution") != "authorized_once"
                or confirmed.get("device_write_executed") is not False
            ):
                raise DlpRegexpSensorMcpOAuthAcceptanceError(
                    "Regexp DLP Sensor MCP confirmation failed."
                )
            callback_phase = "execution readback"
            execution = await session.call_tool(
                "execute_confirmed_v4_dlp_sensor_create",
                {"authorization_ref": authorization_ref},
            )
            result = execution.structured_content
            if (
                execution.is_error
                or not isinstance(result, dict)
                or result.get("contract") != EXECUTION
                or result.get("outcome") != "succeeded"
                or result.get("verification") != "verified"
                or result.get("idempotent_replay") is not False
                or result.get("dlp_secret_association_changes") is not False
                or result.get("regexp_value_returned") is not False
                or result.get("raw_cli_returned") is not False
            ):
                raise DlpRegexpSensorMcpOAuthAcceptanceError(
                    "Regexp DLP Sensor MCP execution readback failed."
                )
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
        raise DlpRegexpSensorMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise DlpRegexpSensorMcpOAuthAcceptanceError(
                f"Regexp DLP Sensor MCP {callback_phase} failed."
            ) from None
        raise

    return {
        "contract": "fortipam_v4_dlp_regexp_sensor_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "dlp_regexp_sensor_tool_surface_complete": True,
        "dlp_regexp_sensor_preview_verified": preview_verified,
        "dlp_regexp_sensor_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(projection: Any, sensor_name: str, is_error: bool) -> None:
    """Reject projections outside the fixed non-returned Regexp contract."""

    if not isinstance(projection, dict):
        raise DlpRegexpSensorMcpOAuthAcceptanceError("Regexp DLP Sensor MCP preview failed.")
    current = projection.get("Current State")
    proposed = projection.get("Proposed Changes")
    expected = projection.get("Expected State")
    preview_ref = projection.get("preview_ref")
    if (
        is_error
        or not isinstance(current, dict)
        or not isinstance(proposed, dict)
        or not isinstance(expected, dict)
        or not isinstance(preview_ref, str)
        or not preview_ref.startswith(PREFIX)
        or projection.get("contract") != WORKFLOW
        or projection.get("device_write_executed") is not False
        or current.get("requested_sensor_name") != sensor_name
        or current.get("sensor_name_exists") is not False
        or proposed.get("operation") != "create_single_http_get_file_regexp_block_dlp_sensor"
        or proposed.get("sensor_name") != sensor_name
        or proposed.get("configuration_profile") != TRANSPORT_PROFILE
        or proposed.get("protocol") != "http-get"
        or proposed.get("filter_type") != "file"
        or proposed.get("filter_by") != "regexp"
        or proposed.get("regexp_pattern_class") != "fixed_lab_sentinel"
        or proposed.get("regexp_value_returned") is not False
        or proposed.get("action") != "block"
        or proposed.get("dlp_secret_association_changes") is not False
        or expected.get("sensor_name_matches") is not True
        or expected.get("sensor_name_exists") is not True
        or expected.get("filter_id_exists") is not True
        or expected.get("filter_name_matches") is not True
        or expected.get("filter_type_matches") is not True
        or expected.get("protocol_matches") is not True
        or expected.get("filter_by_matches") is not True
        or expected.get("regexp_matches") is not True
        or expected.get("action_matches") is not True
        or expected.get("dlp_secret_association_changes") is not False
    ):
        raise DlpRegexpSensorMcpOAuthAcceptanceError(
            "Regexp DLP Sensor C/P/E projection was invalid."
        )


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    for nested in error.exceptions:
        if isinstance(nested, DlpRegexpSensorMcpOAuthAcceptanceError):
            return True
        if isinstance(nested, BaseExceptionGroup) and _contains_acceptance_error(nested):
            return True
    return False


def _write_preview_state(path: Path, preview_ref: str) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise DlpRegexpSensorMcpOAuthAcceptanceError("Preview state directory is invalid.")
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise DlpRegexpSensorMcpOAuthAcceptanceError(
            "Preview state directory must be owner-only."
        )
    if path.exists() or path.is_symlink():
        raise DlpRegexpSensorMcpOAuthAcceptanceError("Preview state file already exists.")
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREFIX):
        raise DlpRegexpSensorMcpOAuthAcceptanceError("Preview state reference is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(
            descriptor,
            json.dumps({"preview_ref": preview_ref}, separators=(",", ":")).encode("utf-8"),
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise DlpRegexpSensorMcpOAuthAcceptanceError("Preview state file is invalid.")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise DlpRegexpSensorMcpOAuthAcceptanceError("Preview state file must be owner-only.")
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DlpRegexpSensorMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    preview_ref = stored.get("preview_ref") if isinstance(stored, dict) else None
    if not isinstance(preview_ref, str) or not preview_ref.startswith(PREFIX):
        raise DlpRegexpSensorMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--preview-sensor-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_dlp_regexp_sensor_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                preview_sensor_name=args.preview_sensor_name,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
            )
        )
    except DlpRegexpSensorMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
