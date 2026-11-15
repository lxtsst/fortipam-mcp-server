#!/usr/bin/env python3
"""Canonical OAuth acceptance for fixed Secret DLP association and separate restore."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

import httpx2
from mcp import ClientSession

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) in sys.path:
    sys.path.remove(str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT))

from scripts import v4_address_mcp_oauth_surface_acceptance as oauth
from scripts import v4_dlp_sftp_audit_sensor_mcp_oauth_acceptance as state_helpers
from fortipam_mcp.secret_dlp_association_mcp_action import (
    ASSOCIATION_TOOLS, RESTORE_TOOLS, Operation, SecretDlpAssociationMcpActionError,
    valid_secret_dlp_ref, validate_secret_dlp_preview,
    validate_secret_dlp_confirmation, validate_secret_dlp_result,
)

STATE_CONTRACT = "fortipam_v4_secret_dlp_association_oauth_preview_state_v1"
ACCEPTANCE_CONTRACT = "fortipam_v4_secret_dlp_association_mcp_oauth_acceptance_v1"


class SecretDlpAssociationMcpOAuthAcceptanceError(RuntimeError):
    """A stable categorical failure; no upstream or private response text."""


def _tools(operation: Operation) -> frozenset[str]:
    return ASSOCIATION_TOOLS if operation == "associate" else RESTORE_TOOLS


def _tool_name(operation: Operation, phase: str) -> str:
    return f"{phase}_v4_secret_dlp_association{'_restore' if operation == 'restore' else ''}_700"


def _write_state(path: Path, value: dict[str, object]) -> None:
    try:
        state_helpers._write_state(path, value)
    except state_helpers.DlpSftpAuditSensorMcpOAuthAcceptanceError:
        raise SecretDlpAssociationMcpOAuthAcceptanceError("Acceptance state file is unavailable.") from None


def _read_preview_state(path: Path, operation: Operation) -> str:
    try:
        state_helpers._validate_parent(path)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600 or not 0 < metadata.st_size <= 1024):
                raise ValueError
            value = json.loads(handle.read(1025))
        if (type(value) is not dict or set(value) != {"contract", "operation", "preview_ref"}
            or value["contract"] != STATE_CONTRACT or value["operation"] != operation
            or not valid_secret_dlp_ref(value["preview_ref"], operation, "preview")):
            raise ValueError
    except (OSError, ValueError, UnicodeError, state_helpers.DlpSftpAuditSensorMcpOAuthAcceptanceError):
        raise SecretDlpAssociationMcpOAuthAcceptanceError("Acceptance preview state is invalid.") from None
    ref = value["preview_ref"]
    assert isinstance(ref, str)
    return ref


def _structured(response: Any) -> dict[str, object]:
    value = getattr(response, "structured_content", None)
    if getattr(response, "is_error", True) or type(value) is not dict:
        raise SecretDlpAssociationMcpOAuthAcceptanceError("Secret DLP association MCP Tool call failed.")
    return dict(value)


async def run_secret_dlp_association_mcp_oauth_acceptance(
    url: str, login_file: Path, client_state_file: Path, *, operation: Operation = "associate",
    ca_file: Path | None = None, preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None, lab_connect_host: str | None = None,
    lab_connect_port: int | None = None, allow_loopback_tunnel: bool = False,
) -> dict[str, object]:
    """Discover, preview, or consume exactly one fixed association/restore phase."""
    if type(operation) is not str or operation not in {"associate", "restore"} or preview_state_file is not None and execute_preview_state_file is not None:
        raise SecretDlpAssociationMcpOAuthAcceptanceError("Secret DLP association inputs are invalid.")
    if preview_state_file is not None:
        try:
            state_helpers._validate_parent(preview_state_file)
        except state_helpers.DlpSftpAuditSensorMcpOAuthAcceptanceError:
            raise SecretDlpAssociationMcpOAuthAcceptanceError("Acceptance state directory is unavailable.") from None
        if preview_state_file.exists() or preview_state_file.is_symlink():
            raise SecretDlpAssociationMcpOAuthAcceptanceError("Acceptance state file already exists.")
    preview_ref = _read_preview_state(execute_preview_state_file, operation) if execute_preview_state_file is not None else None
    preview_verified = execution_verified = False

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified
        names = {tool.name for tool in (await session.list_tools()).tools}
        if not _tools(operation) <= names:
            raise SecretDlpAssociationMcpOAuthAcceptanceError("Secret DLP association MCP Tool surface is incomplete.")
        if preview_state_file is not None:
            response = await session.call_tool(_tool_name(operation, "preview"), {})
            projection = validate_secret_dlp_preview(_structured(response), operation)
            _write_state(preview_state_file, {"contract": STATE_CONTRACT, "operation": operation,
                                              "preview_ref": projection["preview_ref"]})
            preview_verified = True
        if execute_preview_state_file is not None:
            assert preview_ref is not None
            _write_state(execute_preview_state_file.with_name(execute_preview_state_file.name + ".dispatch.json"),
                {"contract": "fortipam_v4_secret_dlp_association_oauth_attempt_v1", "operation": operation,
                 "execution_attempt_claimed": True, "retry_allowed": False})
            confirmation = await session.call_tool(_tool_name(operation, "confirm"), {"preview_ref": preview_ref})
            confirmed = validate_secret_dlp_confirmation(_structured(confirmation), operation, preview_ref)
            execution = await session.call_tool(_tool_name(operation, "execute_confirmed"),
                                                {"authorization_ref": confirmed["authorization_ref"]})
            validate_secret_dlp_result(_structured(execution), operation, require_success=True)
            execute_preview_state_file.unlink()
            execution_verified = True

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(
            url, login_file, client_state_file, ca_file=ca_file, tool_session_callback=callback,
            required_tools=_tools(operation), lab_connect_host=lab_connect_host,
            lab_connect_port=lab_connect_port, allow_loopback_tunnel=allow_loopback_tunnel,
        )
    except (oauth.AddressMcpOAuthSurfaceAcceptanceError, httpx2.HTTPError, SecretDlpAssociationMcpActionError):
        raise SecretDlpAssociationMcpOAuthAcceptanceError("Secret DLP association OAuth/MCP acceptance failed.") from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise SecretDlpAssociationMcpOAuthAcceptanceError("Secret DLP association OAuth/MCP acceptance failed.") from None
        raise
    if (common.get("oauth_metadata_verified") is not True or common.get("mcp_initialized") is not True
        or common.get("token_revoked") is not True or common.get("credential_values_returned") is not False):
        raise SecretDlpAssociationMcpOAuthAcceptanceError("Secret DLP association OAuth/MCP transport acceptance failed.")
    if (preview_state_file is not None and not preview_verified
        or execute_preview_state_file is not None and not execution_verified):
        raise SecretDlpAssociationMcpOAuthAcceptanceError("Secret DLP association requested phase was not verified.")
    return {"contract": ACCEPTANCE_CONTRACT, "operation": operation, "oauth_metadata_verified": True,
        "mcp_initialized": True, "tool_surface_complete": True, "preview_verified": preview_verified,
        "execution_verified": execution_verified, "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified, "token_revoked": True, "file_audit_effect": "unproven",
        "credential_values_returned": False, "token_returned": False, "client_id_returned": False,
        "private_identifiers_returned": False, "raw_response_returned": False}


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(isinstance(item, (SecretDlpAssociationMcpOAuthAcceptanceError, SecretDlpAssociationMcpActionError,
        oauth.AddressMcpOAuthSurfaceAcceptanceError, httpx2.HTTPError))
        or isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item) for item in error.exceptions)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--operation", choices=("associate", "restore"), default="associate")
    parser.add_argument("--ca-file", type=Path)
    phase = parser.add_mutually_exclusive_group()
    phase.add_argument("--preview-state-file", type=Path)
    phase.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument("--lab-connect-host")
    parser.add_argument("--lab-connect-port", type=int)
    parser.add_argument("--allow-loopback-tunnel", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(run_secret_dlp_association_mcp_oauth_acceptance(args.url, args.login_file,
            args.client_state_file, operation=args.operation, ca_file=args.ca_file,
            preview_state_file=args.preview_state_file, execute_preview_state_file=args.execute_preview_state_file,
            lab_connect_host=args.lab_connect_host, lab_connect_port=args.lab_connect_port,
            allow_loopback_tunnel=args.allow_loopback_tunnel))
    except SecretDlpAssociationMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
