#!/usr/bin/env python3
"""Accept explicitly injected Web SFTP log-only DLP create and owned recovery."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import re
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
from fortipam_mcp.dlp_sensor_mcp_action import DLP_PROFILE_SFTP_AUDIT
from fortipam_mcp.dlp_sensor_ssh_transport import DLP_SFTP_AUDIT_SENSOR_PROFILE, _SFTP_AUDIT_SENSOR_NAME

STATE_CONTRACT = "fortipam_v4_dlp_sftp_audit_sensor_oauth_preview_state_v1"
ACCEPTANCE_CONTRACT = "fortipam_v4_dlp_sftp_audit_sensor_mcp_oauth_acceptance_v1"


class DlpSftpAuditSensorMcpOAuthAcceptanceError(RuntimeError):
    """Stable non-disclosing fixed-profile acceptance failure."""


def _prefix(operation: str, *, authorized: bool = False) -> str:
    suffix = "authorized-" if authorized else "preview-"
    return "dlp-sftp-audit-sensor-" + ("delete-" if operation == "delete" else "") + suffix


def _contract(operation: str, *, execution: bool = False) -> str:
    return f"fortipam_v4_dlp_sftp_audit_sensor_{operation}_{'execution' if execution else 'workflow'}_v1"


def _tools(operation: str) -> frozenset[str]:
    return frozenset({f"preview_v4_dlp_sensor_{operation}", f"confirm_v4_dlp_sensor_{operation}",
                      f"execute_confirmed_v4_dlp_sensor_{operation}"})


def _valid_ref(value: object, prefix: str) -> bool:
    return isinstance(value, str) and len(value) <= 128 and re.fullmatch(
        re.escape(prefix) + r"[A-Za-z0-9_-]+", value,
    ) is not None


def _exact(actual: object, expected: object) -> bool:
    """Compare the closed projection with strict scalar types (True is not 1)."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(actual, dict)
        return set(actual) == set(expected) and all(_exact(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        assert isinstance(actual, list)
        return len(actual) == len(expected) and all(_exact(a, b) for a, b in zip(actual, expected))
    return bool(actual == expected)


def _preview_fields(operation: str, sensor_name: str | None) -> dict[str, object]:
    if operation == "delete":
        return {
            "Current State": {"verified_creation_ownership": True, "fixed_log_only_sensor_exists": True,
                "complete_native_profile_digest_matches": True, "secret_reference_count": 0,
                "policy_reference_count": 0, "dependency_source": "qualified_native_global_columns",
                "read_transports": ["rest_api", "ssh_cli"]},
            "Proposed Changes": {"operation": "delete_exact_owned_unreferenced_web_sftp_audit_sensor",
                "dlp_sensor_count_affected": 1, "irreversible_after_execution": True,
                "secret_or_policy_association_changes": False},
            "Expected State": {"owned_audit_sensor_absent": True,
                "readback_transports": ["rest_api", "ssh_cli"], "secret_or_policy_association_changes": False},
        }
    return {
        "Current State": {"requested_sensor_name": sensor_name, "sensor_name_exists": False},
        "Proposed Changes": {"operation": "create_single_web_sftp_file_regexp_log_only_dlp_sensor",
            "sensor_name": sensor_name, "configuration_profile": DLP_SFTP_AUDIT_SENSOR_PROFILE,
            "protocols": ["http-get", "http-post"], "filter_type": "file", "filter_by": "regexp",
            "regexp_pattern_class": "fixed_lab_sentinel", "regexp_value_returned": False,
            "action": "log-only", "filter_count": 1, "dlp_log": "enable", "summary_protocols": [],
            "full_archive_protocols": [], "filter_archive": "disable",
            "remaining_native_fields": "qualified_defaults", "dlp_secret_association_changes": False},
        "Expected State": {**dict.fromkeys(("sensor_name_matches", "sensor_name_exists", "filter_id_exists",
            "filter_name_matches", "filter_type_matches", "protocol_matches", "filter_by_matches",
            "regexp_matches", "action_matches", "native_defaults_match", "filter_count_matches"), True),
            "dlp_secret_association_changes": False},
    }


def _validate_preview(value: Any, is_error: bool, operation: str, sensor_name: str | None) -> str:
    if (is_error or type(value) is not dict
        or set(value) != {"contract", "preview_ref", "expires_at", "Current State", "Proposed Changes",
                          "Expected State", "device_write_executed"}
        or not _valid_ref(value.get("preview_ref"), _prefix(operation))
        or type(value.get("expires_at")) is not int or value["expires_at"] <= 0):
        raise DlpSftpAuditSensorMcpOAuthAcceptanceError("SFTP audit Sensor preview failed.")
    expected = {"contract": _contract(operation), "preview_ref": value["preview_ref"],
                "expires_at": value["expires_at"], "device_write_executed": False,
                **_preview_fields(operation, sensor_name)}
    if not _exact(value, expected):
        raise DlpSftpAuditSensorMcpOAuthAcceptanceError("SFTP audit Sensor C/P/E projection is invalid.")
    ref = value["preview_ref"]
    assert isinstance(ref, str)
    return ref


def _validate_confirmation(value: Any, is_error: bool, operation: str, preview_ref: str) -> str:
    if (is_error or type(value) is not dict
        or set(value) != {"contract", "preview_ref", "authorization_ref", "confirmation", "execution",
                          "expires_at", "device_write_executed"}
        or not _valid_ref(value.get("authorization_ref"), _prefix(operation, authorized=True))
        or type(value.get("expires_at")) is not int or value["expires_at"] <= 0
        or not _exact(value, {"contract": _contract(operation), "preview_ref": preview_ref,
            "authorization_ref": value.get("authorization_ref"), "confirmation": "recorded",
            "execution": "authorized_once", "expires_at": value["expires_at"], "device_write_executed": False})):
        raise DlpSftpAuditSensorMcpOAuthAcceptanceError("SFTP audit Sensor confirmation failed.")
    ref = value["authorization_ref"]
    assert isinstance(ref, str)
    return ref


def _validate_execution(value: Any, is_error: bool, operation: str) -> None:
    expected: dict[str, object] = {"contract": _contract(operation, execution=True),
        "outcome": "succeeded", "verification": "verified", "idempotent_replay": False}
    if operation == "create":
        expected.update({"compensation": "not_requested", "dlp_secret_association_changes": False,
            "regexp_value_returned": False, "raw_cli_returned": False, "raw_api_returned": False})
    else:
        expected.update({"compensation": "fresh_separate_owned_sensor_create_required",
            "irreversible_after_execution": True, "dlp_sensor_name_returned": False,
            "profile_content_returned": False, "file_pattern_changes": False,
            "secret_or_policy_association_changes": False, "license_or_session_changes": False,
            "raw_api_or_cli_response_returned": False})
    if is_error or not _exact(value, expected):
        raise DlpSftpAuditSensorMcpOAuthAcceptanceError("SFTP audit Sensor execution readback failed.")


def _validate_parent(path: Path) -> None:
    try:
        parent = path.parent.lstat()
        if (not path.is_absolute() or path.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077):
            raise OSError
    except OSError:
        raise DlpSftpAuditSensorMcpOAuthAcceptanceError("Acceptance state directory must be owner-only.") from None


def _write_state(path: Path, value: dict[str, object]) -> None:
    _validate_parent(path)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        raise DlpSftpAuditSensorMcpOAuthAcceptanceError("Acceptance state file is unavailable.") from None


def _read_state(path: Path, operation: str) -> str:
    _validate_parent(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077 or not 0 < metadata.st_size <= 1024):
                raise ValueError
            value = json.loads(handle.read(1025))
        if (type(value) is not dict or set(value) != {"contract", "operation", "preview_ref"}
            or value["contract"] != STATE_CONTRACT or value["operation"] != operation
            or not _valid_ref(value["preview_ref"], _prefix(operation))):
            raise ValueError
    except (OSError, ValueError, UnicodeError):
        raise DlpSftpAuditSensorMcpOAuthAcceptanceError("Acceptance preview state is invalid.") from None
    ref = value["preview_ref"]
    assert isinstance(ref, str)
    return ref


async def run_dlp_sftp_audit_sensor_mcp_oauth_acceptance(
    url: str, login_file: Path, client_state_file: Path, *, ca_file: Path | None = None,
    preview_sensor_name: str | None = None, preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None, lab_connect_host: str | None = None,
    lab_connect_port: int | None = None, allow_loopback_tunnel: bool = False,
) -> dict[str, object]:
    """Discover, preview, or execute one explicitly selected fixed create."""
    return await _run(url, login_file, client_state_file, operation="create", ca_file=ca_file,
        preview_sensor_name=preview_sensor_name, preview_state_file=preview_state_file,
        execute_preview_state_file=execute_preview_state_file, lab_connect_host=lab_connect_host,
        lab_connect_port=lab_connect_port, allow_loopback_tunnel=allow_loopback_tunnel)


async def run_dlp_sftp_audit_sensor_delete_mcp_oauth_acceptance(
    url: str, login_file: Path, client_state_file: Path, *, ca_file: Path | None = None,
    preview_state_file: Path | None = None, execute_preview_state_file: Path | None = None,
    lab_connect_host: str | None = None, lab_connect_port: int | None = None,
    allow_loopback_tunnel: bool = False,
) -> dict[str, object]:
    """Discover, preview, or execute same-creator fixed owned recovery only."""
    return await _run(url, login_file, client_state_file, operation="delete", ca_file=ca_file,
        preview_sensor_name=None, preview_state_file=preview_state_file,
        execute_preview_state_file=execute_preview_state_file, lab_connect_host=lab_connect_host,
        lab_connect_port=lab_connect_port, allow_loopback_tunnel=allow_loopback_tunnel)


async def _run(
    url: str, login_file: Path, client_state_file: Path, *, operation: str, ca_file: Path | None,
    preview_sensor_name: str | None, preview_state_file: Path | None,
    execute_preview_state_file: Path | None, lab_connect_host: str | None,
    lab_connect_port: int | None, allow_loopback_tunnel: bool,
) -> dict[str, object]:
    preview_requested = preview_state_file is not None
    if (preview_requested and execute_preview_state_file is not None
        or (operation == "create" and ((preview_sensor_name is not None) != preview_requested))
        or (preview_sensor_name is not None and (not isinstance(preview_sensor_name, str)
            or _SFTP_AUDIT_SENSOR_NAME.fullmatch(preview_sensor_name) is None))):
        raise DlpSftpAuditSensorMcpOAuthAcceptanceError("SFTP audit Sensor inputs are invalid.")
    if preview_state_file is not None:
        _validate_parent(preview_state_file)
        if preview_state_file.exists() or preview_state_file.is_symlink():
            raise DlpSftpAuditSensorMcpOAuthAcceptanceError("Acceptance state file already exists.")
    preview_ref = _read_state(execute_preview_state_file, operation) if execute_preview_state_file is not None else None
    preview_verified = execution_verified = False

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified
        names = {tool.name for tool in (await session.list_tools()).tools}
        if not _tools(operation) <= names:
            raise DlpSftpAuditSensorMcpOAuthAcceptanceError("SFTP audit Sensor MCP Tool surface is incomplete.")
        if preview_state_file is not None:
            arguments = {"configuration_profile": DLP_PROFILE_SFTP_AUDIT}
            if operation == "create":
                assert preview_sensor_name is not None
                arguments["sensor_name"] = preview_sensor_name
            response = await session.call_tool(f"preview_v4_dlp_sensor_{operation}", arguments)
            ref = _validate_preview(response.structured_content, response.is_error, operation, preview_sensor_name)
            _write_state(preview_state_file, {"contract": STATE_CONTRACT, "operation": operation, "preview_ref": ref})
            preview_verified = True
        if execute_preview_state_file is not None:
            assert preview_ref is not None
            # A consumed/uncertain attempt cannot be replayed by this acceptance client.
            _write_state(execute_preview_state_file.with_name(execute_preview_state_file.name + ".dispatch.json"),
                {"contract": "fortipam_v4_dlp_sftp_audit_sensor_oauth_dispatch_v1", "operation": operation,
                 "execution_attempt_claimed": True, "retry_allowed": False})
            confirmation = await session.call_tool(f"confirm_v4_dlp_sensor_{operation}", {"preview_ref": preview_ref})
            authorization_ref = _validate_confirmation(confirmation.structured_content, confirmation.is_error, operation, preview_ref)
            execution = await session.call_tool(f"execute_confirmed_v4_dlp_sensor_{operation}", {"authorization_ref": authorization_ref})
            _validate_execution(execution.structured_content, execution.is_error, operation)
            execute_preview_state_file.unlink()
            execution_verified = True

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(
            url, login_file, client_state_file, ca_file=ca_file, tool_session_callback=callback,
            required_tools=_tools(operation), lab_connect_host=lab_connect_host,
            lab_connect_port=lab_connect_port, allow_loopback_tunnel=allow_loopback_tunnel,
        )
    except (oauth.AddressMcpOAuthSurfaceAcceptanceError, httpx2.HTTPError):
        raise DlpSftpAuditSensorMcpOAuthAcceptanceError("SFTP audit Sensor OAuth/MCP transport failed.") from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise DlpSftpAuditSensorMcpOAuthAcceptanceError("SFTP audit Sensor OAuth/MCP acceptance failed.") from None
        raise
    if (common.get("oauth_metadata_verified") is not True or common.get("mcp_initialized") is not True
        or common.get("token_revoked") is not True or common.get("credential_values_returned") is not False):
        raise DlpSftpAuditSensorMcpOAuthAcceptanceError("SFTP audit Sensor OAuth/MCP transport acceptance failed.")
    if (preview_requested and not preview_verified
        or execute_preview_state_file is not None and not execution_verified):
        raise DlpSftpAuditSensorMcpOAuthAcceptanceError("SFTP audit Sensor requested phase was not verified.")
    return {"contract": ACCEPTANCE_CONTRACT, "operation": operation,
        "configuration_profile": DLP_PROFILE_SFTP_AUDIT, "oauth_metadata_verified": True,
        "mcp_initialized": True, "tool_surface_complete": True, "preview_verified": preview_verified,
        "execution_verified": execution_verified, "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified, "token_revoked": True,
        "credential_values_returned": False, "token_returned": False, "client_id_returned": False,
        "private_identifiers_returned": False, "raw_response_returned": False}


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(isinstance(item, (DlpSftpAuditSensorMcpOAuthAcceptanceError,
        oauth.AddressMcpOAuthSurfaceAcceptanceError, httpx2.HTTPError))
        or isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item) for item in error.exceptions)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--operation", choices=("create", "delete"), default="create")
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--preview-sensor-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument("--lab-connect-host")
    parser.add_argument("--lab-connect-port", type=int)
    parser.add_argument("--allow-loopback-tunnel", action="store_true")
    args = parser.parse_args()
    if args.operation == "delete" and args.preview_sensor_name is not None:
        parser.error("Owned recovery does not accept a target selector.")
    try:
        result = asyncio.run(_run(args.url, args.login_file, args.client_state_file,
            operation=args.operation, ca_file=args.ca_file, preview_sensor_name=args.preview_sensor_name,
            preview_state_file=args.preview_state_file, execute_preview_state_file=args.execute_preview_state_file,
            lab_connect_host=args.lab_connect_host, lab_connect_port=args.lab_connect_port,
            allow_loopback_tunnel=args.allow_loopback_tunnel))
    except DlpSftpAuditSensorMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
