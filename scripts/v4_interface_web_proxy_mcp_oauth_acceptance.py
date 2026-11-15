#!/usr/bin/env python3
"""Accept one bounded V4 Explicit Web Proxy enable or rollback OAuth/MCP flow."""

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
        "preview_v4_interface_explicit_web_proxy_enable",
        "confirm_v4_interface_explicit_web_proxy_enable",
        "execute_confirmed_v4_interface_explicit_web_proxy_enable",
        "preview_v4_interface_explicit_web_proxy_rollback",
        "confirm_v4_interface_explicit_web_proxy_rollback",
        "execute_confirmed_v4_interface_explicit_web_proxy_rollback",
    }
)
FORWARD_TOOLS = (
    "preview_v4_interface_explicit_web_proxy_enable",
    "confirm_v4_interface_explicit_web_proxy_enable",
    "execute_confirmed_v4_interface_explicit_web_proxy_enable",
)
ROLLBACK_TOOLS = (
    "preview_v4_interface_explicit_web_proxy_rollback",
    "confirm_v4_interface_explicit_web_proxy_rollback",
    "execute_confirmed_v4_interface_explicit_web_proxy_rollback",
)
FORWARD_WORKFLOW = "fortipam_v4_interface_explicit_web_proxy_enable_workflow_v1"
FORWARD_EXECUTION = "fortipam_v4_interface_explicit_web_proxy_enable_execution_v1"
FORWARD_PREVIEW_PREFIX = "interface-web-proxy-preview-"
FORWARD_AUTHORIZATION_PREFIX = "interface-web-proxy-authorized-"
ROLLBACK_WORKFLOW = "fortipam_v4_interface_explicit_web_proxy_rollback_workflow_v1"
ROLLBACK_EXECUTION = "fortipam_v4_interface_explicit_web_proxy_rollback_execution_v1"
ROLLBACK_PREVIEW_PREFIX = "interface-web-proxy-rollback-preview-"
ROLLBACK_AUTHORIZATION_PREFIX = "interface-web-proxy-rollback-authorized-"


class InterfaceWebProxyMcpOAuthAcceptanceError(RuntimeError):
    """Raised when bounded Explicit Web Proxy acceptance fails."""


async def run_interface_web_proxy_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    ca_file: Path | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
    allow_insecure_private_ip_lab: bool = False,
    rollback: bool = False,
    expected_tool_count: int | None = None,
    lab_connect_host: str | None = None,
    lab_connect_port: int | None = None,
    allow_loopback_tunnel: bool = False,
) -> dict[str, object]:
    """Verify, preview, or execute one interface action without exposing its name."""

    if preview_state_file is not None and execute_preview_state_file is not None:
        raise InterfaceWebProxyMcpOAuthAcceptanceError(
            "Interface Web Proxy preview and execution inputs cannot be combined."
        )
    if expected_tool_count is not None and (
        type(expected_tool_count) is not int or expected_tool_count < len(TOOLS)
    ):
        raise InterfaceWebProxyMcpOAuthAcceptanceError("Expected tool count is invalid.")
    preview_verified = False
    execution_verified = False
    phase = "Tool-surface discovery"
    selected_tools = ROLLBACK_TOOLS if rollback else FORWARD_TOOLS
    workflow = ROLLBACK_WORKFLOW if rollback else FORWARD_WORKFLOW
    execution = ROLLBACK_EXECUTION if rollback else FORWARD_EXECUTION
    preview_prefix = ROLLBACK_PREVIEW_PREFIX if rollback else FORWARD_PREVIEW_PREFIX
    authorization_prefix = (
        ROLLBACK_AUTHORIZATION_PREFIX if rollback else FORWARD_AUTHORIZATION_PREFIX
    )

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase
        tool_names = {tool.name for tool in (await session.list_tools()).tools}
        if not TOOLS <= tool_names or (
            expected_tool_count is not None and len(tool_names) != expected_tool_count
        ):
            raise InterfaceWebProxyMcpOAuthAcceptanceError(
                "Interface Web Proxy MCP Tool surface is incomplete."
            )
        if preview_state_file is not None:
            phase = "preview"
            reply = await session.call_tool(selected_tools[0], {})
            _validate_preview(
                reply.structured_content,
                reply.is_error,
                rollback=rollback,
            )
            assert isinstance(reply.structured_content, dict)
            _write_preview_state(
                preview_state_file,
                str(reply.structured_content["preview_ref"]),
                prefix=preview_prefix,
            )
            preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"
            confirmation = await session.call_tool(
                selected_tools[1],
                {
                    "preview_ref": _read_preview_ref(
                        execute_preview_state_file,
                        prefix=preview_prefix,
                    )
                },
            )
            body = confirmation.structured_content
            authorization_ref = body.get("authorization_ref") if isinstance(body, dict) else None
            if (
                confirmation.is_error
                or not isinstance(body, dict)
                or not isinstance(authorization_ref, str)
                or not authorization_ref.startswith(authorization_prefix)
                or body.get("contract") != workflow
                or body.get("confirmation") != "recorded"
                or body.get("execution") != "authorized_once"
                or body.get("device_write_executed") is not False
            ):
                raise InterfaceWebProxyMcpOAuthAcceptanceError(
                    "Interface Web Proxy MCP confirmation failed."
                )
            phase = "execution readback"
            reply = await session.call_tool(
                selected_tools[2],
                {"authorization_ref": authorization_ref},
            )
            _validate_execution(
                reply.structured_content,
                reply.is_error,
                rollback=rollback,
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
            allow_insecure_private_ip_lab=allow_insecure_private_ip_lab,
            lab_connect_host=lab_connect_host,
            lab_connect_port=lab_connect_port,
            allow_loopback_tunnel=allow_loopback_tunnel,
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise InterfaceWebProxyMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise InterfaceWebProxyMcpOAuthAcceptanceError(
                f"Interface Web Proxy MCP {phase} failed."
            ) from None
        raise
    return {
        "contract": "fortipam_v4_interface_web_proxy_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "interface_web_proxy_tool_surface_complete": True,
        "exact_tool_count_verified": expected_tool_count is not None,
        "interface_web_proxy_direction": "rollback" if rollback else "forward",
        "interface_web_proxy_preview_verified": preview_verified,
        "interface_web_proxy_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(
    projection: Any,
    is_error: bool,
    *,
    rollback: bool = False,
) -> None:
    """Accept only the single-interface, no-reachability-evidence projection."""

    current = projection.get("Current State") if isinstance(projection, dict) else None
    proposed = projection.get("Proposed Changes") if isinstance(projection, dict) else None
    expected = projection.get("Expected State") if isinstance(projection, dict) else None
    preview_ref = projection.get("preview_ref") if isinstance(projection, dict) else None
    workflow = ROLLBACK_WORKFLOW if rollback else FORWARD_WORKFLOW
    preview_prefix = ROLLBACK_PREVIEW_PREFIX if rollback else FORWARD_PREVIEW_PREFIX
    current_status = "enable" if rollback else "disable"
    current_count = 1 if rollback else 0
    expected_status = "disable" if rollback else "enable"
    expected_count = 0 if rollback else 1
    operation = (
        "restore_interface_explicit_web_proxy_pre_action_state_via_cli_fallback"
        if rollback
        else "enable_explicit_web_proxy_on_one_existing_interface_via_cli_fallback"
    )
    configuration = (
        "disable-one-existing-interface-explicit-web-proxy-v1"
        if rollback
        else "enable-one-existing-interface-explicit-web-proxy-v1"
    )
    if (
        is_error
        or not isinstance(current, dict)
        or not isinstance(proposed, dict)
        or not isinstance(expected, dict)
        or not isinstance(preview_ref, str)
        or not preview_ref.startswith(preview_prefix)
        or projection.get("contract") != workflow
        or projection.get("device_write_executed") is not False
        or current.get("selected_interface_explicit_web_proxy") != current_status
        or current.get("enabled_explicit_web_proxy_interface_count") != current_count
        or current.get("interface_reference_returned") is not False
        or current.get("proxy_port_changed") is not False
        or current.get("proxy_ca_changed") is not False
        or current.get("write_transport") != "ssh_cli_fallback"
        or proposed.get("operation") != operation
        or proposed.get("configuration_profile") != configuration
        or proposed.get("selected_interface_explicit_web_proxy") != expected_status
        or any(
            proposed.get(key) is not False
            for key in (
                "other_interfaces_changed",
                "proxy_port_changed",
                "proxy_ca_changed",
                "vip_or_route_changed",
                "secret_or_target_changed",
                "rest_write_attempted",
            )
        )
        or expected.get("selected_interface_explicit_web_proxy") != expected_status
        or expected.get("enabled_explicit_web_proxy_interface_count") != expected_count
        or (rollback and expected.get("pre_action_state_restored") is not True)
        or any(
            expected.get(key) is not False
            for key in (
                "other_interfaces_changed",
                "proxy_port_changed",
                "proxy_ca_changed",
                "vip_or_route_changed",
                "web_proxy_reachability_verified",
            )
        )
        or expected.get("readback_transport") != "ssh_cli"
    ):
        raise InterfaceWebProxyMcpOAuthAcceptanceError(
            "Interface Web Proxy C/P/E projection was invalid."
        )


def _validate_execution(
    result: Any,
    is_error: bool,
    *,
    rollback: bool = False,
) -> None:
    """Require categorical postcondition without claiming listener reachability."""

    execution = ROLLBACK_EXECUTION if rollback else FORWARD_EXECUTION
    expected_status = "disable" if rollback else "enable"
    expected_count = 0 if rollback else 1

    if (
        is_error
        or not isinstance(result, dict)
        or result.get("contract") != execution
        or result.get("outcome") != "succeeded"
        or result.get("verification") != "verified"
        or result.get("idempotent_replay") is not False
        or (
            not rollback
            and result.get("compensation")
            != "separate_interface_explicit_web_proxy_disable_action_required"
        )
        or (rollback and result.get("pre_action_state_restored") is not True)
        or result.get("selected_interface_explicit_web_proxy") != expected_status
        or result.get("enabled_explicit_web_proxy_interface_count") != expected_count
        or any(
            result.get(key) is not False
            for key in (
                "proxy_port_changed",
                "proxy_ca_changed",
                "vip_or_route_changed",
                "secret_or_target_changed",
                "web_proxy_reachability_verified",
                "raw_cli_returned",
            )
        )
    ):
        raise InterfaceWebProxyMcpOAuthAcceptanceError(
            "Interface Web Proxy MCP execution readback failed."
        )


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(
        isinstance(item, InterfaceWebProxyMcpOAuthAcceptanceError)
        or (isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item))
        for item in error.exceptions
    )


def _write_preview_state(
    path: Path,
    preview_ref: str,
    *,
    prefix: str = FORWARD_PREVIEW_PREFIX,
) -> None:
    if (
        path.parent.is_symlink()
        or not path.parent.is_dir()
        or stat.S_IMODE(path.parent.stat().st_mode) & 0o077
        or path.exists()
        or path.is_symlink()
        or not preview_ref.startswith(prefix)
    ):
        raise InterfaceWebProxyMcpOAuthAcceptanceError("Preview state reference is invalid.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, json.dumps({"preview_ref": preview_ref}).encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(
    path: Path,
    *,
    prefix: str = FORWARD_PREVIEW_PREFIX,
) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise InterfaceWebProxyMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:
        preview_ref = json.loads(path.read_text(encoding="utf-8")).get("preview_ref")
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise InterfaceWebProxyMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    if not isinstance(preview_ref, str) or not preview_ref.startswith(prefix):
        raise InterfaceWebProxyMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument("--allow-insecure-private-ip-lab", action="store_true")
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--expected-tool-count", type=int)
    parser.add_argument("--lab-connect-host")
    parser.add_argument("--lab-connect-port", type=int)
    parser.add_argument("--allow-loopback-tunnel", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_interface_web_proxy_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                ca_file=args.ca_file,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
                allow_insecure_private_ip_lab=args.allow_insecure_private_ip_lab,
                rollback=args.rollback,
                expected_tool_count=args.expected_tool_count,
                lab_connect_host=args.lab_connect_host,
                lab_connect_port=args.lab_connect_port,
                allow_loopback_tunnel=args.allow_loopback_tunnel,
            )
        )
    except InterfaceWebProxyMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
