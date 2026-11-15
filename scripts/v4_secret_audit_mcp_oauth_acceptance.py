#!/usr/bin/env python3
"""Accept one fixed V4 Secret Audit OAuth/MCP C/P/E flow."""

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

TOOLS = frozenset({"preview_v4_secret_audit_generate", "confirm_v4_secret_audit_generate", "execute_confirmed_v4_secret_audit_generate"})
WORKFLOW = "fortipam_v4_secret_audit_generate_workflow_v1"
EXECUTION = "fortipam_v4_secret_audit_generate_cli_fallback_execution_v1"
PREVIEW_PREFIX = "secret-audit-preview-"
AUTHORIZATION_PREFIX = "secret-audit-authorized-"


class SecretAuditMcpOAuthAcceptanceError(RuntimeError): pass


async def run_secret_audit_mcp_oauth_acceptance(url: str, login_file: Path, client_state_file: Path, *, ca_file: Path | None = None, preview_state_file: Path | None = None, execute_preview_state_file: Path | None = None, require_inventory_readback: bool = False, allow_insecure_private_ip_lab: bool = False) -> dict[str, object]:
    if preview_state_file is not None and execute_preview_state_file is not None:
        raise SecretAuditMcpOAuthAcceptanceError("Secret Audit preview and execution inputs cannot be combined.")
    preview_verified = execution_verified = False
    phase = "Tool-surface discovery"
    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}:
            raise SecretAuditMcpOAuthAcceptanceError("Secret Audit MCP Tool surface is incomplete.")
        if preview_state_file is not None:
            phase = "preview"; reply = await session.call_tool("preview_v4_secret_audit_generate", {})
            _validate_preview(reply.structured_content, reply.is_error, require_inventory_readback=require_inventory_readback); assert isinstance(reply.structured_content, dict)
            _write_preview_state(preview_state_file, str(reply.structured_content["preview_ref"])); preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"; confirmation = await session.call_tool("confirm_v4_secret_audit_generate", {"preview_ref": _read_preview_ref(execute_preview_state_file)})
            body = confirmation.structured_content; ref = body.get("authorization_ref") if isinstance(body, dict) else None
            if confirmation.is_error or not isinstance(body, dict) or not isinstance(ref, str) or not ref.startswith(AUTHORIZATION_PREFIX) or body.get("contract") != WORKFLOW or body.get("confirmation") != "recorded" or body.get("execution") != "authorized_once" or body.get("device_write_executed") is not False:
                raise SecretAuditMcpOAuthAcceptanceError("Secret Audit MCP confirmation failed.")
            phase = "execution readback"; reply = await session.call_tool("execute_confirmed_v4_secret_audit_generate", {"authorization_ref": ref}); result = reply.structured_content
            if reply.is_error or not isinstance(result, dict) or result.get("contract") != EXECUTION or result.get("outcome") != "succeeded" or result.get("verification") != "verified" or result.get("idempotent_replay") is not False or result.get("report_generation_command_completed") is not True or result.get("report_content_returned") is not False or result.get("report_name_returned") is not False or result.get("identity_target_folder_secret_data_returned") is not False or result.get("raw_cli_returned") is not False:
                raise SecretAuditMcpOAuthAcceptanceError("Secret Audit MCP execution readback failed.")
            execute_preview_state_file.unlink(); execution_verified = True
    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(url, login_file, client_state_file, ca_file=ca_file, tool_session_callback=callback, required_tools=TOOLS, allow_insecure_private_ip_lab=allow_insecure_private_ip_lab)
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc: raise SecretAuditMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc): raise SecretAuditMcpOAuthAcceptanceError(f"Secret Audit MCP {phase} failed.") from None
        raise
    return {"contract":"fortipam_v4_secret_audit_mcp_oauth_acceptance_v1","oauth_metadata_verified":common["oauth_metadata_verified"],"mcp_initialized":common["mcp_initialized"],"secret_audit_tool_surface_complete":True,"secret_audit_preview_verified":preview_verified,"secret_audit_execution_verified":execution_verified,"device_tool_invoked":preview_verified or execution_verified,"device_write_executed":execution_verified,"token_revoked":common["token_revoked"],"credential_values_returned":common["credential_values_returned"],"token_returned":False,"client_id_returned":False}


def _validate_preview(projection: Any, is_error: bool, *, require_inventory_readback: bool = False) -> None:
    current = projection.get("Current State") if isinstance(projection, dict) else None; proposed = projection.get("Proposed Changes") if isinstance(projection, dict) else None; expected = projection.get("Expected State") if isinstance(projection, dict) else None; ref = projection.get("preview_ref") if isinstance(projection, dict) else None
    inventory_expected = require_inventory_readback
    readback_expected = "rest_inventory_delta" if inventory_expected else "ssh_cli"
    if is_error or not isinstance(current, dict) or not isinstance(proposed, dict) or not isinstance(expected, dict) or not isinstance(ref, str) or not ref.startswith(PREVIEW_PREFIX) or projection.get("contract") != WORKFLOW or projection.get("device_write_executed") is not False or current.get("fixed_cli_preflight_reachable") is not True or current.get("report_inventory_read") is not inventory_expected or proposed.get("operation") != "generate_secret_access_audit_report_via_cli_fallback" or proposed.get("configuration_profile") != "generate-secret-access-audit-report-v1" or proposed.get("caller_controlled_report_scope") is not False or proposed.get("report_content_returned") is not False or proposed.get("report_name_returned") is not False or proposed.get("identity_target_folder_secret_data_returned") is not False or proposed.get("rest_write_attempted") is not False or expected.get("report_generation_command_completed") is not True or expected.get("generated_report_name_observed_internally") is not True or expected.get("report_content_returned") is not False or expected.get("report_name_returned") is not False or expected.get("identity_target_folder_secret_data_returned") is not False or expected.get("readback_transport") != readback_expected:
        raise SecretAuditMcpOAuthAcceptanceError("Secret Audit C/P/E projection was invalid.")

def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(isinstance(item, SecretAuditMcpOAuthAcceptanceError) or (isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item)) for item in error.exceptions)


def _write_preview_state(path: Path, ref: str) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode)&0o077 or path.exists() or path.is_symlink() or not ref.startswith(PREVIEW_PREFIX): raise SecretAuditMcpOAuthAcceptanceError("Preview state reference is invalid.")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try: os.write(fd,json.dumps({"preview_ref":ref},separators=(",", ":")).encode()); os.fsync(fd)
    finally: os.close(fd)
    path.chmod(0o600)
def _read_preview_ref(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode)&0o077: raise SecretAuditMcpOAuthAcceptanceError("Preview state file is invalid.")
    try: ref=json.loads(path.read_text()).get("preview_ref")
    except (OSError,json.JSONDecodeError,AttributeError) as exc: raise SecretAuditMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    if not isinstance(ref,str) or not ref.startswith(PREVIEW_PREFIX): raise SecretAuditMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return ref
def main() -> None:
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--url",required=True); p.add_argument("--login-file",type=Path,required=True); p.add_argument("--client-state-file",type=Path,required=True); p.add_argument("--ca-file",type=Path); p.add_argument("--preview-state-file",type=Path); p.add_argument("--execute-preview-state-file",type=Path); p.add_argument("--require-inventory-readback",action="store_true"); p.add_argument("--allow-insecure-private-ip-lab",action="store_true"); a=p.parse_args()
    try: result=asyncio.run(run_secret_audit_mcp_oauth_acceptance(a.url,a.login_file,a.client_state_file,ca_file=a.ca_file,preview_state_file=a.preview_state_file,execute_preview_state_file=a.execute_preview_state_file,require_inventory_readback=a.require_inventory_readback,allow_insecure_private_ip_lab=a.allow_insecure_private_ip_lab))
    except SecretAuditMcpOAuthAcceptanceError as exc: raise SystemExit(str(exc)) from None
    print(json.dumps(result,sort_keys=True))
if __name__ == "__main__": main()
