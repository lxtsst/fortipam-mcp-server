#!/usr/bin/env python3
"""Accept the self-cleaning V4 ZTNA WAD debug OAuth/MCP flow."""
from __future__ import annotations
import argparse, asyncio, json, os, stat, sys
from pathlib import Path
from typing import Any
from mcp import ClientSession
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
for import_root in (str(SOURCE_ROOT), str(PROJECT_ROOT)):
    while import_root in sys.path:
        sys.path.remove(import_root)
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(SOURCE_ROOT))
from scripts import v4_address_mcp_oauth_surface_acceptance as oauth
TOOLS = frozenset({"preview_v4_ztna_wad_debug_diagnostic", "confirm_v4_ztna_wad_debug_diagnostic", "execute_confirmed_v4_ztna_wad_debug_diagnostic"})
WORKFLOW = "fortipam_v4_ztna_wad_debug_workflow_v1"; EXECUTION = "fortipam_v4_ztna_wad_debug_execution_v1"; PREVIEW_PREFIX = "ztna-wad-debug-preview-"; AUTHORIZATION_PREFIX = "ztna-wad-debug-authorized-"
class ZtnaWadDebugMcpOAuthAcceptanceError(RuntimeError): pass
async def run_ztna_wad_debug_mcp_oauth_acceptance(url: str, login_file: Path, client_state_file: Path, *, preview_state_file: Path | None = None, execute_preview_state_file: Path | None = None, ca_file: Path | None = None, allow_insecure_private_ip_lab: bool = False) -> dict[str, object]:
    if preview_state_file is not None and execute_preview_state_file is not None: raise ZtnaWadDebugMcpOAuthAcceptanceError("ZTNA WAD debug preview and execution inputs cannot be combined.")
    preview_verified = execution_verified = False; phase = "Tool-surface discovery"
    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase
        if not TOOLS <= {tool.name for tool in (await session.list_tools()).tools}: raise ZtnaWadDebugMcpOAuthAcceptanceError("ZTNA WAD debug MCP Tool surface is incomplete.")
        if preview_state_file is not None:
            phase = "preview"; reply = await session.call_tool("preview_v4_ztna_wad_debug_diagnostic", {}); _validate_preview(reply.structured_content, reply.is_error); assert isinstance(reply.structured_content, dict); _write_preview_state(preview_state_file, str(reply.structured_content["preview_ref"])); preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"; confirmation = await session.call_tool("confirm_v4_ztna_wad_debug_diagnostic", {"preview_ref": _read_preview_ref(execute_preview_state_file)}); body = confirmation.structured_content; ref = body.get("authorization_ref") if isinstance(body, dict) else None
            if confirmation.is_error or not isinstance(body, dict) or not isinstance(ref, str) or not ref.startswith(AUTHORIZATION_PREFIX) or body.get("contract") != WORKFLOW or body.get("confirmation") != "recorded" or body.get("execution") != "authorized_once" or body.get("device_write_executed") is not False: raise ZtnaWadDebugMcpOAuthAcceptanceError("ZTNA WAD debug MCP confirmation failed.")
            phase = "execution readback"; reply = await session.call_tool("execute_confirmed_v4_ztna_wad_debug_diagnostic", {"authorization_ref": ref}); _validate_execution(reply.structured_content, reply.is_error); execute_preview_state_file.unlink(); execution_verified = True
    try: common = await oauth.run_address_mcp_oauth_surface_acceptance(url, login_file, client_state_file, ca_file=ca_file, tool_session_callback=callback, required_tools=TOOLS, allow_insecure_private_ip_lab=allow_insecure_private_ip_lab)
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc: raise ZtnaWadDebugMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains(exc): raise ZtnaWadDebugMcpOAuthAcceptanceError(f"ZTNA WAD debug MCP {phase} failed.") from None
        raise
    return {"contract":"fortipam_v4_ztna_wad_debug_mcp_oauth_acceptance_v1","oauth_metadata_verified":common["oauth_metadata_verified"],"mcp_initialized":common["mcp_initialized"],"ztna_wad_debug_tool_surface_complete":True,"ztna_wad_debug_preview_verified":preview_verified,"ztna_wad_debug_execution_verified":execution_verified,"device_tool_invoked":preview_verified or execution_verified,"device_write_executed":execution_verified,"token_revoked":common["token_revoked"],"credential_values_returned":common["credential_values_returned"],"token_returned":False,"client_id_returned":False}
def _validate_preview(x: Any, err: bool) -> None:
    c=x.get("Current State") if isinstance(x,dict) else None; p=x.get("Proposed Changes") if isinstance(x,dict) else None; e=x.get("Expected State") if isinstance(x,dict) else None; r=x.get("preview_ref") if isinstance(x,dict) else None
    if (err or not isinstance(c,dict) or not isinstance(p,dict) or not isinstance(e,dict) or not isinstance(r,str) or not r.startswith(PREVIEW_PREFIX) or x.get("contract")!=WORKFLOW or x.get("device_write_executed") is not False or c.get("global_debug_state")!="disabled" or any(c.get(k) is not False for k in ("raw_cli_returned","identity_tag_target_secret_or_session_data_returned","persistent_configuration_changed")) or p.get("operation")!="run_timeboxed_fixed_ztna_wad_debug_diagnostic" or p.get("configuration_profile")!="fixed-secret-gateway-svc-conn-timeboxed-v1" or p.get("wad_debug_categories")!="fixed_secret_gateway_svc_conn_only" or any(p.get(k) is not True for k in ("global_debug_enabled_temporarily","automatic_cleanup_required")) or any(p.get(k) is not False for k in ("caller_controlled_cli","endpoint_or_tag_input_accepted","persistent_configuration_changed","rest_write_attempted")) or e.get("global_debug_state")!="disabled_after_capture" or e.get("diagnostic_result")!="categorical_device_context_tag_and_launch_evidence_only" or any(e.get(k) is not False for k in ("raw_cli_returned","identity_tag_target_secret_or_session_data_returned","persistent_configuration_changed"))): raise ZtnaWadDebugMcpOAuthAcceptanceError("ZTNA WAD debug C/P/E projection was invalid.")
def _validate_execution(x: Any, err: bool) -> None:
    if (err or not isinstance(x,dict) or x.get("contract")!=EXECUTION or x.get("outcome")!="succeeded" or x.get("verification")!="verified" or x.get("idempotent_replay") is not False or x.get("global_debug_cleanup_confirmed") is not True or x.get("compensation")!="automatic_diagnose_debug_disable_cleanup; reconcile_manually_if_cleanup_unknown" or any(x.get(k) is not False for k in ("raw_cli_returned","identity_tag_target_secret_or_session_data_returned","persistent_configuration_changed"))): raise ZtnaWadDebugMcpOAuthAcceptanceError("ZTNA WAD debug MCP execution readback failed.")
def _contains(e: BaseExceptionGroup) -> bool: return any(isinstance(i,ZtnaWadDebugMcpOAuthAcceptanceError) or (isinstance(i,BaseExceptionGroup) and _contains(i)) for i in e.exceptions)
def _write_preview_state(p: Path,r: str)->None:
    if p.parent.is_symlink() or not p.parent.is_dir() or stat.S_IMODE(p.parent.stat().st_mode)&0o077 or p.exists() or p.is_symlink() or not r.startswith(PREVIEW_PREFIX): raise ZtnaWadDebugMcpOAuthAcceptanceError("Preview state reference is invalid.")
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try: os.write(fd,json.dumps({"preview_ref":r}).encode());os.fsync(fd)
    finally: os.close(fd)
    p.chmod(0o600)
def _read_preview_ref(p:Path)->str:
    if p.is_symlink() or not p.is_file() or stat.S_IMODE(p.stat().st_mode)&0o077: raise ZtnaWadDebugMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:r=json.loads(p.read_text()).get("preview_ref")
    except (OSError,json.JSONDecodeError,AttributeError) as e:raise ZtnaWadDebugMcpOAuthAcceptanceError("Preview state file is invalid.") from e
    if not isinstance(r,str) or not r.startswith(PREVIEW_PREFIX):raise ZtnaWadDebugMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return r
def main()->None:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--url",required=True);p.add_argument("--login-file",type=Path,required=True);p.add_argument("--client-state-file",type=Path,required=True);p.add_argument("--preview-state-file",type=Path);p.add_argument("--execute-preview-state-file",type=Path);p.add_argument("--ca-file",type=Path);p.add_argument("--allow-insecure-private-ip-lab",action="store_true");a=p.parse_args()
    try:r=asyncio.run(run_ztna_wad_debug_mcp_oauth_acceptance(a.url,a.login_file,a.client_state_file,preview_state_file=a.preview_state_file,execute_preview_state_file=a.execute_preview_state_file,ca_file=a.ca_file,allow_insecure_private_ip_lab=a.allow_insecure_private_ip_lab))
    except ZtnaWadDebugMcpOAuthAcceptanceError as e:raise SystemExit(str(e)) from None
    print(json.dumps(r,sort_keys=True))
if __name__=="__main__":main()
