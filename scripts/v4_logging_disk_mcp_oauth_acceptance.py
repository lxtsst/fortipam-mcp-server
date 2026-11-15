#!/usr/bin/env python3
"""Accept one bounded V4 disk-logging disable OAuth/MCP C/P/E flow."""
from __future__ import annotations
import argparse, asyncio, json, os, stat, sys
from pathlib import Path
from typing import Any
from mcp import ClientSession

PROJECT_ROOT=Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path: sys.path.insert(0,str(PROJECT_ROOT))
from scripts import v4_address_mcp_oauth_surface_acceptance as oauth

TOOLS=frozenset({"preview_v4_logging_disk_disable","confirm_v4_logging_disk_disable","execute_confirmed_v4_logging_disk_disable"})
WORKFLOW="fortipam_v4_logging_disk_disable_workflow_v1"; EXECUTION="fortipam_v4_logging_disk_disable_execution_v1"; PREVIEW_PREFIX="logging-disk-preview-"; AUTHORIZATION_PREFIX="logging-disk-authorized-"
class LoggingDiskMcpOAuthAcceptanceError(RuntimeError): pass

async def run_logging_disk_mcp_oauth_acceptance(url:str,login_file:Path,client_state_file:Path,*,ca_file:Path|None=None,preview_state_file:Path|None=None,execute_preview_state_file:Path|None=None)->dict[str,object]:
    if preview_state_file is not None and execute_preview_state_file is not None: raise LoggingDiskMcpOAuthAcceptanceError("Logging-disk preview and execution inputs cannot be combined.")
    preview_ok=execution_ok=False; phase="Tool-surface discovery"
    async def callback(session:ClientSession)->None:
        nonlocal preview_ok,execution_ok,phase
        if not TOOLS<={x.name for x in (await session.list_tools()).tools}: raise LoggingDiskMcpOAuthAcceptanceError("Logging-disk MCP Tool surface is incomplete.")
        if preview_state_file is not None:
            phase="preview"; reply=await session.call_tool("preview_v4_logging_disk_disable",{}); _preview(reply.structured_content,reply.is_error); assert isinstance(reply.structured_content,dict); _write(preview_state_file,str(reply.structured_content["preview_ref"])); preview_ok=True
        if execute_preview_state_file is not None:
            phase="confirmation"; reply=await session.call_tool("confirm_v4_logging_disk_disable",{"preview_ref":_read(execute_preview_state_file)}); body=reply.structured_content; ref=body.get("authorization_ref") if isinstance(body,dict) else None
            if reply.is_error or not isinstance(body,dict) or not isinstance(ref,str) or not ref.startswith(AUTHORIZATION_PREFIX) or body.get("contract")!=WORKFLOW or body.get("confirmation")!="recorded" or body.get("execution")!="authorized_once" or body.get("device_write_executed") is not False: raise LoggingDiskMcpOAuthAcceptanceError("Logging-disk MCP confirmation failed.")
            phase="execution readback"; reply=await session.call_tool("execute_confirmed_v4_logging_disk_disable",{"authorization_ref":ref}); _execution(reply.structured_content,reply.is_error); execute_preview_state_file.unlink(); execution_ok=True
    try: common=await oauth.run_address_mcp_oauth_surface_acceptance(url,login_file,client_state_file,ca_file=ca_file,tool_session_callback=callback,required_tools=TOOLS)
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc: raise LoggingDiskMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains(exc): raise LoggingDiskMcpOAuthAcceptanceError(f"Logging-disk MCP {phase} failed.") from None
        raise
    return {"contract":"fortipam_v4_logging_disk_mcp_oauth_acceptance_v1","oauth_metadata_verified":common["oauth_metadata_verified"],"mcp_initialized":common["mcp_initialized"],"logging_disk_tool_surface_complete":True,"logging_disk_preview_verified":preview_ok,"logging_disk_execution_verified":execution_ok,"device_tool_invoked":preview_ok or execution_ok,"device_write_executed":execution_ok,"token_revoked":common["token_revoked"],"credential_values_returned":common["credential_values_returned"],"token_returned":False,"client_id_returned":False}

def _preview(p:Any,error:bool)->None:
    c=p.get("Current State") if isinstance(p,dict) else None; q=p.get("Proposed Changes") if isinstance(p,dict) else None; e=p.get("Expected State") if isinstance(p,dict) else None; r=p.get("preview_ref") if isinstance(p,dict) else None; unchanged=("remote_syslog_configuration_changed","event_logging_configuration_changed","disk_encryption_changed")
    if error or not isinstance(c,dict) or not isinstance(q,dict) or not isinstance(e,dict) or not isinstance(r,str) or not r.startswith(PREVIEW_PREFIX) or p.get("contract")!=WORKFLOW or p.get("device_write_executed") is not False or c.get("memory_log_status")!="enable" or c.get("disk_log_status")!="enable" or c.get("write_transport")!="ssh_cli_fallback" or any(c.get(x) is not False for x in unchanged) or q.get("operation")!="disable_disk_logging_via_cli_fallback" or q.get("configuration_profile")!="disable-disk-preserve-memory-logging-v1" or q.get("memory_log_status")!="enable" or q.get("disk_log_status")!="disable" or any(q.get(x) is not False for x in (*unchanged,"rest_write_attempted")) or e.get("memory_log_status")!="enable" or e.get("disk_log_status")!="disable" or any(e.get(x) is not False for x in (*unchanged,"logging_effect_verified")) or e.get("readback_transport")!="ssh_cli": raise LoggingDiskMcpOAuthAcceptanceError("Logging-disk C/P/E projection was invalid.")
def _execution(r:Any,error:bool)->None:
    unchanged=("remote_syslog_configuration_changed","event_logging_configuration_changed","disk_encryption_changed","logging_effect_verified","raw_cli_returned")
    if error or not isinstance(r,dict) or r.get("contract")!=EXECUTION or r.get("outcome")!="succeeded" or r.get("verification")!="verified" or r.get("idempotent_replay") is not False or r.get("compensation")!="separate_logging_disk_enable_action_required" or r.get("memory_log_status")!="enable" or r.get("disk_log_status")!="disable" or any(r.get(x) is not False for x in unchanged): raise LoggingDiskMcpOAuthAcceptanceError("Logging-disk MCP execution readback failed.")
def _contains(g:BaseExceptionGroup)->bool: return any(isinstance(x,LoggingDiskMcpOAuthAcceptanceError) or (isinstance(x,BaseExceptionGroup) and _contains(x)) for x in g.exceptions)
def _write(p:Path,r:str)->None:
    if p.parent.is_symlink() or not p.parent.is_dir() or stat.S_IMODE(p.parent.stat().st_mode)&0o077 or p.exists() or p.is_symlink() or not r.startswith(PREVIEW_PREFIX): raise LoggingDiskMcpOAuthAcceptanceError("Preview state reference is invalid.")
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try: os.write(fd,json.dumps({"preview_ref":r},separators=(",",":")).encode()); os.fsync(fd)
    finally: os.close(fd)
    p.chmod(0o600)
def _read(p:Path)->str:
    if p.is_symlink() or not p.is_file() or stat.S_IMODE(p.stat().st_mode)&0o077: raise LoggingDiskMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:r=json.loads(p.read_text()).get("preview_ref")
    except (OSError,json.JSONDecodeError,AttributeError) as exc: raise LoggingDiskMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    if not isinstance(r,str) or not r.startswith(PREVIEW_PREFIX): raise LoggingDiskMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return r
def main()->None:
    p=argparse.ArgumentParser();p.add_argument("--url",required=True);p.add_argument("--login-file",type=Path,required=True);p.add_argument("--client-state-file",type=Path,required=True);p.add_argument("--ca-file",type=Path);p.add_argument("--preview-state-file",type=Path);p.add_argument("--execute-preview-state-file",type=Path);a=p.parse_args()
    try: out=asyncio.run(run_logging_disk_mcp_oauth_acceptance(a.url,a.login_file,a.client_state_file,ca_file=a.ca_file,preview_state_file=a.preview_state_file,execute_preview_state_file=a.execute_preview_state_file))
    except LoggingDiskMcpOAuthAcceptanceError as exc: raise SystemExit(str(exc)) from None
    print(json.dumps(out,sort_keys=True))
if __name__=="__main__":main()
