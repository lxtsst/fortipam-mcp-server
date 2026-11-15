#!/usr/bin/env python3
"""Accept one bounded V4 SNMP Agent enable or rollback OAuth/MCP C/P/E flow."""
from __future__ import annotations
import argparse, asyncio, json, os, stat, sys
from pathlib import Path
from typing import Any
from mcp import ClientSession

PROJECT_ROOT=Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path: sys.path.insert(0,str(PROJECT_ROOT))
from scripts import v4_address_mcp_oauth_surface_acceptance as oauth

FORWARD_TOOLS=("preview_v4_snmp_agent_enable","confirm_v4_snmp_agent_enable","execute_confirmed_v4_snmp_agent_enable")
ROLLBACK_TOOLS=("preview_v4_snmp_agent_rollback","confirm_v4_snmp_agent_rollback","execute_confirmed_v4_snmp_agent_rollback")
TOOLS=frozenset((*FORWARD_TOOLS,*ROLLBACK_TOOLS))
EXPECTED_TOOL_COUNT=298
FORWARD_WORKFLOW="fortipam_v4_snmp_agent_enable_workflow_v1"; FORWARD_EXECUTION="fortipam_v4_snmp_agent_enable_execution_v1"; FORWARD_PREVIEW_PREFIX="snmp-agent-preview-"; FORWARD_AUTHORIZATION_PREFIX="snmp-agent-authorized-"
ROLLBACK_WORKFLOW="fortipam_v4_snmp_agent_rollback_workflow_v1"; ROLLBACK_EXECUTION="fortipam_v4_snmp_agent_rollback_execution_v1"; ROLLBACK_PREVIEW_PREFIX="snmp-agent-rollback-preview-"; ROLLBACK_AUTHORIZATION_PREFIX="snmp-agent-rollback-authorized-"
class SnmpAgentMcpOAuthAcceptanceError(RuntimeError): pass

async def run_snmp_agent_mcp_oauth_acceptance(url:str,login_file:Path,client_state_file:Path,*,ca_file:Path|None=None,preview_state_file:Path|None=None,execute_preview_state_file:Path|None=None,allow_insecure_private_ip_lab:bool=False,rollback:bool=False)->dict[str,object]:
    if preview_state_file is not None and execute_preview_state_file is not None: raise SnmpAgentMcpOAuthAcceptanceError("SNMP preview and execution inputs cannot be combined.")
    selected_tools=ROLLBACK_TOOLS if rollback else FORWARD_TOOLS
    workflow=ROLLBACK_WORKFLOW if rollback else FORWARD_WORKFLOW
    execution=ROLLBACK_EXECUTION if rollback else FORWARD_EXECUTION
    preview_prefix=ROLLBACK_PREVIEW_PREFIX if rollback else FORWARD_PREVIEW_PREFIX
    authorization_prefix=ROLLBACK_AUTHORIZATION_PREFIX if rollback else FORWARD_AUTHORIZATION_PREFIX
    expected_status="disable" if rollback else "enable"
    preview_ok=execution_ok=False; phase="Tool-surface discovery"
    async def callback(session:ClientSession)->None:
        nonlocal preview_ok,execution_ok,phase
        names={x.name for x in (await session.list_tools()).tools}
        if not TOOLS<=names or len(names)!=EXPECTED_TOOL_COUNT: raise SnmpAgentMcpOAuthAcceptanceError("SNMP MCP Tool surface is incomplete.")
        if preview_state_file is not None:
            phase="preview"; reply=await session.call_tool(selected_tools[0],{}); _validate_preview(reply.structured_content,reply.is_error,rollback=rollback); assert isinstance(reply.structured_content,dict); _write(preview_state_file,str(reply.structured_content["preview_ref"]),prefix=preview_prefix); preview_ok=True
        if execute_preview_state_file is not None:
            phase="confirmation"; reply=await session.call_tool(selected_tools[1],{"preview_ref":_read(execute_preview_state_file,prefix=preview_prefix)}); body=reply.structured_content; ref=body.get("authorization_ref") if isinstance(body,dict) else None
            if reply.is_error or not isinstance(body,dict) or not isinstance(ref,str) or not ref.startswith(authorization_prefix) or body.get("contract")!=workflow or body.get("confirmation")!="recorded" or body.get("execution")!="authorized_once" or body.get("device_write_executed") is not False: raise SnmpAgentMcpOAuthAcceptanceError("SNMP MCP confirmation failed.")
            phase="execution readback"; reply=await session.call_tool(selected_tools[2],{"authorization_ref":ref}); result=reply.structured_content
            if reply.is_error or not isinstance(result,dict) or result.get("contract")!=execution or result.get("outcome")!="succeeded" or result.get("verification")!="verified" or result.get("idempotent_replay") is not False or result.get("snmp_agent_status")!=expected_status or (rollback and result.get("pre_action_state_restored") is not True) or any(result.get(x) is not False for x in ("snmp_community_configuration_changed","snmpv3_user_configuration_changed","notification_host_configuration_changed","interface_administrative_access_changed","snmp_query_or_trap_effect_verified","raw_cli_returned")): raise SnmpAgentMcpOAuthAcceptanceError("SNMP MCP execution readback failed.")
            execute_preview_state_file.unlink(); execution_ok=True
    try: common=await oauth.run_address_mcp_oauth_surface_acceptance(url,login_file,client_state_file,ca_file=ca_file,tool_session_callback=callback,required_tools=TOOLS,allow_insecure_private_ip_lab=allow_insecure_private_ip_lab)
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc: raise SnmpAgentMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains(exc): raise SnmpAgentMcpOAuthAcceptanceError(f"SNMP MCP {phase} failed.") from None
        raise
    return {"contract":"fortipam_v4_snmp_agent_mcp_oauth_acceptance_v1","oauth_metadata_verified":common["oauth_metadata_verified"],"mcp_initialized":common["mcp_initialized"],"snmp_agent_tool_surface_complete":True,"exact_tool_count_verified":True,"snmp_agent_direction":"rollback" if rollback else "forward","snmp_agent_preview_verified":preview_ok,"snmp_agent_execution_verified":execution_ok,"device_tool_invoked":preview_ok or execution_ok,"device_write_executed":execution_ok,"token_revoked":common["token_revoked"],"credential_values_returned":common["credential_values_returned"],"token_returned":False,"client_id_returned":False}

def _validate_preview(p:Any,error:bool,*,rollback:bool=False)->None:
    c=p.get("Current State") if isinstance(p,dict) else None; q=p.get("Proposed Changes") if isinstance(p,dict) else None; e=p.get("Expected State") if isinstance(p,dict) else None; r=p.get("preview_ref") if isinstance(p,dict) else None; nochange=("snmp_community_configuration_changed","snmpv3_user_configuration_changed","notification_host_configuration_changed","interface_administrative_access_changed")
    workflow=ROLLBACK_WORKFLOW if rollback else FORWARD_WORKFLOW; prefix=ROLLBACK_PREVIEW_PREFIX if rollback else FORWARD_PREVIEW_PREFIX; current_status="enable" if rollback else "disable"; expected_status="disable" if rollback else "enable"; operation="restore_preconfigured_snmp_agent_disabled_state_via_cli_fallback" if rollback else "enable_preconfigured_snmp_agent_via_cli_fallback"; configuration="disable-preconfigured-system-snmp-agent-v1" if rollback else "enable-preconfigured-system-snmp-agent-v1"
    if error or not isinstance(c,dict) or not isinstance(q,dict) or not isinstance(e,dict) or not isinstance(r,str) or not r.startswith(prefix) or p.get("contract")!=workflow or p.get("device_write_executed") is not False or c.get("snmp_agent_status")!=current_status or c.get("write_transport")!="strict_api_preflight_ssh_cli_fallback" or any(c.get(x) is not False for x in nochange) or q.get("operation")!=operation or q.get("configuration_profile")!=configuration or q.get("snmp_agent_status")!=expected_status or any(q.get(x) is not False for x in (*nochange,"snmp_query_or_trap_sent","rest_write_attempted")) or e.get("snmp_agent_status")!=expected_status or (rollback and e.get("pre_action_state_restored") is not True) or any(e.get(x) is not False for x in (*nochange,"snmp_query_or_trap_effect_verified")) or e.get("readback_transport")!="strict_api_and_ssh_cli": raise SnmpAgentMcpOAuthAcceptanceError("SNMP C/P/E projection was invalid.")
def _contains(g:BaseExceptionGroup)->bool: return any(isinstance(x,SnmpAgentMcpOAuthAcceptanceError) or (isinstance(x,BaseExceptionGroup) and _contains(x)) for x in g.exceptions)
def _write(p:Path,r:str,*,prefix:str=FORWARD_PREVIEW_PREFIX)->None:
    if p.parent.is_symlink() or not p.parent.is_dir() or stat.S_IMODE(p.parent.stat().st_mode)&0o077 or p.exists() or p.is_symlink() or not r.startswith(prefix): raise SnmpAgentMcpOAuthAcceptanceError("Preview state reference is invalid.")
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try: os.write(fd,json.dumps({"preview_ref":r},separators=(",",":")).encode()); os.fsync(fd)
    finally: os.close(fd)
    p.chmod(0o600)
def _read(p:Path,*,prefix:str=FORWARD_PREVIEW_PREFIX)->str:
    if p.is_symlink() or not p.is_file() or stat.S_IMODE(p.stat().st_mode)&0o077: raise SnmpAgentMcpOAuthAcceptanceError("Preview state file is invalid.")
    try:r=json.loads(p.read_text()).get("preview_ref")
    except (OSError,json.JSONDecodeError,AttributeError) as exc: raise SnmpAgentMcpOAuthAcceptanceError("Preview state file is invalid.") from exc
    if not isinstance(r,str) or not r.startswith(prefix): raise SnmpAgentMcpOAuthAcceptanceError("Preview state reference is invalid.")
    return r
def main()->None:
    p=argparse.ArgumentParser();p.add_argument("--url",required=True);p.add_argument("--login-file",type=Path,required=True);p.add_argument("--client-state-file",type=Path,required=True);p.add_argument("--ca-file",type=Path);p.add_argument("--preview-state-file",type=Path);p.add_argument("--execute-preview-state-file",type=Path);p.add_argument("--allow-insecure-private-ip-lab",action="store_true");p.add_argument("--rollback",action="store_true");a=p.parse_args()
    try: out=asyncio.run(run_snmp_agent_mcp_oauth_acceptance(a.url,a.login_file,a.client_state_file,ca_file=a.ca_file,preview_state_file=a.preview_state_file,execute_preview_state_file=a.execute_preview_state_file,allow_insecure_private_ip_lab=a.allow_insecure_private_ip_lab,rollback=a.rollback))
    except SnmpAgentMcpOAuthAcceptanceError as exc: raise SystemExit(str(exc)) from None
    print(json.dumps(out,sort_keys=True))
if __name__=="__main__":main()
