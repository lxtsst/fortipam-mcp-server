#!/usr/bin/env python3
"""Accept one bounded V4 SSH Filter Profile create OAuth/MCP flow."""
from __future__ import annotations
import argparse, asyncio, json, os, stat, sys
from pathlib import Path
from typing import Any
from mcp import ClientSession
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts import v4_address_mcp_oauth_surface_acceptance as oauth
TOOLS=frozenset({"preview_v4_ssh_filter_create","confirm_v4_ssh_filter_create","execute_confirmed_v4_ssh_filter_create"}); WORKFLOW="fortipam_v4_ssh_filter_create_cli_fallback_workflow_v1"; EXECUTION="fortipam_v4_ssh_filter_create_cli_fallback_execution_v1"; PREVIEW="ssh-filter-preview-"; AUTHORIZATION="ssh-filter-authorized-"
class SshFilterMcpOAuthAcceptanceError(RuntimeError):pass
async def run_ssh_filter_mcp_oauth_acceptance(url:str,login_file:Path,client_state_file:Path,*,profile_name:str|None=None,preview_state_file:Path|None=None,execute_preview_state_file:Path|None=None,ca_file:Path|None=None)->dict[str,object]:
 requested=profile_name is not None or preview_state_file is not None
 if requested and execute_preview_state_file is not None:raise SshFilterMcpOAuthAcceptanceError("SSH Filter preview and execution inputs cannot be combined.")
 if requested and (profile_name is None or preview_state_file is None):raise SshFilterMcpOAuthAcceptanceError("SSH Filter preview inputs are incomplete.")
 pv=ev=False; phase="Tool-surface discovery"
 async def callback(s:ClientSession)->None:
  nonlocal pv,ev,phase
  if not TOOLS<={x.name for x in (await s.list_tools()).tools}:raise SshFilterMcpOAuthAcceptanceError("SSH Filter MCP Tool surface is incomplete.")
  if requested:
   assert profile_name is not None and preview_state_file is not None
   phase="preview"; r=await s.call_tool("preview_v4_ssh_filter_create",{"profile_name":profile_name}); _vp(r.structured_content,profile_name,r.is_error); assert isinstance(r.structured_content,dict); _write(preview_state_file,str(r.structured_content["preview_ref"]));pv=True
  if execute_preview_state_file is not None:
   phase="confirmation"; c=await s.call_tool("confirm_v4_ssh_filter_create",{"preview_ref":_read(execute_preview_state_file)}); b=c.structured_content; a=b.get("authorization_ref") if isinstance(b,dict) else None
   if c.is_error or not isinstance(b,dict) or not isinstance(a,str) or not a.startswith(AUTHORIZATION) or b.get("contract")!=WORKFLOW or b.get("confirmation")!="recorded" or b.get("execution")!="authorized_once" or b.get("device_write_executed") is not False:raise SshFilterMcpOAuthAcceptanceError("SSH Filter MCP confirmation failed.")
   phase="execution readback";r=await s.call_tool("execute_confirmed_v4_ssh_filter_create",{"authorization_ref":a});_ve(r.structured_content,r.is_error);execute_preview_state_file.unlink();ev=True
 try:c=await oauth.run_address_mcp_oauth_surface_acceptance(url,login_file,client_state_file,ca_file=ca_file,tool_session_callback=callback,required_tools=TOOLS)
 except oauth.AddressMcpOAuthSurfaceAcceptanceError as e:raise SshFilterMcpOAuthAcceptanceError(str(e)) from None
 except BaseExceptionGroup as e:
  if _contains(e):raise SshFilterMcpOAuthAcceptanceError(f"SSH Filter MCP {phase} failed.") from None
  raise
 return {"contract":"fortipam_v4_ssh_filter_mcp_oauth_acceptance_v1","oauth_metadata_verified":c["oauth_metadata_verified"],"mcp_initialized":c["mcp_initialized"],"ssh_filter_tool_surface_complete":True,"ssh_filter_preview_verified":pv,"ssh_filter_execution_verified":ev,"device_tool_invoked":pv or ev,"device_write_executed":ev,"token_revoked":c["token_revoked"],"credential_values_returned":c["credential_values_returned"],"token_returned":False,"client_id_returned":False}
def _vp(x:Any,n:str,e:bool)->None:
 c=x.get("Current State") if isinstance(x,dict) else None;p=x.get("Proposed Changes") if isinstance(x,dict) else None;q=x.get("Expected State") if isinstance(x,dict) else None;r=x.get("preview_ref") if isinstance(x,dict) else None
 if(e or not isinstance(c,dict) or not isinstance(p,dict) or not isinstance(q,dict) or not isinstance(r,str) or not r.startswith(PREVIEW) or x.get("contract")!=WORKFLOW or x.get("device_write_executed") is not False or c.get("requested_profile_name")!=n or c.get("profile_name_exists") is not False or c.get("write_transport")!="ssh_cli_fallback" or p.get("operation")!="create_ssh_filter_profile_via_cli_fallback" or p.get("profile_name")!=n or p.get("configuration_profile")!="deny-rm-with-log-and-alert-v1" or p.get("mode")!="deny" or p.get("shell_pattern")!="rm" or p.get("pattern_log")!="enable" or p.get("pattern_alert")!="enable" or any(p.get(k) is not False for k in ("secret_or_policy_association_changes","target_or_session_changes","rest_write_attempted")) or any(q.get(k) is not True for k in ("profile_name_matches","profile_name_exists","deny_mode_enabled","rm_pattern_present","pattern_log_enabled","pattern_alert_enabled")) or q.get("secret_or_policy_association_changes") is not False or q.get("readback_transport")!="ssh_cli"):raise SshFilterMcpOAuthAcceptanceError("SSH Filter C/P/E projection was invalid.")
def _ve(x:Any,e:bool)->None:
 if(e or not isinstance(x,dict) or x.get("contract")!=EXECUTION or x.get("outcome")!="succeeded" or x.get("verification")!="verified" or x.get("idempotent_replay") is not False or x.get("compensation")!="separate_ssh_filter_profile_delete_action_required" or any(x.get(k) is not False for k in ("profile_name_returned","secret_or_policy_association_changes","raw_cli_returned"))):raise SshFilterMcpOAuthAcceptanceError("SSH Filter execution result was invalid.")
def _contains(e:BaseExceptionGroup)->bool:return any(isinstance(x,SshFilterMcpOAuthAcceptanceError) or (isinstance(x,BaseExceptionGroup) and _contains(x)) for x in e.exceptions)
def _write(p:Path,r:str)->None:
 if p.parent.is_symlink() or not p.parent.is_dir() or stat.S_IMODE(p.parent.stat().st_mode)&0o077 or p.exists() or p.is_symlink() or not r.startswith(PREVIEW):raise SshFilterMcpOAuthAcceptanceError("Preview state reference is invalid.")
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(fd,json.dumps({"preview_ref":r}).encode());os.fsync(fd)
 finally:os.close(fd)
 p.chmod(0o600)
def _read(p:Path)->str:
 if p.is_symlink() or not p.is_file() or stat.S_IMODE(p.stat().st_mode)&0o077:raise SshFilterMcpOAuthAcceptanceError("Preview state file is invalid.")
 try:r=json.loads(p.read_text()).get("preview_ref")
 except (OSError,json.JSONDecodeError,AttributeError) as e:raise SshFilterMcpOAuthAcceptanceError("Preview state file is invalid.") from e
 if not isinstance(r,str) or not r.startswith(PREVIEW):raise SshFilterMcpOAuthAcceptanceError("Preview state reference is invalid.")
 return r
def main()->None:
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--url",required=True);p.add_argument("--login-file",type=Path,required=True);p.add_argument("--client-state-file",type=Path,required=True);p.add_argument("--profile-name");p.add_argument("--preview-state-file",type=Path);p.add_argument("--execute-preview-state-file",type=Path);p.add_argument("--ca-file",type=Path);a=p.parse_args()
 try:r=asyncio.run(run_ssh_filter_mcp_oauth_acceptance(a.url,a.login_file,a.client_state_file,profile_name=a.profile_name,preview_state_file=a.preview_state_file,execute_preview_state_file=a.execute_preview_state_file,ca_file=a.ca_file))
 except SshFilterMcpOAuthAcceptanceError as e:raise SystemExit(str(e)) from None
 print(json.dumps(r,sort_keys=True))
if __name__=="__main__":main()
