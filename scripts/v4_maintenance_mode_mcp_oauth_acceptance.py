#!/usr/bin/env python3
"""Accept one bounded V4 maintenance-mode enable OAuth/MCP flow."""
from __future__ import annotations
import argparse,asyncio,json,os,stat,sys
from pathlib import Path
from typing import Any
from mcp import ClientSession
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts import v4_address_mcp_oauth_surface_acceptance as oauth
TOOLS=frozenset({"preview_v4_maintenance_mode_enable","confirm_v4_maintenance_mode_enable","execute_confirmed_v4_maintenance_mode_enable"});WORKFLOW="fortipam_v4_maintenance_mode_enable_workflow_v1";EXECUTION="fortipam_v4_maintenance_mode_enable_execution_v1";PREVIEW="maintenance-mode-preview-";AUTH="maintenance-mode-authorized-"
class MaintenanceModeMcpOAuthAcceptanceError(RuntimeError):pass
async def run_maintenance_mode_mcp_oauth_acceptance(url:str,login_file:Path,client_state_file:Path,*,preview_state_file:Path|None=None,execute_preview_state_file:Path|None=None,ca_file:Path|None=None)->dict[str,object]:
 if preview_state_file is not None and execute_preview_state_file is not None:raise MaintenanceModeMcpOAuthAcceptanceError("Maintenance-mode preview and execution inputs cannot be combined.")
 pv=ev=False;phase="Tool-surface discovery"
 async def cb(s:ClientSession)->None:
  nonlocal pv,ev,phase
  if not TOOLS<={t.name for t in (await s.list_tools()).tools}:raise MaintenanceModeMcpOAuthAcceptanceError("Maintenance-mode MCP Tool surface is incomplete.")
  if preview_state_file is not None:
   phase="preview";r=await s.call_tool("preview_v4_maintenance_mode_enable",{});_vp(r.structured_content,r.is_error);assert isinstance(r.structured_content,dict);_write(preview_state_file,str(r.structured_content["preview_ref"]));pv=True
  if execute_preview_state_file is not None:
   phase="confirmation";c=await s.call_tool("confirm_v4_maintenance_mode_enable",{"preview_ref":_read(execute_preview_state_file)});b=c.structured_content;a=b.get("authorization_ref") if isinstance(b,dict) else None
   if c.is_error or not isinstance(b,dict) or not isinstance(a,str) or not a.startswith(AUTH) or b.get("contract")!=WORKFLOW or b.get("confirmation")!="recorded" or b.get("execution")!="authorized_once" or b.get("device_write_executed") is not False:raise MaintenanceModeMcpOAuthAcceptanceError("Maintenance-mode MCP confirmation failed.")
   phase="execution readback";r=await s.call_tool("execute_confirmed_v4_maintenance_mode_enable",{"authorization_ref":a});_ve(r.structured_content,r.is_error);execute_preview_state_file.unlink();ev=True
 try:c=await oauth.run_address_mcp_oauth_surface_acceptance(url,login_file,client_state_file,ca_file=ca_file,tool_session_callback=cb,required_tools=TOOLS)
 except oauth.AddressMcpOAuthSurfaceAcceptanceError as e:raise MaintenanceModeMcpOAuthAcceptanceError(str(e)) from None
 return {"contract":"fortipam_v4_maintenance_mode_mcp_oauth_acceptance_v1","oauth_metadata_verified":c["oauth_metadata_verified"],"mcp_initialized":c["mcp_initialized"],"maintenance_mode_tool_surface_complete":True,"maintenance_mode_preview_verified":pv,"maintenance_mode_execution_verified":ev,"device_tool_invoked":pv or ev,"device_write_executed":ev,"token_revoked":c["token_revoked"],"credential_values_returned":c["credential_values_returned"],"token_returned":False,"client_id_returned":False}
def _vp(x:Any,e:bool)->None:
 c=x.get("Current State") if isinstance(x,dict) else None;p=x.get("Proposed Changes") if isinstance(x,dict) else None;q=x.get("Expected State") if isinstance(x,dict) else None;r=x.get("preview_ref") if isinstance(x,dict) else None
 if(e or not isinstance(c,dict) or not isinstance(p,dict) or not isinstance(q,dict) or not isinstance(r,str) or not r.startswith(PREVIEW) or x.get("contract")!=WORKFLOW or x.get("device_write_executed") is not False or c.get("maintenance_mode_status")!="disable" or c.get("write_transport")!="strict_api_preflight_ssh_cli_fallback" or any(c.get(k) is not False for k in ("critical_process_effect_verified","reboot_requested","firmware_or_license_upload_requested","configuration_restore_requested","tpm_or_disk_encryption_changed")) or p.get("operation")!="enable_maintenance_mode_via_cli_fallback" or p.get("configuration_profile")!="enable-system-maintenance-mode-v1" or p.get("maintenance_mode_status")!="enable" or any(p.get(k) is not False for k in ("critical_process_effect_tested","reboot_requested","firmware_or_license_upload_requested","configuration_restore_requested","tpm_or_disk_encryption_changed","rest_write_attempted")) or q.get("maintenance_mode_status")!="enable" or any(q.get(k) is not False for k in ("critical_process_effect_verified","reboot_requested","firmware_or_license_upload_requested","configuration_restore_requested","tpm_or_disk_encryption_changed")) or q.get("readback_transport")!="strict_api_after_ssh_cli_write"):raise MaintenanceModeMcpOAuthAcceptanceError("Maintenance-mode C/P/E projection was invalid.")
def _ve(x:Any,e:bool)->None:
 if(e or not isinstance(x,dict) or x.get("contract")!=EXECUTION or x.get("outcome")!="succeeded" or x.get("verification")!="verified" or x.get("idempotent_replay") is not False or x.get("compensation")!="separate_maintenance_mode_disable_action_required" or x.get("maintenance_mode_status")!="enable" or any(x.get(k) is not False for k in ("critical_process_effect_verified","reboot_requested","firmware_or_license_upload_requested","configuration_restore_requested","tpm_or_disk_encryption_changed","raw_cli_returned"))):raise MaintenanceModeMcpOAuthAcceptanceError("Maintenance-mode execution result was invalid.")
def _write(p:Path,r:str)->None:
 if p.parent.is_symlink() or not p.parent.is_dir() or stat.S_IMODE(p.parent.stat().st_mode)&0o077 or p.exists() or p.is_symlink() or not r.startswith(PREVIEW):raise MaintenanceModeMcpOAuthAcceptanceError("Preview state reference is invalid.")
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(fd,json.dumps({"preview_ref":r}).encode());os.fsync(fd)
 finally:os.close(fd)
 p.chmod(0o600)
def _read(p:Path)->str:
 if p.is_symlink() or not p.is_file() or stat.S_IMODE(p.stat().st_mode)&0o077:raise MaintenanceModeMcpOAuthAcceptanceError("Preview state file is invalid.")
 try:r=json.loads(p.read_text()).get("preview_ref")
 except (OSError,json.JSONDecodeError,AttributeError) as e:raise MaintenanceModeMcpOAuthAcceptanceError("Preview state file is invalid.") from e
 if not isinstance(r,str) or not r.startswith(PREVIEW):raise MaintenanceModeMcpOAuthAcceptanceError("Preview state reference is invalid.")
 return r
def main()->None:
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--url",required=True);p.add_argument("--login-file",type=Path,required=True);p.add_argument("--client-state-file",type=Path,required=True);p.add_argument("--preview-state-file",type=Path);p.add_argument("--execute-preview-state-file",type=Path);p.add_argument("--ca-file",type=Path);a=p.parse_args();print(json.dumps(asyncio.run(run_maintenance_mode_mcp_oauth_acceptance(a.url,a.login_file,a.client_state_file,preview_state_file=a.preview_state_file,execute_preview_state_file=a.execute_preview_state_file,ca_file=a.ca_file)),sort_keys=True))
if __name__=="__main__":main()
