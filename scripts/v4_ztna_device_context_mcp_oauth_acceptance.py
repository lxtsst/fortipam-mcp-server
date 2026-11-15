#!/usr/bin/env python3
"""Accept the read-only V4 ZTNA device-context OAuth/MCP diagnostic."""
from __future__ import annotations
import argparse, asyncio, json, sys
from pathlib import Path
from typing import Any
from mcp import ClientSession
ROOT=Path(__file__).resolve().parents[1]
SOURCE_ROOT=ROOT/"src"
for import_root in (str(SOURCE_ROOT),str(ROOT)):
 while import_root in sys.path:sys.path.remove(import_root)
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(SOURCE_ROOT))
from scripts import v4_address_mcp_oauth_surface_acceptance as oauth
TOOL="get_v4_ztna_device_context_diagnostic"; CONTRACT="fortipam_v4_ztna_device_context_diagnostic_v1"
class ZtnaDeviceContextMcpOAuthAcceptanceError(RuntimeError):pass
async def run_ztna_device_context_mcp_oauth_acceptance(url:str,login_file:Path,client_state_file:Path,*,ca_file:Path|None=None,allow_insecure_private_ip_lab:bool=False)->dict[str,object]:
 async def callback(s:ClientSession)->None:
  if TOOL not in {x.name for x in (await s.list_tools()).tools}:raise ZtnaDeviceContextMcpOAuthAcceptanceError("ZTNA device-context MCP Tool surface is incomplete.")
  r=await s.call_tool(TOOL,{});_validate(r.structured_content,r.is_error)
 try:c=await oauth.run_address_mcp_oauth_surface_acceptance(url,login_file,client_state_file,ca_file=ca_file,tool_session_callback=callback,required_tools=frozenset({TOOL}),allow_insecure_private_ip_lab=allow_insecure_private_ip_lab)
 except oauth.AddressMcpOAuthSurfaceAcceptanceError as e:raise ZtnaDeviceContextMcpOAuthAcceptanceError(str(e)) from None
 except BaseExceptionGroup as e:
  if any(isinstance(x,ZtnaDeviceContextMcpOAuthAcceptanceError) for x in e.exceptions):raise ZtnaDeviceContextMcpOAuthAcceptanceError("ZTNA device-context MCP diagnostic failed.") from None
  raise
 return {"contract":"fortipam_v4_ztna_device_context_mcp_oauth_acceptance_v1","oauth_metadata_verified":c["oauth_metadata_verified"],"mcp_initialized":c["mcp_initialized"],"ztna_device_context_tool_surface_complete":True,"ztna_device_context_read_verified":True,"device_write_executed":False,"token_revoked":c["token_revoked"],"credential_values_returned":c["credential_values_returned"],"token_returned":False,"client_id_returned":False}
def _validate(x:Any,err:bool)->None:
 if(err or not isinstance(x,dict) or x.get("contract")!=CONTRACT or x.get("execution_status")!="succeeded" or x.get("access_proxy_evidence") not in {"complete","partial","unknown"} or x.get("client_certificate_mode") not in {"enabled","disabled","unknown"} or x.get("empty_certificate_action") not in {"accept","block","unknown"} or x.get("dynamic_endpoint_state") not in {"present","absent","unknown"} or x.get("wad_device_context_state") not in {"present","absent","unknown"} or x.get("first_failed_gate") not in {"none","access_proxy_client_certificate","dynamic_endpoint","wad_device_context","unknown"} or any(x.get(k) is not False for k in ("raw_cli_returned","endpoint_value_returned","access_proxy_reference_returned","tag_value_returned","identity_or_session_value_returned","secret_launch_authorization_assessed","access_policy_tag_assessed","folder_or_secret_ztna_policy_assessed","wad_debug_enabled"))):raise ZtnaDeviceContextMcpOAuthAcceptanceError("ZTNA device-context diagnostic projection was invalid.")
def main()->None:
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--url",required=True);p.add_argument("--login-file",type=Path,required=True);p.add_argument("--client-state-file",type=Path,required=True);p.add_argument("--ca-file",type=Path);p.add_argument("--allow-insecure-private-ip-lab",action="store_true");a=p.parse_args()
 try:r=asyncio.run(run_ztna_device_context_mcp_oauth_acceptance(a.url,a.login_file,a.client_state_file,ca_file=a.ca_file,allow_insecure_private_ip_lab=a.allow_insecure_private_ip_lab))
 except ZtnaDeviceContextMcpOAuthAcceptanceError as e:raise SystemExit(str(e)) from None
 print(json.dumps(r,sort_keys=True))
if __name__=="__main__":main()
