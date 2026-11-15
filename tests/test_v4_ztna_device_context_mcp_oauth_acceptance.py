from __future__ import annotations
import asyncio
from pathlib import Path
import pytest
from scripts import v4_ztna_device_context_mcp_oauth_acceptance as subject
from scripts.v4_ztna_device_context_mcp_oauth_acceptance import ZtnaDeviceContextMcpOAuthAcceptanceError,_validate
def test_only_categorical_readonly_diagnostic_projection_is_accepted()->None:
 x={"contract":"fortipam_v4_ztna_device_context_diagnostic_v1","execution_status":"succeeded","access_proxy_evidence":"complete","client_certificate_mode":"enabled","empty_certificate_action":"block","dynamic_endpoint_state":"present","wad_device_context_state":"present","first_failed_gate":"none","raw_cli_returned":False,"endpoint_value_returned":False,"access_proxy_reference_returned":False,"tag_value_returned":False,"identity_or_session_value_returned":False,"secret_launch_authorization_assessed":False,"access_policy_tag_assessed":False,"folder_or_secret_ztna_policy_assessed":False,"wad_debug_enabled":False};_validate(x,False);x["wad_debug_enabled"]=True
 with pytest.raises(ZtnaDeviceContextMcpOAuthAcceptanceError):_validate(x,False)

def test_private_ip_lab_flag_is_forwarded_to_shared_oauth_acceptance(monkeypatch:pytest.MonkeyPatch)->None:
 observed:dict[str,object]={}
 class Session:
  async def list_tools(self):
   return type("Tools",(),{"tools":[type("Tool",(),{"name":subject.TOOL})()]})()
  async def call_tool(self,*_args:object):
   return type("Result",(),{"structured_content":{"contract":subject.CONTRACT,"execution_status":"succeeded","access_proxy_evidence":"complete","client_certificate_mode":"enabled","empty_certificate_action":"block","dynamic_endpoint_state":"present","wad_device_context_state":"present","first_failed_gate":"none","raw_cli_returned":False,"endpoint_value_returned":False,"access_proxy_reference_returned":False,"tag_value_returned":False,"identity_or_session_value_returned":False,"secret_launch_authorization_assessed":False,"access_policy_tag_assessed":False,"folder_or_secret_ztna_policy_assessed":False,"wad_debug_enabled":False},"is_error":False})()
 async def fake_acceptance(*_args:object,**kwargs:object)->dict[str,object]:
  observed.update(kwargs)
  await kwargs["tool_session_callback"](Session())
  return {"oauth_metadata_verified":True,"mcp_initialized":True,"token_revoked":True,"credential_values_returned":False}
 monkeypatch.setattr(subject.oauth,"run_address_mcp_oauth_surface_acceptance",fake_acceptance)
 result=asyncio.run(subject.run_ztna_device_context_mcp_oauth_acceptance("http://192.0.2.10/path",Path("login"),Path("state"),allow_insecure_private_ip_lab=True))
 assert observed["allow_insecure_private_ip_lab"] is True
 assert result["ztna_device_context_read_verified"] is True
