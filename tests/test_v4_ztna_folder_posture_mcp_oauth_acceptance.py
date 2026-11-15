from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from scripts import v4_ztna_folder_posture_mcp_oauth_acceptance as subject
from scripts.v4_ztna_folder_posture_mcp_oauth_acceptance import (
 ZtnaFolderPostureMcpOAuthAcceptanceError,_validate,
)
def test_only_categorical_readonly_folder_posture_is_accepted()->None:
 x={"contract":"fortipam_v4_ztna_folder_control_posture_v1","execution_status":"succeeded","folder_ztna_control":"explicit_override","folder_ztna_tag_assignment":"configured","folder_ztna_match_logic":"unresolved","folder_reference_returned":False,"tag_value_returned":False,"raw_cli_returned":False,"device_write_executed":False,"secret_override_assessed":False,"match_logic_assessed":False};_validate(x,False);x["tag_value_returned"]=True
 with pytest.raises(ZtnaFolderPostureMcpOAuthAcceptanceError):_validate(x,False)


def test_private_ip_lab_flag_is_forwarded_to_shared_oauth_acceptance(monkeypatch: pytest.MonkeyPatch)->None:
 observed:dict[str,object]={}
 class Session:
  async def list_tools(self):return type("Tools",(),{"tools":[type("Tool",(),{"name":subject.TOOL})()]})()
  async def call_tool(self,*_args:object):return type("Reply",(),{"structured_content":{"contract":"fortipam_v4_ztna_folder_control_posture_v1","execution_status":"succeeded","folder_ztna_control":"explicit_override","folder_ztna_tag_assignment":"configured","folder_ztna_match_logic":"unresolved","folder_reference_returned":False,"tag_value_returned":False,"raw_cli_returned":False,"device_write_executed":False,"secret_override_assessed":False,"match_logic_assessed":False},"is_error":False})()
 async def fake_acceptance(*_args:object,**kwargs:object)->dict[str,object]:
  observed.update(kwargs);await kwargs["tool_session_callback"](Session());return {"oauth_metadata_verified":True,"mcp_initialized":True,"token_revoked":True,"credential_values_returned":False}
 monkeypatch.setattr(subject.oauth,"run_address_mcp_oauth_surface_acceptance",fake_acceptance)
 result=asyncio.run(subject.run_ztna_folder_posture_mcp_oauth_acceptance("http://192.0.2.10/path",Path("login"),Path("state"),allow_insecure_private_ip_lab=True))
 assert observed["allow_insecure_private_ip_lab"] is True
 assert result["ztna_folder_posture_tool_surface_complete"] is True
