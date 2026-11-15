from __future__ import annotations
import asyncio
from pathlib import Path
import stat
import pytest
from scripts import v4_ztna_wad_debug_mcp_oauth_acceptance as subject
from scripts.v4_ztna_wad_debug_mcp_oauth_acceptance import ZtnaWadDebugMcpOAuthAcceptanceError,_read_preview_ref,_validate_execution,_validate_preview,_write_preview_state
def test_preview_state_is_owner_only_and_prefix_bound(tmp_path)->None:
 d=tmp_path/"state";d.mkdir(mode=0o700);d.chmod(0o700);p=d/"preview.json";_write_preview_state(p,"ztna-wad-debug-preview-opaque");assert stat.S_IMODE(p.stat().st_mode)==0o600;assert _read_preview_ref(p)=="ztna-wad-debug-preview-opaque"
 with pytest.raises(ZtnaWadDebugMcpOAuthAcceptanceError):_write_preview_state(p,"invalid")
def test_cleanup_contract_is_exact()->None:
 x={"contract":"fortipam_v4_ztna_wad_debug_workflow_v1","preview_ref":"ztna-wad-debug-preview-opaque","device_write_executed":False,"Current State":{"global_debug_state":"disabled","raw_cli_returned":False,"identity_tag_target_secret_or_session_data_returned":False,"persistent_configuration_changed":False},"Proposed Changes":{"operation":"run_timeboxed_fixed_ztna_wad_debug_diagnostic","configuration_profile":"fixed-secret-gateway-svc-conn-timeboxed-v1","wad_debug_categories":"fixed_secret_gateway_svc_conn_only","global_debug_enabled_temporarily":True,"automatic_cleanup_required":True,"caller_controlled_cli":False,"endpoint_or_tag_input_accepted":False,"persistent_configuration_changed":False,"rest_write_attempted":False},"Expected State":{"global_debug_state":"disabled_after_capture","diagnostic_result":"categorical_device_context_tag_and_launch_evidence_only","raw_cli_returned":False,"identity_tag_target_secret_or_session_data_returned":False,"persistent_configuration_changed":False}}
 _validate_preview(x,False);r={"contract":"fortipam_v4_ztna_wad_debug_execution_v1","outcome":"succeeded","verification":"verified","idempotent_replay":False,"global_debug_cleanup_confirmed":True,"compensation":"automatic_diagnose_debug_disable_cleanup; reconcile_manually_if_cleanup_unknown","raw_cli_returned":False,"identity_tag_target_secret_or_session_data_returned":False,"persistent_configuration_changed":False};_validate_execution(r,False);r["global_debug_cleanup_confirmed"]=False
 with pytest.raises(ZtnaWadDebugMcpOAuthAcceptanceError):_validate_execution(r,False)

def test_private_ip_lab_flag_is_forwarded_to_shared_oauth_acceptance(monkeypatch: pytest.MonkeyPatch)->None:
 observed:dict[str,object]={}
 class Session:
  async def list_tools(self):return type("Tools",(),{"tools":[type("Tool",(),{"name":name})() for name in subject.TOOLS]})()
 async def fake_acceptance(*_args:object,**kwargs:object)->dict[str,object]:
  observed.update(kwargs);await kwargs["tool_session_callback"](Session());return {"oauth_metadata_verified":True,"mcp_initialized":True,"token_revoked":True,"credential_values_returned":False}
 monkeypatch.setattr(subject.oauth,"run_address_mcp_oauth_surface_acceptance",fake_acceptance)
 result=asyncio.run(subject.run_ztna_wad_debug_mcp_oauth_acceptance("http://192.0.2.10/path",Path("login"),Path("state"),allow_insecure_private_ip_lab=True))
 assert observed["allow_insecure_private_ip_lab"] is True
 assert result["ztna_wad_debug_tool_surface_complete"] is True
