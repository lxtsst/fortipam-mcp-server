from __future__ import annotations
import pytest
from scripts.v4_local_user_disable_mcp_oauth_acceptance import LocalUserDisableMcpOAuthAcceptanceError,_ve,_vp
def test_only_enabled_to_disabled_local_user_contract_is_accepted()->None:
 n="mcp-v4-user-disable";x={"contract":"fortipam_v4_local_user_disable_workflow_v1","preview_ref":"local-user-preview-opaque","device_write_executed":False,"Current State":{"requested_username":n,"user_exists":True,"status":"enable"},"Proposed Changes":{"operation":"disable_local_user","username":n},"Expected State":{"username_matches":True,"user_exists":True,"status":"disable"}};_vp(x,n,False)
 r={"contract":"fortipam_v4_local_user_disable_execution_v1","outcome":"succeeded","verification":"verified","idempotent_replay":False,"compensation":"not_requested","credentials_returned":False,"raw_cli_returned":False};_ve(r,False);r["credentials_returned"]=True
 with pytest.raises(LocalUserDisableMcpOAuthAcceptanceError):_ve(r,False)
