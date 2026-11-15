from __future__ import annotations
import stat
import pytest
from scripts.v4_logging_disk_mcp_oauth_acceptance import LoggingDiskMcpOAuthAcceptanceError,_execution,_preview,_read,_write
def test_owner_only_state(tmp_path)->None:
    d=tmp_path/"state";d.mkdir(mode=0o700);d.chmod(0o700);p=d/"preview.json";_write(p,"logging-disk-preview-opaque");assert stat.S_IMODE(p.stat().st_mode)==0o600;assert _read(p)=="logging-disk-preview-opaque"
def test_projection_and_result_are_fixed()->None:
    unchanged={"remote_syslog_configuration_changed":False,"event_logging_configuration_changed":False,"disk_encryption_changed":False}
    p={"contract":"fortipam_v4_logging_disk_disable_workflow_v1","preview_ref":"logging-disk-preview-opaque","device_write_executed":False,"Current State":{"memory_log_status":"enable","disk_log_status":"enable","write_transport":"ssh_cli_fallback",**unchanged},"Proposed Changes":{"operation":"disable_disk_logging_via_cli_fallback","configuration_profile":"disable-disk-preserve-memory-logging-v1","memory_log_status":"enable","disk_log_status":"disable","rest_write_attempted":False,**unchanged},"Expected State":{"memory_log_status":"enable","disk_log_status":"disable","logging_effect_verified":False,"readback_transport":"ssh_cli",**unchanged}}
    _preview(p,False);p["Current State"]["disk_log_status"]="disable"
    with pytest.raises(LoggingDiskMcpOAuthAcceptanceError):_preview(p,False)
    r={"contract":"fortipam_v4_logging_disk_disable_execution_v1","outcome":"succeeded","verification":"verified","idempotent_replay":False,"compensation":"separate_logging_disk_enable_action_required","memory_log_status":"enable","disk_log_status":"disable","logging_effect_verified":False,"raw_cli_returned":False,**unchanged};_execution(r,False)
