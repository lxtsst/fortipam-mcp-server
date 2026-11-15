"""Default-off execution startup; original creation is inspected read-only."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from v4_planning.models import require_ref
from . import job_definition_owned_runtime as definition
from .job_execution_sources import JobExecutionSources
from .job_execution_owned_workflow import JobExecutionOwnedWorkflow
from .job_execution_owned_mcp_action import JobExecutionOwnedMcpAction
from .jwt_rotation_runtime import _document
from .ldap_server_runtime import _path
from .planning_checkpoint_sidecar import UnixPlanningCheckpointClient, UnixPlanningCheckpointClientSettings
from .secret_bulk_import_runtime import _M4PlanningCheckpoint
from .m4_execution_store import PersistentM4ExecutionStateStore

PREFIX = "FORTIPAM_MCP_V4_OWNED_JOB_EXECUTION_700_"
CONTRACT = "fortipam-build29-owned-job-execution-startup-v1"
_ERROR = "The owned Job execution startup is unavailable."


def build_job_execution_owned_candidate(environment: Mapping[str,str]) -> JobExecutionOwnedMcpAction | None:
    try:
        env=dict(environment)
        flags=[env.get(PREFIX+k,"false") for k in ("ENABLED","EXECUTION_ENABLED")]
        if any(type(v) is not str or v not in {"true","false"} for v in flags):raise ValueError
        if flags[0]=="false":
            if flags[1]!="false":raise ValueError
            return None
        if any(k.startswith(PREFIX) and k.removeprefix(PREFIX) not in {"ENABLED","EXECUTION_ENABLED","STARTUP_MANIFEST_FILE"} for k in env):raise ValueError
        for prefix in (definition.PREFIX,"FORTIPAM_MCP_V4_FIXED_JOB_ACTIVATION_700_"):
            if any(env.get(prefix+k,"false")!="false" for k in ("ENABLED","EXECUTION_ENABLED")):raise ValueError
        path=_path(env[PREFIX+"STARTUP_MANIFEST_FILE"]);manifest,fingerprint=_document(path)
        if (set(manifest)!={"contract","phase","original_manifest_file","target_file","checkpoint"}
                or manifest["contract"]!=CONTRACT or manifest["phase"] not in {"activate","observe","cleanup"}):raise ValueError
        if manifest["phase"]=="observe" and flags[1]!="false":raise ValueError
        original_path=_path(manifest["original_manifest_file"]);original,original_hash=_document(original_path)
        if original["contract"] not in {definition.CONTRACT,definition.SELECTED_SECRET_CONTRACT} or original["phase"]!="recover" or path.parent!=original_path.parent/"execution":raise ValueError
        target_path=_path(manifest["target_file"]);target,target_hash=_document(target_path)
        if set(target)!={"target_name","target_address","target_template","secret_template","target_digest","secret_target_digest","target_service_addresses_empty"} or target["target_service_addresses_empty"] is not True:raise ValueError
        checkpoint=manifest["checkpoint"]
        if type(checkpoint) is not dict or set(checkpoint)!={"socket","authority_ref","activate_store_ref","cleanup_store_ref"}:raise ValueError
        socket=Path(checkpoint["socket"])
        if not socket.is_absolute() or ".." in socket.parts:raise ValueError
        for key in ("authority_ref","activate_store_ref","cleanup_store_ref"):require_ref(checkpoint[key],"job_execution_checkpoint")
        if checkpoint["activate_store_ref"]==checkpoint["cleanup_store_ref"]:raise ValueError
        def guard() -> bool:
            try:return _document(path)[1]==fingerprint and _document(original_path)[1]==original_hash and _document(target_path)[1]==target_hash
            except Exception:return False
        def factory() -> JobExecutionOwnedWorkflow:
            owned=None
            try:
                if not guard():raise ValueError
                private={**env,definition.PREFIX+"ENABLED":"true",definition.PREFIX+"EXECUTION_ENABLED":"false",
                    definition.PREFIX+"STARTUP_MANIFEST_FILE":str(original_path)}
                action=definition.build_job_definition_owned_candidate(private)
                if action is None:raise ValueError
                owned=action._factory()
                sources=JobExecutionSources(owned,target)
                client=UnixPlanningCheckpointClient(UnixPlanningCheckpointClientSettings(socket,checkpoint["authority_ref"]))
                def store(phase: str, readonly: bool) -> PersistentM4ExecutionStateStore:
                    ref=checkpoint[phase+"_store_ref"]
                    return PersistentM4ExecutionStateStore(path.parent/phase/"execution.sqlite3",path.parent/phase/"execution.key",
                        monotonic_checkpoint=_M4PlanningCheckpoint(client,ref),checkpoint_store_ref=ref,read_only=readonly)
                return JobExecutionOwnedWorkflow(sources,phase=manifest["phase"],root=path.parent,store_factory=store,
                    source_guard=guard,execution_enabled=flags[1]=="true")
            except BaseException:
                if owned is not None:owned.close()
                raise
        identity=original["identity"]
        return JobExecutionOwnedMcpAction(factory,phase=manifest["phase"],requester_digest=identity["requester_digest"],
            transport_digest=identity["transport_digest"],execution_enabled=flags[1]=="true")
    except Exception:raise ValueError(_ERROR) from None
