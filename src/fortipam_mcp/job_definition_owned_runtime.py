"""Default-off normal startup with protected fixed Job sources and checkpoint."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
from pathlib import Path
from typing import Any

from v4_planning import canonical_digest
from v4_planning.models import require_digest, require_ref

from .job_definition_detail_reader import JobDefinitionDetailReader
from .job_definition_owned_mcp_action import JobDefinitionOwnedMcpAction
from .job_definition_owned_workflow import JobDefinitionOwnedWorkflow
from .job_definition_projection import JobDefinitionExpectation
from .job_definition_sources import JobDefinitionSources
from .jwt_rotation_runtime import _document
from .ldap_server_runtime import _path
from .m4_execution_store import PersistentM4ExecutionStateStore
from .owner_collector_runtime import owner_login_provider
from .owner_session_metadata import OwnerSessionMetadataTransport
from .planning_checkpoint_sidecar import UnixPlanningCheckpointClient, UnixPlanningCheckpointClientSettings
from .secret_bulk_import_runtime import _M4PlanningCheckpoint
from .secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport, load_secret_metadata_http_transport_config
from .target_ssh_transport import TargetSshTransportConfig

PREFIX = "FORTIPAM_MCP_V4_OWNED_JOB_700_"
CONTRACT = "fortipam-build29-owned-disabled-job-startup-v3"
SELECTED_SECRET_CONTRACT = "fortipam-build29-owned-disabled-job-startup-v4"
_ERROR = "The owned disabled Job startup is unavailable."
_FIELDS = {"contract", "phase", "source_file", "identity", "checkpoint"}
_SOURCE_FIELDS = {"candidate_name", "anchor_name", "requester_name", "secret_id", "serial", "body", "max_timeout",
    "ssh_host", "ssh_port", "known_hosts_file", "ssh_timeout_seconds"}


def build_job_definition_owned_candidate(environment: Mapping[str, str]) -> JobDefinitionOwnedMcpAction | None:
    try:
        env = dict(environment)
        flags = [env.get(PREFIX+k, "false") for k in ("ENABLED", "EXECUTION_ENABLED")]
        if any(type(v) is not str or v not in {"true", "false"} for v in flags):raise ValueError
        if flags[0] == "false":
            if flags[1] != "false":raise ValueError
            return None
        if any(k.startswith(PREFIX) and k.removeprefix(PREFIX) not in {"ENABLED", "EXECUTION_ENABLED", "STARTUP_MANIFEST_FILE"} for k in env):
            raise ValueError
        if any(env.get("FORTIPAM_MCP_V4_DISABLED_JOB_700_"+k,"false") != "false" for k in ("ENABLED", "EXECUTION_ENABLED")):
            raise ValueError
        path = _path(env[PREFIX+"STARTUP_MANIFEST_FILE"])
        manifest, fingerprint = _document(path)
        if (set(manifest) != _FIELDS or manifest["contract"] not in {CONTRACT,SELECTED_SECRET_CONTRACT} or manifest["phase"] not in {"create", "recover"}
                or type(manifest["identity"]) is not dict
                or set(manifest["identity"]) != {"environment_ref", "scope_ref", "audience_ref", "requester_digest", "transport_digest"}):
            raise ValueError
        for k,v in manifest["identity"].items():
            if k.endswith("_digest"):require_digest(v,"job_identity")
            else:require_ref(v,"job_scope")
        source_path = _path(manifest["source_file"])
        source, source_fingerprint = _document(source_path)
        retarget = manifest["contract"] == SELECTED_SECRET_CONTRACT
        if set(source) != _SOURCE_FIELDS | ({"source_secret_id"} if retarget else set()):raise ValueError
        if type(source["body"]) is not dict or type(source["secret_id"]) is not int or source["body"].get("secret")!=source["secret_id"]:raise ValueError
        if retarget and (type(source["source_secret_id"]) is not int or not 0<source["source_secret_id"]<=2147483647
                or source["source_secret_id"]==source["secret_id"]):raise ValueError
        known_hosts = _path(source["known_hosts_file"])
        known_fingerprint = hashlib.sha256(known_hosts.read_bytes()).hexdigest()
        cp = manifest["checkpoint"]
        if type(cp) is not dict or set(cp) != {"socket", "authority_ref", "create_store_ref", "recover_store_ref"}:raise ValueError
        socket = Path(cp["socket"])
        if not socket.is_absolute() or ".." in socket.parts:raise ValueError
        for k in ("authority_ref", "create_store_ref", "recover_store_ref"):require_ref(cp[k],"job_checkpoint")
        if cp["create_store_ref"] == cp["recover_store_ref"]:raise ValueError
        credentials = owner_login_provider(env)
        if credentials is None:raise ValueError
        root, phase = path.parent, manifest["phase"]
        binding_digest = canonical_digest({"source_file_digest":source_fingerprint,"identity":manifest["identity"],
            "checkpoint":cp, "known_hosts_digest":known_fingerprint})

        def guard() -> bool:
            try:
                return (_document(path)[1] == fingerprint and _document(source_path)[1] == source_fingerprint
                    and hashlib.sha256(known_hosts.read_bytes()).hexdigest() == known_fingerprint)
            except Exception:return False

        def factory() -> JobDefinitionOwnedWorkflow:
            sources = None
            try:
                if not guard():raise ValueError
                config = load_secret_metadata_http_transport_config(env)
                username, password = credentials()
                ssh = TargetSshTransportConfig(source["ssh_host"],source["ssh_port"],username,password,
                    known_hosts,source["ssh_timeout_seconds"])
                owner = OwnerSessionMetadataTransport(config,owner_name=username,credentials=credentials,
                    folder_path="job-live-source",secret_name="job-live-source",target_name="job-live-source",
                    witness=FortiPamSecretMetadataHttpTransport(config))
                def reader(name: str, *, anchor: bool = False) -> JobDefinitionDetailReader:
                    secret_id=source["source_secret_id"] if retarget and anchor else source["secret_id"]
                    body={**source["body"],"name":name}
                    if retarget and anchor:body["secret"]=secret_id
                    return JobDefinitionDetailReader(owner,expected_serial=source["serial"],
                        expected=JobDefinitionExpectation(name,source["requester_name"],secret_id,"echo BP008_JOB_OK"),
                        expected_create_body=body,expected_max_timeout=source["max_timeout"])
                sources = JobDefinitionSources(candidate=reader(source["candidate_name"]),anchor=reader(source["anchor_name"],anchor=True),ssh=ssh,
                    source_secret_id=source["source_secret_id"] if retarget else None)
                checkpoint = UnixPlanningCheckpointClient(UnixPlanningCheckpointClientSettings(socket,cp["authority_ref"]))
                def store(p: str, read_only: bool) -> PersistentM4ExecutionStateStore:
                    ref = cp[p+"_store_ref"]
                    return PersistentM4ExecutionStateStore(root/p/"execution.sqlite3",root/p/"execution.key",
                        read_only=read_only,monotonic_checkpoint=_M4PlanningCheckpoint(checkpoint,ref),checkpoint_store_ref=ref)
                return JobDefinitionOwnedWorkflow(sources,root=root,phase=phase,source_binding_digest=binding_digest,
                    identity=manifest["identity"],store_factory=store,source_guard=guard,execution_enabled=flags[1] == "true")
            except BaseException:
                if sources is not None:sources.close()
                raise
        return JobDefinitionOwnedMcpAction(factory,phase=phase,requester_digest=manifest["identity"]["requester_digest"],
            transport_digest=manifest["identity"]["transport_digest"],execution_enabled=flags[1] == "true")
    except Exception:
        raise ValueError(_ERROR) from None
