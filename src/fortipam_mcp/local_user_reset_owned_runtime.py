"""Default-off normal-main composition from protected original-owned inputs.

The descriptor contains metadata/paths only. Existing central API and Owner
references resolve through their fixed loaders. No material is staged here,
no checkpoint process starts, and no device request occurs during construction.
The explicit VERIFY_LOGIN flag requires the matching v2 descriptor and already
staged v2 material; it cannot upgrade an existing v1 fixture binding.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from typing import Any

from v4_planning import M4ExecutionPlan,M4ExecutionAuthorization

from .ldap_server_runtime import _key,_read
from .local_user_reset_fixture_create import LocalUserResetFixtureCreateDraft
from .local_user_reset_fixture_custody import LocalResetFixtureAckCustody
from .local_user_reset_fixture_material import LocalResetInitialMaterialSource
from .local_user_reset_fixture_sources import LocalResetFixtureSources
from .local_user_reset_fixture_state import LocalResetFixtureStateReader
from .local_user_reset_owned_inspector import LocalResetFixtureOwnedInspector
from .local_user_reset_owned_material import LocalResetOwnedMaterialSource
from .local_user_reset_owned_mcp import LocalResetOwnedMcpAction,LocalResetOwnedMcpError
from .local_user_reset_policy_reader import FortiPamLocalUserResetPolicyReader
from .m4_execution_store import PersistentM4ExecutionStateStore
from .owner_collector_runtime import owner_login_provider
from .owner_session_metadata import OwnerSessionMetadataTransport
from .planning_checkpoint_sidecar import UnixPlanningCheckpointClient,UnixPlanningCheckpointClientSettings
from .secret_bulk_import_runtime import _M4PlanningCheckpoint
from .secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport,load_secret_metadata_http_transport_config,_zeroize_mutable
from .target_ssh_transport import TargetSshTransportConfig

PREFIX="FORTIPAM_MCP_V4_OWNED_RESET_"
CONTRACT="fortipam-build29-original-owned-reset-runtime/v1"
LOGIN_CONTRACT="fortipam-build29-original-owned-reset-login-runtime/v2"
_ERROR="The protected original-owned reset runtime is unavailable."
_FIELDS={"contract","original_directory","original_packet_file","original_witness_key_file","original_store_file",
    "original_store_key_file","original_checkpoint_store_ref","original_draft_file","initial_material_directory",
    "initial_witness_key_file","reset_material_directory","reset_witness_key_file","reset_store_file","reset_store_key_file",
    "reset_checkpoint_store_ref","checkpoint_socket","checkpoint_authority_ref","authority_key_file","expected_serial",
    "api_principal","ssh_host","ssh_port","ssh_known_hosts_file","ssh_timeout_seconds","environment_ref","scope_ref",
    "audience_ref","transport_digest"}


def _metadata(path: Path,fields: set[str],maximum: int=65536) -> dict[str,Any]:
    from .local_user_reset_projection import _object_spans
    from . import secret_bulk_import_metadata as m
    from .secret_metadata_http_transport import _json_value_end,_skip_json_space
    raw=_read(path,maximum)
    try:
        left=_skip_json_space(raw,0);right=_json_value_end(raw,left)
        if _skip_json_space(raw,right)!=len(raw):raise ValueError
        m._validate_json(raw,left,right,depth=0,budget=[100000]);spans=_object_spans(raw,left,right)
        if set(spans)!=fields:raise ValueError
        return {key:m._scalar(raw,span) for key,span in spans.items()}
    finally:_zeroize_mutable(raw)


def _path(value: object) -> Path:
    if type(value) is not str or not 0<len(value)<=4096:raise ValueError
    path=Path(value)
    if not path.is_absolute() or ".." in path.parts:raise ValueError
    return path


def build_local_reset_owned_candidate(environment: Mapping[str,str]) -> LocalResetOwnedMcpAction|None:
    enabled=environment.get(PREFIX+"ENABLED","false");gate=environment.get(PREFIX+"EXECUTION_ENABLED","false")
    login=environment.get(PREFIX+"VERIFY_LOGIN","false")
    if login not in {"true","false"} or enabled=="false" and login=="true":raise LocalResetOwnedMcpError(_ERROR)
    if enabled not in {"true","false"} or gate not in {"true","false"} or enabled=="false" and gate=="true":
        raise LocalResetOwnedMcpError(_ERROR)
    if enabled=="false":return None
    state=source=original=initial=inspector=material=None
    try:
        descriptor=_metadata(_path(environment[PREFIX+"DESCRIPTOR_FILE"]),_FIELDS)
        if descriptor["contract"]!=(LOGIN_CONTRACT if login=="true" else CONTRACT):raise ValueError
        checkpoint=UnixPlanningCheckpointClient(UnixPlanningCheckpointClientSettings(_path(descriptor["checkpoint_socket"]),
            descriptor["checkpoint_authority_ref"]))
        def store(prefix: str,*,read_only: bool=False) -> PersistentM4ExecutionStateStore:
            ref=descriptor[prefix+"_checkpoint_store_ref"]
            return PersistentM4ExecutionStateStore(_path(descriptor[prefix+"_store_file"]),
                _path(descriptor[prefix+"_store_key_file"]),read_only=read_only,
                monotonic_checkpoint=_M4PlanningCheckpoint(checkpoint,ref),checkpoint_store_ref=ref)
        original_store=store("original",read_only=True)
        raw=_read(_path(descriptor["original_packet_file"]),65536)
        try:
            packet=json.loads(raw)
            if type(packet) is not dict or set(packet)!={"pins","plan","authorization","vdom"}:raise ValueError
            plan=M4ExecutionPlan(**packet["plan"]);authorization=M4ExecutionAuthorization(**packet["authorization"])
        finally:_zeroize_mutable(raw)
        original=LocalResetFixtureAckCustody(directory=_path(descriptor["original_directory"]),
            packet_file=_path(descriptor["original_packet_file"]),witness_key_file=_path(descriptor["original_witness_key_file"]),
            plan=plan,authorization=authorization,store=original_store,expected_vdom="root")
        original.inspect_original_full_state();original.inspect_original_absence()
        record=_metadata(_path(descriptor["original_draft_file"]),{"username","access_profile","source_defaults_digest",
            "nonmaterial_request_digest","wire","response_vdom"})
        wire=record["wire"]
        if (type(wire) is not str or len(wire)>32768 or hashlib.sha256(wire.encode("ascii")).hexdigest()!=original._pins.body_digest
                or record["nonmaterial_request_digest"]!=original._pins.body_digest):raise ValueError
        draft=LocalUserResetFixtureCreateDraft(record["username"],record["access_profile"],record["source_defaults_digest"],
            record["nonmaterial_request_digest"],wire.encode("ascii"),record["response_vdom"])
        config=load_secret_metadata_http_transport_config(environment);provider=owner_login_provider(environment)
        if provider is None:raise ValueError
        username,password=provider()
        try:
            if type(descriptor["ssh_port"]) is not int or type(descriptor["ssh_timeout_seconds"]) not in (int,float):raise ValueError
            ssh=TargetSshTransportConfig(descriptor["ssh_host"],descriptor["ssh_port"],username,password,
                _path(descriptor["ssh_known_hosts_file"]),descriptor["ssh_timeout_seconds"])
        finally:del username,password
        state=LocalResetFixtureStateReader(config,draft=draft,api_principal=descriptor["api_principal"],
            serial_digest=original._pins.serial_digest,actor_context_digest=original._pins.actor_context_digest,
            material_directory=_path(descriptor["initial_material_directory"]))
        owner=OwnerSessionMetadataTransport(config,owner_name=ssh.username,credentials=provider,
            folder_path="owned-reset-readiness",secret_name="owned-reset-readiness",target_name="owned-reset-readiness",
            witness=FortiPamSecretMetadataHttpTransport(config))
        source=LocalResetFixtureSources(state_reader=state,owner=owner,ssh=ssh,expected_serial=descriptor["expected_serial"])
        policy=FortiPamLocalUserResetPolicyReader(config)
        initial=LocalResetInitialMaterialSource(source,policy,original_store,directory=_path(descriptor["initial_material_directory"]),
            witness_key_file=_path(descriptor["initial_witness_key_file"]))
        inspector=LocalResetFixtureOwnedInspector(source,original,initial)
        material=LocalResetOwnedMaterialSource(inspector,policy,store("reset"),directory=_path(descriptor["reset_material_directory"]),
            witness_key_file=_path(descriptor["reset_witness_key_file"]),execution_enabled=gate=="true",verify_login=login=="true")
        return LocalResetOwnedMcpAction(material,authority_key=_key(_path(descriptor["authority_key_file"])),
            environment_ref=descriptor["environment_ref"],scope_ref=descriptor["scope_ref"],audience_ref=descriptor["audience_ref"],
            transport_digest=descriptor["transport_digest"],execution_enabled=gate=="true")
    except Exception:
        for obj in (material,inspector,initial,original,source,state):
            if obj is not None:
                try:obj.close()
                except Exception:pass
        raise LocalResetOwnedMcpError(_ERROR) from None
