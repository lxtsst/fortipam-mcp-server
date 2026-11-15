"""Default-off material-free startup using the original associated manifest."""
from __future__ import annotations

from collections.abc import Mapping
from .ldap_server_runtime import _path, _private_file
from .m4_execution_store import PersistentM4ExecutionStateStore
from .radius_remote_user_contract import RadiusRemoteUserBinding
from .radius_server_pair_contract import RadiusServerPairBinding
from .radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport
from .radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow
from .radius_remote_user_pair_handoff import load_radius_target_handoff
from .radius_remote_user_preparation import load_radius_user_preparation, NAME as PREPARATION_FILE
from .radius_remote_user_preparation_reader import RadiusRemoteUserPreparationReader
from .radius_remote_user_absence_guard import RadiusRemoteUserAbsenceGuard
from .radius_server_pair_recovery_workflow import RadiusServerPairRecoveryWorkflow
from .radius_remote_user_recovery_mcp_action import RadiusRemoteUserRecoveryMcpAction
from .radius_remote_user_lifecycle_runtime import _profile, _ROLES, PREFIX as FORWARD_PREFIX
from . import radius_server_pair_lifecycle_runtime as pair_runtime
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config

PREFIX = "FORTIPAM_MCP_V4_RADIUS_USER_RECOVERY_700_"
_ERROR = "FortiPAM RADIUS User recovery startup is unavailable."


def _flag(environment: Mapping[str, str], name: str) -> bool:
    value = environment.get(PREFIX + name, "false")
    if type(value) is not str or value not in {"true", "false"}: raise ValueError
    return value == "true"


def build_radius_remote_user_recovery_candidate(environment: Mapping[str, str]) -> RadiusRemoteUserRecoveryMcpAction | None:
    workflow: RadiusRemoteUserLiveWorkflow | RadiusRemoteUserPreparationReader | None = None
    pair_recovery = None
    guard = None
    try:
        environment = dict(environment)
        enabled, execute = _flag(environment, "ENABLED"), _flag(environment, "EXECUTION_ENABLED")
        if not enabled:
            if execute: raise ValueError
            return None
        if any(name.startswith(PREFIX) and name.removeprefix(PREFIX) not in {
                "ENABLED", "EXECUTION_ENABLED", "STARTUP_MANIFEST_FILE"} for name in environment): raise ValueError
        if any(environment.get(prefix + name, "false") != "false"
                for prefix in (FORWARD_PREFIX, pair_runtime.PREFIX)
                for name in ("ENABLED", "EXECUTION_ENABLED")):
            raise ValueError
        manifest_path = _path(environment[PREFIX + "STARTUP_MANIFEST_FILE"])
        manifest, paths, pair_manifest, pair_paths, keys, pair_keys, context = _profile(manifest_path)
        # No initializer may manufacture a missing namespace, ledger or authority.
        for role in _ROLES: _private_file(paths[role + "_database_file"])
        for role in pair_runtime._ROLES: _private_file(pair_paths[role + "_database_file"])
        for name in ("runtime.namespace.json", "operation.lock", "create-ack.json", "created.json"):
            _private_file(pair_paths["state_directory"] / name)
        user_directory = paths["user_state_directory"]
        _private_file(user_directory / "operation.lock")
        user_declarations = ("namespace.json", "radius-target.handoff.json", "user-create.runtime.json", "user-remove.runtime.json")
        complete = all((user_directory / name).exists() for name in user_declarations)
        for name in (*user_declarations, PREPARATION_FILE):
            path = user_directory / name
            if path.exists() or path.is_symlink(): _private_file(path)
        config = load_secret_metadata_http_transport_config(environment)
        radius = RadiusServerPairBinding(**pair_manifest["binding"])
        binding = RadiusRemoteUserBinding(radius=radius, **manifest["binding"])
        identity = pair_manifest["identity"]
        reader = FortiPamRadiusPairHttpTransport(config, radius, expected_serial=identity["expected_serial"],
            state_directory=pair_paths["state_directory"])
        pair_runtime._pin(reader, pair_manifest, pair_keys, context, existing_only=True)
        original_radius = PersistentM4ExecutionStateStore(pair_paths["create_database_file"],
            pair_paths["create_execution_key_file"], read_only=True)
        original_user = PersistentM4ExecutionStateStore(paths["user_create_database_file"],
            paths["user_create_execution_key_file"], read_only=True)
        # A pre-reservation packet (including an interrupted write) grants no User authority.
        if (user_directory / "user-create.authority.json").exists() and original_user.claim_count == 0:
            complete = False
        removal = PersistentM4ExecutionStateStore(paths["user_remove_database_file"], paths["user_remove_execution_key_file"], read_only=not complete)
        user_keys = (keys["user_create_authority_key_file"], keys["user_remove_authority_key_file"])
        scope_identity = {name: identity[name] for name in ("environment_ref", "audience_ref")}
        scope_identity.update(requester_digest=identity["allowed_requester_digest"], transport_digest=identity["allowed_transport_digest"],
            **manifest["identity"])
        target = None
        if (user_directory / PREPARATION_FILE).exists():
            target = load_radius_user_preparation(config, binding, user_state_directory=user_directory,
                radius_state_directory=pair_paths["state_directory"], expected_serial=identity["expected_serial"],
                original_radius_store=original_radius, user_stores=(original_user, removal),
                user_authority_keys=user_keys, identity=scope_identity)
        if (user_directory / "radius-target.handoff.json").exists():
            target = load_radius_target_handoff(config, binding, user_state_directory=user_directory,
                radius_state_directory=pair_paths["state_directory"], expected_serial=identity["expected_serial"],
                original_radius_store=original_radius, authority_key=user_keys[0])
        if target is None: raise ValueError
        if complete:
            workflow = RadiusRemoteUserLiveWorkflow(binding, config, target=target, state_directory=user_directory,
                operation="remove", execution_store=removal, original_create_store=original_user,
                authority_key=user_keys[1], original_create_authority_key=user_keys[0],
                environment_ref=identity["environment_ref"], scope_ref=manifest["identity"]["user_remove_scope_ref"],
                audience_ref=identity["audience_ref"], allowed_requester_digest=identity["allowed_requester_digest"],
                allowed_transport_digest=identity["allowed_transport_digest"], execution_enabled=execute, existing_only=True)
            if workflow._reader._read_state("user-create.runtime.json").get("scope_ref") != manifest["identity"]["user_create_scope_ref"]:
                raise ValueError
            workflow._cleanup_provenance()
        else:
            workflow = RadiusRemoteUserPreparationReader(binding, config, target=target, state_directory=user_directory,
                user_stores=(original_user, removal), user_keys=user_keys, identity=scope_identity)
        guard = RadiusRemoteUserAbsenceGuard(workflow)
        pair_store = PersistentM4ExecutionStateStore(pair_paths["recovery_database_file"], pair_paths["recovery_execution_key_file"])
        pair_recovery = RadiusServerPairRecoveryWorkflow(radius, config,
            expected_serial=identity["expected_serial"], state_directory=pair_paths["state_directory"],
            execution_store=pair_store, authority_key=pair_keys["recovery_authority_key_file"],
            environment_ref=identity["environment_ref"], scope_ref=identity["recovery_scope_ref"],
            audience_ref=identity["audience_ref"], allowed_requester_digest=identity["allowed_requester_digest"],
            allowed_transport_digest=identity["allowed_transport_digest"], execution_enabled=execute,
            user_absence_guard=guard)
        return RadiusRemoteUserRecoveryMcpAction(workflow, pair_recovery=pair_recovery, execution_enabled=execute)
    except Exception:
        if workflow is not None: workflow.close()
        if pair_recovery is not None: pair_recovery.close()
        elif guard is not None: guard.close()
        raise ValueError(_ERROR) from None
