"""Owner-only startup composition for the fixed withdrawal candidate.

The manifest carries metadata and file references only. Continuity, invocation
and native claim keys are 64 hexadecimal characters (optional outer whitespace);
the workflow key is exactly 32 raw bytes, matching its existing store contract.
No login provider is invoked and no device connection is opened at startup.
"""
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .owner_collector_runtime import PREFIX as OWNER_PREFIX, owner_login_provider
from .secret_approval_build29_http_transport import _raw_members, _validate_ack_json
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space, _zeroize_mutable,
)
from .secret_request_approval_revoke_continuity import SecretRequestApprovalRevokeContinuityExpected, _decode
from .secret_request_approval_revoke_detail_contract import SecretRequestApprovalRevokeDetailBinding
from .secret_request_approval_revoke_http_transport import FortiPamSecretRequestApprovalRevokeHttpTransport
from .secret_request_approval_revoke_live_workflow import SecretRequestApprovalRevokeLiveWorkflow, _private_directory, _private_file
from .secret_request_approval_revoke_mcp_action import SecretRequestApprovalRevokeMcpAction
from .secret_request_approval_revoke_resolver import OwnerOnlySecretRequestApprovalRevokeResolver, _read
from .secret_request_create_invocation_witness import OwnerOnlySecretRequestCreateInvocationWitnessStore

PREFIX = "FORTIPAM_MCP_V4_SECRET_REQUEST_APPROVAL_REVOKE_700_"
CONTRACT = "fortipam-v4-secret-request-approval-revoke-startup-v1"
_UNAVAILABLE = "FortiPAM Request approval withdrawal startup is unavailable."
_PATH_KEYS = frozenset({"continuity_file", "invocation_witness_file", "create_claim_file", "parent_binding_file",
    "continuity_hmac_key_file", "invocation_witness_hmac_key_file", "native_claim_file",
    "native_claim_hmac_key_file", "workflow_database_file", "workflow_hmac_key_file"})
_PARENT_KEYS = frozenset({"environment_ref", "scope_ref", "secret_name", "folder_path", "folder_id", "template_name", "target_name"})
_SCHEMA = {
    "paths": _PATH_KEYS,
    "binding": frozenset({"request_id", "secret_id", "requester", "approval_profile_name", "original_reviewer", "source_serial"}),
    "original_parent": _PARENT_KEYS,
    "reviewer_mapping": frozenset({"original_reviewer", "allowed_requester_digest", "allowed_transport_digest"}),
    "transport": frozenset({"base_url", "timeout_seconds", "ca_file"}),
}


def _flag(environment: Mapping[str, str], name: str) -> bool:
    value = environment.get(PREFIX + name, "false")
    if type(value) is not str or value not in {"true", "false"}:
        raise ValueError
    return value == "true"


def _path(value: Any) -> Path:
    if type(value) is not str or not value or len(value) > 4096:
        raise ValueError
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError
    _private_directory(path.parent)
    if path.exists() or path.is_symlink():
        _private_file(path)
    return path


def _manifest(path: Path) -> dict[str, Any]:
    raw = _read(path, 32768)
    try:
        start = _skip_json_space(raw, 0)
        end = _json_value_end(raw, start)
        _validate_ack_json(raw, start, end)
        if raw[start] != 123:
            raise ValueError
        # Reject unknown/nested fields before decoding any values, including
        # credentials smuggled into otherwise valid metadata objects.
        seen: set[str] = set()
        for key, _, left, right, _ in _raw_members(raw, start, end):
            if key in seen or key not in set(_SCHEMA) | {"contract", "original_intent_ref"}:
                raise ValueError
            seen.add(key)
            if key in _SCHEMA:
                if raw[left] != 123:
                    raise ValueError
                children: set[str] = set()
                for name, _, a, _, _ in _raw_members(raw, left, right):
                    if name in children or name not in _SCHEMA[key] or raw[a] in (123, 91):
                        raise ValueError
                    children.add(name)
                if children != _SCHEMA[key]:
                    raise ValueError
            elif raw[left] != 34:
                raise ValueError
        if seen != set(_SCHEMA) | {"contract", "original_intent_ref"}:
            raise ValueError
        value = _decode(bytes(raw))
        if value["contract"] != CONTRACT:
            raise ValueError
        return value
    finally:
        _zeroize_mutable(raw)


def _key(path: Path, *, hexadecimal: bool) -> bytes:
    raw = _read(path, 129 if hexadecimal else 32)
    try:
        if hexadecimal:
            encoded = bytes(raw).strip()
            if len(encoded) != 64 or any(chr(c) not in "0123456789abcdefABCDEF" for c in encoded):
                raise ValueError
            return bytes.fromhex(encoded.decode("ascii"))
        if len(raw) != 32:
            raise ValueError
        return bytes(raw)
    finally:
        _zeroize_mutable(raw)


def build_secret_request_approval_revoke_candidate(
    environment: Mapping[str, str],
) -> SecretRequestApprovalRevokeMcpAction | None:
    """Build once from independently protected metadata; default reads no files."""
    try:
        enabled, execution = _flag(environment, "ENABLED"), _flag(environment, "EXECUTION_ENABLED")
        if not enabled:
            if execution:
                raise ValueError
            return None
        manifest_path = _path(environment[PREFIX + "STARTUP_MANIFEST_FILE"])
        manifest = _manifest(manifest_path)
        paths = {name: _path(value) for name, value in manifest["paths"].items()}
        login_path = _path(environment[OWNER_PREFIX + "LOGIN_ENV_FILE"])
        protected = [manifest_path, login_path, *paths.values()]
        config = manifest["transport"]
        if config["ca_file"] is not None:
            protected.append(_path(config["ca_file"]))
        if len(set(protected)) != len(protected):
            raise ValueError
        # SQLite may create sidecars; none may overwrite another protected input.
        database = paths["workflow_database_file"]
        if any(Path(str(database) + suffix) in protected for suffix in ("-wal", "-shm", "-journal")):
            raise ValueError
        keys = {name: _key(paths[name + "_hmac_key_file"], hexadecimal=name != "workflow")
                for name in ("continuity", "invocation_witness", "native_claim", "workflow")}
        if len(set(keys.values())) != 4:
            raise ValueError
        binding = SecretRequestApprovalRevokeDetailBinding(**manifest["binding"])
        reviewer = manifest["reviewer_mapping"]
        if reviewer["original_reviewer"] != binding.original_reviewer:
            raise ValueError
        invocation = OwnerOnlySecretRequestCreateInvocationWitnessStore(
            paths["invocation_witness_file"], keys["invocation_witness"]).load()
        parent = _read(paths["parent_binding_file"], 32768)
        try:
            start = _skip_json_space(parent, 0)
            end = _json_value_end(parent, start)
            _validate_ack_json(parent, start, end)
            if parent[start] != 123:
                raise ValueError
            # Existing original parent metadata only; reject material-valued
            # unknown fields before the generic JSON decoder can see them.
            parent_fields = {"contract", "version", "requester_digest", "environment_ref", "scope_ref",
                "approval_profile_object_ref", "approval_profile_ref", "approval_profile_name",
                "secret_approval_object_ref", "folder_path", "secret_name", "secret_id"}
            for name, _, left, _, _ in _raw_members(parent, start, end):
                if name not in parent_fields or parent[left] in (123, 91):
                    raise ValueError
            _decode(bytes(parent))
            expected = SecretRequestApprovalRevokeContinuityExpected(
                binding=binding, created_record=invocation.created_record, parent_binding_json=bytes(parent),
                requester_digest=invocation.requester_digest, transport_digest=invocation.transport_digest,
                **manifest["original_parent"])
        finally:
            _zeroize_mutable(parent)
        resolver = OwnerOnlySecretRequestApprovalRevokeResolver(
            continuity_path=paths["continuity_file"], invocation_path=paths["invocation_witness_file"],
            create_claim_path=paths["create_claim_file"], continuity_key=keys["continuity"],
            invocation_key=keys["invocation_witness"], expected=expected,
            intent_ref=manifest["original_intent_ref"])
        resolver.resolve()  # Includes the exact terminal BOUND claim before composition.
        credentials = owner_login_provider(environment)
        if credentials is None:
            raise ValueError
        parsed = urlsplit(config["base_url"])
        if parsed.username is not None or parsed.password is not None:
            raise ValueError
        if type(config["timeout_seconds"]) not in (int, float):
            raise ValueError
        transport = FortiPamSecretRequestApprovalRevokeHttpTransport(
            SecretMetadataHttpTransportConfig(bearer_token="unused-owner-session", **config),
            binding, credentials, claim_path=paths["native_claim_file"], hmac_key=keys["native_claim"],
            execution_enabled=execution)
        workflow = SecretRequestApprovalRevokeLiveWorkflow(
            database, paths["workflow_hmac_key_file"], transport, resolver,
            allowed_requester_digest=reviewer["allowed_requester_digest"],
            allowed_transport_digest=reviewer["allowed_transport_digest"], execution_enabled=execution)
        return SecretRequestApprovalRevokeMcpAction(workflow, execution_enabled=execution)
    except Exception:
        raise ValueError(_UNAVAILABLE) from None
