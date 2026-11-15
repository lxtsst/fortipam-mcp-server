"""Default-off startup and deferred protected public-key/Owner providers."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from v4_planning.models import require_ref

from .jwt_manual_key_contract import JwtManualCreatePlan, JwtManualPublicKey, _default_digest, _require_digest, _NAME
from .jwt_manual_key_owner_http import JwtManualKeyOwnerHttp, JwtManualKeyOwnerHttpConfig
from .jwt_manual_key_owner_mcp_action import JwtManualKeyOwnerMcpAction
from .jwt_manual_key_owner_workflow import JwtManualKeyOwnerWorkflow
from .jwt_manual_key_request_contract import JwtManualCreateRequest
from .ldap_server_runtime import _key, _path, _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .owner_collector_runtime import owner_login_provider, PREFIX as OWNER_PREFIX
from .secret_approval_build29_http_transport import _validate_ack_json
from .secret_metadata_http_transport import _skip_json_space, _json_value_end, _zeroize_mutable
from .secret_request_approval_revoke_detail_contract import _reject_raw_duplicates

PREFIX = "FORTIPAM_MCP_V4_JWT_OWNER_700_"
CONTRACT = "fortipam-build29-jwt-owner-startup-v1"
_ERROR = "FortiPAM Owner JWT startup is unavailable."
_KEYS = ("witness", "create.execution", "create.authority", "remove.execution", "remove.authority")
_BINDING = {"name", "nonce", "schema_digest", "defaults", "serial_digest", "public_key_digest"}
_IDENTITY = {"environment_ref", "scope_ref", "audience_ref"}


def _flag(environment: Mapping[str, str], suffix: str) -> bool:
    value = environment.get(PREFIX + suffix, "false")
    if type(value) is not str or value not in {"true", "false"}:
        raise ValueError
    return value == "true"


def _manifest(path: Path) -> tuple[dict[str, Any], str]:
    raw = _read(path, 16384)
    try:
        start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            raise ValueError
        _validate_ack_json(raw, start, end); _reject_raw_duplicates(raw, start, end)
        data = json.loads(raw)
        if (type(data) is not dict or set(data) != {"contract", "phase", "binding", "wire", "identity", "public_key_file"}
                or data["contract"] != CONTRACT or data["phase"] not in {"create", "remove"}
                or type(data["binding"]) is not dict or set(data["binding"]) != _BINDING
                or type(data["identity"]) is not dict or set(data["identity"]) != _IDENTITY
                or type(data["wire"]) is not dict or set(data["wire"]) != {f.name for f in fields(JwtManualKeyOwnerHttpConfig)}):
            raise ValueError
        binding = data["binding"]
        if type(binding["name"]) is not str or _NAME.fullmatch(binding["name"]) is None or len(binding["name"]) > 35:
            raise ValueError
        for name in _BINDING - {"name", "defaults"}:
            _require_digest(binding[name])
        _default_digest(binding["defaults"])
        for name in _IDENTITY:
            require_ref(data["identity"][name], name)
        return data, hashlib.sha256(raw).hexdigest()
    finally:
        _zeroize_mutable(raw)


def build_jwt_manual_key_owner_candidate(environment: Mapping[str, str]) -> JwtManualKeyOwnerMcpAction | None:
    """Prepare local bindings only; no login, key material or device IO here."""
    try:
        environment = dict(environment)
        enabled, execute = _flag(environment, "ENABLED"), _flag(environment, "EXECUTION_ENABLED")
        if not enabled:
            if execute:
                raise ValueError
            return None
        if any(k.startswith(PREFIX) and k.removeprefix(PREFIX) not in {
                "ENABLED", "EXECUTION_ENABLED", "STARTUP_MANIFEST_FILE"} for k in environment):
            raise ValueError
        path = _path(environment[PREFIX + "STARTUP_MANIFEST_FILE"])
        manifest, fingerprint = _manifest(path)
        config = JwtManualKeyOwnerHttpConfig(**manifest["wire"])
        credentials = owner_login_provider(environment)
        if credentials is None:
            raise ValueError
        root, phase = path.parent, manifest["phase"]
        directories = {name: _path(str(root / name), directory=True)
            for name in ("native", "create-authority", "remove-authority")}
        keys = {name: _path(str(root / (name + ".key"))) for name in _KEYS}
        if len({_key(p) for p in keys.values()}) != len(_KEYS):
            raise ValueError
        public_path = Path(manifest["public_key_file"])
        if not public_path.is_absolute() or ".." in public_path.parts:
            raise ValueError
        if phase == "create" and os.path.lexists(directories["native"] / "create.claim.json"):
            raise ValueError
        login_reference = {k: v for k, v in environment.items() if k.startswith(OWNER_PREFIX)}
        if config.credential_reference_digest != hashlib.sha256(json.dumps(login_reference,
                sort_keys=True, separators=(",", ":")).encode()).hexdigest():
            raise ValueError
        ca_path = _path(config.ca_file, central=True)
        ca_fingerprint = hashlib.sha256(ca_path.read_bytes()).hexdigest()

        def guard() -> bool:
            # Metadata and trust-root changes invalidate this exact candidate.
            try:
                return _manifest(path)[1] == fingerprint and hashlib.sha256(ca_path.read_bytes()).hexdigest() == ca_fingerprint
            except Exception:
                return False

        def factory() -> JwtManualKeyOwnerWorkflow:
            source = None
            request: JwtManualCreateRequest | None = None
            try:
                if not guard():
                    raise ValueError
                extra: dict[str, Any] = {}
                if phase == "create":
                    pem = _read(public_path, 2047)
                    try:
                        key = JwtManualPublicKey(bytes(pem))
                        binding = manifest["binding"]
                        if key.digest != binding["public_key_digest"]:
                            raise ValueError
                        plan = JwtManualCreatePlan(binding["name"], binding["nonce"], key, binding["defaults"],
                            schema_digest=binding["schema_digest"], serial_digest=binding["serial_digest"])
                        request = JwtManualCreateRequest(plan, binding["defaults"],
                            schema_digest=binding["schema_digest"], serial_digest=binding["serial_digest"])
                    finally:
                        _zeroize_mutable(pem)
                    source = JwtManualKeyOwnerHttp(config, request, credentials,
                        directory=directories["native"], witness_key_file=keys["witness"],
                        source_guard=guard, execution_enabled=execute)
                else:
                    source = JwtManualKeyOwnerHttp.from_original_creation(config, credentials,
                        directory=directories["native"], witness_key_file=keys["witness"],
                        source_guard=guard, execution_enabled=execute)
                    binding = manifest["binding"]
                    if (source._request._name != binding["name"]
                            or source._request.schema_digest != binding["schema_digest"]
                            or source._request.serial_digest != binding["serial_digest"]
                            or source._request.defaults_digest != _default_digest(binding["defaults"])):
                        raise ValueError
                    extra = {"creation_store": PersistentM4ExecutionStateStore(root / "create.sqlite3",
                        keys["create.execution"], read_only=True),
                        "creation_authority_directory": directories["create-authority"],
                        "creation_authority_key_file": keys["create.authority"]}
                store = PersistentM4ExecutionStateStore(root / (phase + ".sqlite3"), keys[phase + ".execution"])
                workflow = JwtManualKeyOwnerWorkflow(source, store, phase=phase,
                    directory=directories[phase + "-authority"], authority_key_file=keys[phase + ".authority"],
                    **manifest["identity"], execution_enabled=execute, source_guard=guard, **extra)
                # Qualification of original ownership precedes any product IO.
                workflow._original_creation()
                source.__enter__()
                return workflow
            except BaseException:
                if source is not None:
                    source.close()
                elif request is not None:
                    request.close()
                raise

        return JwtManualKeyOwnerMcpAction(factory, phase=phase, requester_digest=config.requester_digest,
            transport_digest=config.transport_digest, execution_enabled=execute)
    except Exception:
        raise ValueError(_ERROR) from None
