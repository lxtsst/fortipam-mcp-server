"""Persist pre-dispatch intent; qualify it only against original pair ACK/M4."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any
from v4_planning import M4ExecutionPlan, M4ExecutionAuthorization
from v4_planning.material_provider import MaterialLeaseRequest, MaterialProviderClass, MaterialPurpose
from .ldap_server_projection import _digest
from .m4_execution_store import PersistentM4ExecutionStateStore
from .radius_remote_user_contract import RadiusRemoteUserBinding
from .radius_remote_user_http_transport import FortiPamRadiusRemoteUserHttpTransport
from .radius_remote_user_owned_target import RadiusRemoteUserOwnedTarget
from .radius_remote_user_pair_handoff import _api, _journal, _store, _packet, _wire, _ownership
from .radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport
from .radius_server_pair_m4_runtime import RadiusPairM4ExecutionBinding
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig

NAME = "radius-target.preparation.json"
CONTRACT = "fortipam-700-build29-radius-user-preparation-private-v1"
_DOMAIN = b"fortipam-radius-user-preparation-v1\x00"
_ERROR = "The original RADIUS User preparation is unavailable."
_FIELDS = {"contract", "user_parameters_digest", "radius_parameters_digest", "api_digest", "user_journal",
    "radius_journal", "original_store", "user_stores", "user_authority_keys", "identity", "execution"}


def _signature(payload: dict[str, Any], key: bytes) -> str:
    if type(key) is not bytes or not 32 <= len(key) <= 4096: raise ValueError
    return hmac.new(key, _DOMAIN + _wire(payload), hashlib.sha256).hexdigest()


def retain_radius_user_preparation(reader: FortiPamRadiusRemoteUserHttpTransport, *, authority_key: bytes,
        user_stores: tuple[PersistentM4ExecutionStateStore, PersistentM4ExecutionStateStore],
        user_authority_keys: tuple[bytes, bytes], identity: dict[str, str]) -> str:
    """Fsync original intent before pair dispatch; never claim creation success."""
    try:
        if type(reader) is not FortiPamRadiusRemoteUserHttpTransport or authority_key != user_authority_keys[0]: raise ValueError
        reader._check(); target = reader._target
        if target._recovery_only or target._handoff_digest is not None: raise ValueError
        for store in (target._store, *user_stores):
            store.verify_ready()
            if store.claim_count != 0 or not hmac.compare_digest(store._load_key(), store._key): raise ValueError
        e, t = target._execution, target._target
        payload = {"contract": CONTRACT, "user_parameters_digest": reader._binding.parameters_digest,
            "radius_parameters_digest": reader._binding.radius.parameters_digest, "api_digest": _api(reader._config, reader._serial),
            "user_journal": _journal(reader._directory, reader._directory_identity),
            "radius_journal": _journal(t._directory, t._directory_identity), "original_store": _store(target._store),
            "user_stores": [_store(store) for store in user_stores],
            "user_authority_keys": [hashlib.sha256(key).hexdigest() for key in user_authority_keys], "identity": identity,
            "execution": {"plan": asdict(e.plan), "authorization": asdict(e.authorization),
                "lease_request": asdict(e.lease_request), "policy_decision_digest": e.policy_decision_digest,
                "scope_digest": e.scope_digest, "audience_digest": e.audience_digest}}
        packet = json.loads(_wire({"payload": payload, "signature": _signature(payload, authority_key)}))
        if len(_wire(packet)) > 8192: raise ValueError
        with reader._locked():
            if set(reader._directory.iterdir()) != {reader._directory / "operation.lock"}: raise ValueError
            reader._write_once(NAME, packet)
            if reader._read_state(NAME) != packet: raise ValueError
        return _digest(packet)
    except Exception:
        raise RuntimeError(_ERROR) from None


def load_radius_user_preparation(config: SecretMetadataHttpTransportConfig, binding: RadiusRemoteUserBinding, *,
        user_state_directory: Path, radius_state_directory: Path, expected_serial: str,
        original_radius_store: PersistentM4ExecutionStateStore,
        user_stores: tuple[PersistentM4ExecutionStateStore, PersistentM4ExecutionStateStore],
        user_authority_keys: tuple[bytes, bytes], identity: dict[str, str]) -> RadiusRemoteUserOwnedTarget:
    """Read signed original binding, then demand actual successful M4 and ACK."""
    try:
        with _packet(user_state_directory, name=NAME) as (packet, user_identity):
            p = packet["payload"]
            if (type(p) is not dict or set(p) != _FIELDS or type(packet["signature"]) is not str
                    or not hmac.compare_digest(packet["signature"], _signature(p, user_authority_keys[0]))
                    or p["contract"] != CONTRACT or p["user_parameters_digest"] != binding.parameters_digest
                    or p["radius_parameters_digest"] != binding.radius.parameters_digest
                    or p["api_digest"] != _api(config, expected_serial)
                    or p["user_journal"] != _journal(user_state_directory, user_identity)
                    or p["original_store"] != _store(original_radius_store)
                    or p["user_stores"] != [_store(store) for store in user_stores]
                    or p["user_authority_keys"] != [hashlib.sha256(key).hexdigest() for key in user_authority_keys]
                    or p["identity"] != identity): raise ValueError
            for store in (original_radius_store, *user_stores):
                store.verify_ready()
                if not hmac.compare_digest(store._load_key(), store._key): raise ValueError
            execution = p["execution"]
            if type(execution) is not dict or set(execution) != {"plan", "authorization", "lease_request",
                    "policy_decision_digest", "scope_digest", "audience_digest"}: raise ValueError
            request = dict(execution["lease_request"])
            request["provider_class"] = MaterialProviderClass(request["provider_class"])
            request["purpose"] = MaterialPurpose(request["purpose"])
            e = RadiusPairM4ExecutionBinding(M4ExecutionPlan(**execution["plan"]),
                M4ExecutionAuthorization(**execution["authorization"]), binding.radius, MaterialLeaseRequest(**request),
                execution["policy_decision_digest"], execution["scope_digest"], execution["audience_digest"])
            reader = FortiPamRadiusPairHttpTransport(config, binding.radius, expected_serial=expected_serial,
                state_directory=radius_state_directory)
            if p["radius_journal"] != _journal(radius_state_directory, reader._directory_identity): raise ValueError
            target = RadiusRemoteUserOwnedTarget(binding, reader, e, original_radius_store,
                recovery_only=True, preparation_digest=_digest(packet))
            with reader._locked(existing=True):
                target._original_execution(); _ownership(target)
            return target
    except Exception:
        raise RuntimeError(_ERROR) from None
