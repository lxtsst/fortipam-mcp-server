"""Signed durable pair provenance for recovery-only User recomposition.

One fixed protected local record; no key values, material acquisition, product
writes or authority renewal. Loading never reads current RADIUS configuration.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
from typing import Any

from v4_planning import M4ExecutionPlan, M4ExecutionAuthorization
from v4_planning.material_provider import MaterialLeaseRequest, MaterialProviderClass, MaterialPurpose

from .ldap_server_projection import _digest
from .m4_execution_store import PersistentM4ExecutionStateStore
from .radius_remote_user_contract import RadiusRemoteUserBinding, RadiusRemoteUserError
from .radius_remote_user_http_transport import FortiPamRadiusRemoteUserHttpTransport
from .radius_remote_user_owned_target import RadiusRemoteUserOwnedTarget
from .radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport, _Connection, _unique_pairs
from .radius_server_pair_m4_runtime import RadiusPairM4ExecutionBinding
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig

_NAME = "radius-target.handoff.json"
_CONTRACT = "fortipam-700-build29-radius-user-target-handoff-private-v1"
_DOMAIN = b"fortipam-radius-user-target-handoff-v1\x00"
_ERROR = "The private RADIUS target handoff is unavailable."
_FIELDS = {"contract", "user_parameters_digest", "radius_parameters_digest", "api_digest", "user_journal",
    "radius_journal", "original_store", "original_execution_digest", "ownership_digest", "execution"}


def _wire(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _signature(payload: dict[str, Any], key: bytes) -> str:
    if type(key) is not bytes or not 32 <= len(key) <= 4096:
        raise ValueError
    return hmac.new(key, _DOMAIN + _wire(payload), hashlib.sha256).hexdigest()


def _api(config: SecretMetadataHttpTransportConfig, serial: str) -> str:
    return _digest({"origin": config.base_url, "serial": serial, "ca": config.ca_file,
        "actor": hashlib.sha256(config.bearer_token.encode()).hexdigest()})


def _journal(path: Path, identity: tuple[int, int]) -> dict[str, object]:
    return {"path": str(path), "identity": list(identity)}


def _store(store: PersistentM4ExecutionStateStore) -> dict[str, str]:
    return {"path": str(store._path), "key_path": str(store._key_path),
        "key_digest": hashlib.sha256(store._key).hexdigest()}


def _ownership(target: RadiusRemoteUserOwnedTarget) -> str:
    t, e = target._target, target._execution
    claim, ack = t._ownership_records()
    created = t._read_state("created.json")
    t._record(created, {"claim_digest", "ack_record_digest", "parameters_digest", "state_digest"}, set())
    if (created["claim_digest"] != _digest(claim) or created["ack_record_digest"] != _digest(ack)
            or created["parameters_digest"] != target._binding.radius.parameters_digest
            or claim["request_digest"] != _digest(asdict(e.lease_request))
            or claim["current_digest"] != e.plan.expected_current_digest
            or claim["actor_digest"] != hashlib.sha256(t._config.bearer_token.encode()).hexdigest()):
        raise ValueError
    return _digest({"claim": claim, "ack": ack, "created": created})


def retain_radius_target_handoff(reader: FortiPamRadiusRemoteUserHttpTransport, *, authority_key: bytes) -> RadiusRemoteUserOwnedTarget:
    """Persist once after fresh original pair qualification and before any User POST."""
    try:
        if type(reader) is not FortiPamRadiusRemoteUserHttpTransport:
            raise ValueError
        reader._check()
        target = reader._target
        if target._recovery_only or target._handoff_digest is not None or authority_key == target._store._key:
            raise ValueError
        target._store.verify_ready()
        if not hmac.compare_digest(target._store._load_key(), target._store._key):
            raise ValueError
        with reader._locked(existing=True), target.hold():
            reader._namespace()
            if any(reader._exists(name) for name in ("create.claim.json", "create-ack.json", "created.json",
                    "delete.claim.json", "delete-ack.json", "deleted.json")):
                raise ValueError
            e, t = target._execution, target._target
            payload = {"contract": _CONTRACT, "user_parameters_digest": reader._binding.parameters_digest,
                "radius_parameters_digest": reader._binding.radius.parameters_digest,
                "api_digest": _api(reader._config, reader._serial),
                "user_journal": _journal(reader._directory, reader._directory_identity),
                "radius_journal": _journal(t._directory, t._directory_identity), "original_store": _store(target._store),
                "original_execution_digest": target._original_execution(), "ownership_digest": _ownership(target),
                "execution": {"plan": asdict(e.plan), "authorization": asdict(e.authorization),
                    "lease_request": asdict(e.lease_request), "policy_decision_digest": e.policy_decision_digest,
                    "scope_digest": e.scope_digest, "audience_digest": e.audience_digest}}
            # Normalize string enums before comparison with the retained JSON.
            packet = json.loads(_wire({"payload": payload, "signature": _signature(payload, authority_key)}))
            if len(_wire(packet)) > 8192:
                raise ValueError
            reader._write_once(_NAME, packet)
            if reader._read_state(_NAME) != packet:
                raise ValueError
            return RadiusRemoteUserOwnedTarget(reader._binding, t, e, target._store, handoff_digest=_digest(packet))
    except Exception:
        raise RadiusRemoteUserError(_ERROR) from None


@contextmanager
def _packet(directory: Path, *, name: str = _NAME) -> Iterator[tuple[dict[str, Any], tuple[int, int]]]:
    """Read only the fixed file under the existing owner-only journal lock."""
    if (name not in {_NAME, "radius-target.preparation.json"} or not isinstance(directory, Path)
            or not directory.is_absolute() or ".." in directory.parts):
        raise ValueError
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    lock = source = None
    try:
        for part in directory.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise ValueError
        lock = os.open("operation.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        FortiPamRadiusRemoteUserHttpTransport._file_info(lock)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        before = FortiPamRadiusRemoteUserHttpTransport._file_info(source)
        if not 0 < before.st_size <= 8192: raise ValueError
        raw = os.read(source, 8193)
        after = FortiPamRadiusRemoteUserHttpTransport._file_info(source)
        if (len(raw) != before.st_size or os.read(source, 1)
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError
        packet = json.loads(raw, object_pairs_hook=_unique_pairs)
        if type(packet) is not dict or set(packet) != {"payload", "signature"}:
            raise ValueError
        yield packet, (info.st_dev, info.st_ino)
    finally:
        if source is not None: os.close(source)
        if lock is not None: os.close(lock)
        os.close(descriptor)


def load_radius_target_handoff(config: SecretMetadataHttpTransportConfig, binding: RadiusRemoteUserBinding, *,
        user_state_directory: Path, radius_state_directory: Path, expected_serial: str,
        original_radius_store: PersistentM4ExecutionStateStore, authority_key: bytes,
        clock: Callable[[], int] | None = None,
        connection_factory: Callable[..., _Connection] | None = None) -> RadiusRemoteUserOwnedTarget:
    """Verify old signed metadata/ACK/M4 only; return a guard that cannot forward."""
    try:
        if (type(config) is not SecretMetadataHttpTransportConfig or type(binding) is not RadiusRemoteUserBinding
                or type(original_radius_store) is not PersistentM4ExecutionStateStore
                or authority_key == original_radius_store._key):
            raise ValueError
        with _packet(user_state_directory) as (packet, user_identity):
            payload = packet["payload"]
            if (type(payload) is not dict or set(payload) != _FIELDS or type(packet["signature"]) is not str
                    or not hmac.compare_digest(packet["signature"], _signature(payload, authority_key))
                    or payload["contract"] != _CONTRACT or payload["user_parameters_digest"] != binding.parameters_digest
                    or payload["radius_parameters_digest"] != binding.radius.parameters_digest
                    or payload["user_journal"] != _journal(user_state_directory, user_identity)
                    or payload["api_digest"] != _api(config, expected_serial)
                    or payload["original_store"] != _store(original_radius_store)):
                raise ValueError
            original_radius_store.verify_ready()
            if not hmac.compare_digest(original_radius_store._load_key(), original_radius_store._key):
                raise ValueError
            execution = payload["execution"]
            if type(execution) is not dict or set(execution) != {"plan", "authorization", "lease_request",
                    "policy_decision_digest", "scope_digest", "audience_digest"}:
                raise ValueError
            request = dict(execution["lease_request"])
            request["provider_class"] = MaterialProviderClass(request["provider_class"])
            request["purpose"] = MaterialPurpose(request["purpose"])
            e = RadiusPairM4ExecutionBinding(M4ExecutionPlan(**execution["plan"]),
                M4ExecutionAuthorization(**execution["authorization"]), binding.radius, MaterialLeaseRequest(**request),
                execution["policy_decision_digest"], execution["scope_digest"], execution["audience_digest"])
            transport = FortiPamRadiusPairHttpTransport(config, binding.radius, expected_serial=expected_serial,
                state_directory=radius_state_directory, clock=clock, connection_factory=connection_factory)
            if payload["radius_journal"] != _journal(radius_state_directory, transport._directory_identity):
                raise ValueError
            guard = RadiusRemoteUserOwnedTarget(binding, transport, e, original_radius_store,
                recovery_only=True, handoff_digest=_digest(packet))
            with transport._locked(existing=True):
                if (guard._original_execution() != payload["original_execution_digest"]
                        or _ownership(guard) != payload["ownership_digest"]):
                    raise ValueError
            return guard
    except Exception:
        raise RadiusRemoteUserError(_ERROR) from None
