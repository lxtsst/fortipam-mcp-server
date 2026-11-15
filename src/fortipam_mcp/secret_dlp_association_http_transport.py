"""Private fixed build-29 Owner DLP PUT and same-instance verified restoration."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import hmac
from http.cookies import SimpleCookie
import json
import math
import os
from pathlib import Path
import re
import stat
from threading import Lock
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_metadata_reader import _validate_value
from .local_user_reset_projection import _object_spans
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_dlp_association_contract import (
    SecretDlpAssociationIdentity, SecretDlpAssociationInspection, SecretDlpAssociationReadback,
    fixed_log_only_sensor_profile, qualify_secret_dlp_association_inspection,
)
from .secret_metadata_http_transport import (
    COLLECTION_PATH, MAX_RESPONSE_BYTES, SecretMetadataHttpTransportConfig,
    _json_value_end, _skip_json_space, _ssl_context, _zeroize_mutable,
)

if TYPE_CHECKING:
    from .secret_dlp_opaque_carrier import SecretDlpOpaqueCarrier

_UNAVAILABLE = "The fixed Secret DLP association is unavailable."
_ACTOR = "/api/v2/monitor/web-ui/state"
_ROLE_FIELDS = "name|accprofile|status|remote-auth|wildcard"
_ACK_FIELDS = frozenset({"version", "build", "http_method", "http_status", "status", "path", "name",
                         "vdom", "serial", "revision", "old_revision", "revision_changed", "mkey", "action", "error"})
_READ_FIELDS = _ACK_FIELDS | {"results", "size", "matched_count", "limit_reached"}


class SecretDlpAssociationHttpTransportError(RuntimeError):
    """Stable categorical failure, with no private binding or response values."""


class SecretDlpDispatchPhase(str, Enum):
    IDLE = "idle"
    PREFLIGHT = "preflight"
    CURRENT_READ = "current_read"
    BODY_PREPARATION = "body_preparation"
    FINAL_READ = "final_read"
    CLAIM_RESERVATION = "claim_reservation"
    PUT = "put"
    ACK = "ack"
    AFTER_READ = "after_read"
    PRESERVATION = "preservation"
    LOGOUT = "logout"
    COMPLETE = "complete"


class SecretDlpQualification(str, Enum):
    UNKNOWN = "unknown"
    QUALIFIED = "qualified"
    REJECTED = "rejected"


class SecretDlpPreservationMatch(str, Enum):
    UNKNOWN = "unknown"
    MATCH = "match"
    MISMATCH = "mismatch"


@dataclass(frozen=True, slots=True)
class SecretDlpPreservationObservation:
    identity: SecretDlpPreservationMatch = SecretDlpPreservationMatch.UNKNOWN
    sensor_name: SecretDlpPreservationMatch = SecretDlpPreservationMatch.UNKNOWN
    actor_digest: SecretDlpPreservationMatch = SecretDlpPreservationMatch.UNKNOWN
    preservation_digest: SecretDlpPreservationMatch = SecretDlpPreservationMatch.UNKNOWN
    opaque_field_digest: SecretDlpPreservationMatch = SecretDlpPreservationMatch.UNKNOWN
    redacted_metadata_witness_digest: SecretDlpPreservationMatch = SecretDlpPreservationMatch.UNKNOWN
    sensor_digest: SecretDlpPreservationMatch = SecretDlpPreservationMatch.UNKNOWN
    native_sensor_json: SecretDlpPreservationMatch = SecretDlpPreservationMatch.UNKNOWN


@dataclass(frozen=True, slots=True)
class SecretDlpDispatchObservation:
    """Private diagnostics only; categories cannot grant dispatch or ownership."""

    phase: SecretDlpDispatchPhase = SecretDlpDispatchPhase.IDLE
    put_dispatch_attempted: bool = False
    ack_qualified: SecretDlpQualification = SecretDlpQualification.UNKNOWN
    after_read_qualified: SecretDlpQualification = SecretDlpQualification.UNKNOWN
    logout_verified: SecretDlpQualification = SecretDlpQualification.UNKNOWN
    proposed_state_match: SecretDlpPreservationMatch = SecretDlpPreservationMatch.UNKNOWN
    preservation: SecretDlpPreservationObservation = SecretDlpPreservationObservation()


@dataclass(frozen=True, slots=True, repr=False)
class SecretDlpAssociationHttpBinding:
    identity: SecretDlpAssociationIdentity
    owner_name: str
    expected_serial: str
    sensor_name: str

    def __post_init__(self) -> None:
        identity = self.identity
        if (type(identity) is not SecretDlpAssociationIdentity
                or any(type(v) is not int or not 0 < v <= 2_147_483_647 for v in (identity.id, identity.folder))
                or identity.template != "Unix Account (SSH Password)"
                or not _name(identity.target) or not _name(self.owner_name) or not _name(self.expected_serial)
                or not _name(identity.name) or re.fullmatch(r"mcp-v4-bp005-dlp-audit-[A-Za-z0-9][A-Za-z0-9._-]*", identity.name) is None):
            raise SecretDlpAssociationHttpTransportError(_UNAVAILABLE)
        fixed_log_only_sensor_profile(sensor_name=self.sensor_name)


@dataclass(frozen=True, slots=True, repr=False)
class _Ownership:
    baseline: SecretDlpAssociationInspection
    associated: SecretDlpAssociationInspection


class FortiPamSecretDlpAssociationHttpTransport:
    """Explicit concrete Owner/config binding; no default loader or generic writer."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, owner: OwnerSessionMetadataTransport,
                 binding: SecretDlpAssociationHttpBinding, *, claim_dir: Path) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                    or type(owner) is not OwnerSessionMetadataTransport
                    or type(binding) is not SecretDlpAssociationHttpBinding
                    or owner._config is not config or owner._owner_name != binding.owner_name
                    or owner._bound_secret_name != binding.identity.name or owner._client is not None):
                raise ValueError
            _ssl_context(config)
            self._config, self._owner, self._binding = config, owner, binding
            self._claim_dir = Path(claim_dir)
            self._directory_identity = self._check_directory()
            self._claim_key = _digest({"serial": binding.expected_serial, "secret_id": binding.identity.id})
            self._secret_path = f"{COLLECTION_PATH}/{binding.identity.id}"
            self._template_path = "/api/v2/cmdb/secret/template/" + quote(binding.identity.template, safe="")
            self._sensor_path = "/api/v2/cmdb/dlp/sensor/" + quote(binding.sensor_name, safe="")
            self._role_path = "/api/v2/cmdb/system/admin/" + quote(binding.owner_name, safe="") + "?format=" + quote(_ROLE_FIELDS, safe="")
            self._closed = False
            self._association_attempted = False
            self._restore_attempted = False
            self._lock = Lock()
            self._ownership: _Ownership | None = None
            self._dispatch_observation = SecretDlpDispatchObservation()
            from .secret_dlp_opaque_carrier import SecretDlpOpaqueBinding, SecretDlpOpaqueWitness
            self._witness = SecretDlpOpaqueWitness(SecretDlpOpaqueBinding(
                expected_secret_id=binding.identity.id, expected_folder_id=binding.identity.folder,
                expected_secret_name=binding.identity.name, expected_target=binding.identity.target,
                expected_serial=binding.expected_serial, expected_template=binding.identity.template,
            ))
        except Exception:
            raise SecretDlpAssociationHttpTransportError(_UNAVAILABLE) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._ownership = None
            self._witness.close()

    @property
    def dispatch_observation(self) -> SecretDlpDispatchObservation:
        """Read the last in-memory dispatch categories from the private helper."""
        with self._lock:
            return self._dispatch_observation

    def inspect_association(self) -> SecretDlpAssociationInspection:
        return self._inspect(restore=False)

    def inspect_owned_restore(self) -> SecretDlpAssociationInspection:
        return self._inspect(restore=True)

    def _inspect(self, *, restore: bool) -> SecretDlpAssociationInspection:
        with self._lock:
            try:
                self._available(restore)
                with self._owner.authenticated():
                    current, carrier = self._read()
                    try:
                        self._phase(current, restore)
                    finally:
                        carrier.close()
                if not self._owner.logout_verified:
                    raise ValueError
                return current
            except Exception:
                raise SecretDlpAssociationHttpTransportError(_UNAVAILABLE) from None

    def associate_and_readback(self, expected_state_digest: str, *, expires_at: float,
                               clock: Callable[[], float]) -> SecretDlpAssociationReadback:
        return self._dispatch(expected_state_digest, expires_at=expires_at, clock=clock, restore=False)

    def restore_and_readback(self, expected_state_digest: str, *, expires_at: float,
                             clock: Callable[[], float]) -> SecretDlpAssociationReadback:
        return self._dispatch(expected_state_digest, expires_at=expires_at, clock=clock, restore=True)

    def _dispatch(self, expected_state_digest: str, *, expires_at: float,
                  clock: Callable[[], float], restore: bool) -> SecretDlpAssociationReadback:
        with self._lock:
            carrier: SecretDlpOpaqueCarrier | None = None
            body, ack_raw = bytearray(), bytearray()
            authenticated = False
            try:
                self._available(restore)
                self._dispatch_observation = SecretDlpDispatchObservation(phase=SecretDlpDispatchPhase.PREFLIGHT)
                if not _hash(expected_state_digest):
                    raise ValueError
                _deadline(expires_at, clock)
                with self._owner.authenticated():
                    authenticated = True
                    self._dispatch_observation = replace(self._dispatch_observation, phase=SecretDlpDispatchPhase.CURRENT_READ)
                    before, carrier = self._read()
                    self._phase(before, restore)
                    if not hmac.compare_digest(before.state_digest, expected_state_digest):
                        raise ValueError
                    self._dispatch_observation = replace(self._dispatch_observation, phase=SecretDlpDispatchPhase.BODY_PREPARATION)
                    body = carrier.encode_association(
                        json.loads(before.native_sensor_json), expected_sensor_name=before.sensor_name,
                        expected_sensor_digest=before.sensor_digest,
                        expected_preservation_digest=before.preservation_digest,
                        expected_opaque_field_digest=before.opaque_field_digest, restore=restore,
                    )
                    csrf = self._csrf()
                    # Requalify every private source after body/client preparation.
                    self._dispatch_observation = replace(self._dispatch_observation, phase=SecretDlpDispatchPhase.FINAL_READ)
                    final, final_carrier = self._read()
                    try:
                        self._phase(final, restore)
                        if final != before:
                            raise ValueError
                    finally:
                        final_carrier.close()
                    _deadline(expires_at, clock)
                    self._dispatch_observation = replace(self._dispatch_observation, phase=SecretDlpDispatchPhase.CLAIM_RESERVATION)
                    self._reserve(restore, before)
                    # A claim is consumed even if this last check or dispatch fails.
                    _deadline(expires_at, clock)
                    ack_raw = self._exchange(self._secret_path, body=body, csrf=csrf,
                                             expires_at=expires_at, clock=clock)
                    self._dispatch_observation = replace(self._dispatch_observation, phase=SecretDlpDispatchPhase.ACK)
                    try:
                        self._ack(ack_raw)
                    except Exception:
                        self._dispatch_observation = replace(self._dispatch_observation, ack_qualified=SecretDlpQualification.REJECTED)
                        raise
                    self._dispatch_observation = replace(self._dispatch_observation,
                        ack_qualified=SecretDlpQualification.QUALIFIED, phase=SecretDlpDispatchPhase.AFTER_READ)
                    try:
                        after, after_carrier = self._read()
                    except Exception:
                        self._dispatch_observation = replace(self._dispatch_observation, after_read_qualified=SecretDlpQualification.REJECTED)
                        raise
                    self._dispatch_observation = replace(self._dispatch_observation,
                        after_read_qualified=SecretDlpQualification.QUALIFIED, phase=SecretDlpDispatchPhase.PRESERVATION)
                    try:
                        expected_phase = "baseline" if restore else "associated"
                        categories = SecretDlpPreservationObservation(**{
                            field: SecretDlpPreservationMatch.MATCH if getattr(before, field) == getattr(after, field)
                            else SecretDlpPreservationMatch.MISMATCH
                            for field in SecretDlpPreservationObservation.__dataclass_fields__
                        })
                        self._dispatch_observation = replace(self._dispatch_observation, preservation=categories,
                            proposed_state_match=SecretDlpPreservationMatch.MATCH if after.phase == expected_phase
                            else SecretDlpPreservationMatch.MISMATCH)
                        preserved = after.phase == expected_phase and _preserved(before, after)
                    finally:
                        after_carrier.close()
                    self._dispatch_observation = replace(self._dispatch_observation, phase=SecretDlpDispatchPhase.LOGOUT)
                result = SecretDlpAssociationReadback(True, self._owner.logout_verified, preserved, after)
                if result.logout_verified and preserved:
                    if restore:
                        assert self._ownership is not None
                        if after != self._ownership.baseline:
                            raise ValueError
                        self._ownership = None
                    else:
                        self._ownership = _Ownership(before, after)
                    self._dispatch_observation = replace(self._dispatch_observation, phase=SecretDlpDispatchPhase.COMPLETE)
                elif not preserved:
                    self._dispatch_observation = replace(self._dispatch_observation, phase=SecretDlpDispatchPhase.PRESERVATION)
                return result
            except Exception:
                raise SecretDlpAssociationHttpTransportError(_UNAVAILABLE) from None
            finally:
                if authenticated:
                    self._dispatch_observation = replace(self._dispatch_observation,
                        logout_verified=SecretDlpQualification.QUALIFIED if self._owner.logout_verified
                        else SecretDlpQualification.REJECTED)
                if carrier is not None:
                    carrier.close()
                _zeroize_mutable(body)
                _zeroize_mutable(ack_raw)

    def _read(self) -> tuple[SecretDlpAssociationInspection, SecretDlpOpaqueCarrier]:
        actor = self._actor()
        sensor_raw, secret_raw, template_raw = bytearray(), bytearray(), bytearray()
        carrier: SecretDlpOpaqueCarrier | None = None
        try:
            sensor_raw = self._exchange(self._sensor_path)
            sensor = self._decode(sensor_raw, "dlp", "sensor")
            secret_raw = self._exchange(self._secret_path)
            template_raw = self._exchange(self._template_path)
            carrier = self._witness.capture(secret_raw, template_raw)
            state = qualify_secret_dlp_association_inspection(
                carrier.projection, sensor, identity=self._binding.identity,
                sensor_name=self._binding.sensor_name, actor_digest=actor,
                redacted_metadata_witness_digest=carrier.redacted_metadata_witness_digest,
            )
            return state, carrier
        except Exception:
            if carrier is not None:
                carrier.close()
            raise
        finally:
            for raw in (sensor_raw, secret_raw, template_raw):
                _zeroize_mutable(raw)

    def _actor(self) -> str:
        actor_raw, role_raw = bytearray(), bytearray()
        try:
            actor_raw = self._exchange(_ACTOR)
            self._envelope(actor_raw, "web-ui", "state", monitor=True)
            actor_digest = _actor_context(actor_raw, expected_name=self._binding.owner_name)
            role_raw = self._exchange(self._role_path)
            role = self._decode(role_raw, "system", "admin")
            row = role["results"]
            if isinstance(row, list) and len(row) == 1:
                row = row[0]
            expected = {"name": self._binding.owner_name, "accprofile": "super_admin", "status": "enable",
                        "remote-auth": "disable", "wildcard": "disable"}
            if (not isinstance(row, dict) or not set(expected) <= set(row)
                    or not set(row) <= set(expected) | {"q_origin_key"}
                    or any(type(row[k]) is not type(v) or row[k] != v for k, v in expected.items())
                    or "q_origin_key" in row and (type(row["q_origin_key"]) is not str
                                                  or row["q_origin_key"] != self._binding.owner_name)):
                raise ValueError
            return _digest({"actor": actor_digest, "admin": row, "serial": self._binding.expected_serial,
                            "version": "v7.0.0", "build": 29})
        finally:
            _zeroize_mutable(actor_raw); _zeroize_mutable(role_raw)

    def _exchange(self, path: str, *, body: bytearray | None = None, csrf: str | None = None,
                  expires_at: float | None = None, clock: Callable[[], float] | None = None) -> bytearray:
        if (self._closed or self._owner._client is None or path not in {
                _ACTOR, self._role_path, self._sensor_path, self._secret_path, self._template_path}
                or self._owner._clock() >= self._owner._expires_at
                or body is not None and (path != self._secret_path or not csrf)):
            raise ValueError
        raw = bytearray()
        headers = {"Accept": "application/json", "User-Agent": "fortipam-bp005-secret-dlp/1"}
        kwargs: dict[str, Any] = {"headers": headers}
        if body is not None:
            headers.update({"Content-Type": "application/json", "X-CSRFTOKEN": str(csrf)})
            kwargs["content"] = bytes(body)
        try:
            if body is not None:
                if expires_at is None or clock is None:
                    raise ValueError
                _deadline(expires_at, clock)
                self._dispatch_observation = replace(self._dispatch_observation,
                    phase=SecretDlpDispatchPhase.PUT, put_dispatch_attempted=True)
            with self._owner._client.stream("GET" if body is None else "PUT", path, **kwargs) as response:
                if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes(chunk_size=4096):
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            return raw
        except Exception:
            _zeroize_mutable(raw)
            raise
        finally:
            kwargs.clear(); headers.clear()

    def _envelope(self, raw: bytearray, path: str, table: str, *, method: str = "GET",
                  monitor: bool = False) -> dict[str, tuple[int, int]]:
        start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            raise ValueError
        _validate_value(raw, start, end, depth=0)
        spans = _object_spans(raw, start, end)
        if not set(spans) <= (_READ_FIELDS if method == "GET" else _ACK_FIELDS):
            raise ValueError
        header = {k: json.loads(raw[left:right]) for k, (left, right) in spans.items() if k != "results"}
        expected: dict[str, object] = {"version": "v7.0.0", "build": 29, "http_method": method,
                                      "path": path, "name": table, "serial": self._binding.expected_serial}
        if not monitor or "http_status" in header:
            expected["http_status"] = 200
        if (any(type(header.get(k)) is not type(v) or header[k] != v for k, v in expected.items())
                or header.get("status") not in {"success", "OK"}
                or "vdom" in header and header["vdom"] != "root"
                or "action" in header and header["action"] != ""
                or "error" in header and header["error"] is not None and (
                    type(header["error"]) is not int or header["error"] != 0)):
            raise ValueError
        for key in ("revision", "old_revision"):
            if key in header and (type(header[key]) is not str or len(header[key]) > 255
                    or any(ord(c) < 32 or ord(c) == 127 for c in header[key])):
                raise ValueError
        for key in ("size", "matched_count"):
            if key in header and (type(header[key]) is not int or header[key] != 1):
                raise ValueError
        if "limit_reached" in header and header["limit_reached"] is not False:
            raise ValueError
        if "revision_changed" in header and type(header["revision_changed"]) is not bool:
            raise ValueError
        if method == "PUT" and "revision_changed" in header and header["revision_changed"] is not True:
            raise ValueError
        return spans

    def _decode(self, raw: bytearray, path: str, table: str) -> dict[str, Any]:
        self._envelope(raw, path, table)
        payload: dict[str, Any] = json.loads(raw)
        expected_mkey = self._binding.sensor_name if table == "sensor" else self._binding.owner_name
        if "mkey" in payload and (type(payload["mkey"]) is not str or payload["mkey"] != expected_mkey):
            raise ValueError
        return payload

    def _ack(self, raw: bytearray) -> None:
        spans = self._envelope(raw, "secret", "database", method="PUT")
        # Actual DLP PUT ACK qualification is pending; only this bound ID is accepted.
        key = json.loads(raw[slice(*spans["mkey"])])
        if type(key) is not int or key != self._binding.identity.id:
            raise ValueError

    def _csrf(self) -> str:
        cookie = self._owner._client.build_request("GET", self._config.base_url + self._secret_path).headers.get("cookie")
        if not cookie:
            raise ValueError
        jar: SimpleCookie = SimpleCookie(); jar.load(cookie)
        token = jar.get("ccsrftoken")
        if token is None or not token.value or any(ord(c) < 33 or ord(c) > 126 for c in token.value):
            raise ValueError
        return token.value

    def _phase(self, state: SecretDlpAssociationInspection, restore: bool) -> None:
        if restore:
            if self._ownership is None or state != self._ownership.associated:
                raise ValueError
        elif state.phase != "baseline":
            raise ValueError

    def _check_directory(self) -> tuple[int, int]:
        info = self._claim_dir.lstat()
        if (not self._claim_dir.is_absolute() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError
        return info.st_dev, info.st_ino

    def _claim_path(self, restore: bool) -> Path:
        return self._claim_dir / (self._claim_key + (".restore.claim" if restore else ".associate.claim"))

    def _available(self, restore: bool) -> None:
        if (self._closed or self._check_directory() != self._directory_identity
                or os.path.lexists(self._claim_path(restore)) or restore and self._ownership is None
                or (self._restore_attempted if restore else self._association_attempted)
                or not restore and (self._ownership is not None or os.path.lexists(self._claim_path(True)))):
            raise ValueError

    def _reserve(self, restore: bool, state: SecretDlpAssociationInspection) -> None:
        self._available(restore)
        directory = os.open(self._claim_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if ((info.st_dev, info.st_ino) != self._directory_identity or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            fd = os.open(self._claim_path(restore).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            if restore:
                self._restore_attempted = True
            else:
                self._association_attempted = True
            with os.fdopen(fd, "w") as file:
                json.dump({"contract": "secret-dlp-association-claim-v1", "state": "reserved",
                           "operation": "restore" if restore else "associate", "state_digest": state.state_digest}, file)
                file.flush(); os.fsync(file.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)


def _name(value: object) -> bool:
    return type(value) is str and 0 < len(value.encode()) <= 255 and all(ord(c) >= 32 and ord(c) != 127 for c in value)


def _hash(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _preserved(before: SecretDlpAssociationInspection, after: SecretDlpAssociationInspection) -> bool:
    return all(getattr(before, field) == getattr(after, field) for field in (
        "identity", "sensor_name", "actor_digest", "preservation_digest", "opaque_field_digest",
        "redacted_metadata_witness_digest", "sensor_digest", "native_sensor_json"))


def _deadline(expires_at: float, clock: Callable[[], float]) -> None:
    if (not callable(clock) or type(expires_at) not in {int, float} or not math.isfinite(expires_at)
            or not clock() < expires_at):
        raise ValueError
