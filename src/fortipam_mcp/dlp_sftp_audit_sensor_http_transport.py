"""Fixed build29 Web SFTP log-only Sensor POST and complete native readback.

Only an explicitly bound process may construct this transport. It has no
environment loader and never accepts caller-selected filters or protocols.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re
import threading
from typing import Any, Literal, Protocol, TYPE_CHECKING
from urllib.parse import quote

from .dlp_sensor_delete_http_transport import (
    COLLECTION_PATH, MAX_RESPONSE_BYTES, DlpSensorDeleteHttpTransportConfig,
    DlpSensorDeleteInspection, _record, _ssl_context,
)
from .dlp_sensor_ssh_transport import (
    DlpRegexpSensorInspection, DlpRegexpSensorReadback, _sftp_audit_sensor_name,
)
from .secret_dlp_association_contract import (
    FILTER_NAME, REGEXP_SENTINEL, fixed_log_only_sensor_digest, fixed_log_only_sensor_profile,
)
from .secret_dlp_dependency_ssh_reader import DlpDependencyInspection
if TYPE_CHECKING:
    from .dlp_api_actor_guard import DlpApiActorEvidence, DlpApiActorGuard

_UNAVAILABLE = "FortiPAM V4 Web SFTP audit Sensor transport is unavailable."
_ACK_FIELDS = frozenset({
    "version", "build", "http_method", "http_status", "status", "path", "name", "vdom",
    "serial", "revision", "old_revision", "revision_changed", "mkey", "action", "error",
})


class DlpSftpAuditSensorHttpTransportError(RuntimeError):
    """Stable failure without selectors, credentials, or raw responses."""


class DlpSftpAuditSensorSshReader(Protocol):
    """The existing pinned finite-CLI presence reader, without CLI writes."""

    def inspect_sftp_audit_sensor(self, sensor_name: str) -> DlpRegexpSensorInspection: ...


class DlpSftpAuditSensorDependencyObserver(Protocol):
    """Fresh full native columns qualified by their compiled source reader."""

    def inspect(self, sensor_name: str) -> DlpDependencyInspection: ...


@dataclass(frozen=True, slots=True)
class DlpSftpAuditSensorInspection(DlpRegexpSensorInspection):
    """Private pinned identity and fixed-profile current-state digest."""

    source_digest: str


@dataclass(frozen=True, slots=True)
class DlpSftpAuditSensorReadback(DlpRegexpSensorReadback):
    """All native fields and exact filter count must qualify together."""

    native_defaults_match: bool

    @property
    def verified(self) -> bool:
        return super(DlpSftpAuditSensorReadback, self).verified and self.native_defaults_match


@dataclass(frozen=True, slots=True, repr=False)
class _CreationOwnership:
    sensor_name: str
    device_serial: str
    native_digest: str
    canonical_digest: str
    actor_digest: str


@dataclass(frozen=True, slots=True)
class DlpSftpAuditSensorDeleteInspection(DlpSensorDeleteInspection):
    """Complete native profile and dependency observation bound to ownership."""

    dependency_digest: str
    secret_object_count: int
    policy_object_count: int
    actor_digest: str


@dataclass(frozen=True, slots=True)
class DlpSftpAuditSensorDeleteReadback:
    """Independent pinned REST and finite-CLI absence after one DELETE."""

    api_absent: bool
    ssh_absent: bool

    @property
    def verified(self) -> bool:
        return self.api_absent and self.ssh_absent


class FortiPamDlpSftpAuditSensorHttpTransport:
    """Create the one absent privately bound Sensor once over verified TLS."""

    def __init__(
        self,
        config: DlpSensorDeleteHttpTransportConfig,
        ssh_reader: DlpSftpAuditSensorSshReader,
        *,
        sensor_name: str,
        expected_serial: str,
        client_factory: Callable[..., Any] | None = None,
        dependency_observer: DlpSftpAuditSensorDependencyObserver | None = None,
        actor_guard: DlpApiActorGuard | None = None,
    ) -> None:
        if (not isinstance(config, DlpSensorDeleteHttpTransportConfig)
                or not isinstance(expected_serial, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", expected_serial) is None):
            raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
        try:
            self._sensor_name = _sftp_audit_sensor_name(sensor_name)
        except Exception:
            raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE) from None
        self._config = config
        self._ssh_reader = ssh_reader
        self._expected_serial = expected_serial
        self._client_factory = client_factory
        self._dependency_observer = dependency_observer
        self._actor_guard = actor_guard
        self._prepared = False
        self._prepared_actor_digest: str | None = None
        self._attempted = False
        self._ownership: _CreationOwnership | None = None
        self._delete_attempted = False
        self._lock = threading.RLock()

    def inspect_sftp_sensor(self, sensor_name: str) -> DlpSftpAuditSensorInspection:
        """Prove exact REST/SSH presence agreement on the pinned appliance."""

        with self._lock:
            self._require_binding(sensor_name)
            if self._attempted:
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            actor = self._observe_actor()
            status, payload = self._request("GET", self._detail_path(), None)
            record = _record(payload)
            if status not in {200, 404} or (status == 200 and (
                    record is None or record.get("name") != self._sensor_name)):
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            exists = status == 200
            ssh = self._ssh_reader.inspect_sftp_audit_sensor(self._sensor_name)
            if (not isinstance(ssh, DlpRegexpSensorInspection)
                    or type(ssh.sensor_name_exists) is not bool
                    or ssh.sensor_name_exists != exists):
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            self._prepared = not exists
            self._prepared_actor_digest = actor.evidence_digest if not exists else None
            digest = hashlib.sha256(json.dumps(
                {"serial": self._expected_serial, "build": 29,
                 "version": "v7.0.0", "sensor_name": self._sensor_name,
                 "exists": exists, "fixed_profile": _body(self._sensor_name),
                 "actor_digest": actor.evidence_digest},
                sort_keys=True, separators=(",", ":"),
            ).encode("ascii")).hexdigest()
            return DlpSftpAuditSensorInspection(exists, digest)

    def create_sftp_and_readback(
        self, sensor_name: str, *, expires_at: int, clock: Callable[[], int],
    ) -> DlpSftpAuditSensorReadback:
        """Final absence read, one POST attempt, and complete fixed readback."""

        with self._lock:
            self._require_binding(sensor_name)
            if (not self._prepared or self._attempted or type(expires_at) is not int
                    or not callable(clock) or clock() >= expires_at):
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            if self.inspect_sftp_sensor(sensor_name).sensor_name_exists:
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            if clock() >= expires_at:
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            self._attempted = True
            status, _ = self._request(
                "POST", COLLECTION_PATH, _body(self._sensor_name),
                deadline=(expires_at, clock),
            )
            if status != 200:
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            status, payload = self._request("GET", self._detail_path(), None)
            record = _record(payload)
            if status != 200 or record is None:
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            readback = _readback(payload, self._sensor_name)
            if readback.verified:
                actor_digest = self._prepared_actor_digest
                if not isinstance(actor_digest, str) or not _digest(actor_digest):
                    raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
                self._ownership = _CreationOwnership(
                    self._sensor_name, self._expected_serial, _native_digest(record),
                    fixed_log_only_sensor_digest(payload, expected_sensor_name=self._sensor_name),
                    actor_digest,
                )
            return readback

    def inspect_owned_sftp_delete_target(self) -> DlpSftpAuditSensorDeleteInspection:
        """Reject unknown ownership or any incomplete global dependency source."""

        try:
            return self._inspect_owned_sftp_delete_target()
        except Exception:
            raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE) from None

    def _inspect_owned_sftp_delete_target(self) -> DlpSftpAuditSensorDeleteInspection:

        with self._lock:
            ownership = self._require_ownership()
            if self._delete_attempted or self._dependency_observer is None:
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            actor = self._observe_actor()
            if not hmac.compare_digest(actor.evidence_digest, ownership.actor_digest):
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            status, payload = self._request("GET", self._detail_path(), None)
            record = _record(payload)
            if (status != 200 or record is None
                    or not hmac.compare_digest(_native_digest(record), ownership.native_digest)
                    or not hmac.compare_digest(fixed_log_only_sensor_digest(
                        payload, expected_sensor_name=self._sensor_name), ownership.canonical_digest)):
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            ssh = self._ssh_reader.inspect_sftp_audit_sensor(self._sensor_name)
            if (not isinstance(ssh, DlpRegexpSensorInspection)
                    or ssh.sensor_name_exists is not True):
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            observation = self._dependency_observer.inspect(self._sensor_name)
            if (not isinstance(observation, DlpDependencyInspection)
                    or observation.sensor_name != self._sensor_name
                    or observation.device_serial != self._expected_serial
                    or observation.version != "v7.0.0" or type(observation.build) is not int
                    or observation.build != 29 or not _digest(observation.evidence_digest)
                    or any(type(value) is not int or value < 0 for value in (
                        observation.secret_object_count, observation.policy_object_count,
                        observation.secret_reference_count, observation.policy_reference_count))
                    or observation.secret_reference_count > observation.secret_object_count
                    or observation.policy_reference_count > observation.policy_object_count):
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            return DlpSftpAuditSensorDeleteInspection(
                exists=True,
                eligible_fixed_sensor=(observation.secret_reference_count == 0
                                       and observation.policy_reference_count == 0),
                secret_reference_count=observation.secret_reference_count,
                policy_reference_count=observation.policy_reference_count,
                target_digest=ownership.native_digest,
                dependency_digest=observation.evidence_digest,
                secret_object_count=observation.secret_object_count,
                policy_object_count=observation.policy_object_count,
                actor_digest=actor.evidence_digest,
            )

    def delete_owned_sftp_and_readback(
        self, *, expected_target_digest: str, expected_state_digest: str,
        expires_at: int, clock: Callable[[], int],
    ) -> DlpSftpAuditSensorDeleteReadback:
        """Fresh exact ownership/dependencies, one DELETE, dual absence readback."""

        with self._lock:
            ownership = self._require_ownership()
            if (self._delete_attempted or not _digest(expected_target_digest)
                    or not _digest(expected_state_digest) or type(expires_at) is not int
                    or not callable(clock) or clock() >= expires_at
                    or not hmac.compare_digest(expected_target_digest, ownership.native_digest)):
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            current = self.inspect_owned_sftp_delete_target()
            if (not current.eligible_fixed_sensor
                    or not hmac.compare_digest(_recovery_inspection_digest(current), expected_state_digest)
                    or clock() >= expires_at):
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            self._delete_attempted = True
            self._request("DELETE", self._detail_path(), None, deadline=(expires_at, clock))
            status, _ = self._request("GET", self._detail_path(), None)
            ssh = self._ssh_reader.inspect_sftp_audit_sensor(self._sensor_name)
            if not isinstance(ssh, DlpRegexpSensorInspection) or type(ssh.sensor_name_exists) is not bool:
                raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
            readback = DlpSftpAuditSensorDeleteReadback(status == 404, not ssh.sensor_name_exists)
            if readback.verified:
                self._ownership = None
            return readback

    def _require_ownership(self) -> _CreationOwnership:
        ownership = self._ownership
        if (ownership is None or ownership.sensor_name != self._sensor_name
                or ownership.device_serial != self._expected_serial):
            raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)
        return ownership

    def _observe_actor(self) -> DlpApiActorEvidence:
        try:
            from .dlp_api_actor_guard import DlpApiActorEvidence, DlpApiActorGuard

            guard = self._actor_guard
            if not isinstance(guard, DlpApiActorGuard) or type(guard) is not DlpApiActorGuard:
                raise ValueError("concrete actor guard required")
            guard.require_same_config(self._config)
            evidence = guard.observe()
            if (not isinstance(evidence, DlpApiActorEvidence)
                    or evidence.device_serial != self._expected_serial
                    or evidence.version != "v7.0.0" or type(evidence.build) is not int
                    or evidence.build != 29 or not _digest(evidence.role_projection_digest)
                    or not _digest(evidence.evidence_digest)):
                raise ValueError("actor evidence differs")
            return evidence
        except Exception:
            raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE) from None

    def _require_binding(self, sensor_name: str) -> None:
        if sensor_name != self._sensor_name:
            raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE)

    def _detail_path(self) -> str:
        return f"{COLLECTION_PATH}/{quote(self._sensor_name, safe='')}"

    def _request(
        self, method: Literal["GET", "POST", "DELETE"], path: str,
        body: Mapping[str, object] | None,
        *, deadline: tuple[int, Callable[[], int]] | None = None,
    ) -> tuple[int, Mapping[str, object]]:
        try:
            if not (
                (method == "GET" and path == self._detail_path() and body is None)
                or (method == "POST" and path == COLLECTION_PATH
                    and body == _body(self._sensor_name))
                or (method == "DELETE" and path == self._detail_path() and body is None
                    and self._delete_attempted and self._ownership is not None)
            ):
                raise ValueError("compiled request required")
            import httpx

            factory = self._client_factory or httpx.Client
            with factory(verify=_ssl_context(self._config),
                         timeout=self._config.timeout_seconds,
                         follow_redirects=False, trust_env=False) as client:
                if method in {"POST", "DELETE"}:
                    actor = self._observe_actor()
                    expected_actor = (
                        self._prepared_actor_digest if method == "POST"
                        else self._require_ownership().actor_digest
                    )
                    if (not isinstance(expected_actor, str) or not _digest(expected_actor)
                            or not hmac.compare_digest(actor.evidence_digest, expected_actor)):
                        raise ValueError("actor drift before dispatch")
                    if deadline is None or deadline[1]() >= deadline[0]:
                        raise ValueError("authorization expired before dispatch")
                with client.stream(
                    method, f"{self._config.base_url}{path}",
                    headers={"Accept": "application/json",
                             "Authorization": f"Bearer {self._config.bearer_token}"},
                    json=body,
                ) as response:
                    status = response.status_code
                    if (status not in {200, 404} or (method in {"POST", "DELETE"} and status != 200)
                            or "json" not in response.headers.get("content-type", "").lower()):
                        raise ValueError("response unavailable")
                    content = bytearray()
                    for chunk in response.iter_bytes(chunk_size=4096):
                        if len(content) + len(chunk) > MAX_RESPONSE_BYTES:
                            raise ValueError("response limit exceeded")
                        content.extend(chunk)
            payload = json.loads(content, object_pairs_hook=_unique_object)
            expected = {
                "status": "success" if status == 200 else "error", "http_status": status,
                "http_method": method, "path": "dlp", "name": "sensor",
                "version": "v7.0.0", "build": 29, "serial": self._expected_serial,
            }
            if not isinstance(payload, dict) or any(
                    type(payload.get(key)) is not type(value) or payload.get(key) != value
                    for key, value in expected.items()):
                raise ValueError("pinned envelope unavailable")
            error = payload.get("error")
            if (status == 200 and error is not None and (type(error) is not int or error != 0)):
                raise ValueError("success contradicts error")
            if (status == 404 and (payload.get("results") not in (None, [])
                    or payload.get("result") not in (None, [])
                    or (error is not None and (type(error) is not int or error >= 0)))):
                raise ValueError("absence contradicts response")
            if "mkey" in payload and (type(payload["mkey"]) is not str
                    or payload["mkey"] != self._sensor_name):
                raise ValueError("response binding differs")
            if method in {"POST", "DELETE"}:
                _acknowledgement(payload, self._sensor_name)
            return status, payload
        except Exception:
            raise DlpSftpAuditSensorHttpTransportError(_UNAVAILABLE) from None


def _body(sensor_name: str) -> dict[str, object]:
    return dict(fixed_log_only_sensor_profile(sensor_name=sensor_name))


def _native_digest(record: Mapping[str, object]) -> str:
    return hashlib.sha256(json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")).hexdigest()


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _recovery_inspection_digest(current: DlpSftpAuditSensorDeleteInspection) -> str:
    return _native_digest(asdict(current))


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response member")
        result[key] = value
    return result


def _acknowledgement(payload: Mapping[str, object], sensor_name: str) -> None:
    """Known build29 write grammar; the DLP mutations remain unqualified live."""

    if (not set(payload) <= _ACK_FIELDS or type(payload.get("mkey")) is not str
            or payload["mkey"] != sensor_name
            or ("vdom" in payload and payload["vdom"] != "root")
            or ("action" in payload and payload["action"] != "")):
        raise ValueError("fixed acknowledgement required")
    for key in ("revision", "old_revision"):
        if key in payload:
            value = payload[key]
            if (not isinstance(value, str) or len(value) > 255
                    or any(ord(character) < 32 or ord(character) == 127 for character in value)):
                raise ValueError("revision grammar unavailable")
    if "revision_changed" in payload and payload["revision_changed"] is not True:
        raise ValueError("write acknowledgement contradicts change")


def _readback(payload: Mapping[str, object], sensor_name: str) -> DlpSftpAuditSensorReadback:
    record = _record(payload) or {}
    filters = record.get("filter")
    item = filters[0] if isinstance(filters, list) and len(filters) == 1 else None
    try:
        fixed_log_only_sensor_digest(payload, expected_sensor_name=sensor_name)
        defaults_match = True
    except Exception:
        defaults_match = False
    return DlpSftpAuditSensorReadback(
        sensor_name_exists=record.get("name") == sensor_name,
        filter_id_exists=isinstance(item, Mapping) and type(item.get("id")) is int and item.get("id") == 1,
        filter_name_matches=isinstance(item, Mapping) and item.get("name") == FILTER_NAME,
        filter_type_matches=isinstance(item, Mapping) and item.get("type") == "file",
        protocol_matches=isinstance(item, Mapping) and item.get("proto") == "http-get http-post",
        filter_by_matches=isinstance(item, Mapping) and item.get("filter-by") == "regexp",
        regexp_matches=isinstance(item, Mapping) and item.get("regexp") == REGEXP_SENTINEL,
        action_matches=isinstance(item, Mapping) and item.get("action") == "log-only",
        native_defaults_match=defaults_match,
    )
