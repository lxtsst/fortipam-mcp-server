"""Unregistered build-29 paired RADIUS create and original-ACK recovery.

Private create callers supply server authorization and a material-provider lease.
No runtime composition, material acquisition or MCP Tool is provided here.
Native observation has a separate default-closed gate; connectivity is unqualified.
An uncertain dispatch permanently consumes its local claim.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import threading
import time
from typing import Any, Literal, Protocol, cast
from urllib.parse import quote, urlsplit

from v4_planning.material_provider import C3MaterialBinding, MaterialLeaseRequest, MaterialProviderClass, MaterialPurpose

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .ldap_server_projection import _digest
from .radius_server_http_transport import _CONNECT_MARKERS as _FOREIGN_MARKERS
from .radius_server_contract import (
    RadiusServerCreateObservation, RadiusServerCreateOutcome,
)
from .radius_server_pair_contract import (
    ACTION_ID, ACTION_VERSION, CONTRACT, RadiusServerPairError, RadiusServerPairBinding,
    project_radius_pair_ack, project_radius_pair_absence, qualify_radius_pair_created_state, pair_create_body, pair_owned_connect_body,
)
from .radius_server_pair_owned_connect_contract import (
    CONTRACT as OWNED_CONNECT_CONTRACT, CONNECT_PATH, RadiusPairOwnedConnectObservation,
    project_pair_owned_connect_observation,
)
from .radius_server_projection import (
    RadiusServerSchema, RadiusServerState, _ProtectedProjection,
    project_radius_defaults, project_radius_detail, project_radius_schema,
)
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable,
)

_PATH = "/api/v2/cmdb/user/radius"
_UNAVAILABLE = "The private RADIUS server transport is unavailable."
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MARKERS = frozenset({"create.claim.json", "create-ack.json", "created.json",
    "create-diagnostic.json", "delete.claim.json", "delete-ack.json", "deleted.json"})
_NATIVE_MARKERS = {ordinal: frozenset("pair-native-" + ordinal + suffix for suffix in (
    ".claim.json", ".result.json", ".diagnostic.json")) for ordinal in ("primary", "secondary")}
_MARKERS = _MARKERS | _NATIVE_MARKERS["primary"] | _NATIVE_MARKERS["secondary"]
CreateAuthorizer = Callable[[RadiusServerPairBinding, MaterialLeaseRequest, str], bool]
RecoveryAuthorizer = Callable[[RadiusServerPairBinding, str, str], bool]
OwnedConnectAuthorizer = Callable[[RadiusServerPairBinding, str, str, str], bool]


class _Response(Protocol):
    status: int
    def readinto(self, buffer: memoryview) -> int: ...
    def getheader(self, name: str, default: str = "") -> str: ...
    def close(self) -> None: ...


class _Socket(Protocol):
    def shutdown(self, how: int) -> None: ...


class _Connection(Protocol):
    sock: _Socket | None
    def connect(self) -> None: ...
    def request(self, method: str, url: str, body: memoryview | None,
                headers: dict[str, str]) -> None: ...
    def getresponse(self) -> _Response: ...
    def close(self) -> None: ...


class RadiusServerReadiness(_ProtectedProjection):
    """Protected C/P/E source snapshot; only its salted digest may leave."""

    __slots__ = ("schema", "defaults", "state_digest", "observed_at")
    schema: RadiusServerSchema
    defaults: RadiusServerState
    state_digest: str
    observed_at: int

    def __init__(self, schema: RadiusServerSchema, defaults: RadiusServerState,
                 digest: str, observed_at: int) -> None:
        for key, value in (("schema", schema), ("defaults", defaults),
                           ("state_digest", digest), ("observed_at", observed_at)):
            object.__setattr__(self, key, value)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


class FortiPamRadiusPairHttpTransport(C3MaterialBinding):
    """One owner-bound selector, default-closed create and separate recovery."""

    __slots__ = ("_config", "_binding", "_serial", "_directory", "_directory_identity",
        "_request", "_expected", "_execution_enabled", "_recovery_enabled", "_authorize_create",
        "_authorize_recovery", "_owned_connect_enabled", "_ordinal", "_authorize_owned_connect",
        "_clock", "_last_clock", "_clock_failed", "_clock_lock", "_factory")

    def __init__(self, config: SecretMetadataHttpTransportConfig,
                 binding: RadiusServerPairBinding, *, expected_serial: str,
                 state_directory: Path, execution_request: MaterialLeaseRequest | None = None,
                 expected_current_digest: str | None = None, execution_enabled: bool = False,
                 recovery_enabled: bool = False, create_authorizer: CreateAuthorizer | None = None,
                 recovery_authorizer: RecoveryAuthorizer | None = None,
                 owned_connect_enabled: bool = False, owned_connect_ordinal: str | None = None,
                 owned_connect_authorizer: OwnedConnectAuthorizer | None = None,
                 clock: Callable[[], int] | None = None,
                 connection_factory: Callable[..., _Connection] | None = None) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                or type(binding) is not RadiusServerPairBinding
                or type(expected_serial) is not str
                or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_serial) is None
                or type(execution_enabled) is not bool or type(recovery_enabled) is not bool
                or not isinstance(state_directory, Path) or not state_directory.is_absolute()
                or ".." in state_directory.parts
                or any(path.is_symlink() for path in (state_directory, *state_directory.parents))
                or clock is not None and not callable(clock)):
                raise ValueError
            config.__post_init__()
            parsed = urlsplit(config.base_url)
            if not parsed.hostname or parsed.username is not None or parsed.password is not None:
                raise ValueError
            info = state_directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_uid != os.getuid()):
                raise ValueError
            if execution_enabled:
                if (type(execution_request) is not MaterialLeaseRequest
                    or type(expected_current_digest) is not str
                    or _DIGEST.fullmatch(expected_current_digest) is None
                    or not callable(create_authorizer)):
                    raise ValueError
                execution_request.__post_init__()
                if (execution_request.action_id != ACTION_ID
                    or execution_request.action_version != ACTION_VERSION
                    or execution_request.provider_class is not MaterialProviderClass.OWNED_LAB_FIXTURE_REFERENCE
                    or execution_request.purpose is not MaterialPurpose.INITIAL_ONBOARDING
                    or execution_request.expires_at - execution_request.requested_at > 60):
                    raise ValueError
            if recovery_enabled and not callable(recovery_authorizer):
                raise ValueError
            if (type(owned_connect_enabled) is not bool
                    or owned_connect_ordinal is not None and owned_connect_ordinal not in {"primary", "secondary"}
                    or owned_connect_enabled and (execution_enabled or recovery_enabled
                        or owned_connect_ordinal is None or not callable(owned_connect_authorizer))):
                raise ValueError
            if execution_enabled and recovery_enabled:
                raise ValueError
        except Exception:
            raise RadiusServerPairError(_UNAVAILABLE) from None
        self._config, self._binding, self._serial = config, binding, expected_serial
        self._directory, self._directory_identity = state_directory, (info.st_dev, info.st_ino)
        self._request, self._expected = execution_request, expected_current_digest
        self._execution_enabled, self._recovery_enabled = execution_enabled, recovery_enabled
        self._authorize_create, self._authorize_recovery = create_authorizer, recovery_authorizer
        self._owned_connect_enabled, self._ordinal = owned_connect_enabled, owned_connect_ordinal
        self._authorize_owned_connect = owned_connect_authorizer
        self._clock = clock or (lambda: int(time.time()))
        self._last_clock: int | None = None
        self._clock_failed = False
        self._clock_lock = threading.RLock()
        self._factory = connection_factory or http.client.HTTPSConnection

    def _now(self) -> int:
        with self._clock_lock:
            value = self._clock()
            if (self._clock_failed or type(value) is not int or value < 0
                or self._last_clock is not None and value < self._last_clock):
                self._clock_failed = True
                raise RadiusServerPairError(_UNAVAILABLE)
            self._last_clock = value
            return value

    def _directory_fd(self) -> int:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in self._directory.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            if ((info.st_dev, info.st_ino) != self._directory_identity
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            return descriptor
        except Exception:
            os.close(descriptor)
            raise RadiusServerPairError(_UNAVAILABLE) from None

    @contextmanager
    def _locked(self, *, existing: bool = False) -> Iterator[None]:
        directory = self._directory_fd()
        descriptor = None
        try:
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            if not existing:
                flags |= os.O_CREAT
            descriptor = os.open("operation.lock", flags,
                                 0o600, dir_fd=directory)
            self._file_info(descriptor)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)

    @staticmethod
    def _file_info(descriptor: int) -> os.stat_result:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.getuid() or info.st_nlink != 1):
            raise ValueError
        return info

    def _exists(self, name: str) -> bool:
        directory = self._directory_fd()
        try:
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
                return True
            except FileNotFoundError:
                return False
        finally:
            os.close(directory)

    def _write_once(self, name: str, value: object) -> None:
        if name not in _MARKERS | {"namespace.json", "runtime.namespace.json"}:
            raise ValueError
        directory = self._directory_fd()
        try:
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "w") as stream:
                json.dump(value, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _read_state(self, name: str) -> dict[str, object]:
        if name not in _MARKERS | {"namespace.json", "runtime.namespace.json"}:
            raise ValueError
        directory = self._directory_fd()
        descriptor = None
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            before = self._file_info(descriptor)
            if not 0 < before.st_size <= 8192:
                raise ValueError
            raw = os.read(descriptor, 8193)
            after = self._file_info(descriptor)
            if (len(raw) != before.st_size or os.read(descriptor, 1)
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError
            result = json.loads(raw, object_pairs_hook=_unique_pairs)
            if type(result) is not dict:
                raise ValueError
            return result
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)

    def _namespace(self) -> None:
        if any(self._exists(name) for name in _FOREIGN_MARKERS):
            raise ValueError
        expected = {"contract": CONTRACT, "parameters_digest": self._binding.parameters_digest,
            "device_digest": _digest({"serial": self._serial, "origin": self._config.base_url})}
        if not self._exists("namespace.json"):
            if any(self._exists(name) for name in _MARKERS):
                raise ValueError
            self._write_once("namespace.json", expected)
        if self._read_state("namespace.json") != expected:
            raise ValueError

    def _exchange(self, method: str, path: str, *, stop: float, body: bytearray | None = None,
                  before_send: Callable[[], None] | None = None) -> tuple[int, bytearray]:
        """Only the compiled selector/routes; retain the socket across Connection: close."""
        raw = bytearray()
        try:
            detail = _PATH + "/" + quote(self._binding.name, safe="")
            allowed = (method == "GET" and path in {
                _PATH + "?action=schema&with_meta=true", _PATH + "?action=default&with_meta=true",
                _PATH + "?format=name&with_meta=true", detail + "?with_meta=true"}
                and body is None or method == "POST" and path == _PATH and type(body) is bytearray
                or method == "DELETE" and path == detail and body is None
                or method == "POST" and path == CONNECT_PATH and type(body) is bytearray
                and self._owned_connect_enabled is True and self._execution_enabled is False
                and self._recovery_enabled is False and callable(before_send))
            connection = response = body_view = None
            watchdog = None
            raw = bytearray(2 * 1048576 + 1)
            expired = threading.Event()
            try:
                if not allowed or stop <= time.monotonic():
                    raise ValueError
                parsed = urlsplit(self._config.base_url)
                if parsed.hostname is None:
                    raise ValueError
                context = _ssl_context(self._config)
                if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                    raise ValueError
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                connection = self._factory(parsed.hostname, parsed.port or 443,
                    timeout=min(self._config.timeout_seconds, stop - time.monotonic()), context=context)
                if before_send is not None:
                    before_send()
                connection.connect()
                active_socket = connection.sock
                if active_socket is None or stop <= time.monotonic():
                    raise ValueError

                def interrupt() -> None:
                    expired.set()
                    try:
                        active_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

                watchdog = threading.Timer(stop - time.monotonic(), interrupt)
                watchdog.daemon = True
                watchdog.start()
                if before_send is not None:
                    before_send()
                if stop <= time.monotonic():
                    raise ValueError
                if body is not None:
                    body_view = memoryview(body).toreadonly()
                connection.request(method, path, body_view, {
                    "Authorization": "Bearer " + self._config.bearer_token,
                    "Accept": "application/json", "Accept-Encoding": "identity", "Content-Type": "application/json",
                    "User-Agent": "fortipam-private-radius-pair-create/1", "Connection": "close", "Cache-Control": "no-store"})
                response = connection.getresponse()
                if "json" not in response.getheader("Content-Type", "").lower():
                    raise ValueError
                used = 0
                while used < len(raw):
                    if expired.is_set() or stop <= time.monotonic():
                        raise ValueError
                    with memoryview(raw)[used:] as destination:
                        count = response.readinto(destination)
                    if type(count) is not int or count < 0 or used + count > len(raw) - 1:
                        raise ValueError
                    if not count:
                        break
                    used += count
                if not used or expired.is_set() or stop <= time.monotonic() or type(response.status) is not int:
                    raise ValueError
                raw = _take_mutable_prefix(raw, used)
                return response.status, raw
            except Exception:
                _zeroize_mutable(raw)
                raise RadiusServerPairError(_UNAVAILABLE) from None
            finally:
                if watchdog is not None:
                    watchdog.cancel()
                    watchdog.join()
                if body_view is not None:
                    body_view.release()
                for resource in (response, connection):
                    if resource is not None:
                        try:
                            resource.close()
                        except Exception:
                            pass
        except BaseException:
            _erase_transfer_storage(raw)
            raise

    def _components(self, stop: float) -> RadiusServerReadiness:
        before = self._now()
        code, raw = self._exchange("GET", _PATH + "?action=schema&with_meta=true", stop=stop)
        try:
            if code != 200:
                raise ValueError
            schema = project_radius_schema(raw, expected_serial=self._serial)
        finally:
            _zeroize_mutable(raw)
        code, raw = self._exchange("GET", _PATH + "?action=default&with_meta=true", stop=stop)
        try:
            if code != 200:
                raise ValueError
            defaults = project_radius_defaults(raw, schema, expected_serial=self._serial)
        finally:
            _zeroize_mutable(raw)
        digest = _digest({"contract": CONTRACT, "parameters": self._binding.parameters_digest,
            "schema": schema.state_digest, "defaults": defaults.state_digest,
            "serial": hashlib.sha256(self._serial.encode()).hexdigest()})
        return RadiusServerReadiness(schema, defaults, digest, before)

    def _absence(self, stop: float) -> None:
        for path, collection in ((_PATH + "?format=name&with_meta=true", True),
                (_PATH + "/" + quote(self._binding.name, safe="") + "?with_meta=true", False)):
            code, raw = self._exchange("GET", path, stop=stop)
            project_radius_pair_absence(raw, self._binding, expected_serial=self._serial,
                                   http_status=code, collection=collection)

    def _inspect_create(self, stop: float) -> RadiusServerReadiness:
        self._namespace()
        if any(self._exists(name) for name in _MARKERS):
            raise ValueError
        observation = self._components(stop)
        self._absence(stop)
        if not 0 <= self._now() - observation.observed_at < 60:
            raise ValueError
        return observation

    def inspect_create(self) -> RadiusServerReadiness:
        try:
            with self._locked():
                return self._inspect_create(time.monotonic() + 60)
        except Exception:
            raise RadiusServerPairError(_UNAVAILABLE) from None

    def _detail(self, observation: RadiusServerReadiness, stop: float) -> RadiusServerState:
        code, raw = self._exchange("GET", _PATH + "/" + quote(self._binding.name, safe="")
                                 + "?with_meta=true", stop=stop)
        try:
            if code != 200:
                raise ValueError
            state = project_radius_detail(raw, observation.schema, expected_serial=self._serial)
            # The projector rejects populated unclassified arrays. These two
            # proven-empty values may use different JSON whitespace in detail
            # and defaults; retain the original default token representation
            # without changing the frozen pre-create digest or password hashes.
            opaque = dict(state.opaque_token_digests)
            for field in ("class", "accounting-server"):
                opaque[field] = observation.defaults.opaque_token_digests[field]
            state = RadiusServerState(state.values, opaque, state.metadata, observation.schema)
            qualify_radius_pair_created_state(state, observation.defaults, observation.schema,
                                         self._binding, expected_serial=self._serial)
            return state
        finally:
            _zeroize_mutable(raw)

    def _lease_valid(self, binding: RadiusServerPairBinding, request: MaterialLeaseRequest) -> None:
        if (self._owned_connect_enabled or not self._execution_enabled or binding is not self._binding or type(request) is not MaterialLeaseRequest
            or request != self._request or not request.requested_at <= self._now() < request.expires_at
            or self._authorize_create is None
            or self._authorize_create(binding, request, self._expected or "") is not True):
            raise ValueError
        # The server authorizer may block or observe a wall-clock adjustment.
        # Check again after it returns, immediately before the send boundary.
        if (self._owned_connect_enabled or not self._execution_enabled or request != self._request
            or not request.requested_at <= self._now() < request.expires_at):
            raise ValueError

    def _create_and_verify_pair_material(self, binding: RadiusServerPairBinding,
            request: MaterialLeaseRequest, primary: memoryview, secondary: memoryview) -> RadiusServerCreateOutcome:
        body = bytearray()
        claimed = False
        stage = "preflight"
        code: int | None = None
        try:
            with self._locked():
                self._lease_valid(binding, request)
                stop = time.monotonic() + min(60, request.expires_at - self._now())
                current = self._inspect_create(stop)
                if not hmac.compare_digest(current.state_digest, self._expected or ""):
                    raise ValueError
                self._lease_valid(binding, request)
                body = pair_create_body(binding, primary, secondary)
                claim = {"contract": CONTRACT, "parameters_digest": binding.parameters_digest,
                    "request_digest": _digest(asdict(request)), "current_digest": current.state_digest,
                    "actor_digest": hashlib.sha256(self._config.bearer_token.encode()).hexdigest(),
                    "claimed_at": self._now()}
                self._write_once("create.claim.json", claim)
                claimed = True
                stage = "post"
                code, raw = self._exchange("POST", _PATH, body=body, stop=stop,
                    before_send=lambda: self._lease_valid(binding, request))
                _zeroize_mutable(body)
                ack_digest = project_radius_pair_ack(raw, binding, expected_serial=self._serial,
                                                http_status=code, method="POST")
                stage, code = "ack_persist", None
                ack = {"claim_digest": _digest(claim), "parameters_digest": binding.parameters_digest,
                    "ack_digest": ack_digest, "acknowledged_at": self._now()}
                self._write_once("create-ack.json", ack)
                stage = "readback"
                detail = self._detail(current, stop)
                self._lease_valid(binding, request)
                stage = "created_persist"
                self._write_once("created.json", self._created_record(claim, ack, detail))
                return RadiusServerCreateOutcome.VERIFIED_CREATED
        except Exception:
            if claimed:
                try:
                    self._write_once("create-diagnostic.json", {"stage": stage,
                        "http_status": code if type(code) is int and 100 <= code <= 599 else None})
                except Exception:
                    pass
            return RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
        finally:
            _zeroize_mutable(body)

    def _created_record(self, claim: dict[str, object], ack: dict[str, object],
                        state: RadiusServerState) -> dict[str, object]:
        return {"claim_digest": _digest(claim), "ack_record_digest": _digest(ack),
            "parameters_digest": self._binding.parameters_digest, "state_digest": state.state_digest}

    @staticmethod
    def _record(record: dict[str, object], digests: set[str], times: set[str]) -> None:
        if set(record) != digests | times:
            raise ValueError
        if any(type(record[key]) is not str or _DIGEST.fullmatch(str(record[key])) is None for key in digests):
            raise ValueError
        if any(type(record[key]) is not int or record[key] < 0 for key in times):  # type: ignore[operator]
            raise ValueError

    def _create_claim(self) -> dict[str, object]:
        claim = self._read_state("create.claim.json")
        self._namespace()
        if claim.get("contract") != CONTRACT:
            raise ValueError
        self._record({key: value for key, value in claim.items() if key != "contract"},
            {"parameters_digest", "request_digest", "current_digest", "actor_digest"}, {"claimed_at"})
        if claim["parameters_digest"] != self._binding.parameters_digest:
            raise ValueError
        return claim

    def _ownership_records(self) -> tuple[dict[str, object], dict[str, object]]:
        claim, ack = self._create_claim(), self._read_state("create-ack.json")
        self._record(ack, {"claim_digest", "parameters_digest", "ack_digest"}, {"acknowledged_at"})
        if (claim["parameters_digest"] != self._binding.parameters_digest
            or ack["parameters_digest"] != self._binding.parameters_digest
            or ack["claim_digest"] != _digest(claim)
            or ack["acknowledged_at"] < claim["claimed_at"]):  # type: ignore[operator]
            raise ValueError
        return claim, ack

    def inspect_uncertain_create(self) -> RadiusServerCreateObservation:
        """Observe a consumed create without ACK; never adopt, write or retry it.

        Presence is diagnostic only, including when it differs from the intended
        state. Absence requires both fixed reads. Every failed read stays unknown.
        """
        raw = bytearray()
        try:
            with self._locked(existing=True):
                self._create_claim()
                if any(self._exists(name) for name in ("delete.claim.json", "delete-ack.json", "deleted.json")):
                    raise ValueError
                stop = time.monotonic() + 60
                current = self._components(stop)
                code, raw = self._exchange("GET", _PATH + "/" + quote(self._binding.name, safe="")
                                           + "?with_meta=true", stop=stop)
                if code == 200:
                    observed = project_radius_detail(raw, current.schema, expected_serial=self._serial)
                    if observed.values["name"] != self._binding.name:
                        raise ValueError
                    return RadiusServerCreateObservation.PRESENT_OBSERVED
                project_radius_pair_absence(raw, self._binding, expected_serial=self._serial,
                                       http_status=code, collection=False)
                code, raw = self._exchange("GET", _PATH + "?format=name&with_meta=true", stop=stop)
                project_radius_pair_absence(raw, self._binding, expected_serial=self._serial,
                                       http_status=code, collection=True)
                return RadiusServerCreateObservation.ABSENT_OBSERVED
        except Exception:
            return RadiusServerCreateObservation.NOT_ASSESSED
        finally:
            _zeroize_mutable(raw)

    def _inspect_owned(self, stop: float) -> dict[str, object]:
        if self._exists("delete.claim.json") or self._exists("delete-ack.json") or self._exists("deleted.json"):
            raise ValueError
        claim, ack = self._ownership_records()
        current = self._components(stop)
        if current.state_digest != claim["current_digest"]:
            raise ValueError
        state = self._detail(current, stop)
        expected = self._created_record(claim, ack, state)
        if self._exists("created.json"):
            if self._read_state("created.json") != expected:
                raise ValueError
        else:
            # A successful ACK may survive a failed first readback. Never adopt
            # an object from a consumed claim alone or from a 2xx status.
            self._write_once("created.json", expected)
        return expected

    def inspect_owned(self) -> bool:
        """Original-ACK reconciliation only; never reacquire or dispatch material."""
        try:
            with self._locked():
                self._inspect_owned(time.monotonic() + 60)
                return True
        except Exception:
            raise RadiusServerPairError(_UNAVAILABLE) from None

    def inspect_recovery(self) -> tuple[str, str]:
        """Private original-ACK/current-state digests for a separate recovery plan."""
        try:
            with self._locked(existing=True):
                owned = self._inspect_owned(time.monotonic() + 60)
                return _digest(owned), str(owned["state_digest"])
        except Exception:
            raise RadiusServerPairError(_UNAVAILABLE) from None

    def _native_names(self) -> tuple[str, str, str]:
        if self._ordinal not in {"primary", "secondary"}:
            raise ValueError
        prefix = "pair-native-" + str(self._ordinal)
        return prefix + ".claim.json", prefix + ".result.json", prefix + ".diagnostic.json"

    def inspect_owned_connect(self) -> tuple[str, str]:
        try:
            with self._locked(existing=True):
                if any(self._exists(name) for name in self._native_names()):
                    raise ValueError
                owned = self._inspect_owned(time.monotonic() + 60)
                return _digest(owned), str(owned["state_digest"])
        except Exception:
            raise RadiusServerPairError(_UNAVAILABLE) from None

    def observe_owned_connect(self) -> RadiusPairOwnedConnectObservation:
        """One fixed ordinal, original ACK and full pair state; no material intake."""
        body, raw = bytearray(), bytearray()
        claimed = False
        stage = "preflight"
        code: int | None = None
        try:
            with self._locked(existing=True):
                claim_name, result_name, diagnostic_name = self._native_names()
                if (self._owned_connect_enabled is not True or self._execution_enabled or self._recovery_enabled
                        or any(self._exists(name) for name in self._native_names())):
                    raise ValueError
                stop = time.monotonic() + 60
                owned = self._inspect_owned(stop)

                def authorized() -> None:
                    if (self._owned_connect_enabled is not True or self._execution_enabled or self._recovery_enabled
                            or self._authorize_owned_connect is None
                            or self._authorize_owned_connect(self._binding, str(self._ordinal), _digest(owned),
                                str(owned["state_digest"])) is not True
                            or self._owned_connect_enabled is not True or self._execution_enabled or self._recovery_enabled):
                        raise ValueError

                authorized()
                if self._ordinal not in {"primary", "secondary"}:
                    raise ValueError
                ordinal = cast(Literal["primary", "secondary"], self._ordinal)
                body = pair_owned_connect_body(self._binding, ordinal)
                marker = {"contract": OWNED_CONNECT_CONTRACT, "ordinal": ordinal,
                    "created_digest": _digest(owned), "claimed_at": self._now()}
                self._write_once(claim_name, marker)
                claimed, stage = True, "native_post"
                code, raw = self._exchange("POST", CONNECT_PATH, body=body, stop=stop, before_send=authorized)
                stage = "observation_projection"
                observation = project_pair_owned_connect_observation(raw, self._binding, ordinal=ordinal,
                    expected_serial=self._serial, http_status=code)
                stage = "state_preservation"
                if self._inspect_owned(stop) != owned:
                    raise ValueError
                authorized()
                self._write_once(result_name, {"claim_digest": _digest(marker), "observation": observation.as_dict()})
                return observation
        except Exception:
            if claimed:
                try:
                    self._write_once(diagnostic_name, {"stage": stage,
                        "http_status": code if type(code) is int and 100 <= code <= 599 else None})
                except Exception:
                    pass
            raise RadiusServerPairError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(body)
            _zeroize_mutable(raw)

    def inspect_owned_connect_observation(self) -> RadiusPairOwnedConnectObservation:
        """Read a consumed ordinal and unchanged row; never permit another POST."""
        try:
            with self._locked(existing=True):
                claim_name, result_name, diagnostic_name = self._native_names()
                owned = self._inspect_owned(time.monotonic() + 60)
                if self._exists(diagnostic_name):
                    raise ValueError
                marker = self._read_state(claim_name)
                if marker.get("contract") != OWNED_CONNECT_CONTRACT or marker.get("ordinal") != self._ordinal:
                    raise ValueError
                self._record({k: v for k, v in marker.items() if k not in {"contract", "ordinal"}},
                    {"created_digest"}, {"claimed_at"})
                if marker["created_digest"] != _digest(owned):
                    raise ValueError
                result = self._read_state(result_name)
                if set(result) != {"claim_digest", "observation"} or result["claim_digest"] != _digest(marker):
                    raise ValueError
                value = result["observation"]
                if type(value) is not dict:
                    raise ValueError
                observation = RadiusPairOwnedConnectObservation(value["ordinal"], value["http_status"], value["status_token"],
                    value["result_status_only"], value["negative_status"], value["reject_only_shape"])
                if observation.ordinal != self._ordinal or value != observation.as_dict():
                    raise ValueError
                return observation
        except Exception:
            raise RadiusServerPairError(_UNAVAILABLE) from None

    def close_owned_connect(self) -> None:
        self._owned_connect_enabled = False

    def delete_owned(self) -> bool:
        """Independent one-shot recovery; current full state and q_ref=0 are mandatory."""
        try:
            with self._locked():
                if self._owned_connect_enabled or not self._recovery_enabled or self._authorize_recovery is None:
                    raise ValueError
                stop = time.monotonic() + 60
                owned = self._inspect_owned(stop)

                def authorized() -> None:
                    if (self._owned_connect_enabled or not self._recovery_enabled or self._authorize_recovery is None
                        or self._authorize_recovery(self._binding, _digest(owned), str(owned["state_digest"])) is not True):
                        raise ValueError

                authorized()
                marker = {"created_digest": _digest(owned), "claimed_at": self._now()}
                self._write_once("delete.claim.json", marker)
                code, raw = self._exchange("DELETE", _PATH + "/" + quote(self._binding.name, safe=""),
                    stop=stop, before_send=authorized)
                digest = project_radius_pair_ack(raw, self._binding, expected_serial=self._serial,
                                           http_status=code, method="DELETE")
                self._write_once("delete-ack.json", {"claim_digest": _digest(marker), "ack_digest": digest})
                self._absence(stop)
                self._write_once("deleted.json", {"created_digest": _digest(owned), "verified_at": self._now()})
                return True
        except Exception:
            raise RadiusServerPairError(_UNAVAILABLE) from None

    def inspect_deleted(self) -> bool:
        """Read-only reconciliation of consumed DELETE; never authorizes its retry."""
        try:
            with self._locked():
                claim, ack = self._ownership_records()
                owned, marker = self._read_state("created.json"), self._read_state("delete.claim.json")
                self._record(owned, {"claim_digest", "ack_record_digest", "parameters_digest", "state_digest"}, set())
                self._record(marker, {"created_digest"}, {"claimed_at"})
                if (owned["claim_digest"] != _digest(claim) or owned["ack_record_digest"] != _digest(ack)
                    or owned["parameters_digest"] != self._binding.parameters_digest
                    or marker["created_digest"] != _digest(owned)):
                    raise ValueError
                self._absence(time.monotonic() + 60)
                return True
        except Exception:
            raise RadiusServerPairError(_UNAVAILABLE) from None
