"""Default-closed fixed Remote User HTTP lifecycle; no Tool or M4 composition.

One disabled Standard direct-RADIUS row, original ACK ownership and material-free
independent recovery. Server authorizers must be supplied by the future own M4
workflow; this adapter neither approves nor acquires any credential.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
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
from typing import Any, Literal
from urllib.parse import quote, urlsplit

from v4_planning.material_provider import _OpaqueC3Object

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .ldap_server_projection import _digest
from .radius_remote_user_contract import (
    CONTRACT, RadiusRemoteUserBinding, RadiusRemoteUserCreateDraft, RadiusRemoteUserError,
    RadiusRemoteUserObservedState, prepare_radius_remote_user_create,
    qualify_radius_remote_user_detail, qualify_radius_remote_user_ack,
    qualify_radius_remote_user_absence, project_radius_remote_user_detail,
)
from .radius_remote_user_owned_target import RadiusRemoteUserOwnedTarget, RadiusRemoteUserTargetObservation
from .radius_server_pair_http_transport import _Connection, _unique_pairs
from .local_user_reset_projection import _schema_fields, _object_spans
from .local_user_reset_metadata_reader import _validate_value
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable, _skip_json_space, _json_value_end,
)

_PATH = "/api/v2/cmdb/system/admin"
_UNAVAILABLE = "The private RADIUS Remote User HTTP workflow is unavailable."
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MARKERS = {"create.claim.json", "create-ack.json", "created.json", "create-diagnostic.json",
    "delete.claim.json", "delete-ack.json", "deleted.json"}
_WORKFLOW_FILES = {"user-create.runtime.json", "user-remove.runtime.json", "user-create.authority.json", "radius-target.handoff.json", "radius-target.preparation.json"}
CreateAuthorizer = Callable[[RadiusRemoteUserBinding, str, str, str], bool]
RecoveryAuthorizer = Callable[[RadiusRemoteUserBinding, str, str], bool]


def _create_error_code(raw: bytearray, status: int, serial: str, scope: str) -> int | None:
    """Diagnostic only: decode a negative code from the exact error envelope."""
    try:
        if type(status) is not int or not 400 <= status <= 599:
            return None
        start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw): return None
        _validate_value(raw, start, end, depth=0)
        top = _object_spans(raw, start, end)
        for name, value in {"build": 29, "version": "v7.0.0", "serial": serial,
                "path": "system", "name": "admin", "http_method": "POST",
                "http_status": status, "status": "error", "vdom": scope}.items():
            with memoryview(raw)[slice(*top[name])] as token:
                if not hmac.compare_digest(token, json.dumps(value, separators=(",", ":")).encode()): return None
        with memoryview(raw)[slice(*top["error"])] as token:
            if re.fullmatch(rb"-[1-9][0-9]{0,6}", token) is None: return None
            code = int(bytes(token))
        return code if -1_000_000 <= code < 0 else None
    except Exception:
        return None


@dataclass(frozen=True, slots=True, repr=False)
class RadiusRemoteUserReadiness(_OpaqueC3Object):
    draft: RadiusRemoteUserCreateDraft
    schema: dict[str, Any]
    target_digest: str

    @property
    def state_digest(self) -> str:
        return _digest({"contract": CONTRACT, "source_defaults_digest": self.draft.source_defaults_digest,
            "request_digest": self.draft.request_digest, "target_digest": self.target_digest})


class FortiPamRadiusRemoteUserHttpTransport(_OpaqueC3Object):
    def __init__(self, config: SecretMetadataHttpTransportConfig, binding: RadiusRemoteUserBinding, *,
            target: RadiusRemoteUserOwnedTarget, state_directory: Path,
            execution_enabled: bool = False, expected_current_digest: str | None = None,
            execution_context_digest: str | None = None,
            create_authorizer: CreateAuthorizer | None = None,
            recovery_enabled: bool = False, recovery_authorizer: RecoveryAuthorizer | None = None,
            clock: Callable[[], int] | None = None,
            connection_factory: Callable[..., _Connection] | None = None) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(binding) is not RadiusRemoteUserBinding
                    or type(target) is not RadiusRemoteUserOwnedTarget or target._binding is not binding
                    or target._target._config is not config
                    or type(execution_enabled) is not bool or type(recovery_enabled) is not bool
                    or execution_enabled and recovery_enabled
                    or execution_enabled and (not callable(create_authorizer)
                        or type(expected_current_digest) is not str or _DIGEST.fullmatch(expected_current_digest) is None
                        or type(execution_context_digest) is not str or _DIGEST.fullmatch(execution_context_digest) is None)
                    or recovery_enabled and not callable(recovery_authorizer)
                    or clock is not None and not callable(clock)
                    or not isinstance(state_directory, Path) or not state_directory.is_absolute()
                    or ".." in state_directory.parts
                    or any(p.is_symlink() for p in (state_directory, *state_directory.parents))):
                raise ValueError
            config.__post_init__()
            origin = urlsplit(config.base_url)
            if (not origin.hostname or origin.username is not None or origin.password is not None
                    or origin.port is not None and not 1 <= origin.port <= 65535):
                raise ValueError
            info = state_directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                    or info.st_uid != os.getuid() or state_directory == target._target._directory
                    or state_directory in target._target._directory.parents
                    or target._target._directory in state_directory.parents):
                raise ValueError
            self._config, self._binding, self._target = config, binding, target
            self._serial = target._target._serial
            self._directory, self._directory_identity = state_directory, (info.st_dev, info.st_ino)
            self._execution_enabled, self._recovery_enabled = execution_enabled, recovery_enabled
            self._initial_mode = (execution_enabled, recovery_enabled)
            self._closed = False
            self._expected = expected_current_digest
            self._execution_context = execution_context_digest
            self._authorize_create, self._authorize_recovery = create_authorizer, recovery_authorizer
            self._clock = clock or (lambda: int(time.time()))
            self._last_clock: int | None = None
            self._clock_failed = False
            self._clock_lock = threading.RLock()
            self._factory = connection_factory or http.client.HTTPSConnection
            self._config_pin = self._composition()
        except Exception:
            raise RadiusRemoteUserError(_UNAVAILABLE) from None

    def _composition(self) -> tuple[object, ...]:
        if (self._target._binding is not self._binding or self._target._target._config is not self._config
                or self._target._target._serial != self._serial):
            raise ValueError
        return (id(self._config), self._config.base_url, self._serial, self._binding.parameters_digest,
            id(self._target), self._directory, self._directory_identity, id(self._factory), id(self._clock),
            id(self._authorize_create), id(self._authorize_recovery), self._expected, self._execution_context)

    def _check(self) -> None:
        if (self._closed or (self._execution_enabled, self._recovery_enabled) != self._initial_mode
                or self._composition() != self._config_pin):
            raise ValueError

    def _now(self) -> int:
        with self._clock_lock:
            try:
                value = self._clock()
                if (self._clock_failed or type(value) is not int or value < 0
                    or self._last_clock is not None and value < self._last_clock):
                    raise ValueError
                self._last_clock = value
                return value
            except Exception:
                self._clock_failed = True
                raise RadiusRemoteUserError(_UNAVAILABLE) from None

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
            raise RadiusRemoteUserError(_UNAVAILABLE) from None

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
        if name not in _MARKERS | _WORKFLOW_FILES | {"namespace.json"}:
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
        if name not in _MARKERS | _WORKFLOW_FILES | {"namespace.json"}:
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

    def _authority_marker_digest(self) -> str:
        """Hash one bounded metadata marker without interpreting partial JSON."""
        directory = self._directory_fd()
        descriptor = None
        raw = bytearray(32769)
        try:
            descriptor = os.open("user-create.authority.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            before = self._file_info(descriptor)
            if not 0 <= before.st_size <= 32768: raise ValueError
            count = os.readv(descriptor, [raw])
            after = self._file_info(descriptor)
            if (count != before.st_size or os.read(descriptor, 1)
                    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)): raise ValueError
            raw = _take_mutable_prefix(raw, count)
            return hashlib.sha256(raw).hexdigest()
        finally:
            _zeroize_mutable(raw)
            if descriptor is not None: os.close(descriptor)
            os.close(directory)

    def _exchange(self, method: str, path: str, *, stop: float, body: bytearray | None = None,
                  before_send: Callable[[], None] | None = None) -> tuple[int, bytearray]:
        """Only the compiled selector/routes; retain the socket across Connection: close."""
        raw = bytearray()
        try:
            detail = _PATH + "/" + quote(self._binding.username, safe="")
            allowed = (method == "GET" and path in {
                _PATH + "?action=schema&with_meta=true", _PATH + "?action=default&with_meta=true",
                _PATH + "?format=name&with_meta=true", detail + "?with_meta=true"} and body is None
                or method == "POST" and path == _PATH and type(body) is bytearray and callable(before_send)
                or method == "DELETE" and path == detail and body is None and callable(before_send))
            connection = response = body_view = None
            watchdog = None
            raw = bytearray(1048576 + 1)
            expired = threading.Event()
            try:
                self._check()
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
                    "User-Agent": "fortipam-private-radius-remote-user/1", "Connection": "close", "Cache-Control": "no-store"})
                response = connection.getresponse()
                if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                    raise ValueError
                if response.getheader("Content-Encoding", "identity").lower() != "identity":
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
            except BaseException as error:
                _zeroize_mutable(raw)
                if not isinstance(error, Exception):
                    raise
                raise RadiusRemoteUserError(_UNAVAILABLE) from None
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

    def _namespace(self, *, existing_only: bool = False, preparation_digest: str | None = None) -> None:
        self._check()
        expected = {"contract": CONTRACT, "binding_digest": self._binding.parameters_digest,
            "device_digest": _digest({"serial": self._serial, "origin": self._config.base_url}),
            "target_journal_digest": _digest({"path": str(self._target._target._directory),
                "identity": list(self._target._target._directory_identity),
                "pair": self._binding.radius.parameters_digest})}
        if not self._exists("namespace.json"):
            if existing_only: raise ValueError
            forbidden = _MARKERS | _WORKFLOW_FILES
            if preparation_digest is not None:
                if (self._target._recovery_only or _digest(self._read_state("radius-target.preparation.json")) != preparation_digest):
                    raise ValueError
                forbidden = forbidden - {"radius-target.preparation.json"}
            if any(self._exists(name) for name in forbidden):
                raise ValueError
            self._write_once("namespace.json", expected)
        if self._read_state("namespace.json") != expected:
            raise ValueError

    def _components(self, stop: float) -> tuple[dict[str, Any], RadiusRemoteUserCreateDraft]:
        raw = bytearray()
        try:
            code, raw = self._exchange("GET", _PATH + "?action=schema&with_meta=true", stop=stop)
            if code != 200:
                raise ValueError
            schema = json.loads(raw, object_pairs_hook=_unique_pairs)
            _schema_fields(schema)
            if schema.get("serial") != self._serial:
                raise ValueError
            _zeroize_mutable(raw)
            code, raw = self._exchange("GET", _PATH + "?action=default&with_meta=true", stop=stop)
            if code != 200:
                raise ValueError
            draft = prepare_radius_remote_user_create(raw, schema, self._binding, expected_serial=self._serial)
            return schema, draft
        finally:
            _zeroize_mutable(raw)

    def _absence(self, draft: RadiusRemoteUserCreateDraft, stop: float) -> None:
        for path, collection in ((_PATH + "/" + quote(self._binding.username, safe="") + "?with_meta=true", False),
                (_PATH + "?format=name&with_meta=true", True)):
            code, raw = self._exchange("GET", path, stop=stop)
            try:
                qualify_radius_remote_user_absence(raw, self._binding, expected_serial=self._serial,
                    expected_vdom=draft._response_vdom, http_status=code, collection=collection)
            finally:
                _zeroize_mutable(raw)

    def _read_current(self, target: RadiusRemoteUserTargetObservation, stop: float) -> RadiusRemoteUserReadiness:
        schema, draft = self._components(stop)
        self._absence(draft, stop)
        return RadiusRemoteUserReadiness(draft, schema, target.observation_digest)

    def inspect_create(self) -> RadiusRemoteUserReadiness:
        try:
            self._check()
            stop = time.monotonic() + 60
            with self._locked(), self._target.hold(stop=stop) as target:
                self._namespace()
                if any(self._exists(name) for name in _MARKERS):
                    raise ValueError
                return self._read_current(target, stop)
        except Exception:
            raise RadiusRemoteUserError(_UNAVAILABLE) from None

    def _detail(self, schema: dict[str, Any], draft: RadiusRemoteUserCreateDraft,
            stop: float) -> RadiusRemoteUserObservedState:
        code, raw = self._exchange("GET", _PATH + "/" + quote(self._binding.username, safe="") + "?with_meta=true", stop=stop)
        if code != 200:
            _zeroize_mutable(raw)
            raise ValueError
        return qualify_radius_remote_user_detail(raw, schema, draft, expected_serial=self._serial)

    def create_and_verify(self) -> str:
        """One fixed POST, authorized separately; uncertain dispatch cannot replay."""
        body = bytearray()
        claimed = False
        stage, code = "preflight", None
        error_code = None
        try:
            self._check()
            if not self._execution_enabled or self._recovery_enabled or self._authorize_create is None:
                raise ValueError
            stop = time.monotonic() + 60
            with self._locked(), self._target.hold(stop=stop) as target:
                self._namespace()
                if (not self._execution_enabled or self._recovery_enabled or self._authorize_create is None
                        or any(self._exists(name) for name in _MARKERS)):
                    raise ValueError
                current = self._read_current(target, stop)
                if current.state_digest != self._expected:
                    raise ValueError

                def authorized() -> None:
                    self._check()
                    if (not self._execution_enabled or self._recovery_enabled or self._authorize_create is None
                            or self._authorize_create(self._binding, current.state_digest,
                                current.draft.request_digest, current.target_digest) is not True):
                        raise ValueError
                    fresh_target = self._target._inspect_locked(stop)
                    fresh = self._read_current(fresh_target, stop)
                    if fresh.state_digest != current.state_digest:
                        raise ValueError
                    self._check()
                    if (not self._execution_enabled or self._recovery_enabled or self._authorize_create is None
                            or self._authorize_create(self._binding, current.state_digest,
                                current.draft.request_digest, current.target_digest) is not True):
                        raise ValueError

                authorized()
                claim: dict[str, object] = {"contract": CONTRACT, "binding_digest": self._binding.parameters_digest,
                    "execution_context_digest": self._execution_context,
                    "current_digest": current.state_digest, "request_digest": current.draft.request_digest,
                    "defaults_digest": current.draft.source_defaults_digest, "target_digest": current.target_digest,
                    "actor_digest": hashlib.sha256(self._config.bearer_token.encode()).hexdigest(),
                    "claimed_at": self._now()}
                self._write_once("create.claim.json", claim)
                claimed = True
                body = bytearray(current.draft._wire)
                stage = "post"
                code, raw = self._exchange("POST", _PATH, body=body, stop=stop, before_send=authorized)
                _zeroize_mutable(body)
                stage = "ack_validate"
                error_code = _create_error_code(raw, code, self._serial, current.draft._response_vdom)
                ack = {"claim_digest": _digest(claim), "ack_digest": qualify_radius_remote_user_ack(raw,
                    self._binding, expected_serial=self._serial, expected_vdom=current.draft._response_vdom,
                    method="POST", http_status=code), "acknowledged_at": self._now()}
                stage, code = "ack_persist", None
                self._write_once("create-ack.json", ack)
                stage = "readback"
                state = self._detail(current.schema, current.draft, stop)
                self._check()
                if not self._execution_enabled:
                    raise ValueError
                stage = "created_persist"
                self._write_once("created.json", self._created_record(claim, ack, state))
                return "verified_created"
        except Exception:
            if claimed:
                # Match the existing pair adapter: retain only a categorical
                # stage/status, never a response, error text or authority.
                try:
                    diagnostic: dict[str, object] = {"stage": stage,
                        "http_status": code if type(code) is int and 100 <= code <= 599 else None}
                    if error_code is not None: diagnostic["error_code"] = error_code
                    self._write_once("create-diagnostic.json", diagnostic)
                except Exception:
                    pass
                return "reconciliation_required"
            raise RadiusRemoteUserError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(body)

    @staticmethod
    def _record(record: dict[str, object], digests: set[str], times: set[str]) -> None:
        if set(record) != digests | times:
            raise ValueError
        if any(type(record[k]) is not str or _DIGEST.fullmatch(str(record[k])) is None for k in digests):
            raise ValueError
        if any(type(record[k]) is not int or record[k] < 0 for k in times):  # type: ignore[operator]
            raise ValueError

    def _create_claim(self) -> dict[str, object]:
        self._namespace()
        claim = self._read_state("create.claim.json")
        if claim.get("contract") != CONTRACT or claim.get("binding_digest") != self._binding.parameters_digest:
            raise ValueError
        self._record({k: v for k, v in claim.items() if k != "contract"},
            {"binding_digest", "execution_context_digest", "current_digest", "request_digest", "defaults_digest", "target_digest", "actor_digest"}, {"claimed_at"})
        return claim

    def _ownership(self) -> tuple[dict[str, object], dict[str, object]]:
        claim, ack = self._create_claim(), self._read_state("create-ack.json")
        self._record(ack, {"claim_digest", "ack_digest"}, {"acknowledged_at"})
        if ack["claim_digest"] != _digest(claim) or ack["acknowledged_at"] < claim["claimed_at"]:  # type: ignore[operator]
            raise ValueError
        return claim, ack

    def inspect_unclaimed_absence(self, *, expected_draft: tuple[str, str] | None = None) -> bool:
        """Read fixed dual absence only when no User HTTP mutation was claimed."""
        try:
            with self._locked(existing=True):
                self._namespace(existing_only=True)
                if any(self._exists(name) for name in _MARKERS): raise ValueError
                stop = time.monotonic() + 60
                _, draft = self._components(stop)
                if expected_draft is not None and (draft.source_defaults_digest, draft.request_digest) != expected_draft:
                    raise ValueError
                self._absence(draft, stop)
                if any(self._exists(name) for name in _MARKERS): raise ValueError
                return True
        except Exception:
            raise RadiusRemoteUserError(_UNAVAILABLE) from None

    def inspect_uncertain_create(self) -> Literal["present_observed", "absent_observed", "not_assessed"]:
        """Observe a consumed POST without adoption, journal repair or retry."""
        raw = bytearray()
        try:
            with self._locked(existing=True):
                claim = self._create_claim()
                if any(self._exists(name) for name in {"delete.claim.json", "delete-ack.json", "deleted.json"}):
                    raise ValueError
                stop = time.monotonic() + 60
                schema, draft = self._components(stop)
                if draft.request_digest != claim["request_digest"] or draft.source_defaults_digest != claim["defaults_digest"]:
                    raise ValueError
                code, raw = self._exchange("GET", _PATH + "/" + quote(self._binding.username, safe="") + "?with_meta=true", stop=stop)
                if code == 200:
                    project_radius_remote_user_detail(raw, schema, draft, expected_serial=self._serial)
                    return "present_observed"
                qualify_radius_remote_user_absence(raw, self._binding, expected_serial=self._serial,
                    expected_vdom=draft._response_vdom, http_status=code, collection=False)
                code, raw = self._exchange("GET", _PATH + "?format=name&with_meta=true", stop=stop)
                qualify_radius_remote_user_absence(raw, self._binding, expected_serial=self._serial,
                    expected_vdom=draft._response_vdom, http_status=code, collection=True)
                return "absent_observed"
        except Exception:
            return "not_assessed"
        finally:
            _zeroize_mutable(raw)

    def _created_record(self, claim: dict[str, object], ack: dict[str, object],
            state: RadiusRemoteUserObservedState) -> dict[str, object]:
        return {"claim_digest": _digest(claim), "ack_digest": _digest(ack),
            "binding_digest": self._binding.parameters_digest, "state_digest": state.nonmaterial_state_digest,
            "assigned_id": state.assigned_id}

    def _owned(self, stop: float) -> tuple[dict[str, object], RadiusRemoteUserCreateDraft]:
        if any(self._exists(name) for name in {"delete.claim.json", "delete-ack.json", "deleted.json"}):
            raise ValueError
        claim, ack = self._ownership()
        schema, draft = self._components(stop)
        if draft.request_digest != claim["request_digest"] or draft.source_defaults_digest != claim["defaults_digest"]:
            raise ValueError
        state = self._detail(schema, draft, stop)
        expected = self._created_record(claim, ack, state)
        if self._exists("created.json"):
            if self._read_state("created.json") != expected:
                raise ValueError
        else:
            # A retained successful original ACK may qualify a fresh full read;
            # a consumed POST claim alone never grants adoption or deletion.
            self._write_once("created.json", expected)
        return expected, draft

    def inspect_recovery(self) -> tuple[str, str]:
        try:
            with self._locked(existing=True):
                owned, _ = self._owned(time.monotonic() + 60)
                return _digest(owned), str(owned["state_digest"])
        except Exception:
            raise RadiusRemoteUserError(_UNAVAILABLE) from None

    def delete_owned(self) -> bool:
        try:
            with self._locked(existing=True):
                if self._execution_enabled or not self._recovery_enabled or self._authorize_recovery is None:
                    raise ValueError
                stop = time.monotonic() + 60
                owned, draft = self._owned(stop)

                def authorized() -> None:
                    self._check()
                    if (self._execution_enabled or not self._recovery_enabled or self._authorize_recovery is None
                            or self._authorize_recovery(self._binding, _digest(owned), str(owned["state_digest"])) is not True):
                        raise ValueError
                    schema, fresh = self._components(stop)
                    if fresh.request_digest != draft.request_digest or fresh.source_defaults_digest != draft.source_defaults_digest:
                        raise ValueError
                    state = self._detail(schema, fresh, stop)
                    if state.nonmaterial_state_digest != owned["state_digest"]:
                        raise ValueError
                    self._check()
                    if (self._execution_enabled or not self._recovery_enabled or self._authorize_recovery is None
                            or self._authorize_recovery(self._binding, _digest(owned), str(owned["state_digest"])) is not True):
                        raise ValueError

                authorized()
                claim = {"created_digest": _digest(owned), "claimed_at": self._now()}
                self._write_once("delete.claim.json", claim)
                code, raw = self._exchange("DELETE", _PATH + "/" + quote(self._binding.username, safe=""),
                    stop=stop, before_send=authorized)
                ack_digest = qualify_radius_remote_user_ack(raw, self._binding, expected_serial=self._serial,
                    expected_vdom=draft._response_vdom, method="DELETE", http_status=code)
                self._write_once("delete-ack.json", {"claim_digest": _digest(claim), "ack_digest": ack_digest})
                self._absence(draft, stop)
                self._write_once("deleted.json", {"created_digest": _digest(owned), "verified_at": self._now()})
                return True
        except Exception:
            raise RadiusRemoteUserError(_UNAVAILABLE) from None

    def inspect_deleted(self) -> bool:
        """Dual-absence reconciliation after a consumed DELETE; never retry it."""
        try:
            with self._locked(existing=True):
                claim, ack = self._ownership()
                owned, deletion = self._read_state("created.json"), self._read_state("delete.claim.json")
                if (owned.get("claim_digest") != _digest(claim) or owned.get("ack_digest") != _digest(ack)
                        or owned.get("binding_digest") != self._binding.parameters_digest
                        or deletion.get("created_digest") != _digest(owned)):
                    raise ValueError
                if (set(owned) != {"claim_digest", "ack_digest", "binding_digest", "state_digest", "assigned_id"}
                        or type(owned["assigned_id"]) is not int or owned["assigned_id"] <= 0):
                    raise ValueError
                self._record({k: v for k, v in owned.items() if k != "assigned_id"},
                    {"claim_digest", "ack_digest", "binding_digest", "state_digest"}, set())
                self._record(deletion, {"created_digest"}, {"claimed_at"})
                stop = time.monotonic() + 60
                _, draft = self._components(stop)
                if draft.request_digest != claim["request_digest"] or draft.source_defaults_digest != claim["defaults_digest"]:
                    raise ValueError
                self._absence(draft, stop)
                return True
        except Exception:
            raise RadiusRemoteUserError(_UNAVAILABLE) from None

    def close(self) -> None:
        self._closed = True
        self._execution_enabled = self._recovery_enabled = False
