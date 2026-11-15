"""Fixed Instruction Profile HTTP lifecycle with original-ACK ownership.

No Tool or authority is registered here. Callers hold operation_lock across
current-state checks, independently authorized dispatch and fixed readback.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import stat
import threading
import time
from typing import Any, Literal, cast
from urllib.parse import quote, urlsplit

from .mutable_json_buffer import _take_mutable_prefix
from .instruction_profile_contract import (
    WIRE_FIELDS, InstructionProfileCreatePlan, _Private, _require_digest,
    build_instruction_profile_create_body,
)
from .ldap_server_http_transport import _Connection
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable,
)

CONTRACT = "fortipam-700-build29-owned-instruction-profile-transport-v1"
Phase = Literal["create", "delete"]
_UNAVAILABLE = "The private owned Instruction Profile transport is unavailable."
_LIMIT = 262144
_PLAN = "creation.plan.json"
_LOCK = "operation.lock"
_PATH = "/api/v2/cmdb/secret/instruction-profile"
_ANCHORS = ("create.claim.json", "create-ack.json", "created.json")



def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


class InstructionProfileHttpTransportError(RuntimeError):
    """Stable, value-free failure, including unknown mutation outcomes."""


def _members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _constant(value: str) -> None:
    raise ValueError


def _timestamp(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError
    return value


class InstructionProfileReadiness(_Private):
    __slots__ = ("state_digest", "observed_at")
    state_digest: str
    observed_at: int

    def __init__(self, state_digest: str, observed_at: int) -> None:
        _require_digest(state_digest)
        object.__setattr__(self, "state_digest", state_digest)
        object.__setattr__(self, "observed_at", _timestamp(observed_at))


class FortiPamInstructionProfileHttpTransport(_Private):
    """One fixed private profile, with independent create and delete dispatches."""

    __slots__ = ("_config", "_binding", "_phase", "_enabled", "_directory", "_directory_identity",
                 "_serial_digest", "_schema_digest", "_namespace", "_clock", "_last_clock",
                 "_clock_failed", "_factory", "_lock_owner")
    _config: SecretMetadataHttpTransportConfig
    _binding: InstructionProfileCreatePlan
    _phase: Phase
    _enabled: bool
    _directory: Path
    _directory_identity: tuple[int, int]
    _serial_digest: str
    _schema_digest: str
    _namespace: str
    _clock: Callable[[], int]
    _last_clock: int | None
    _clock_failed: bool
    _factory: Callable[..., _Connection]
    _lock_owner: int | None

    def __init__(self, config: SecretMetadataHttpTransportConfig, binding: InstructionProfileCreatePlan, *,
                 serial_digest: str, schema_digest: str, state_directory: Path, phase: Phase,
                 execution_enabled: bool = False, clock: Callable[[], int] | None = None,
                 connection_factory: Callable[..., _Connection] | None = None) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(binding) is not InstructionProfileCreatePlan
                    or type(phase) is not str or phase not in {"create", "delete"}
                    or type(execution_enabled) is not bool or clock is not None and not callable(clock)
                    or not isinstance(state_directory, Path) or not state_directory.is_absolute()
                    or ".." in state_directory.parts
                    or any(p.is_symlink() for p in (state_directory, *state_directory.parents))):
                raise ValueError
            config.__post_init__()
            url = urlsplit(config.base_url)
            if not url.hostname or url.username is not None or url.password is not None:
                raise ValueError
            for digest in (serial_digest, schema_digest):
                _require_digest(digest)
            if serial_digest != binding._serial or schema_digest != binding._schema:
                raise ValueError
            info = state_directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            identity = (info.st_dev, info.st_ino)
            namespace = _digest({"contract": CONTRACT, "binding": binding.digest,
                "directory": str(state_directory), "directory_identity": identity,
                "serial": serial_digest, "schema": schema_digest, "api_base_url": config.base_url,
                "api_identity": hashlib.sha256(config.bearer_token.encode()).hexdigest(),
                "api_ca": hashlib.sha256(Path(config.ca_file).read_bytes()).hexdigest() if config.ca_file else None})
            values: dict[str, object] = {"_config": config, "_binding": binding, "_phase": phase,
                "_enabled": execution_enabled, "_directory": state_directory, "_directory_identity": identity,
                "_serial_digest": serial_digest, "_schema_digest": schema_digest, "_namespace": namespace,
                "_clock": clock or (lambda: int(time.time())), "_last_clock": None, "_clock_failed": False,
                "_factory": connection_factory or http.client.HTTPSConnection,
                "_lock_owner": None}
            for key, value in values.items():
                object.__setattr__(self, key, value)
        except Exception:
            raise InstructionProfileHttpTransportError(_UNAVAILABLE) from None

    def close(self) -> None:
        """Disable future dispatch while preserving original custody records."""
        object.__setattr__(self, "_enabled", False)

    def _now(self) -> int:
        try:
            now = _timestamp(self._clock())
            if self._clock_failed or self._last_clock is not None and now < self._last_clock:
                raise ValueError
            object.__setattr__(self, "_last_clock", now)
            return now
        except Exception:
            object.__setattr__(self, "_clock_failed", True)
            raise ValueError from None

    def _directory_fd(self) -> int:
        descriptor = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if ((info.st_dev, info.st_ino) != self._directory_identity or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            os.close(descriptor)
            raise ValueError
        return descriptor

    def _write_once(self, name: str, value: object) -> None:
        raw = bytearray(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())
        directory = self._directory_fd()
        try:
            if not 0 < len(raw) <= _LIMIT:
                raise ValueError
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            _zeroize_mutable(raw)
            os.close(directory)

    def _read(self, name: str, *, expected_digest: str | None = None) -> dict[str, Any]:
        directory = self._directory_fd()
        descriptor = None
        raw = bytearray()
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= _LIMIT):
                raise ValueError
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                raw = bytearray(stream.read(_LIMIT + 1))
            if expected_digest is not None:
                _require_digest(expected_digest)
                if hashlib.sha256(raw).hexdigest() != expected_digest:
                    raise ValueError
            value = json.loads(raw, object_pairs_hook=_members, parse_constant=_constant)
            if len(raw) != info.st_size or type(value) is not dict:
                raise ValueError
            return cast(dict[str, Any], value)
        finally:
            _zeroize_mutable(raw)
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)

    @contextmanager
    def operation_lock(self) -> Iterator[None]:
        directory = descriptor = None
        try:
            if self._lock_owner is not None:
                raise ValueError
            directory = self._directory_fd()
            descriptor = os.open(_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0):
                raise ValueError
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            current = os.stat(_LOCK, dir_fd=directory, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError
            object.__setattr__(self, "_lock_owner", threading.get_ident())
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                os.close(directory)
            raise InstructionProfileHttpTransportError(_UNAVAILABLE) from None
        try:
            yield
        finally:
            object.__setattr__(self, "_lock_owner", None)
            os.close(descriptor)
            os.close(directory)

    def _locked(self) -> None:
        if self._lock_owner != threading.get_ident():
            raise ValueError

    def _request(self, method: str, path: str, *, body: bytearray | None = None,
                 guard: Callable[[], None] | None = None, deadline: int | None = None,
                 capture_name: str | None = None) -> dict[str, Any] | None:
        response = connection = view = None
        raw = bytearray(_LIMIT + 1)
        try:
            allowed_gets = {self._detail_path(), _PATH + "?format=name",
                _PATH + "?action=schema&with_meta=true", _PATH + "?action=default&with_meta=true"}
            if method == "GET":
                if path not in allowed_gets or body is not None or capture_name is not None:
                    raise ValueError
            elif (method == "POST" and path == _PATH and type(body) is bytearray
                  and capture_name == "create-response.json"):
                pass
            elif (method == "DELETE" and path == self._delete_path() and body is None
                  and capture_name == "delete-response.json"):
                pass
            else:
                raise ValueError
            url = urlsplit(self._config.base_url)
            context = _ssl_context(self._config)
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            timeout = self._config.timeout_seconds
            if deadline is not None:
                remaining = deadline - self._now()
                if remaining <= 0:
                    raise ValueError
                timeout = min(timeout, remaining)
            connection = self._factory(url.hostname, url.port or 443, timeout=timeout, context=context)
            if body is not None:
                view = memoryview(body).toreadonly()
            if method != "GET":
                if guard is None or deadline is None:
                    raise ValueError
                guard()
                connection.connect()
                guard()
                if self._now() >= deadline:
                    raise ValueError
            connection.request(method, path, view, {"Authorization": "Bearer " + self._config.bearer_token,
                "Accept": "application/json", "Content-Type": "application/json", "Accept-Encoding": "identity",
                "Connection": "close", "Cache-Control": "no-store", "User-Agent": "fortipam-mcp-owned-instruction-profile/1"})
            response = connection.getresponse()
            if "json" not in response.getheader("Content-Type", "").lower():
                raise ValueError
            used = 0
            while used <= _LIMIT:
                with memoryview(raw)[used:] as buffer:
                    count = response.readinto(buffer)
                if type(count) is not int or count < 0 or used + count > _LIMIT:
                    raise ValueError
                if not count:
                    break
                used += count
            raw = _take_mutable_prefix(raw, used)
            payload = json.loads(raw, object_pairs_hook=_members, parse_constant=_constant)
            if capture_name is not None:
                self._write_once(capture_name, {"namespace": self._namespace, "binding": self._binding.digest,
                    "http_status": response.status, "payload": payload})
            if type(payload) is not dict:
                raise ValueError
            route = path.split("?", 1)[0].split("/")
            for key, expected in {"version": "v7.0.0", "build": 29, "http_method": method,
                                  "path": route[4], "name": route[5]}.items():
                if type(payload.get(key)) is not type(expected) or payload[key] != expected:
                    raise ValueError
            serial = payload.get("serial")
            if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != self._serial_digest:
                raise ValueError
            if response.status == 404 and method == "GET" and path == self._detail_path():
                if payload.get("status") != "error" or type(payload.get("http_status")) is not int or payload["http_status"] != 404 or payload.get("results") not in (None, []):
                    raise ValueError
                return None
            if response.status != 200 or payload.get("status") != "success" or type(payload.get("http_status")) is not int or payload["http_status"] != 200:
                raise ValueError
            return cast(dict[str, Any], payload)
        finally:
            _zeroize_mutable(raw)
            if view is not None:
                view.release()
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        pass

    def _delete_path(self) -> str:
        return _PATH + "/" + quote(self._binding._name, safe="")

    def _detail_path(self) -> str:
        return self._delete_path() + "?with_meta=true"

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

    def _context(self) -> dict[str, object]:
        return {"contract": CONTRACT, "namespace": self._namespace, "binding": self._binding.digest,
                "schema": self._schema_digest, "serial": self._serial_digest}

    def _plan(self, *, initialize: bool = False) -> dict[str, object]:
        self._locked()
        expected = self._context()
        if not self._exists(_PLAN):
            if not initialize or any(self._exists(name) for name in (
                    *_ANCHORS, "create-response.json", "delete.claim.json", "delete-response.json", "deleted.json")):
                raise ValueError
            self._write_once(_PLAN, expected)
        if self._read(_PLAN) != expected:
            raise ValueError
        return expected

    def _body(self) -> bytearray:
        return build_instruction_profile_create_body(self._binding,
            {"name": "", "brief": "", "detail": ""},
            schema_digest=self._schema_digest, serial_digest=self._serial_digest)

    def _record(self, value: object, *, expected_reference_count: int = 0) -> dict[str, Any]:
        metadata = {"q_global_entry": bool, "q_mkey_type": str, "q_name": str,
            "q_no_edit": bool, "q_no_rename": bool, "q_origin_key": str,
            "q_path": str, "q_ref": int, "q_static": bool, "q_type": int}
        if (type(expected_reference_count) is not int or expected_reference_count not in {0, 1}
                or type(value) is not dict or set(value) != WIRE_FIELDS | set(metadata)
                or any(type(value[key]) is not kind for key, kind in metadata.items())
                or any(type(value[key]) is not str for key in WIRE_FIELDS)
                or value["q_origin_key"] != self._binding._name
                or value["q_path"] != "secret" or value["q_name"] != "instruction-profile"
                or value["q_mkey_type"] != "string" or value["q_ref"] != expected_reference_count
                or any(value[key] is not False for key in ("q_static", "q_no_edit", "q_global_entry"))):
            raise ValueError
        body = self._body()
        try:
            if {key: value[key] for key in WIRE_FIELDS} != json.loads(body):
                raise ValueError
            return cast(dict[str, Any], value)
        finally:
            _zeroize_mutable(body)

    def _snapshot(self, *, exists: bool, expected_reference_count: int = 0) -> dict[str, Any] | None:
        schema = self._request("GET", _PATH + "?action=schema&with_meta=true")
        if (schema is None or hashlib.sha256(json.dumps(schema["results"]["children"],
                sort_keys=True).encode()).hexdigest() != self._schema_digest):
            raise ValueError
        defaults = self._request("GET", _PATH + "?action=default&with_meta=true")
        if defaults is None or defaults.get("results") != {"name": "", "brief": "", "detail": ""}:
            raise ValueError
        collection = self._request("GET", _PATH + "?format=name")
        if collection is None:
            raise ValueError
        rows = collection.get("results")
        if (type(rows) is not list or len(rows) != (1 if exists else 0)
                or collection.get("limit_reached", False) is not False
                or any(type(collection.get(k)) is not int or collection[k] != len(rows)
                       for k in ("size", "matched_count"))):
            raise ValueError
        if exists and (type(rows[0]) is not dict
                or not {"name"} <= set(rows[0]) <= {"name", "q_origin_key"}
                or rows[0]["name"] != self._binding._name
                or rows[0].get("q_origin_key", self._binding._name) != self._binding._name):
            raise ValueError
        payload = self._request("GET", self._detail_path())
        if not exists:
            if payload is not None:
                raise ValueError
            return None
        if payload is None:
            raise ValueError
        value = payload.get("results")
        if type(value) is list and len(value) == 1:
            value = value[0]
        return self._record(value, expected_reference_count=expected_reference_count)

    def _ack(self, payload: object, phase: str) -> dict[str, Any]:
        if type(payload) is not dict:
            raise ValueError
        for key, expected in {"version": "v7.0.0", "build": 29,
                "http_method": "POST" if phase == "create" else "DELETE",
                "path": "secret", "name": "instruction-profile", "status": "success",
                "http_status": 200, "mkey": self._binding._name}.items():
            if type(payload.get(key)) is not type(expected) or payload[key] != expected:
                raise ValueError
        serial = payload.get("serial")
        if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != self._serial_digest:
            raise ValueError
        return cast(dict[str, Any], payload)

    def _anchors(self) -> dict[str, str]:
        claim, ack, created = (self._read(name) for name in _ANCHORS)
        if (claim.get("context") != self._context() or claim.get("phase") != "create"
                or ack.get("claim_digest") != _digest(claim)
                or ack.get("context") != self._context()
                or created.get("claim_digest") != _digest(claim)
                or created.get("ack_digest") != _digest(ack)
                or created.get("context") != self._context()):
            raise ValueError
        self._ack(ack.get("response"), "create")
        self._record(created.get("record"))
        return {name: _digest(value) for name, value in zip(_ANCHORS, (claim, ack, created))}

    def _current(self, *, allow_consumed: bool = False) -> tuple[str, dict[str, str]]:
        self._locked()
        self._plan(initialize=self._phase == "create")
        if self._phase == "delete" and self._exists("historical-cleanup.consumed.json"):
            raise ValueError
        if not allow_consumed and self._exists(self._phase + ".claim.json"):
            raise ValueError
        anchors = {} if self._phase == "create" else self._anchors()
        record = self._snapshot(exists=self._phase == "delete")
        if self._phase == "delete" and record != self._read("created.json")["record"]:
            raise ValueError
        return _digest({**self._context(), "phase": self._phase, "record": record, "anchors": anchors}), anchors

    def inspect_current(self) -> InstructionProfileReadiness:
        try:
            current, _ = self._current()
            return InstructionProfileReadiness(current, self._now())
        except Exception:
            raise InstructionProfileHttpTransportError(_UNAVAILABLE) from None

    def expected_state_digest(self) -> str:
        self._locked()
        self._plan()
        return _digest({**self._context(), "phase": self._phase,
                        "state": "created-owned" if self._phase == "create" else "deleted-owned"})

    def dispatch(self, *, expected_current_digest: str, plan_digest: str,
                 authorization_digest: str, expires_at: int, before_send: Callable[[], None]) -> None:
        body = None
        try:
            self._locked()
            if self._enabled is not True or not callable(before_send):
                raise ValueError
            for value in (expected_current_digest, plan_digest, authorization_digest):
                _require_digest(value)
            _timestamp(expires_at)
            issued = self._now()
            if not issued < expires_at <= issued + 60:
                raise ValueError
            current, anchors = self._current()
            if current != expected_current_digest:
                raise ValueError
            before_send()
            phase = self._phase
            claim = {"context": self._context(), "phase": phase, "plan_digest": plan_digest,
                "authorization_digest": authorization_digest, "current_digest": current,
                "anchors": anchors, "issued_at": issued, "expires_at": expires_at}
            self._write_once(phase + ".claim.json", claim)

            def guard() -> None:
                self._locked()
                before_send()
                if (self._enabled is not True or self._read(phase + ".claim.json") != claim
                        or self._current(allow_consumed=True) != (current, anchors)):
                    raise ValueError
                if not issued <= self._now() < expires_at:
                    raise ValueError

            if phase == "create":
                body = self._body()
            payload = self._request("POST" if phase == "create" else "DELETE",
                _PATH if phase == "create" else self._delete_path(), body=body, guard=guard,
                deadline=expires_at, capture_name=phase + "-response.json")
            ack = {"context": self._context(), "claim_digest": _digest(claim), "response": self._ack(payload, phase)}
            self._write_once(phase + "-ack.json", ack)
            record = self._snapshot(exists=phase == "create")
            if phase == "create":
                self._write_once("created.json", {"context": self._context(), "claim_digest": _digest(claim),
                    "ack_digest": _digest(ack), "record": record})
            else:
                if self._anchors() != anchors:
                    raise ValueError
                self._write_once("deleted.json", {"context": self._context(), "claim_digest": _digest(claim),
                    "ack_digest": _digest(ack), "anchors": anchors, "absent": True})
        except Exception:
            raise InstructionProfileHttpTransportError(_UNAVAILABLE) from None
        finally:
            if body is not None:
                _zeroize_mutable(body)

    def inspect_postcondition(self) -> str:
        try:
            self._locked()
            self._plan()
            anchors = self._anchors()
            if self._phase == "create":
                if self._snapshot(exists=True) != self._read("created.json")["record"]:
                    raise ValueError
            else:
                claim, ack, deleted = (self._read(name) for name in ("delete.claim.json", "delete-ack.json", "deleted.json"))
                self._ack(ack.get("response"), "delete")
                if (claim.get("context") != self._context() or claim.get("phase") != "delete"
                        or claim.get("anchors") != anchors or ack.get("context") != self._context()
                        or ack.get("claim_digest") != _digest(claim)
                        or deleted != {"context": self._context(), "claim_digest": _digest(claim),
                            "ack_digest": _digest(ack), "anchors": anchors, "absent": True}):
                    raise ValueError
                self._snapshot(exists=False)
            return self.expected_state_digest()
        except Exception:
            raise InstructionProfileHttpTransportError(_UNAVAILABLE) from None
