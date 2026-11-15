"""Private owned disabled-APL lifecycle; no Tool registration or authorization.

Create reuses the accepted four-field disabled-create implementation. Update
and restore use the native complete-state contract. Each phase consumes its own
durable claim; an original create ACK is required for every later operation.
The caller must hold operation_lock across inspection and authorized dispatch.
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
from .apl_create_http_transport import (
    AplCreateHttpBinding, FortiPamAplCreateHttpTransport,
    BINDING_CONTRACT as LEGACY_CONTRACT,
    _digest as _legacy_digest,
)
from .apl_role_update_contract import (
    AplRoleTransition, AplRoleUpdateBinding, CONFIG_FIELDS, _Private, _digest,
    _require_digest, build_role_transition_body, verify_role_transition,
)
from .ldap_server_http_transport import _Connection
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable,
)

CONTRACT = "fortipam-700-build29-owned-apl-role-transport-v1"
Phase = Literal["create", "update", "restore", "delete"]
_UNAVAILABLE = "The private owned APL role transport is unavailable."
_LIMIT = 4 * 1048576
_PLAN = "creation.plan.json"
_LOCK = "operation.lock"
_RULE_PATH = "/api/v2/cmdb/user/auto-provision-rule"
_ANCHORS = ("create.claim.json", "create-ack.json", "created.json", "legacy-create.claim.json")
_OWNERSHIP = "creation.ownership.json"


class AplRoleUpdateHttpTransportError(RuntimeError):
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


class AplRoleUpdateReadiness(_Private):
    __slots__ = ("state_digest", "observed_at")
    state_digest: str
    observed_at: int

    def __init__(self, state_digest: str, observed_at: int) -> None:
        _require_digest(state_digest)
        object.__setattr__(self, "state_digest", state_digest)
        object.__setattr__(self, "observed_at", _timestamp(observed_at))


class FortiPamAplRoleUpdateHttpTransport(_Private):
    """One original owned fixture, two fixed Role states and four closed phases."""

    __slots__ = ("_config", "_binding", "_phase", "_enabled", "_directory", "_directory_identity",
                 "_serial_digest", "_schema_digest", "_namespace", "_clock", "_last_clock",
                 "_clock_failed", "_factory", "_lock_owner", "_inspected_plan")
    _config: SecretMetadataHttpTransportConfig
    _binding: AplRoleUpdateBinding
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
    _inspected_plan: str | None

    def __init__(self, config: SecretMetadataHttpTransportConfig, binding: AplRoleUpdateBinding, *,
                 serial_digest: str, schema_digest: str, state_directory: Path, phase: Phase,
                 execution_enabled: bool = False, clock: Callable[[], int] | None = None,
                 connection_factory: Callable[..., _Connection] | None = None) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(binding) is not AplRoleUpdateBinding
                    or type(phase) is not str or phase not in {"create", "update", "restore", "delete"}
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
                "_lock_owner": None, "_inspected_plan": None}
            for key, value in values.items():
                object.__setattr__(self, key, value)
        except Exception:
            raise AplRoleUpdateHttpTransportError(_UNAVAILABLE) from None

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

    def _read(self, name: str) -> dict[str, Any]:
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
            raise AplRoleUpdateHttpTransportError(_UNAVAILABLE) from None
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
                 guard: Callable[[], None] | None = None, deadline: int | None = None) -> dict[str, Any] | None:
        response = connection = view = None
        raw = bytearray(_LIMIT + 1)
        try:
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
                "Connection": "close", "Cache-Control": "no-store", "User-Agent": "fortipam-mcp-owned-apl/1"})
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

    def _detail_path(self) -> str:
        return _RULE_PATH + "/" + quote(self._binding.rule_name, safe="") + "?with_meta=true"

    def _detail(self, path: str, name: str, *, absent: bool = False) -> dict[str, Any] | None:
        value = self._request("GET", path)
        if value is None and absent:
            return None
        if value is None:
            raise ValueError
        row = value.get("results")
        if type(row) is list and len(row) == 1:
            row = row[0]
        if type(row) is not dict or row.get("name") != name or row.get("q_origin_key") != name:
            raise ValueError
        return cast(dict[str, Any], row)

    def _components(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        schema = self._request("GET", _RULE_PATH + "?action=schema&with_meta=true")
        if schema is None or hashlib.sha256(json.dumps(schema["results"]["children"], sort_keys=True).encode()).hexdigest() != self._schema_digest:
            raise ValueError
        binding = self._binding
        dependencies = {key: self._detail("/api/v2/cmdb/" + table + "/" + quote(name, safe=""), name)
            for key, table, name in (("group", "user/group", binding.group_name),
                ("original_role", "system/accprofile", binding.original_role),
                ("updated_role", "system/accprofile", binding.updated_role))}
        # These fixed reads omit with_meta; preserve every returned member.
        if any(row is None or set(row) & {"q_ref", "q_static", "q_no_edit", "q_global_entry"}
               for row in dependencies.values()):
            raise ValueError
        collection = self._request("GET", _RULE_PATH)
        if collection is None:
            raise ValueError
        rows = collection.get("results")
        if (type(rows) is not list or len(rows) >= 200 or collection.get("limit_reached", False) is not False
                or any(type(collection.get(key)) is not int or collection[key] != len(rows) for key in ("size", "matched_count"))
                or any(type(row) is not dict or type(row.get("name")) is not str for row in rows)
                or len({row["name"] for row in rows}) != len(rows)):
            raise ValueError
        return rows, dependencies

    def _defaults(self) -> dict[str, Any]:
        result = self._request("GET", _RULE_PATH + "?action=default&with_meta=true")
        if result is None or type(result.get("results")) is not dict or set(result["results"]) != set(CONFIG_FIELDS):
            raise ValueError
        defaults = cast(dict[str, Any], result["results"])
        if (type(defaults["accprofile"]) is not dict
                or any(type(defaults[key]) is not str or len(defaults[key]) > 8192
                       for key in CONFIG_FIELDS if key != "accprofile")
                or defaults["status"] not in {"enable", "disable"}):
            raise ValueError
        return defaults

    def _plan(self) -> dict[str, Any]:
        plan = self._read(_PLAN)
        if (set(plan) != {"contract", "namespace", "binding_digest", "schema_digest", "serial_digest",
                         "dependencies", "original_rules", "defaults", "prepared_at"}
                or plan["contract"] != CONTRACT or plan["namespace"] != self._namespace
                or plan["binding_digest"] != self._binding.digest or plan["schema_digest"] != self._schema_digest
                or plan["serial_digest"] != self._serial_digest or _timestamp(plan["prepared_at"]) > self._now()):
            raise ValueError
        return plan

    def _prepare(self) -> None:
        directory = self._directory_fd()
        try:
            if self._phase != "create" or set(os.listdir(directory)) != {_LOCK}:
                raise ValueError
        finally:
            os.close(directory)
        now = self._now()
        rows, dependencies = self._components()
        if any(row["name"] == self._binding.rule_name for row in rows) or self._detail(self._detail_path(), self._binding.rule_name, absent=True) is not None:
            raise ValueError
        self._write_once(_PLAN, {"contract": CONTRACT, "namespace": self._namespace,
            "binding_digest": self._binding.digest, "schema_digest": self._schema_digest, "serial_digest": self._serial_digest,
            "dependencies": dependencies, "original_rules": rows, "defaults": self._defaults(), "prepared_at": now})

    def _claim(self, phase: Phase, plan: dict[str, Any]) -> dict[str, Any]:
        claim = self._read(phase + ".claim.json")
        if (set(claim) != {"contract", "phase", "state_plan_digest", "plan_digest", "authorization_digest",
                          "current_digest", "claimed_at", "expires_at"}
                or claim["contract"] != CONTRACT or claim["phase"] != phase or claim["state_plan_digest"] != _digest(plan)
                or not 0 < _timestamp(claim["expires_at"]) - _timestamp(claim["claimed_at"]) <= 60
                or _timestamp(claim["claimed_at"]) > self._now()):
            raise ValueError
        for key in ("plan_digest", "authorization_digest", "current_digest"):
            _require_digest(claim[key])
        if claim["current_digest"] != self._fingerprint(plan, after=False, phase=phase):
            raise ValueError
        return claim

    def _ack(self, phase: Phase, plan: dict[str, Any]) -> dict[str, Any]:
        claim, ack = self._claim(phase, plan), self._read(phase + "-ack.json")
        if (set(ack) != {"contract", "phase", "claim_digest", "response_digest", "acknowledged_at"}
                or ack["contract"] != CONTRACT or ack["phase"] != phase or ack["claim_digest"] != _digest(claim)
                or not _timestamp(claim["claimed_at"]) <= _timestamp(ack["acknowledged_at"]) <= self._now()):
            raise ValueError
        _require_digest(ack["response_digest"])
        return ack

    def _creation_records(self, plan: dict[str, Any]) -> dict[str, str]:
        ack = self._ack("create", plan)
        created, legacy = self._read("created.json"), self._read("legacy-create.claim.json")
        if (set(created) != {"claim_digest", "ack_digest", "legacy_claim_digest", "record", "ordered_rules", "transition_digest"}
                or created["claim_digest"] != ack["claim_digest"] or created["ack_digest"] != _digest(ack)
                or created["legacy_claim_digest"] != _digest(legacy)
                or set(legacy) != {"contract", "state", "baseline_digest", "binding_digest"}
                or legacy["contract"] != LEGACY_CONTRACT or legacy["state"] != "post_attempt_reserved"):
            raise ValueError
        _require_digest(legacy["baseline_digest"])
        expected_binding = _legacy_digest([self._binding.rule_name, self._binding.group_name, self._binding.original_role])
        expected_baseline = _legacy_digest([{row["name"]: row for row in plan["original_rules"]},
            plan["dependencies"]["group"], plan["dependencies"]["original_role"]])
        if (legacy["binding_digest"] != expected_binding or legacy["baseline_digest"] != expected_baseline
                or self._transition(plan, created["record"]).digest != created["transition_digest"]):
            raise ValueError
        return {name: _digest(self._read(name)) for name in _ANCHORS}

    def _anchors(self, plan: dict[str, Any]) -> dict[str, str]:
        anchors = self._creation_records(plan)
        ownership = self._read(_OWNERSHIP)
        if ownership != {"contract": CONTRACT, "state_plan_digest": _digest(plan), "creation_anchors": anchors}:
            raise ValueError
        return {**anchors, _OWNERSHIP: _digest(ownership)}

    def _transition(self, plan: dict[str, Any], record: Mapping[str, object]) -> AplRoleTransition:
        return AplRoleTransition(record, self._binding, **self._context(plan))

    def _context(self, plan: dict[str, Any]) -> dict[str, str]:
        return {"schema_digest": self._schema_digest, "serial_digest": self._serial_digest,
                "dependencies_digest": _digest(plan["dependencies"])}

    def _unused(self, plan: dict[str, Any]) -> None:
        forbidden: tuple[str, ...] = (self._phase,)
        if self._phase == "create":
            forbidden = ("create", "update", "restore", "delete")
        elif self._phase == "update":
            forbidden = ("update", "restore", "delete")
        elif self._phase == "restore":
            forbidden = ("restore", "delete")
            self._ack("update", plan)
        if any(os.path.lexists(self._directory / (phase + suffix)) for phase in forbidden
               for suffix in (".claim.json", "-ack.json", "-verified.json")):
            raise ValueError
        if self._phase != "create":
            self._anchors(plan)
        if self._phase == "delete" and os.path.lexists(self._directory / "update.claim.json"):
            self._verified("restore", plan)

    def _fingerprint(self, plan: dict[str, Any], *, after: bool, phase: Phase | None = None) -> str:
        phase = phase or self._phase
        label = {"create": ("absent", "original"), "update": ("original", "updated"),
                 "restore": ("updated", "original"), "delete": ("original", "absent")}[phase][after]
        return _digest({"contract": CONTRACT, "namespace": self._namespace, "phase": phase,
                        "plan": _digest(plan), "state": label,
                        "ownership": None if phase == "create" else self._anchors(plan)})

    def _fresh(self, plan: dict[str, Any], *, after: bool = False) -> dict[str, Any] | None:
        rows, dependencies = self._components()
        if _digest(dependencies) != _digest(plan["dependencies"]):
            raise ValueError
        absent = (self._phase == "create" and not after) or (self._phase == "delete" and after)
        record = self._detail(self._detail_path(), self._binding.rule_name, absent=absent)
        if absent:
            if record is not None or _digest(rows) != _digest(plan["original_rules"]):
                raise ValueError
            if self._phase == "create" and _digest(self._defaults()) != _digest(plan["defaults"]):
                raise ValueError
            return None
        if record is None:
            raise ValueError
        created = self._read("created.json")
        self._anchors(plan)
        updated = (self._phase == "update" and after) or (self._phase == "restore" and not after)
        expected = dict(created["record"], accprofile=self._binding.updated_role if updated else self._binding.original_role)
        expected_rows = [dict(row, accprofile=expected["accprofile"]) if row["name"] == self._binding.rule_name else row
                         for row in created["ordered_rules"]]
        if _digest(record) != _digest(expected) or _digest(rows) != _digest(expected_rows):
            raise ValueError
        verify_role_transition(record, self._transition(plan, created["record"]),
                               phase="update" if updated else "restore", **self._context(plan))
        return record

    def inspect_current(self) -> AplRoleUpdateReadiness:
        try:
            self._locked()
            now = self._now()
            if not os.path.lexists(self._directory / _PLAN):
                self._prepare()
            plan = self._plan()
            self._unused(plan)
            self._fresh(plan)
            if not 0 <= self._now() - now < 60:
                raise ValueError
            object.__setattr__(self, "_inspected_plan", _digest(plan))
            return AplRoleUpdateReadiness(self._fingerprint(plan, after=False), now)
        except Exception:
            raise AplRoleUpdateHttpTransportError(_UNAVAILABLE) from None

    def expected_state_digest(self) -> str:
        try:
            self._locked()
            plan = self._plan()
            if self._inspected_plan != _digest(plan):
                raise ValueError
            return self._fingerprint(plan, after=True)
        except Exception:
            raise AplRoleUpdateHttpTransportError(_UNAVAILABLE) from None

    def _persist_ack(self, payload: dict[str, Any] | None, claim: dict[str, Any]) -> None:
        if payload is None or type(payload.get("mkey")) is not str or payload["mkey"] != self._binding.rule_name:
            raise ValueError
        self._write_once(self._phase + "-ack.json", {"contract": CONTRACT, "phase": self._phase,
            "claim_digest": _digest(claim), "response_digest": _digest(payload), "acknowledged_at": self._now()})

    def _create(self, plan: dict[str, Any], claim: dict[str, Any], guard: Callable[[], None], deadline: int) -> None:
        owner = self

        class OwnedCreate(FortiPamAplCreateHttpTransport):
            def _request(self, method: Literal["GET", "POST"], path: str, table: str,
                         key: str | None, body: dict[str, str] | None) -> Mapping[str, object]:
                route = "/api/v2/cmdb/" + path + "/" + table + ("" if key is None else "/" + quote(key, safe=""))
                raw = bytearray(json.dumps(body, separators=(",", ":")).encode()) if body is not None else None
                try:
                    response = owner._request(method, route, body=raw, guard=guard, deadline=deadline)
                    if response is None:
                        raise ValueError
                    if method == "POST":
                        owner._persist_ack(response, claim)
                    return response
                finally:
                    if raw is not None:
                        _zeroize_mutable(raw)

        binding = self._binding
        legacy = OwnedCreate(self._config, AplCreateHttpBinding(binding.rule_name, binding.group_name, binding.original_role),
                            self._directory / "legacy-create.claim.json")
        if not legacy.inspect(binding.rule_name, binding.group_name, binding.original_role).create_baseline_verified:
            raise ValueError
        guard()
        if not legacy.create_disabled_and_readback(binding.rule_name, binding.group_name, binding.original_role).verified:
            raise ValueError
        rows, deps = self._components()
        record = self._detail(self._detail_path(), binding.rule_name)
        expected = dict(plan["defaults"], name=binding.rule_name, status="disable", accprofile=binding.original_role)
        expected["remote-group"] = binding.group_name
        if (record is None or {k: record[k] for k in CONFIG_FIELDS} != expected
                or [row for row in rows if row["name"] != binding.rule_name] != plan["original_rules"]
                or _digest(deps) != _digest(plan["dependencies"])):
            raise ValueError
        transition = self._transition(plan, record)
        if [row for row in rows if row["name"] == binding.rule_name] != [{key: record[key] for key in (*CONFIG_FIELDS, "q_origin_key")}]:
            raise ValueError
        self._write_once("created.json", {"claim_digest": _digest(claim), "ack_digest": _digest(self._ack("create", plan)),
            "legacy_claim_digest": _digest(self._read("legacy-create.claim.json")), "record": record,
            "ordered_rules": rows, "transition_digest": transition.digest})
        self._write_once(_OWNERSHIP, {"contract": CONTRACT, "state_plan_digest": _digest(plan),
                                     "creation_anchors": self._creation_records(plan)})

    def dispatch(self, *, expected_current_digest: str, expires_at: int, plan_digest: str,
                 authorization_digest: str, before_send: Callable[[], None]) -> None:
        body = bytearray()
        try:
            self._locked()
            now = self._now()
            if not self._enabled or type(expires_at) is not int or not 0 < expires_at - now <= 60 or not callable(before_send):
                raise ValueError
            for value in (expected_current_digest, plan_digest, authorization_digest):
                _require_digest(value)
            before_send()
            if self.inspect_current().state_digest != expected_current_digest:
                raise ValueError
            plan = self._plan()
            anchors = self._anchors(plan) if self._phase != "create" else None
            now = self._now()
            if now >= expires_at:
                raise ValueError
            claim = {"contract": CONTRACT, "phase": self._phase, "state_plan_digest": _digest(plan),
                "plan_digest": plan_digest, "authorization_digest": authorization_digest,
                "current_digest": expected_current_digest, "claimed_at": now, "expires_at": expires_at}
            self._write_once(self._phase + ".claim.json", claim)

            def guard() -> None:
                self._locked()
                if not now <= self._now() < expires_at:
                    raise ValueError
                before_send()
                if self._plan() != plan or self._claim(self._phase, plan) != claim:
                    raise ValueError
                if anchors is not None and self._anchors(plan) != anchors:
                    raise ValueError

            guard()
            current = self._fresh(plan)
            if self._phase == "create":
                self._create(plan, claim, guard, expires_at)
            else:
                if self._phase in ("update", "restore"):
                    if current is None:
                        raise ValueError
                    transition = self._transition(plan, self._read("created.json")["record"])
                    body = build_role_transition_body(current, transition, phase=self._phase, **self._context(plan))
                payload = self._request("DELETE" if self._phase == "delete" else "PUT",
                    _RULE_PATH + "/" + quote(self._binding.rule_name, safe=""),
                    body=body if self._phase != "delete" else None, guard=guard, deadline=expires_at)
                _zeroize_mutable(body)
                self._persist_ack(payload, claim)
            after = self._fresh(plan, after=True)
            if self._phase in ("update", "restore") and after is not None:
                verify_role_transition(after, self._transition(plan, self._read("created.json")["record"]),
                                       phase=self._phase, **self._context(plan))
            guard()
            self._write_once(self._phase + "-verified.json", {"contract": CONTRACT, "phase": self._phase,
                "claim_digest": _digest(claim), "state_digest": self._fingerprint(plan, after=True), "verified_at": self._now()})
        except Exception:
            raise AplRoleUpdateHttpTransportError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(body)

    def _verified(self, phase: Phase, plan: dict[str, Any]) -> dict[str, Any]:
        ack, verified = self._ack(phase, plan), self._read(phase + "-verified.json")
        if (set(verified) != {"contract", "phase", "claim_digest", "state_digest", "verified_at"}
                or verified["contract"] != CONTRACT or verified["phase"] != phase
                or verified["claim_digest"] != ack["claim_digest"]
                or verified["state_digest"] != self._fingerprint(plan, after=True, phase=phase)
                or not _timestamp(ack["acknowledged_at"]) <= _timestamp(verified["verified_at"]) <= self._now()):
            raise ValueError
        _require_digest(verified["state_digest"])
        return verified

    def inspect_postcondition(self) -> str:
        try:
            self._locked()
            now = self._now()
            plan = self._plan()
            verified = self._verified(self._phase, plan)
            if verified["state_digest"] != self._fingerprint(plan, after=True):
                raise ValueError
            self._anchors(plan)
            self._fresh(plan, after=True)
            if not 0 <= self._now() - now < 60:
                raise ValueError
            return cast(str, verified["state_digest"])
        except Exception:
            raise AplRoleUpdateHttpTransportError(_UNAVAILABLE) from None
