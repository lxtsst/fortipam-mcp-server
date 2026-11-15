"""Fixed build29 disk-log size update and original-ACK restoration."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import hashlib
from http.cookies import SimpleCookie
from ipaddress import IPv4Address
import re
from typing import Any

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from .crl_import_transport import _token, digest
from .ldap_server_projection import _members, _validate
from .local_user_reset_fixture_preflight import _actor_context
from .m4_execution_store import PersistentM4ExecutionStateStore
from .owner_session_metadata import OwnerSessionMetadataTransport
from .target_api_dependency_reader import _private_http_logs

CONTRACT = "fortipam-700-build29-owned-log-disk-size-v1"
DISK = "/api/v2/cmdb/log.disk/setting"
MEMORY = "/api/v2/cmdb/log.memory/setting"
_ERROR = "The fixed disk-log size lifecycle is unavailable."
_OPAQUE_DOMAIN = b"fortipam-log-disk-size:uploadpass-token:v1\0"
_DISK_FIELDS = {
    "diskfull": "option", "dlp-archive-quota": "integer",
    "full-final-warning-threshold": "integer", "full-first-warning-threshold": "integer",
    "full-second-warning-threshold": "integer", "interface": "string",
    "interface-select-method": "option", "ips-archive": "option", "log-quota": "integer",
    "max-log-file-size": "integer", "max-policy-packet-capture-size": "integer",
    "maximum-log-age": "integer", "report-quota": "integer", "roll-day": "option",
    "roll-schedule": "option", "roll-time": "user", "source-ip": "ipv4-address",
    "status": "option", "upload": "option", "upload-delete-files": "option",
    "upload-destination": "option", "upload-ssl-conn": "option", "uploaddir": "string",
    "uploadip": "ipv4-address", "uploadpass": "password", "uploadport": "integer",
    "uploadsched": "option", "uploadtime": "user", "uploadtype": "option", "uploaduser": "string",
}
_RANGES = {
    "dlp-archive-quota": (0, 4294967295), "full-final-warning-threshold": (3, 100),
    "full-first-warning-threshold": (1, 98), "full-second-warning-threshold": (2, 99),
    "log-quota": (0, 4294967295), "max-log-file-size": (1, 100),
    "max-policy-packet-capture-size": (0, 4294967295), "maximum-log-age": (0, 3650),
    "report-quota": (0, 4294967295), "uploadport": (0, 65535),
}


def _disk_baseline(row: object) -> dict[str, Any]:
    if type(row) is not dict or set(row) != set(_DISK_FIELDS):
        raise ValueError(_ERROR)
    for key, kind in _DISK_FIELDS.items():
        value = row[key]
        if kind == "password":
            if (type(value) is not dict or set(value) != {"opaque_sha256"}
                    or type(value["opaque_sha256"]) is not str
                    or re.fullmatch(r"[a-f0-9]{64}", value["opaque_sha256"]) is None):
                raise ValueError(_ERROR)
        elif kind == "integer":
            if type(value) is not int or not _RANGES[key][0] <= value <= _RANGES[key][1]:
                raise ValueError(_ERROR)
        elif type(value) is not str or len(value.encode("utf-8")) > 4096:
            raise ValueError(_ERROR)
    return {**row, "uploadpass": dict(row["uploadpass"])}


def disk_projection(raw: bytearray, span: tuple[int, int] | None = None) -> dict[str, Any]:
    """Hash the opaque password JSON token without decoding or returning it."""
    try:
        if type(raw) is not bytearray or not 0 < len(raw) <= 1048576:
            raise ValueError
        bounds = (0, len(raw)) if span is None else span
        _validate(raw, bounds)
        fields = _members(raw, bounds)
        if set(fields) != set(_DISK_FIELDS):
            raise ValueError
        opaque = fields["uploadpass"]
        if raw[opaque[0]] != 34:
            raise ValueError
        witness = hashlib.sha256(_OPAQUE_DOMAIN)
        witness.update(memoryview(raw)[opaque[0]:opaque[1]])
        row = {key: _token(raw, value) for key, value in fields.items() if key != "uploadpass"}
        row["uploadpass"] = {"opaque_sha256": witness.hexdigest()}
        return _disk_baseline(row)
    except Exception:
        raise ValueError(_ERROR) from None


def memory_projection(row: object) -> dict[str, str]:
    if type(row) is not dict or set(row) != {"status"} or row["status"] not in {"enable", "disable"}:
        raise ValueError(_ERROR)
    return {"status": row["status"]}


def _envelope(raw: bytearray, serial: str, scope: str, *, method: str = "GET") -> dict[str, tuple[int, int]]:
    _validate(raw, (0, len(raw)))
    top = _members(raw, (0, len(raw)))
    for key, wanted in {"http_method": method, "status": "success", "version": "v7.0.0",
            "build": 29, "serial": serial, "path": scope, "name": "setting", "vdom": "root"}.items():
        actual = _token(raw, top[key])
        if type(actual) is not type(wanted) or actual != wanted:
            raise ValueError(_ERROR)
    if "http_status" in top and (type(_token(raw, top["http_status"])) is not int
            or _token(raw, top["http_status"]) != 200):
        raise ValueError(_ERROR)
    return top


def _ack(raw: bytearray, serial: str) -> None:
    """Verify only fixed ACK metadata; never decode an echoed record."""
    _envelope(raw, serial, "log.disk", method="PUT")


def _schema(schema: object, expected_digest: str, *, disk: bool) -> dict[str, Any]:
    fields = _DISK_FIELDS if disk else {"status": "option"}
    if (type(schema) is not dict or schema.get("category") != "complex"
            or schema.get("mkey") is not None or schema.get("mkey_type") is not None
            or digest(schema) != expected_digest or type(schema.get("children")) is not dict):
        raise ValueError(_ERROR)
    children = schema["children"]
    if (set(children) != set(fields)
            or any(type(children[key]) is not dict or children[key].get("type") != kind
                   for key, kind in fields.items())):
        raise ValueError(_ERROR)
    if disk:
        scalar = children["max-log-file-size"]
        if any(type(scalar.get(key)) is not int or scalar[key] != value
               for key, value in {"default": 20, "min-value": 1, "max-value": 100}.items()):
            raise ValueError(_ERROR)
    return dict(children)


def _validate_values(row: dict[str, Any], children: dict[str, Any]) -> None:
    for key, spec in children.items():
        value, kind = row[key], spec["type"]
        if kind == "integer":
            if not spec["min-value"] <= value <= spec["max-value"]:
                raise ValueError(_ERROR)
        elif kind == "option":
            choices = {option["name"] for option in spec["options"]}
            values = value.split(" ") if spec.get("multiple_values") is True and value else [value]
            if not values or len(values) != len(set(values)) or any(item not in choices for item in values):
                raise ValueError(_ERROR)
        elif kind == "string" and "size" in spec:
            if len(value.encode("utf-8")) > spec["size"]:
                raise ValueError(_ERROR)
        elif kind == "ipv4-address":
            if str(IPv4Address(value)) != value:
                raise ValueError(_ERROR)


class LoggingDiskSizeTransport:
    """Keep both singleton baselines exact while changing only one scalar."""

    def __init__(self, *, owner_factory: Callable[[], OwnerSessionMetadataTransport],
                 owner_name: str, serial: str, nonce: str, disk_schema_digest: str,
                 memory_schema_digest: str, baseline_disk: dict[str, Any], baseline_memory: dict[str, Any]) -> None:
        if (not callable(owner_factory) or any(type(v) is not str or not v for v in (owner_name, serial))
                or type(nonce) is not str or re.fullmatch(r"[a-f0-9]{16}", nonce) is None
                or any(type(v) is not str or re.fullmatch(r"[a-f0-9]{64}", v) is None
                       for v in (disk_schema_digest, memory_schema_digest))):
            raise ValueError(_ERROR)
        self._factory, self._owner, self._serial = owner_factory, owner_name, serial
        self._schemas = {DISK: disk_schema_digest, MEMORY: memory_schema_digest}
        self._baseline_disk, self._baseline_memory = _disk_baseline(baseline_disk), memory_projection(baseline_memory)
        if (self._baseline_disk["max-log-file-size"] != 20 or self._baseline_disk["status"] != "enable"
                or self._baseline_memory["status"] != "disable"):
            raise ValueError(_ERROR)
        self._changed_disk = {**self._baseline_disk, "max-log-file-size": 21}
        self.parameters_digest = digest({"contract": CONTRACT, "nonce": nonce, "serial": serial,
            "owner_digest": hashlib.sha256(owner_name.encode()).hexdigest(), "schemas": self._schemas,
            "disk": self._baseline_disk, "memory": self._baseline_memory, "size": [20, 21]})
        self._initial_digest = self._state_digest(self._baseline_disk, self._baseline_memory)
        self._changed_digest = self._state_digest(self._changed_disk, self._baseline_memory)
        self._attempted = {"update": False, "recover": False}
        self._acks: dict[str, str] = {}

    @property
    def _ack_digest(self) -> str | None:
        return self._acks.get("update")

    @staticmethod
    def _state_digest(disk: dict[str, Any], memory: dict[str, Any]) -> str:
        return digest({"contract": CONTRACT, "disk": disk, "memory": memory})

    @contextmanager
    def _session(self) -> Iterator[Any]:
        owner = self._factory()
        try:
            with _private_http_logs(), owner.authenticated():
                raw = self._request(owner._client, "GET", "/api/v2/monitor/web-ui/state")
                try:
                    top = _members(raw, (0, len(raw)))
                    if _token(raw, top["serial"]) != self._serial:
                        raise ValueError
                    _actor_context(raw, expected_name=self._owner)
                finally:
                    raw[:] = bytes(len(raw))
                yield owner._client
            if not owner.logout_verified:
                raise ValueError
        except Exception:
            raise ValueError(_ERROR) from None

    def _request(self, client: Any, method: str, path: str, *, body: bytes | None = None,
                 guard: Callable[[], None] | None = None) -> bytearray:
        allowed = {"/api/v2/monitor/web-ui/state", *(route + query for route in (DISK, MEMORY)
            for query in ("?action=schema&with_meta=true", "?with_meta=true"))}
        if method == "GET":
            if path not in allowed or body is not None:
                raise ValueError(_ERROR)
        elif not (method == "PUT" and path == DISK and body in {
                b'{"max-log-file-size":21}', b'{"max-log-file-size":20}'} and guard is not None):
            raise ValueError(_ERROR)
        headers = {"Accept-Encoding": "identity", "Cache-Control": "no-cache, no-store"}
        if method == "PUT":
            cookies = SimpleCookie()
            cookies.load(client.build_request("GET", path).headers.get("cookie", ""))
            csrf = cookies.get("ccsrftoken")
            if csrf is None or not csrf.value or len(csrf.value) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in csrf.value):
                raise ValueError(_ERROR)
            headers.update({"X-CSRFTOKEN": csrf.value, "Content-Type": "application/json"})
            assert guard is not None
            guard()
        raw = bytearray()
        try:
            with client.stream(method, path, content=body, headers=headers) as response:
                if response.status_code != 200 or response.headers.get("content-encoding", "identity") != "identity":
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > 1048576:
                        raise ValueError
                    raw.extend(chunk)
            return raw
        except Exception:
            raw[:] = bytes(len(raw))
            raise ValueError(_ERROR) from None

    def _observe(self, client: Any) -> tuple[dict[str, Any], dict[str, str]]:
        states: list[dict[str, Any]] = []
        for route in (DISK, MEMORY):
            scope = "log.disk" if route == DISK else "log.memory"
            raw = self._request(client, "GET", route + "?action=schema&with_meta=true")
            try:
                top = _envelope(raw, self._serial, scope)
                children = _schema(_token(raw, top["results"]), self._schemas[route], disk=route == DISK)
            finally:
                raw[:] = bytes(len(raw))
            raw = self._request(client, "GET", route + "?with_meta=true")
            try:
                top = _envelope(raw, self._serial, scope)
                row = (disk_projection(raw, top["results"]) if route == DISK
                       else memory_projection(_token(raw, top["results"])))
                _validate_values(row, children)
                states.append(row)
            finally:
                raw[:] = bytes(len(raw))
        return states[0], states[1]

    def inspect(self, phase: str) -> tuple[str, str]:
        if (phase not in self._attempted or self._attempted[phase]
                or phase == "recover" and "update" not in self._acks):
            raise ValueError(_ERROR)
        with self._session() as client:
            disk, memory = self._observe(client)
        if disk != (self._baseline_disk if phase == "update" else self._changed_disk) or memory != self._baseline_memory:
            raise ValueError(_ERROR)
        return ((self._initial_digest, self._changed_digest) if phase == "update"
                else (self._changed_digest, self._initial_digest))

    def dispatch(self, phase: str, *, current_digest: str, plan: M4ExecutionPlan,
                 authorization: M4ExecutionAuthorization, store: PersistentM4ExecutionStateStore,
                 guard: Callable[[], None]) -> None:
        if (phase not in self._attempted or self._attempted[phase]
                or phase == "recover" and "update" not in self._acks
                or plan.action_id != "logging-disk-size-native-" + phase or plan.adapter_ref != CONTRACT
                or plan.parameters_digest != self.parameters_digest or plan.expected_current_digest != current_digest
                or current_digest != (self._initial_digest if phase == "update" else self._changed_digest)):
            raise ValueError(_ERROR)
        _require_m4_dispatch_ownership(plan, authorization, store)
        def final_guard() -> None:
            guard()
            _require_m4_dispatch_ownership(plan, authorization, store)
        with self._session() as client:
            disk, memory = self._observe(client)
            if disk != (self._baseline_disk if phase == "update" else self._changed_disk) or memory != self._baseline_memory:
                raise ValueError(_ERROR)
            final_guard()
            self._attempted[phase] = True
            raw = self._request(client, "PUT", DISK, guard=final_guard,
                body=b'{"max-log-file-size":21}' if phase == "update" else b'{"max-log-file-size":20}')
            try:
                _ack(raw, self._serial)
                self._acks[phase] = hashlib.sha256(raw).hexdigest()
            finally:
                raw[:] = bytes(len(raw))

    def postcondition(self, phase: str) -> str:
        if phase not in self._attempted or not self._attempted[phase] or phase not in self._acks:
            raise ValueError(_ERROR)
        with self._session() as client:
            disk, memory = self._observe(client)
        if disk != (self._changed_disk if phase == "update" else self._baseline_disk) or memory != self._baseline_memory:
            raise ValueError(_ERROR)
        return self._changed_digest if phase == "update" else self._initial_digest
