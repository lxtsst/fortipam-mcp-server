"""Fixed native timeout update on one connected existing build29 EMS connector."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import hashlib
from http.cookies import SimpleCookie
import re
from typing import Any
from urllib.parse import quote, urlencode

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from .crl_import_transport import _frame, _token, digest
from .ldap_server_projection import _members
from .local_user_reset_fixture_preflight import _actor_context
from .m4_execution_store import PersistentM4ExecutionStateStore
from .owner_session_metadata import OwnerSessionMetadataTransport
from .target_api_dependency_reader import _private_http_logs

CONTRACT = "fortipam-700-build29-owned-ems-timeout-v1"
COLLECTION = "/api/v2/cmdb/endpoint-control/fctems"
STATUS = "/api/v2/monitor/endpoint-control/ems/status"
_ERROR = "The fixed EMS timeout lifecycle is unavailable."
_FIELDS = {"call-timeout": "integer", "capabilities": "option", "cloud-server-type": "option",
    "fortinetone-cloud-authentication": "option", "https-port": "integer", "name": "string",
    "preserve-ssl-session": "option", "pull-avatars": "option", "pull-malware-hash": "option",
    "pull-sysinfo": "option", "pull-tags": "option", "pull-vulnerabilities": "option",
    "server": "string", "source-ip": "ipv4-address-any", "websocket-override": "option"}
_Q_FIELDS = {"q_origin_key", "q_ref", "q_static", "q_global_entry", "q_mkey_type", "q_name",
    "q_no_edit", "q_no_rename", "q_path", "q_type"}
# Native readback also carries the existing trust fingerprint outside the schema.
_READ_FIELDS = {**_FIELDS, "certificate-fingerprint": "string"}


def connector_projection(rows: object) -> list[dict[str, Any]]:
    if type(rows) is not list or not 1 <= len(rows) <= 16:
        raise ValueError(_ERROR)
    result = []
    for row in rows:
        if (type(row) is not dict or set(row) - _Q_FIELDS != set(_READ_FIELDS)
                or any(type(row[key]) is not (int if kind == "integer" else str) for key, kind in _READ_FIELDS.items())
                or not row["name"] or len(row["name"]) > 79
                or row.get("q_origin_key", row["name"]) != row["name"]
                or type(row.get("q_global_entry", False)) is not bool
                or type(row.get("q_ref", 0)) is not int or row.get("q_ref", 0) < 0):
            raise ValueError(_ERROR)
        result.append({**{key: row[key] for key in _READ_FIELDS},
            "q_global_entry": row.get("q_global_entry", False), "q_ref": row.get("q_ref", 0)})
    if len({row["name"] for row in result}) != len(result):
        raise ValueError(_ERROR)
    return sorted(result, key=lambda row: row["name"])


class EmsTimeoutTransport:
    """One pruned field PUT and original-ACK restoration; no EMS authorization."""

    def __init__(self, *, owner_factory: Callable[[], OwnerSessionMetadataTransport],
                 owner_name: str, serial: str, name: str, nonce: str,
                 schema_digest: str, baseline_rows: list[dict[str, Any]]) -> None:
        if (not callable(owner_factory) or any(type(v) is not str or not v for v in (owner_name, serial, name))
                or type(nonce) is not str or re.fullmatch(r"[a-f0-9]{16}", nonce) is None
                or type(schema_digest) is not str or re.fullmatch(r"[a-f0-9]{64}", schema_digest) is None):
            raise ValueError(_ERROR)
        self._factory, self._owner, self._serial, self._name = owner_factory, owner_name, serial, name
        self._schema = schema_digest
        self._baseline = connector_projection(baseline_rows)
        selected = [row for row in self._baseline if row["name"] == name]
        if len(selected) != 1 or selected[0]["call-timeout"] != 30:
            raise ValueError(_ERROR)
        self._changed = [dict(row, **{"call-timeout": 31}) if row["name"] == name else dict(row) for row in self._baseline]
        self.parameters_digest = digest({"contract": CONTRACT, "nonce": nonce, "serial": serial,
            "owner_digest": hashlib.sha256(owner_name.encode()).hexdigest(), "name": name,
            "schema": schema_digest, "baseline": self._baseline, "timeout": [30, 31]})
        self._initial_digest = digest({"contract": CONTRACT, "rows": self._baseline, "connected": True})
        self._changed_digest = digest({"contract": CONTRACT, "rows": self._changed, "connected": True})
        self._attempted = {"update": False, "recover": False}
        self._ack_digest: str | None = None

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

    def _request(self, client: Any, method: str, path: str, *,
                 body: bytes | None = None, guard: Callable[[], None] | None = None) -> bytearray:
        allowed = {"/api/v2/monitor/web-ui/state", COLLECTION + "?action=schema&with_meta=true",
            COLLECTION + "?with_meta=true", STATUS + "?" + urlencode({"ems_name": self._name})}
        if method == "GET":
            if path not in allowed or body is not None:
                raise ValueError(_ERROR)
        elif not (method == "PUT" and path == COLLECTION + "/" + quote(self._name, safe="")
                  and body in {b'{"call-timeout":31}', b'{"call-timeout":30}'} and guard is not None):
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

    def _json(self, client: Any, path: str, *, status: bool = False) -> dict[str, Any]:
        raw = self._request(client, "GET", path)
        try:
            return _frame(raw, self._serial, method="GET", path="endpoint-control", name="ems" if status else "fctems")
        finally:
            raw[:] = bytes(len(raw))

    def _observe(self, client: Any) -> list[dict[str, Any]]:
        schema = self._json(client, COLLECTION + "?action=schema&with_meta=true")["results"]
        children = schema["children"]
        timeout = children["call-timeout"]
        if (schema.get("mkey") != "name" or schema.get("mkey_type") != "string" or schema.get("category") != "table"
                or {key: value["type"] for key, value in children.items()} != _FIELDS
                or digest(schema) != self._schema
                or any(type(timeout.get(key)) is not int or timeout[key] != value for key, value in
                       {"default": 30, "min-value": 1, "max-value": 180}.items())):
            raise ValueError(_ERROR)
        table = self._json(client, COLLECTION + "?with_meta=true")
        rows = connector_projection(table["results"])
        if (table.get("limit_reached", False) is not False
                or table.get("matched_count", len(rows)) != len(rows)):
            raise ValueError(_ERROR)
        state = self._json(client, STATUS + "?" + urlencode({"ems_name": self._name}), status=True)
        if state.get("action") != "status" or state["results"].get("ems_status") != "success":
            raise ValueError(_ERROR)
        return rows

    def inspect(self, phase: str) -> tuple[str, str]:
        if (phase not in self._attempted or self._attempted[phase]
                or phase == "recover" and self._ack_digest is None):
            raise ValueError(_ERROR)
        with self._session() as client:
            rows = self._observe(client)
        if rows != (self._baseline if phase == "update" else self._changed):
            raise ValueError(_ERROR)
        return ((self._initial_digest, self._changed_digest) if phase == "update"
                else (self._changed_digest, self._initial_digest))

    def dispatch(self, phase: str, *, current_digest: str, plan: M4ExecutionPlan,
                 authorization: M4ExecutionAuthorization, store: PersistentM4ExecutionStateStore,
                 guard: Callable[[], None]) -> None:
        if (phase not in self._attempted or self._attempted[phase]
                or plan.action_id != "ems-timeout-native-" + phase or plan.adapter_ref != CONTRACT
                or plan.parameters_digest != self.parameters_digest or plan.expected_current_digest != current_digest):
            raise ValueError(_ERROR)
        _require_m4_dispatch_ownership(plan, authorization, store)
        if self.inspect(phase)[0] != current_digest:
            raise ValueError(_ERROR)
        def final_guard() -> None:
            guard()
            _require_m4_dispatch_ownership(plan, authorization, store)
        with self._session() as client:
            rows = self._observe(client)
            if rows != (self._baseline if phase == "update" else self._changed):
                raise ValueError(_ERROR)
            final_guard()
            self._attempted[phase] = True
            raw = self._request(client, "PUT", COLLECTION + "/" + quote(self._name, safe=""),
                body=b'{"call-timeout":31}' if phase == "update" else b'{"call-timeout":30}', guard=final_guard)
            try:
                ack = _frame(raw, self._serial, method="PUT", path="endpoint-control", name="fctems")
                if ack.get("mkey") != self._name:
                    raise ValueError
                if phase == "update":
                    self._ack_digest = hashlib.sha256(raw).hexdigest()
            finally:
                raw[:] = bytes(len(raw))

    def postcondition(self, phase: str) -> str:
        if phase not in self._attempted or not self._attempted[phase] or self._ack_digest is None:
            raise ValueError(_ERROR)
        with self._session() as client:
            rows = self._observe(client)
        if rows != (self._changed if phase == "update" else self._baseline):
            raise ValueError(_ERROR)
        return self._changed_digest if phase == "update" else self._initial_digest
