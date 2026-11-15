"""Fixed native single-member ZTNA group creation and original-owned recovery."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import hashlib
from http.cookies import SimpleCookie
import json
import re
from typing import Any
from urllib.parse import quote, urlencode
from uuid import UUID

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan
from v4_planning.execution_kernel import _require_m4_dispatch_ownership

from .crl_import_transport import _frame, digest
from .ldap_server_projection import _members
from .local_user_reset_fixture_preflight import _actor_context
from .m4_execution_store import PersistentM4ExecutionStateStore
from .owner_session_metadata import OwnerSessionMetadataTransport
from .target_api_dependency_reader import _private_http_logs

CONTRACT = "fortipam-700-build29-owned-single-tag-group-v2"
COLLECTION = "/api/v2/cmdb/firewall/addrgrp"
TAGS = "/api/v2/cmdb/firewall/address?format=name%7Ctype%7Csub-type&with_meta=true"
_ERROR = "The fixed ZTNA group lifecycle is unavailable."
_FIELDS = {"name": "string", "uuid": "uuid", "member": "table", "comment": "var-string",
    "type": "option", "category": "option", "color": "integer", "tagging": "table",
    "exclude": "option", "exclude-member": "table", "allow-routing": "option", "fabric-object": "option"}
_META = {"q_origin_key", "q_class", "q_global_entry", "q_mkey_type", "q_name", "q_no_edit", "q_no_rename",
    "q_path", "q_ref", "q_static", "q_type"}
_ZERO_UUID = "00000000-0000-0000-0000-000000000000"


def tag_projection(frame: dict[str, Any]) -> list[dict[str, str]]:
    rows = frame["results"]
    if (type(rows) is not list or len(rows) >= 200 or frame.get("limit_reached", False) is not False
            or frame.get("matched_count", len(rows)) != len(rows)):
        raise ValueError(_ERROR)
    projected = []
    for row in rows:
        if (type(row) is not dict or set(row) - _META != {"name", "type", "sub-type"}
                or any(type(row[key]) is not str for key in ("name", "type", "sub-type"))
                or not row["name"] or len(row["name"]) > 79
                or row.get("q_origin_key", row["name"]) != row["name"]):
            raise ValueError(_ERROR)
        projected.append({key: row[key] for key in ("name", "type", "sub-type")})
    if len({row["name"] for row in projected}) != len(projected):
        raise ValueError(_ERROR)
    return sorted(projected, key=lambda row: row["name"])


def validate_defaults(defaults: dict[str, Any]) -> None:
    expected = {"name": "", "uuid": _ZERO_UUID, "member": [], "comment": "", "type": "default",
        "category": "default", "color": 0, "tagging": [], "exclude": "disable", "exclude-member": [],
        "allow-routing": "disable", "fabric-object": "disable"}
    if defaults != expected or type(defaults["color"]) is not int:
        raise ValueError(_ERROR)


def configured_group(row: dict[str, Any]) -> dict[str, Any]:
    """Preserve persisted fields and identity, excluding derived UI hints."""
    if (type(row) is not dict or set(row) - _META != set(_FIELDS)
            or type(row["name"]) is not str or not row["name"] or len(row["name"]) > 79
            or row.get("q_origin_key", row["name"]) != row["name"]
            or type(row["uuid"]) is not str or str(UUID(row["uuid"])) != row["uuid"] or row["uuid"] == _ZERO_UUID
            or type(row.get("q_global_entry", False)) is not bool or type(row["member"]) is not list or len(row["member"]) > 128):
        raise ValueError(_ERROR)
    result = {key: json.loads(json.dumps(row[key])) for key in _FIELDS}
    members = []
    for member in row["member"]:
        if (type(member) is not dict or set(member) - _META != {"name"} or type(member["name"]) is not str
                or not member["name"] or len(member["name"]) > 79 or member.get("q_origin_key", member["name"]) != member["name"]):
            raise ValueError(_ERROR)
        members.append({"name": member["name"]})
    result["member"] = members
    result["_global_entry"] = row.get("q_global_entry", False)
    return result


class NativeZtnaGroupTransport:
    """A private fixed name/member and preserved initial group table; no EMS dispatch."""

    def __init__(self, *, owner_factory: Callable[[], OwnerSessionMetadataTransport], owner_name: str, serial: str,
                 name: str, member: str, nonce: str, schema_digest: str, defaults: dict[str, Any],
                 tags_digest: str, baseline_groups: list[dict[str, Any]] | None = None) -> None:
        if (not callable(owner_factory) or any(type(value) is not str or not value for value in (owner_name, serial, name, member))
                or re.fullmatch(r"[a-f0-9]{16}", nonce) is None or name != "mcp-v4-ztna-" + nonce
                or not 1 <= len(member) <= 79 or any(ord(c) < 32 or ord(c) == 127 for c in member)
                or any(re.fullmatch(r"[a-f0-9]{64}", value) is None for value in (schema_digest, tags_digest))):
            raise ValueError(_ERROR)
        validate_defaults(defaults)
        if baseline_groups is not None and (type(baseline_groups) is not list or len(baseline_groups) > 32):
            raise ValueError(_ERROR)
        original = [configured_group(row) for row in baseline_groups or []]
        if any(row["name"] == name for row in original) or len({row["name"] for row in original}) != len(original):
            raise ValueError(_ERROR)
        self._original_groups = sorted(original, key=lambda row: row["name"])
        self._factory, self._owner, self._serial, self._name, self._member = owner_factory, owner_name, serial, name, member
        self._schema, self._tags, self._defaults = schema_digest, tags_digest, json.loads(json.dumps(defaults))
        self._body = dict(self._defaults, name=name, category="ztna-ems-tag",
            member=[{"name": member, "q_origin_key": member, "datasource": "firewall.address"}])
        self.parameters_digest = digest({"contract": CONTRACT, "nonce": nonce, "owner": owner_name,
            "serial": serial, "schema": schema_digest, "tags": tags_digest, "body": self._body,
            "original_groups": self._original_groups})
        self._baseline = digest({"parameters": self.parameters_digest, "original_group_snapshot_verified": True})
        self._expected = digest({"parameters": self.parameters_digest, "original": self._baseline,
                                 "one_native_group_verified": True})
        self._created: dict[str, Any] | None = None
        self._ack_digest: str | None = None
        self._qtype: int | None = None
        self._attempted = {"create": False, "recover": False}

    @contextmanager
    def _session(self) -> Iterator[Any]:
        owner = self._factory()
        try:
            with _private_http_logs(), owner.authenticated():
                raw = self._request(owner._client, "GET", "/api/v2/monitor/web-ui/state")
                try:
                    top = _members(raw, (0, len(raw)))
                    if json.loads(raw[slice(*top["serial"])]) != self._serial:
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
        object_path = COLLECTION + "/" + quote(self._name, safe="")
        usage = "/api/v2/monitor/system/object/usage?" + urlencode({"mkey": self._name,
            "qtypes": json.dumps([self._qtype], separators=(",", ":"))})
        fixed_gets = {"/api/v2/monitor/web-ui/state", COLLECTION + "?action=schema&with_meta=true",
            COLLECTION + "?action=default&with_meta=true", COLLECTION + "?with_meta=true", TAGS,
            "/api/v2/monitor/web-ui/object-urls"}
        if method == "GET":
            if path not in fixed_gets and not (self._created is not None and self._qtype is not None and path == usage):
                raise ValueError(_ERROR)
        elif not (method == "POST" and path == COLLECTION and body is not None
                  or method == "DELETE" and self._created is not None and path == object_path and body is None):
            raise ValueError(_ERROR)
        headers = {"Accept-Encoding": "identity", "Cache-Control": "no-cache, no-store"}
        if method != "GET":
            if guard is None:
                raise ValueError(_ERROR)
            cookies = SimpleCookie(); cookies.load(client.build_request("GET", path).headers.get("cookie", ""))
            csrf = cookies.get("ccsrftoken")
            if csrf is None or not csrf.value or len(csrf.value) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in csrf.value):
                raise ValueError(_ERROR)
            headers.update({"X-CSRFTOKEN": csrf.value, "Content-Type": "application/json"}); guard()
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
            raw[:] = bytes(len(raw)); raise ValueError(_ERROR) from None

    def _json(self, client: Any, path: str, *, name: str = "addrgrp", table: str = "firewall") -> dict[str, Any]:
        raw = self._request(client, "GET", path)
        try:
            return _frame(raw, self._serial, method="GET", path=table, name=name)
        finally:
            raw[:] = bytes(len(raw))

    def _observe(self, client: Any) -> list[dict[str, Any]]:
        schema = self._json(client, COLLECTION + "?action=schema&with_meta=true")["results"]["children"]
        if ({key: field.get("type", "table") for key, field in schema.items()} != _FIELDS
                or digest(schema) != self._schema or schema["name"].get("size") != 79
                or schema["name"].get("required") is not True or schema["member"].get("required") is not True
                or set(schema["member"]["children"]) != {"name"}):
            raise ValueError(_ERROR)
        defaults = self._json(client, COLLECTION + "?action=default&with_meta=true")["results"]
        validate_defaults(defaults)
        if defaults != self._defaults:
            raise ValueError(_ERROR)
        tags = tag_projection(self._json(client, TAGS, name="address"))
        if digest(tags) != self._tags or not any(row == {"name": self._member, "type": "dynamic", "sub-type": "ems-tag"} for row in tags):
            raise ValueError(_ERROR)
        table = self._json(client, COLLECTION + "?with_meta=true")
        rows = table["results"]
        if (type(rows) is not list or len(rows) > len(self._original_groups) + 1 or table.get("limit_reached", False) is not False
                or table.get("matched_count", len(rows)) != len(rows)):
            raise ValueError(_ERROR)
        own = [row for row in rows if row.get("name") == self._name]
        other = sorted((configured_group(row) for row in rows if row.get("name") != self._name), key=lambda row: row["name"])
        if len(own) > 1 or other != self._original_groups:
            raise ValueError(_ERROR)
        return own

    def _verify_created(self, rows: list[dict[str, Any]], *, first: bool = False) -> None:
        if len(rows) != 1:
            raise ValueError(_ERROR)
        row = rows[0]
        if (type(row) is not dict or set(row) - _META != set(_FIELDS) or row["name"] != self._name
                or any(row[key] != self._body[key] for key in _FIELDS if key not in {"uuid", "member"})
                or type(row["uuid"]) is not str or str(UUID(row["uuid"])) != row["uuid"] or row["uuid"] == _ZERO_UUID
                or type(row["member"]) is not list or len(row["member"]) != 1):
            raise ValueError(_ERROR)
        member = row["member"][0]
        if (type(member) is not dict or set(member) - _META != {"name"} or member["name"] != self._member
                or member.get("q_origin_key", self._member) != self._member):
            raise ValueError(_ERROR)
        actual = configured_group(row)
        if actual["_global_entry"] is not False:
            raise ValueError(_ERROR)
        if first:
            self._created = actual
        elif actual != self._created:
            raise ValueError(_ERROR)

    def _zero_references(self, client: Any) -> None:
        if self._created is None:
            raise ValueError(_ERROR)
        lookup = self._json(client, "/api/v2/monitor/web-ui/object-urls", name="object-urls", table="web-ui")
        matches = [key for key, value in lookup["results"]["by_type"].items() if value.get("path") == "firewall.addrgrp"]
        if len(matches) != 1 or re.fullmatch(r"0|[1-9][0-9]{0,8}", matches[0]) is None:
            raise ValueError(_ERROR)
        qtype = int(matches[0])
        if self._qtype is not None and self._qtype != qtype:
            raise ValueError(_ERROR)
        self._qtype = qtype
        usage = self._json(client, "/api/v2/monitor/system/object/usage?" + urlencode({"mkey": self._name,
            "qtypes": json.dumps([qtype], separators=(",", ":"))}), name="object", table="system")
        if usage.get("mkey") != self._name or usage["results"].get("currently_using") != []:
            raise ValueError(_ERROR)

    def inspect(self, phase: str) -> tuple[str, str]:
        if phase not in self._attempted or self._attempted[phase]:
            raise ValueError(_ERROR)
        with self._session() as client:
            rows = self._observe(client)
            if phase == "create":
                if rows or self._created is not None:
                    raise ValueError(_ERROR)
                return self._baseline, self._expected
            if self._created is None or self._ack_digest is None:
                raise ValueError(_ERROR)
            self._verify_created(rows); self._zero_references(client)
            return self._expected, self._baseline

    def dispatch(self, phase: str, *, current_digest: str, plan: M4ExecutionPlan,
                 authorization: M4ExecutionAuthorization, store: PersistentM4ExecutionStateStore,
                 guard: Callable[[], None]) -> None:
        if (phase not in self._attempted or self._attempted[phase] or plan.action_id != "ztna-group-native-" + phase
                or plan.adapter_ref != CONTRACT or plan.parameters_digest != self.parameters_digest
                or plan.expected_current_digest != current_digest):
            raise ValueError(_ERROR)
        _require_m4_dispatch_ownership(plan, authorization, store)
        def final_guard() -> None:
            guard(); _require_m4_dispatch_ownership(plan, authorization, store)
        with self._session() as client:
            rows = self._observe(client)
            if phase == "create":
                if rows:
                    raise ValueError(_ERROR)
                method, path, body = "POST", COLLECTION, json.dumps(self._body, separators=(",", ":")).encode()
            else:
                self._verify_created(rows); self._zero_references(client)
                method, path, body = "DELETE", COLLECTION + "/" + quote(self._name, safe=""), None
            final_guard(); self._attempted[phase] = True
            raw = self._request(client, method, path, body=body, guard=final_guard)
            try:
                ack = _frame(raw, self._serial, method=method, path="firewall", name="addrgrp")
                if ack.get("mkey") != self._name:
                    raise ValueError(_ERROR)
                if phase == "create":
                    self._ack_digest = hashlib.sha256(raw).hexdigest()
            finally:
                raw[:] = bytes(len(raw))

    def postcondition(self, phase: str) -> str:
        if phase not in self._attempted or not self._attempted[phase]:
            raise ValueError(_ERROR)
        with self._session() as client:
            rows = self._observe(client)
            if phase == "create":
                if self._ack_digest is None:
                    raise ValueError(_ERROR)
                self._verify_created(rows, first=True); self._zero_references(client)
                return self._expected
            if rows:
                raise ValueError(_ERROR)
            return self._baseline
