"""Fixed protected role/admin metadata channel and fresh complete observations.

No configuration route or caller-selected query is admitted. The native Admin
table is a POST metadata RPC; its internal directory/cache effects are unknown.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import json
from threading import RLock
import time

from v4_planning.material_provider import _OpaqueC3Object

from .ems_tag_contract import VERSION, DisabledLinuxProcessTag, _canonical, _envelope
from .ems_tag_http_transport import NativeEmsTagHttpTransport, EmsTagHttpError, _SIGNIN, _SIGNOUT, _CHECK
from .ems_tag_identity_contract import (
    CONTRACT, ROLE_INDEX, ADMIN_INDEX, EmsTagIdentityScope,
    role_catalog, admin_catalog, admin_detail_path, qualify_admin_detail, _uid,
)
from .ems_tag_role_contract import _PERMISSION_LABELS, qualify_permission_schema, qualify_role_detail
from .ems_tag_sources import METADATA_PATH, CATALOG_PATH, EmsTagSources, _pick, _MissingField

_ERROR = "The private EMS identity source is unavailable."
_DOMAIN = b"ems-complete-role-admin-source/v1\x00"


class NativeEmsIdentityHttpTransport(NativeEmsTagHttpTransport):
    """Identity reads, with one opt-in Tag reference on the same Owner session."""

    def make_readonly_tag_reference(self, draft: DisabledLinuxProcessTag, *, source_key: bytes,
                                    reference_enabled: bool = False) -> EmsTagSources:
        """Avoid a second Owner login; never admit a configuration route."""
        try:
            with self._lock:
                if (type(self) is not NativeEmsIdentityHttpTransport or reference_enabled is not True
                        or hasattr(self, "_tag_reference_source")
                        or getattr(self.get_json, "__func__", None) is not NativeEmsTagHttpTransport.get_json):
                    raise ValueError
                source = NativeEmsTagHttpTransport.make_sources(self, draft, source_key=source_key)
                session = self.session_binding_digest(source_key)
                self._tag_reference_source = source
                self._tag_reference_key, self._tag_reference_draft = source._key, source._draft
                self._tag_reference_session = session
                return source
        except Exception:
            raise EmsTagHttpError(_ERROR) from None

    def _reserve(self, method: str, path: str) -> tuple[str, int]:
        if (method, path) in {("GET", "/"), ("POST", _SIGNIN), ("POST", _SIGNOUT), ("GET", _CHECK)}:
            return super()._reserve(method, path)
        self._pins()
        if self._failed or not self._live:
            raise ValueError
        if method == "GET" and (path == CATALOG_PATH or path.startswith("/api/v1/tags/zero_trust/")):
            reference = getattr(self, "_tag_reference_source", None)
            if (type(reference) is not EmsTagSources or reference._closed
                    or reference._key != self._tag_reference_key or reference._draft is not self._tag_reference_draft
                    or reference._instance != self._binding or reference._owner != self._owner
                    or getattr(reference._get, "__self__", None) is not self
                    or getattr(reference._get, "__func__", None) is not NativeEmsTagHttpTransport.get_json
                    or self.session_binding_digest(reference._key) != self._tag_reference_session):
                raise ValueError
            return super()._reserve(method, path)
        fixed = {("GET", METADATA_PATH), ("GET", ROLE_INDEX), ("POST", ADMIN_INDEX)}
        if (method, path) not in fixed and (method != "GET" or path not in getattr(self, "_identity_details", frozenset())):
            raise ValueError
        if self._counts.get(path, 0) >= 12:
            raise ValueError
        self._counts[path] = self._counts.get(path, 0) + 1
        return path, 2097152 if path == METADATA_PATH else 262144

    def _select_details(self, roles: tuple[bytes, ...], admins: tuple[bytes, ...]) -> None:
        self._pins()
        paths = {"/api/v1/roles/" + json.loads(raw)["uid"] + "/get" for raw in roles}
        paths.update(admin_detail_path(raw) for raw in admins)
        self._identity_details = frozenset(paths)

    def _admin_table(self) -> object:
        try:
            with self._lock:
                status, payload = self._request("POST", ADMIN_INDEX)
                if status != 200:
                    raise ValueError
                _envelope(payload)
                return payload
        except Exception:
            self._failed = True
            raise EmsTagHttpError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagIdentityObservation(_OpaqueC3Object):
    source_context_digest: str
    actor_digest: str
    full_scope: EmsTagIdentityScope
    observed_at: int
    expires_at: int


class EmsTagIdentitySources(_OpaqueC3Object):
    def __init__(self, transport: NativeEmsIdentityHttpTransport, *, source_key: bytes,
                 clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(transport) is not NativeEmsIdentityHttpTransport or type(source_key) is not bytes
                    or not 32 <= len(source_key) <= 4096 or not transport._live or transport._owner is None
                    or clock is not None and not callable(clock)):
                raise ValueError
            transport._pins()
            self._transport, self._key = transport, source_key
            self._binding, self._owner = transport._binding, transport._owner
            self._session = transport.session_binding_digest(source_key)
            self._clock = clock or (lambda: int(time.time()))
            self._last, self._closed = -1, False
            self._actor: str | None = None
            self._source: str | None = None
            self._current: EmsTagIdentityObservation | None = None
            self._current_mac: str | None = None
            self._actor_role: dict[str, object] | None = None
            self._stage, self._complete_passes = "not_started", 0
            self._lock = RLock()
        except Exception:
            raise ValueError(_ERROR) from None

    def _now(self) -> int:
        value = self._clock()
        if self._closed or type(value) is not int or value < 0 or value < self._last:
            raise ValueError
        self._last = value
        return value

    def _pins(self) -> None:
        self._transport._pins()
        if (self._closed or self._transport._failed or not self._transport._live
                or self._transport._binding != self._binding or self._transport._owner != self._owner
                or getattr(self._transport.get_json, "__func__", None) is not NativeEmsTagHttpTransport.get_json
                or getattr(self._transport._admin_table, "__func__", None) is not NativeEmsIdentityHttpTransport._admin_table
                or self._transport.session_binding_digest(self._key) != self._session):
            raise ValueError

    def _mac(self, purpose: str, value: object) -> str:
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00" + _canonical(value), hashlib.sha256).hexdigest()

    def _identity(self) -> tuple[str, dict[str, str]]:
        self._pins()
        value = _envelope(self._transport.get_json(METADATA_PATH))
        consts, actor = _pick(value, "consts"), _pick(value, "User")
        system = _pick(consts, "System")
        if (_pick(system, "VERSION_FULL") != VERSION or _pick(system, "VERSION") != "7.4.8"
                or _pick(system, "SITES_ENABLED") is not False or _pick(consts, "CHROME") is not False
                or _pick(value, "ActiveVdom") != "Default" or _pick(value, "ShowGlobal") is not True
                or _pick(value, "ShowVdom") is not True or _pick(actor, "is_global") is not True
                or type(_pick(consts, "SUCCESS")) is not int or _pick(consts, "SUCCESS") != 1):
            raise ValueError
        types = _pick(_pick(consts, "User"), "Type")
        if any(_pick(types, key) != item for key, item in {"Builtin": "BuiltIn", "Ems": "EMS", "Ldap": "LDAP"}.items()):
            raise ValueError
        permission = _pick(consts, "Permissions")
        if type(permission) is not dict or len(permission) != len(_PERMISSION_LABELS):
            raise ValueError
        wire = {label: _pick(permission, label) for label in _PERMISSION_LABELS}
        qualify_permission_schema(wire)
        role = _pick(actor, "role")
        if type(role) is not dict or any(type(role.get(key)) is not bool for key in wire.values()) or role["is_super"] is not True:
            raise ValueError
        try:
            name = _pick(actor, "name")
        except _MissingField:
            name = _pick(actor, "username")
        if type(name) is not str or name.casefold() != self._owner:
            raise ValueError
        self._actor_role = {"uid": _uid(_pick(role, "uid")), **{key: role[key] for key in wire.values()}}
        return self._mac("actor", {"name": name.casefold(), "role": role,
            "profile": "sites-off/chrome-off/default/global-owner", "version": VERSION}), wire

    def _scope(self, wire: dict[str, str]) -> EmsTagIdentityScope:
        schema = qualify_permission_schema(wire)
        self._stage = "role_catalog"
        roles = role_catalog(self._transport.get_json(ROLE_INDEX))
        self._stage = "admin_table"
        admins = admin_catalog(self._transport._admin_table())
        self._transport._select_details(roles, admins)
        uids = frozenset(json.loads(raw)["uid"] for raw in roles)
        self._stage = "role_details"
        details = tuple(qualify_role_detail(_envelope(self._transport.get_json(
            "/api/v1/roles/" + json.loads(raw)["uid"] + "/get")), schema) for raw in roles)
        self._stage = "admin_details"
        users = tuple(qualify_admin_detail(self._transport.get_json(admin_detail_path(raw)), raw, uids) for raw in admins)
        self._stage = "complete_scope"
        result = EmsTagIdentityScope(schema, roles, details, admins, users)
        self._stage = "actor_scope_join"
        if self._actor_role is None:raise ValueError
        actor_roles = [json.loads(detail._raw) for detail in details if detail._uid == self._actor_role["uid"]]
        owners = [json.loads(raw) for raw in users if json.loads(raw)["name"].casefold() == self._owner
                  and json.loads(raw)["vdom"] is None and json.loads(raw).get("is_global") is True]
        if (len(actor_roles) != 1 or any(type(actor_roles[0].get(key)) is not type(item) or actor_roles[0].get(key) != item
                for key, item in self._actor_role.items()) or len(owners) != 1
                or owners[0]["role_uid"] != self._actor_role["uid"] or owners[0]["user_type"] != "BuiltIn"):
            raise ValueError
        self._complete_passes += 1
        return result

    @property
    def source_context_digest(self) -> str:
        try:
            self._pins()
            if self._source is None or self._actor is None or self._source != self._mac("source", {
                    "contract": CONTRACT, "binding": self._binding, "session": self._session, "actor": self._actor}):
                raise ValueError
            return self._source
        except Exception:
            self.close();raise ValueError(_ERROR) from None

    def _observation_mac(self, observed: EmsTagIdentityObservation) -> str:
        return self._mac("observation", {"source": observed.source_context_digest, "actor": observed.actor_digest,
            "scope": observed.full_scope.digest, "observed_at": observed.observed_at, "expires_at": observed.expires_at})

    def observe(self) -> EmsTagIdentityObservation:
        try:
            with self._lock:
                started = self._now()
                self._stage = "identity_before"
                actor, wire = self._identity()
                if self._actor is not None and actor != self._actor:
                    raise ValueError
                first, second = self._scope(wire), self._scope(wire)
                self._stage = "identity_after"
                last_actor, last_wire = self._identity()
                self._stage = "observation_comparison"
                if first.digest != second.digest or actor != last_actor or wire != last_wire or self._now() >= started + 60:
                    raise ValueError
                self._actor = actor
                self._source = self._mac("source", {"contract": CONTRACT, "binding": self._binding, "session": self._session, "actor": actor})
                observed = EmsTagIdentityObservation(self._source, actor, second, started, started + 60)
                self._current, self._current_mac = observed, self._observation_mac(observed)
                self._stage = "finished"
                return observed
        except Exception:
            self.close();raise ValueError(_ERROR) from None

    def check_current(self, observed: EmsTagIdentityObservation) -> None:
        try:
            with self._lock:
                self._pins();now = self._now()
                if (type(observed) is not EmsTagIdentityObservation or observed is not self._current
                        or observed.source_context_digest != self.source_context_digest or observed.actor_digest != self._actor
                        or type(observed.observed_at) is not int or type(observed.expires_at) is not int
                        or observed.expires_at != observed.observed_at + 60 or not observed.observed_at <= now < observed.expires_at
                        or self._current_mac != self._observation_mac(observed)):
                    raise ValueError
                observed.full_scope.__post_init__()
        except Exception:
            self.close();raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed, self._current, self._current_mac = True, None, None
