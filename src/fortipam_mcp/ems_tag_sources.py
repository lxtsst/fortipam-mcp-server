"""Fixed, fresh EMS tag source join for a protected authenticated GET channel.

Trusted composition must supply the real TLS/instance/site binding and current
owner session. No login, HTTP writer, Tool or permission authority is provided.
Only fixed metadata/catalog routes and IDs from that complete catalog are read.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from threading import RLock
import time
from typing import Any, TYPE_CHECKING
from urllib.parse import urlencode

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .ems_tag_contract import (
    CONTRACT, VERSION, MAX_ORIGINAL_TAGS, DisabledLinuxProcessTag, EmsTagFullScope,
    _canonical, _envelope, create_current_digest, qualify_tag_catalog, qualify_tag_detail,
)

if TYPE_CHECKING:
    from .ems_tag_account_tag_source import EmsOriginalAccountTagSession

METADATA_PATH = "/api/v1/init_consts"
CATALOG_PATH = "/api/v1/tags/zero_trust/index?" + urlencode({"query": json.dumps(
    {"mode": 1, "start_index": 0, "end_index": 255, "filters": []}, separators=(",", ":"))})
_ERROR = "The private EMS tag source is unavailable."
SOURCE_CONTRACT = "ems-disabled-tag-live-source-v2"
_DOMAIN = b"ems-disabled-tag-live-source-v2\x00"


class EmsTagSourceError(ValueError):
    """Value-free refusal; an interrupted source cannot be reused."""


class _MissingField(ValueError):
    pass


def _pick(value: object, name: str) -> Any:
    if type(value) is not dict:
        raise ValueError
    snake = re.sub(r"([a-z])([A-Z])", r"\1_\2", name).lower()
    camel = re.sub(r"_([a-z])", lambda m: m[1].upper(), snake)
    aliases = set((name, name.lower(), name.upper(), snake, snake.upper(), camel,
                   camel[:1].upper() + camel[1:]))
    present = aliases.intersection(value)
    if not present:
        raise _MissingField
    if len(present) != 1:
        raise ValueError
    return value[present.pop()]


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagSourceObservation(_OpaqueC3Object):
    source_context_digest: str
    actor_digest: str
    full_scope: EmsTagFullScope
    observed_at: int
    expires_at: int


class EmsTagSources(_OpaqueC3Object):
    """One authenticated owner/channel; detached observations are never live."""

    def __init__(self, *, draft: DisabledLinuxProcessTag, owner_name: str,
                 instance_scope_digest: str, source_key: bytes,
                 get_json: Callable[[str], object], clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(draft) is not DisabledLinuxProcessTag or type(owner_name) is not str
                    or not 0 < len(owner_name) <= 256 or "\x00" in owner_name
                    or type(source_key) is not bytes or not 32 <= len(source_key) <= 4096
                    or not callable(get_json) or clock is not None and not callable(clock)):
                raise ValueError
            draft.__post_init__()
            require_digest(instance_scope_digest, "ems_instance_scope")
            self._draft, self._owner = draft, owner_name.casefold()
            self._instance, self._key, self._get = instance_scope_digest, source_key, get_json
            self._clock = clock or (lambda: int(time.time()))
            self._actor: str | None = None
            self._source: str | None = None
            self._current: EmsTagSourceObservation | None = None
            self._current_mac: str | None = None
            self._original_account: EmsOriginalAccountTagSession | None = None
            self._last, self._closed, self._lock = -1, False, RLock()
        except Exception:
            raise EmsTagSourceError(_ERROR) from None

    def _mac(self, purpose: str, value: object) -> str:
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00" + _canonical(value),
                        hashlib.sha256).hexdigest()

    def _now(self) -> int:
        now = self._clock()
        if self._closed or type(now) is not int or now < 0 or now < self._last:
            raise ValueError
        self._last = now
        return now

    def _identity(self) -> str:
        payload = self._get(METADATA_PATH)
        data = _envelope(payload)
        consts, user = _pick(data, "consts"), _pick(data, "User")
        system = _pick(consts, "System")
        if _pick(system, "VERSION_FULL") != VERSION or _pick(system, "VERSION") != "7.4.8":
            raise ValueError
        self._tag_constants(data)
        if self._original_account is not None:
            return self._account_session().qualify_identity(self, payload)
        if (_pick(system, "SITES_ENABLED") is not False
                or _pick(data, "ActiveVdom") != "Default"
                or _pick(data, "ShowGlobal") is not True
                or _pick(data, "ShowVdom") is not True
                or _pick(user, "is_global") is not True):
            raise ValueError
        success = _pick(consts, "SUCCESS")
        if type(success) is not int or success != 1:
            raise ValueError
        try:
            name = _pick(user, "name")
        except _MissingField:
            name = _pick(user, "username")
        role, permission = _pick(user, "role"), _pick(_pick(consts, "Permissions"), "SUPER")
        if (type(name) is not str or name.casefold() != self._owner
                or type(permission) is not str or not permission
                or type(role) is not dict or role.get(permission) is not True):
            raise ValueError
        return self._mac("authenticated-owner", {"name": name.casefold(), "role": role,
            "super_permission": permission, "sites_enabled": False, "active_vdom": "Default",
            "show_global": True, "show_vdom": True, "global_actor": True})

    @staticmethod
    def _tag_constants(data: object) -> None:
        consts = _pick(data, "consts")
        system = _pick(consts, "System")
        success = _pick(consts, "SUCCESS")
        if type(success) is not int or success != 1:
            raise ValueError
        cv = _pick(consts, "ComplianceVerification")
        process, linux = _pick(_pick(cv, "RuleType"), "PROCESS"), _pick(_pick(cv, "OS"), "LINUX")
        simple = _pick(_pick(system, "MATCH_TYPE"), "Simple")
        maximum = _pick(cv, "TAG_LENGTH_MAX")
        if (type(process) is not int or process != 6 or type(linux) is not int or linux != 3
                or type(simple) is not int or simple != 1 or type(maximum) is not int or maximum != 58):
            raise ValueError
        rule_details = _pick(cv, "RuleTypeDetails")
        if type(rule_details) is not dict:
            raise ValueError
        os_types = _pick(rule_details.get("6"), "OS_TYPES")
        if (type(os_types) is not list or any(type(item) is not int for item in os_types)
                or linux not in os_types):
            raise ValueError

    def _account_session(self) -> EmsOriginalAccountTagSession:
        """Resolve the exact type; boundary methods validate their live pins."""
        from .ems_tag_account_tag_source import EmsOriginalAccountTagSession
        if type(self._original_account) is not EmsOriginalAccountTagSession:
            raise ValueError
        return self._original_account

    def require_phase(self, phase: str, requester_digest: str) -> None:
        """Keep ordinary SUPER sources unchanged; pin explicit Account purposes."""
        self._now()
        if self._original_account is not None:
            self._account_session().require_phase(phase, requester_digest, source=self)

    def _checked_context_digest(self) -> str:
        """Check the signed identity after the caller's live source boundary.

        This metadata check grants no authority and does not replace require_phase.
        The public getter continues to validate live Account pins independently.
        """
        if self._closed or self._source is None or self._actor is None:
            raise ValueError
        expected = self._mac("source", {"contract": CONTRACT, "source_contract": SOURCE_CONTRACT, "version": VERSION,
            "instance_scope": self._instance, "actor": self._actor})
        if not hmac.compare_digest(expected, self._source):
            raise ValueError
        return self._source

    @property
    def source_context_digest(self) -> str:
        try:
            with self._lock:
                self._now()
                if self._source is None or self._actor is None:
                    raise ValueError
                if self._original_account is not None:
                    self._account_session().check_source(self)
                return self._checked_context_digest()
        except Exception:
            self.close()
            raise EmsTagSourceError(_ERROR) from None

    def _scope(self) -> EmsTagFullScope:
        catalog = qualify_tag_catalog(self._get(CATALOG_PATH))
        if catalog.count > MAX_ORIGINAL_TAGS + 1:
            raise ValueError
        details = tuple(qualify_tag_detail(self._get("/api/v1/tags/zero_trust/" + str(identifier) + "/get"))
                        for identifier in catalog._ids)
        return EmsTagFullScope(catalog, details)

    def _observation_mac(self, observed: EmsTagSourceObservation) -> str:
        return self._mac("current-observation", {"source": observed.source_context_digest,
            "actor": observed.actor_digest, "scope": observed.full_scope.digest,
            "observed_at": observed.observed_at, "expires_at": observed.expires_at})

    def observe(self) -> EmsTagSourceObservation:
        try:
            with self._lock:
                started = self._now()
                if self._original_account is not None:
                    self._account_session().check_source(self)
                actor = self._identity()
                if self._actor is not None and not hmac.compare_digest(actor, self._actor):
                    raise ValueError
                first, second = self._scope(), self._scope()
                tail = qualify_tag_catalog(self._get(CATALOG_PATH))
                if (first.digest != second.digest or second.catalog.digest != tail.digest
                        or not hmac.compare_digest(actor, self._identity())):
                    raise ValueError
                if self._original_account is not None:
                    self._account_session().accept_scope(second)
                now = self._now()
                if now >= started + 60:
                    raise ValueError
                self._actor = actor
                self._source = self._mac("source", {"contract": CONTRACT, "source_contract": SOURCE_CONTRACT, "version": VERSION,
                    "instance_scope": self._instance, "actor": actor})
                current = EmsTagSourceObservation(self._source, actor, second, started, started + 60)
                self._current = current
                self._current_mac = self._observation_mac(current)
                return current
        except Exception:
            self.close()
            raise EmsTagSourceError(_ERROR) from None

    def check_current(self, observed: EmsTagSourceObservation) -> None:
        try:
            with self._lock:
                now = self._now()
                if (type(observed) is not EmsTagSourceObservation or observed is not self._current
                        or observed.source_context_digest != self.source_context_digest
                        or observed.actor_digest != self._actor
                        or type(observed.observed_at) is not int or type(observed.expires_at) is not int
                        or observed.expires_at != observed.observed_at + 60
                        or not observed.observed_at <= now < observed.expires_at
                        or self._current_mac != self._observation_mac(observed)):
                    raise ValueError
                observed.full_scope.__post_init__()
        except Exception:
            self.close()
            raise EmsTagSourceError(_ERROR) from None

    def current_digest(self, observed: EmsTagSourceObservation) -> str:
        self.check_current(observed)
        return create_current_digest(self._draft, observed.full_scope.digest, self.source_context_digest)

    def close(self) -> None:
        with self._lock:
            self._closed, self._current, self._current_mac = True, None, None
