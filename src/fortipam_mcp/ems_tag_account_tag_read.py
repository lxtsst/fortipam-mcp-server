"""Original-account-only Tag read qualification; no mutable Tag admission."""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from v4_planning.material_provider import _OpaqueC3Object

from .ems_tag_account_authentication import EmsAccountAuthenticationProbe
from .ems_tag_account_contract import _password_valid
from .ems_tag_account_custody import EmsAccountCustody
from .ems_tag_account_enrollment import EmsAccountCentralEnrollment
from .ems_tag_contract import EmsTagFullScope, MAX_ORIGINAL_TAGS, _canonical, _envelope, qualify_tag_catalog, qualify_tag_detail
from .ems_tag_http_transport import NativeEmsTagHttpTransport, _SIGNIN
from .ems_tag_identity_sources import NativeEmsIdentityHttpTransport
from .ems_tag_sources import EmsTagSources, METADATA_PATH, CATALOG_PATH
from .local_user_reset_material_source import _write_once
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = "ems-7.4.8.2245-original-account-tag-read-v1"
_ERROR = "The original EMS account Tag read qualification is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class EmsAccountTagReadProof(_OpaqueC3Object):
    original_digest: str
    actor_verified: bool
    backend_http_status: int
    account_scope_parsed: bool
    account_scope_matches_owner: bool
    owner_scope_unchanged: bool
    complete_read_qualified: bool
    own_session_closed: bool


class EmsAccountTagReadProbe(_OpaqueC3Object):
    """One fixed read purpose, closed session and no reusable authorization."""

    def __init__(self, enrollment: EmsAccountCentralEnrollment, original: EmsAccountCustody,
                 transport: NativeEmsTagHttpTransport, owner_tags: EmsTagSources, *,
                 execution_enabled: bool = False) -> None:
        try:
            if type(owner_tags) is not EmsTagSources or type(execution_enabled) is not bool:raise ValueError
            self._guard = EmsAccountAuthenticationProbe(enrollment, original, transport)
            owner_transport = getattr(owner_tags._get, "__self__", None)
            if (type(owner_transport) is not NativeEmsIdentityHttpTransport
                    or owner_transport is not enrollment._sources._transport
                    or getattr(owner_transport, "_tag_reference_source", None) is not owner_tags
                    or owner_transport is transport
                    or getattr(owner_tags._get, "__func__", None) is not NativeEmsTagHttpTransport.get_json
                    or not owner_transport._live or owner_transport._failed
                    or owner_transport._binding != enrollment._sources._binding
                    or owner_tags._instance != enrollment._sources._binding
                    or owner_tags._owner != enrollment._sources._owner
                    or owner_transport._owner != owner_tags._owner
                    or owner_tags._key in (enrollment._sources._key, enrollment._key, original._key,
                        original._store._key, enrollment._parent._key, enrollment._parent._store._key)):raise ValueError
            self._enrollment, self._original, self._transport = enrollment, original, transport
            self._owner_tags: EmsTagSources = owner_tags
            self._owner_transport: NativeEmsIdentityHttpTransport = owner_transport
            self._owner_key, self._owner_draft = owner_tags._key, owner_tags._draft
            self._owner_session = owner_transport.session_binding_digest(original._key)
            self._reservation = original._store._path.name + ".ems-account-tag-read." + self._guard._owned.context_digest + ".json"
            self._enabled, self._closed, self._attempted = execution_enabled, False, False
            self._deadline: int | None = None
            self._account_session: str | None = None
            self._last, self._lock = -1, RLock()
            self._pins()
        except Exception:raise ValueError(_ERROR) from None

    def _pins(self, *, denied_read: bool = False) -> None:
        self._guard._check()
        if (self._closed or self._owner_tags._key != self._owner_key or self._owner_tags._draft is not self._owner_draft
                or self._owner_tags._instance != self._enrollment._sources._binding
                or self._owner_tags._owner != self._enrollment._sources._owner
                or getattr(self._owner_tags._get, "__self__", None) is not self._owner_transport
                or self._owner_transport is not self._enrollment._sources._transport
                or self._owner_transport._tag_reference_source is not self._owner_tags
                or getattr(self._owner_tags._get, "__func__", None) is not NativeEmsTagHttpTransport.get_json
                or self._owner_transport.session_binding_digest(self._original._key) != self._owner_session):raise ValueError
        now = self._enrollment._now()
        if now < self._last or self._deadline is not None and now >= self._deadline:raise ValueError
        self._last = now
        if self._transport._failed:
            # A refused channel can only yield a negative result and own logout;
            # it is never reopened, read again or accepted as a source.
            if not denied_read or self._account_session is None or self._transport._response_status not in (401, 403):raise ValueError
        elif (self._account_session is not None
                and self._transport.session_binding_digest(self._original._key) != self._account_session):raise ValueError

    def _scope(self) -> EmsTagFullScope:
        catalog = qualify_tag_catalog(self._transport.get_json(CATALOG_PATH))
        if catalog.count > MAX_ORIGINAL_TAGS + 1:raise ValueError
        details = tuple(qualify_tag_detail(self._transport.get_json("/api/v1/tags/zero_trust/" + str(i) + "/get"))
                        for i in catalog._ids)
        return EmsTagFullScope(catalog, details)

    def _account_scope(self) -> EmsTagFullScope:
        self._pins();self._guard._metadata(self._transport.get_json(METADATA_PATH))
        first, second = self._scope(), self._scope()
        tail = qualify_tag_catalog(self._transport.get_json(CATALOG_PATH))
        self._guard._metadata(self._transport.get_json(METADATA_PATH));self._pins()
        if first.digest != second.digest or tail.digest != second.catalog.digest:raise ValueError
        return second

    def run_once(self) -> EmsAccountTagReadProof:
        body = bytearray();loaded: tuple[bytearray, bytearray] | None = None;writer = None
        actor = parsed = matched = unchanged = False;status = 0;closure = None
        try:
            with self._lock:
                if not self._enabled or self._closed or self._attempted:raise ValueError
                self._attempted = True;self._enrollment._sources.observe();self._pins()
                before = self._owner_tags.observe();self._owner_tags.check_current(before)
                current = self._enrollment._sources._current
                if current is None:raise ValueError
                self._deadline = min(before.expires_at, current.expires_at, self._enrollment._prepare()["expires_at"])
                self._pins();writer = self._enrollment._take_writer(self._guard._reference)
                try:
                    self._pins()
                    claim = dict(contract=CONTRACT, original=self._guard._owned.custody_digest,
                        account_scope=self._guard._owned.created_scope_digest, owner_tag_scope=before.full_scope.digest,
                        reference=self._guard._reference, requester=self._enrollment._requester,
                        expires_at=self._deadline, configuration_mutations=0)
                    raw = bytearray(_canonical(dict(value=claim, signature=self._original._mac("account-tag-read-claim", claim))))
                    try:_write_once(self._original._store._path.parent, self._original._parent_identity, self._reservation, raw)
                    finally:_zeroize_mutable(raw)
                finally:self._enrollment._release_writer(writer);writer = None
                code, _ = self._transport._request("GET", "/")
                if code != 200:raise ValueError
                self._pins();loaded = self._enrollment._loader.load_secret_create_material_once()
                if (type(loaded) is not tuple or len(loaded) != 2 or any(type(item) is not bytearray for item in loaded)
                        or loaded[0] is loaded[1] or loaded[0] != self._enrollment._draft._metadata_body["name"].encode("ascii")
                        or len(loaded[1]) != 44):raise ValueError
                with memoryview(loaded[1]) as password:
                    if not _password_valid(password):raise ValueError
                self._pins();body.extend(b'{"name":"');body.extend(loaded[0]);body.extend(b'","password":"')
                body.extend(loaded[1]);body.extend(b'"}')
                code, reply = self._transport._request("POST", _SIGNIN, body)
                if code != 200:raise ValueError
                _envelope(reply)
                self._transport._owner, self._transport._live = self._enrollment._draft._metadata_body["name"].casefold(), True
                for item in loaded:_zeroize_mutable(item)
                loaded = None
                self._account_session = self._transport.session_binding_digest(self._original._key)
                self._guard._metadata(self._transport.get_json(METADATA_PATH));actor = True
                try:
                    scope = self._account_scope();status = 200;parsed = True
                    matched = scope.digest == before.full_scope.digest
                except Exception:
                    observed_status = self._transport._response_status
                    status = observed_status if type(observed_status) is int else 0
                denied = actor and not parsed and self._transport._failed and status in (401, 403)
                self._enrollment._sources.observe();self._pins(denied_read=denied)
                after = self._owner_tags.observe();self._owner_tags.check_current(after);self._pins(denied_read=denied)
                unchanged = before.full_scope.digest == after.full_scope.digest
                if not unchanged:raise ValueError
        except Exception:raise ValueError(_ERROR) from None
        finally:
            _zeroize_mutable(body)
            if loaded is not None:
                for item in loaded:
                    if type(item) is bytearray:_zeroize_mutable(item)
            if writer is not None:self._enrollment._release_writer(writer)
            self._enabled, self._closed = False, True
            self._guard._enabled, self._guard._closed = False, True
            closure = self._transport.close()
        if (not closure.own_logout_verified or not closure.next_session_check_401 or not closure.cookie_jar_cleared
                or not closure.owned_mutable_buffers_cleared or not closure.connections_closed):raise ValueError(_ERROR)
        return EmsAccountTagReadProof(self._guard._owned.custody_digest, actor, status, parsed, matched, unchanged,
                                     actor and parsed and matched and unchanged, True)
