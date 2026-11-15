"""Private original-Account session for one fixed Tag create or recovery.

The closed read proof is not an input. Original verified Account/Role custody,
used central material, live Owner scope and a durable purpose claim are required.
The existing Tag authorities, M4 adapters and original recovery remain mandatory.
"""
from __future__ import annotations

import hashlib
from threading import RLock

from v4_planning.material_provider import _OpaqueC3Object

from .ems_tag_account_authentication import EmsAccountAuthenticationProbe
from .ems_tag_account_contract import _password_valid, parameters_digest
from .ems_tag_account_custody import EmsAccountCustody
from .ems_tag_account_enrollment import EmsAccountCentralEnrollment
from .ems_tag_account_tag_preclaim import EmsTagPreclaimRecoveryPreparation
from .ems_tag_contract import EmsTagFullScope, _canonical, _envelope
from .ems_tag_custody import EmsTagOriginalCustody
from .ems_tag_http_transport import NativeEmsTagHttpTransport, EmsTagSessionClosure, _SIGNIN
from .ems_tag_identity_sources import NativeEmsIdentityHttpTransport
from .ems_tag_sources import EmsTagSources
from .local_user_reset_material_source import _write_once
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = "ems-7.4.8.2245-original-account-tag-session-v1"
_ERROR = "The private original EMS account Tag session is unavailable."


class EmsOriginalAccountTagSession(_OpaqueC3Object):
    """No ordinary runtime activation, credential export or independent writer."""

    def __init__(self, enrollment: EmsAccountCentralEnrollment, original: EmsAccountCustody,
                 transport: NativeEmsTagHttpTransport, owner_tags: EmsTagSources, *,
                 source_key: bytes, phase: str, tag_original: EmsTagOriginalCustody | None = None,
                 execution_enabled: bool = False,
                 recovery_preparation: EmsTagPreclaimRecoveryPreparation | None = None) -> None:
        try:
            if (type(owner_tags) is not EmsTagSources or type(execution_enabled) is not bool
                    or type(source_key) is not bytes or not 32 <= len(source_key) <= 4096
                    or phase not in ("create", "recover")
                    or phase == "create" and tag_original is not None
                    or recovery_preparation is not None and (type(recovery_preparation) is not EmsTagPreclaimRecoveryPreparation
                        or phase != "recover" or recovery_preparation._tag is not tag_original
                        or recovery_preparation._key_hash != hashlib.sha256(source_key).hexdigest())
                    or phase == "recover" and (type(tag_original) is not EmsTagOriginalCustody
                        or tag_original._store._read_only is not True)):
                raise ValueError
            self._guard = EmsAccountAuthenticationProbe(enrollment, original, transport, recovery_preparation=recovery_preparation)
            self._preparation = recovery_preparation
            owner = getattr(owner_tags._get, "__self__", None)
            if (type(owner) is not NativeEmsIdentityHttpTransport
                    or owner is not enrollment._sources._transport
                    or getattr(owner, "_tag_reference_source", None) is not owner_tags
                    or getattr(owner_tags._get, "__func__", None) is not NativeEmsTagHttpTransport.get_json
                    or owner_tags._original_account is not None
                    or owner_tags._instance != enrollment._sources._binding
                    or owner_tags._owner != enrollment._sources._owner or owner._owner != owner_tags._owner
                    or len({source_key, owner_tags._key, enrollment._sources._key, enrollment._key,
                        original._key, original._store._key, enrollment._parent._key,
                        enrollment._parent._store._key}) != 8):
                raise ValueError
            self._enrollment, self._original, self._transport = enrollment, original, transport
            self._owner_tags, self._owner_transport = owner_tags, owner
            self._owner_key, self._draft = owner_tags._key, owner_tags._draft
            self._owner_session = owner.session_binding_digest(original._key)
            self._key, self._phase, self._tag_original = source_key, phase, tag_original
            self._tag_birth = tag_original.inspect_created_scope() if tag_original is not None else None
            if tag_original is not None and (tag_original._draft != self._draft
                    or tag_original._plan.requester_digest != enrollment._requester):
                raise ValueError
            self._enabled, self._closed, self._attempted = execution_enabled, False, False
            self._source: EmsTagSources | None = None
            self._session: str | None = None
            self._first_scope: EmsTagFullScope | None = None
            self._last_scope: EmsTagFullScope | None = None
            self._reservation = (original._store._path.name + ".ems-account-tag-" + phase + "."
                + self._guard._owned.context_digest + ".json")
            if recovery_preparation is not None:self._reservation = recovery_preparation.reservation_name
            self._lock = RLock()
            self._pins()
        except Exception:
            raise ValueError(_ERROR) from None

    def _pins(self) -> None:
        owner, tags, enrollment = self._owner_transport, self._owner_tags, self._enrollment
        if (self._closed or tags._closed or tags._key != self._owner_key or tags._draft is not self._draft
                or tags._original_account is not None
                or getattr(tags._get, "__self__", None) is not owner
                or getattr(tags._get, "__func__", None) is not NativeEmsTagHttpTransport.get_json
                or owner is not enrollment._sources._transport or owner._tag_reference_source is not tags
                or tags._instance != enrollment._sources._binding or tags._owner != enrollment._sources._owner
                or owner.session_binding_digest(self._original._key) != self._owner_session):
            raise ValueError
        # Refresh only the fixed Owner identity window; old Account/Role scope
        # must still match the original full birth, including all permissions.
        now = enrollment._now()
        current = enrollment._sources._current
        if current is None or now >= current.expires_at - 10:
            enrollment._sources.observe()
        self._guard._check()
        if self._session is not None and self._transport.session_binding_digest(self._key) != self._session:
            raise ValueError
        if self._tag_original is not None and self._tag_original.inspect_created_scope() != self._tag_birth:
            raise ValueError

    def check_source(self, source: EmsTagSources) -> None:
        self._pins()
        if (not self._enabled or not self._attempted or source is not self._source or source._closed
                or source._key != self._key or source._draft is not self._draft
                or source._original_account is not self or source._instance != self._transport._binding
                or source._owner != self._enrollment._draft._metadata_body["name"].casefold()
                or getattr(source._get, "__self__", None) is not self._transport
                or getattr(source._get, "__func__", None) is not NativeEmsTagHttpTransport.get_json
                or self._session is None):
            raise ValueError

    def require_phase(self, phase: str, requester_digest: str, *, source: EmsTagSources | None = None) -> None:
        if source is None:self._pins()
        else:self.check_source(source)
        if phase != self._phase or requester_digest != self._enrollment._requester:
            raise ValueError

    def qualify_identity(self, source: EmsTagSources, payload: object) -> str:
        self.check_source(source)
        self._guard._metadata(payload)
        return source._mac("authenticated-original-account", dict(contract=CONTRACT,
            original=self._guard._owned.custody_digest, parent=self._guard._owned.parent_digest,
            account_scope=self._guard._owned.created_scope_digest, reference=self._guard._reference,
            account_parameters=parameters_digest(self._enrollment._draft, self._guard._reference,
                self._enrollment._owned.custody_digest)))

    def before_observe(self) -> None:
        self._pins()

    def accept_scope(self, scope: EmsTagFullScope) -> None:
        self._pins()
        scope.__post_init__()
        if self._first_scope is None or self._last_scope is None and scope.digest != self._first_scope.digest:
            raise ValueError
        self._last_scope = scope

    def open_once(self) -> EmsTagSources:
        body = bytearray()
        loaded: tuple[bytearray, bytearray] | None = None
        writer = None
        try:
            with self._lock:
                if not self._enabled or self._closed or self._attempted:
                    raise ValueError
                self._attempted = True
                self._pins()
                observed = self._owner_tags.observe()
                self._owner_tags.check_current(observed)
                self._first_scope = observed.full_scope
                if (self._phase == "create" and observed.full_scope.catalog.contains_draft(self._draft)
                        or self._tag_birth is not None and observed.full_scope.digest != self._tag_birth.created_scope_digest):
                    raise ValueError
                self._pins()
                writer = self._enrollment._take_writer(self._guard._reference)
                try:
                    self._pins()
                    if self._preparation is not None:self._preparation.require_unused()
                    claim = dict(contract=CONTRACT, original=self._guard._owned.custody_digest,
                        reference=self._guard._reference, parent=self._guard._owned.parent_digest,
                        account_scope=self._guard._owned.created_scope_digest, phase=self._phase,
                        parameters=self._draft.parameters_digest, source_key_sha256=hashlib.sha256(self._key).hexdigest(),
                        tag_original=self._tag_birth.custody_digest if self._tag_birth is not None else None,
                        owner_tag_scope=observed.full_scope.digest, requester=self._enrollment._requester)
                    if self._preparation is not None:claim["preclaim_recovery"] = self._preparation.claim_fields()
                    raw = bytearray(_canonical(dict(value=claim,
                        signature=self._original._mac("account-tag-session-claim", claim))))
                    try:
                        _write_once(self._original._store._path.parent, self._original._parent_identity, self._reservation, raw)
                    finally:
                        _zeroize_mutable(raw)
                finally:
                    self._enrollment._release_writer(writer)
                    writer = None
                code, _ = self._transport._request("GET", "/")
                if code != 200:
                    raise ValueError
                self._pins()
                loaded = self._enrollment._loader.load_secret_create_material_once()
                if (type(loaded) is not tuple or len(loaded) != 2
                        or any(type(item) is not bytearray for item in loaded) or loaded[0] is loaded[1]
                        or loaded[0] != self._enrollment._draft._metadata_body["name"].encode("ascii")
                        or len(loaded[1]) != 44):
                    raise ValueError
                with memoryview(loaded[1]) as password:
                    if not _password_valid(password):
                        raise ValueError
                self._pins()
                body.extend(b'{"name":"');body.extend(loaded[0]);body.extend(b'","password":"')
                body.extend(loaded[1]);body.extend(b'"}')
                code, reply = self._transport._request("POST", _SIGNIN, body)
                if code != 200:
                    raise ValueError
                _envelope(reply)
                self._transport._owner = self._enrollment._draft._metadata_body["name"].casefold()
                self._transport._live = True
                for item in loaded:
                    _zeroize_mutable(item)
                loaded = None
                self._session = self._transport.session_binding_digest(self._key)
                source = self._transport.make_sources(self._draft, source_key=self._key)
                source._clock = self._enrollment._clock
                self._source = source
                source._original_account = self
                current = source.observe()
                source.check_current(current)
                if self._tag_birth is not None and (source.source_context_digest != self._tag_birth.source_context_digest
                        or self._session == self._tag_birth.actor_binding.owner_session_digest):
                    raise ValueError
                return source
        except Exception:
            self._enabled = False
            self._closed = True
            if self._source is not None:
                self._source.close()
            self._transport.close()
            raise ValueError(_ERROR) from None
        finally:
            _zeroize_mutable(body)
            if loaded is not None:
                for item in loaded:
                    if type(item) is bytearray:
                        _zeroize_mutable(item)
            if writer is not None:
                self._enrollment._release_writer(writer)

    def close(self) -> EmsTagSessionClosure:
        """Check final Owner graph, then always close only the Account session."""
        valid = False
        try:
            with self._lock:
                self._pins()
                self._enrollment._sources.observe()
                self._pins()
                observed = self._owner_tags.observe()
                self._owner_tags.check_current(observed)
                valid = self._last_scope is not None and observed.full_scope.digest == self._last_scope.digest
        except Exception:
            pass
        finally:
            self._enabled, self._closed = False, True
            if self._source is not None:
                self._source.close()
            closure = self._transport.close()
        if (not valid or not closure.own_logout_verified or not closure.next_session_check_401
                or not closure.cookie_jar_cleared or not closure.owned_mutable_buffers_cleared
                or not closure.connections_closed):
            raise ValueError(_ERROR)
        return closure
