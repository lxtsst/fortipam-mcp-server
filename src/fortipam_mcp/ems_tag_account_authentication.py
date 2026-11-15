"""One protected login probe for an originally verified, unchanged EMS account."""
from __future__ import annotations

from dataclasses import dataclass
import json
from threading import RLock

from v4_planning.material_provider import _OpaqueC3Object

from .ems_tag_account_contract import _password_valid
from .ems_tag_account_custody import EmsAccountCustody
from .ems_tag_account_enrollment import EmsAccountCentralEnrollment
from .ems_tag_account_tag_preclaim import EmsTagPreclaimRecoveryPreparation
from .ems_tag_contract import VERSION, _canonical, _envelope
from .ems_tag_http_transport import NativeEmsTagHttpTransport, _SIGNIN
from .ems_tag_identity_sources import EmsTagIdentitySources
from .ems_tag_role_contract import qualify_permission_schema
from .ems_tag_sources import METADATA_PATH, _pick, _MissingField
from .local_user_reset_material_source import _write_once
from .secret_metadata_http_transport import _zeroize_mutable

_ERROR = "The private original EMS account authentication is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class EmsAccountAuthenticationProof(_OpaqueC3Object):
    original_digest: str
    scope_digest: str
    authenticated: bool
    exact_role_mask: bool
    own_session_closed: bool


class EmsAccountAuthenticationProbe(_OpaqueC3Object):
    """This proof grants no Tag authority and never leaves a live test session."""

    def __init__(self, enrollment: EmsAccountCentralEnrollment, original: EmsAccountCustody,
                 transport: NativeEmsTagHttpTransport, *, execution_enabled: bool = False,
                 recovery_preparation: EmsTagPreclaimRecoveryPreparation | None = None) -> None:
        try:
            if (type(enrollment) is not EmsAccountCentralEnrollment or type(original) is not EmsAccountCustody
                    or type(transport) is not NativeEmsTagHttpTransport or type(execution_enabled) is not bool
                    or recovery_preparation is not None and type(recovery_preparation) is not EmsTagPreclaimRecoveryPreparation
                    or original._store._read_only is not True or transport._live or transport._counts
                    or transport._owner is not None or bool(list(transport._jar))):raise ValueError
            self._enrollment, self._original, self._transport = enrollment, original, transport
            self._preparation = recovery_preparation
            if recovery_preparation is not None:recovery_preparation.check(enrollment, original)
            self._sources: EmsTagIdentitySources = enrollment._sources
            self._owned = original.require_recovery_source(self._sources, enrollment._requester)
            self._reference = str(enrollment._prepare(live=recovery_preparation is None)["reference"])
            self._source = self._sources.source_context_digest
            self._reservation = original._store._path.name + ".ems-account-login." + self._owned.context_digest + ".json"
            self._enabled, self._closed, self._attempted, self._lock = execution_enabled, False, False, RLock()
            self._check()
        except Exception:raise ValueError(_ERROR) from None

    def _check(self) -> None:
        enrollment, original, transport = self._enrollment, self._original, self._transport
        transport._pins()
        if self._preparation is not None:self._preparation.check(enrollment, original)
        if (self._closed or original.require_recovery_source(self._sources, enrollment._requester) != self._owned
                or enrollment._sources is not self._sources or self._sources.source_context_digest != self._source
                or enrollment._draft != original._draft
                or str(enrollment._prepare(live=self._preparation is None)["reference"]) != self._reference
                or self._owned.material_reference != self._reference or self._owned.parent_digest != enrollment._owned.custody_digest
                or transport._binding != self._sources._binding or transport._config.binding_digest != self._sources._binding
                or getattr(transport._request, "__func__", None) is not NativeEmsTagHttpTransport._request):raise ValueError
        enrollment.check_registered(live=self._preparation is None)
        current = self._sources._current
        if current is None or current.full_scope.digest != self._owned.created_scope_digest:raise ValueError
        self._sources.check_current(current)
        used = enrollment._record("material.used.json")
        if (set(used) != {"reference", "plan_digest", "authorization_digest", "claimed_at"}
                or used["reference"] != self._reference or used["plan_digest"] != original._issued.plan.plan_digest
                or used["authorization_digest"] != original._issued.authorization.authorization_digest
                or type(used["claimed_at"]) is not int or not original._issued.authorization.issued_at
                <= used["claimed_at"] < original._issued.authorization.expires_at):raise ValueError

    def _metadata(self, payload: object) -> None:
        value = _envelope(payload);actor, consts = _pick(value, "User"), _pick(value, "consts")
        system = _pick(consts, "System")
        if (_pick(system, "VERSION_FULL") != VERSION or _pick(system, "VERSION") != "7.4.8"
                or _pick(system, "SITES_ENABLED") is not False or _pick(consts, "CHROME") is not False
                or _pick(actor, "is_global") is not False):raise ValueError
        try:name = _pick(actor, "name")
        except _MissingField:name = _pick(actor, "username")
        if type(name) is not str or name != self._enrollment._draft._metadata_body["name"]:raise ValueError
        current = self._sources._current
        if current is None:raise ValueError
        if qualify_permission_schema(_pick(consts, "Permissions")).digest != current.full_scope.schema.digest:raise ValueError
        expected = [detail for detail in current.full_scope._role_details if detail._uid == self._enrollment._draft.role_uid]
        if len(expected) != 1:raise ValueError
        role = _pick(actor, "role");raw = json.loads(expected[0]._raw)
        if (type(role) is not dict or role.get("uid") != expected[0]._uid
                or any(type(role.get(wire)) is not bool or role[wire] != raw[wire] for wire in current.full_scope.schema._wire)):
            raise ValueError
        if "id" in actor and (type(actor["id"]) is not int or actor["id"] != self._owned.account_numeric_id):raise ValueError

    def run_once(self) -> EmsAccountAuthenticationProof:
        body = bytearray();loaded: tuple[bytearray, bytearray] | None = None;success = False
        closure = None;writer = None
        try:
            with self._lock:
                if not self._enabled or self._closed or self._attempted or self._preparation is not None:raise ValueError
                self._attempted = True
                self._sources.observe();self._check()
                writer = self._enrollment._take_writer(self._reference)
                try:
                    self._check()
                    claim = dict(original=self._owned.custody_digest, scope=self._owned.created_scope_digest,
                        reference=self._reference, requester=self._enrollment._requester, owner_source=self._source)
                    record = bytearray(_canonical(dict(value=claim, signature=self._original._mac("account-login-claim", claim))))
                    try:_write_once(self._original._store._path.parent,
                        self._original._parent_identity, self._reservation, record)
                    finally:_zeroize_mutable(record)
                finally:self._enrollment._release_writer(writer);writer = None
                status, _ = self._transport._request("GET", "/")
                if status != 200:raise ValueError
                self._check();loaded = self._enrollment._loader.load_secret_create_material_once()
                if (type(loaded) is not tuple or len(loaded) != 2 or any(type(item) is not bytearray for item in loaded)
                        or loaded[0] is loaded[1] or loaded[0] != self._enrollment._draft._metadata_body["name"].encode("ascii")
                        or len(loaded[1]) != 44):raise ValueError
                with memoryview(loaded[1]) as password:
                    if not _password_valid(password):raise ValueError
                self._check();body.extend(b'{"name":"');body.extend(loaded[0]);body.extend(b'","password":"')
                body.extend(loaded[1]);body.extend(b'"}')
                status, reply = self._transport._request("POST", _SIGNIN, body)
                if status != 200:raise ValueError
                _envelope(reply)
                self._transport._owner, self._transport._live = self._enrollment._draft._metadata_body["name"].casefold(), True
                for item in loaded:_zeroize_mutable(item)
                loaded = None
                self._metadata(self._transport.get_json(METADATA_PATH))
                self._sources.observe();self._check();success = True
        except Exception:raise ValueError(_ERROR) from None
        finally:
            _zeroize_mutable(body)
            if loaded is not None:
                for item in loaded:
                    if type(item) is bytearray:_zeroize_mutable(item)
            if writer is not None:self._enrollment._release_writer(writer)
            self._enabled, self._closed = False, True
            closure = self._transport.close()
        if (not success or not closure.own_logout_verified or not closure.next_session_check_401
                or not closure.cookie_jar_cleared or not closure.owned_mutable_buffers_cleared or not closure.connections_closed):
            raise ValueError(_ERROR)
        return EmsAccountAuthenticationProof(self._owned.custody_digest, self._owned.created_scope_digest, True, True, True)
