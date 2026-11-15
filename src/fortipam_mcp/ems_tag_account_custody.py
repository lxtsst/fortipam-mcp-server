"""Original active-M4 Account ACK/birth custody and readonly verified reopen."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
from pathlib import Path
from threading import RLock
import time
from typing import Any, TYPE_CHECKING

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import M4Claim, _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .ems_tag_account_authority import EmsAccountFixtureIssued
from .ems_tag_account_contract import CONTRACT, ACTION_ID, ACTION_VERSION, ADAPTER_REF, TARGET_REF, parameters_digest, current_digest, expected_digest
from .ems_tag_account_effect import verify_account_created
from .ems_tag_account_recovery import (
    EmsAccountRecoveryIssued, ACTION_ID as RECOVERY_ACTION_ID, ADAPTER_REF as RECOVERY_ADAPTER_REF,
    recovery_parameters, recovery_current, recovery_expected,
)
from .ems_tag_admin_contract import ProspectiveEmsTagManagerAccount
from .ems_tag_contract import _canonical
from .ems_tag_custody import _decode, _ack_data
from .ems_tag_identity_contract import EmsTagIdentityScope, _admin_id
from .ems_tag_identity_sources import EmsTagIdentitySources
from .ldap_server_runtime import _key, _read
from .local_user_reset_material_source import _directory_identity, _write_once
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

if TYPE_CHECKING:
    from .ems_tag_account_authority import EmsAccountFixtureAuthority
    from .ems_tag_account_recovery import EmsAccountRecoveryAuthority

_ERROR = "The private original EMS account custody is unavailable."
_DOMAIN = b"ems-original-account-custody/v1\x00"
_NAMES = frozenset({"binding.json", "send.json", "ack-attempt.json", "ack.json", "effect-attempt.json", "effect.json", "failure.json"})
_ATTEMPT = {"send_digest", "attempted_at", "http_status", "complete", "json_content_type", "root_complete", "envelope_valid", "reply_digest"}


@dataclass(frozen=True, slots=True, repr=False)
class EmsAccountOriginal(_OpaqueC3Object):
    context_digest: str
    custody_digest: str
    baseline_digest: str
    created_scope_digest: str
    account_digest: str
    account_numeric_id: int
    parent_digest: str
    material_reference: str

    def __post_init__(self) -> None:
        for value in (self.context_digest, self.custody_digest, self.baseline_digest,
                      self.created_scope_digest, self.account_digest, self.parent_digest):require_digest(value, "account_original")
        _admin_id(self.account_numeric_id);require_ref(self.material_reference, "account_material")


class EmsAccountCustody(_OpaqueC3Object):
    def __init__(self, directory: Path, witness_key_file: Path, store: PersistentM4ExecutionStateStore,
                 authority: EmsAccountFixtureAuthority | EmsAccountRecoveryAuthority, *, clock: Callable[[], int] | None = None) -> None:
        try:
            from .ems_tag_account_authority import EmsAccountFixtureAuthority
            from .ems_tag_account_recovery import EmsAccountRecoveryAuthority
            if type(authority) not in (EmsAccountFixtureAuthority, EmsAccountRecoveryAuthority) or authority._issued is None:raise ValueError
            authority.verify(authority._issued.plan, authority._issued.authorization, now_epoch=authority._now())
            sources = authority._sources;key = _key(Path(witness_key_file))
            original = None
            forbidden: tuple[bytes, ...]
            if type(authority) is EmsAccountFixtureAuthority:
                enrollment = authority._enrollment;draft = enrollment._draft
                forbidden = (enrollment._key, enrollment._parent._key, enrollment._parent._store._key)
            elif type(authority) is EmsAccountRecoveryAuthority:
                original = authority._original;draft = authority._draft
                forbidden = (original._key, original._store._key)
            else:raise ValueError
            if key in (sources._key, authority._key, *forbidden):raise ValueError
            binding = dict(instance=sources._binding, owner=self._tag(key, "owner", sources._owner),
                session=sources._transport.session_binding_digest(key), caller_transport=authority._binding["transport_digest"],
                issuer=hashlib.sha256(authority._key).hexdigest())
            self._setup(directory, witness_key_file, store, draft, authority._reference,
                authority._issued, binding, sources=sources, original=original, clock=clock)
            if store._read_only:raise ValueError
        except Exception:raise ValueError(_ERROR) from None

    @staticmethod
    def _tag(key: bytes, purpose: str, value: object) -> str:
        return hmac.new(key, _DOMAIN + purpose.encode() + b"\x00" + _canonical(value), hashlib.sha256).hexdigest()

    def _mac(self, purpose: str, value: object) -> str:
        return self._tag(self._key, purpose, value)

    def _setup(self, directory: Path, key_file: Path, store: PersistentM4ExecutionStateStore,
               draft: ProspectiveEmsTagManagerAccount, reference: str, issued: EmsAccountFixtureIssued | EmsAccountRecoveryIssued,
               binding: dict[str, Any], *, sources: EmsTagIdentitySources | None, original: EmsAccountCustody | None,
               clock: Callable[[], int] | None) -> None:
        if (type(store) is not PersistentM4ExecutionStateStore or not store.monotonic_checkpoint_protocol_bound
                or type(draft) is not ProspectiveEmsTagManagerAccount or type(issued) not in (EmsAccountFixtureIssued, EmsAccountRecoveryIssued)
                or clock is not None and not callable(clock)):raise ValueError
        self._directory, self._key_file, self._store = Path(directory), Path(key_file), store
        self._identity, self._parent_identity = _directory_identity(self._directory), _directory_identity(store._path.parent)
        self._key = _key(self._key_file)
        if (self._key == store._key or self._key_file.parent == self._directory
                or self._key_file in (store._path, store._key_path)):raise ValueError
        self._draft, self._reference, self._issued, self._binding = draft, reference, issued, binding
        self._sources, self._original = sources, original
        self._phase = "recover" if type(issued) is EmsAccountRecoveryIssued else "create"
        self._reservation = store._path.name + ".ems-account-send." + issued.plan.plan_digest + ".json"
        self._clock = clock or (lambda: int(time.time()))
        self._closed, self._last, self._lock = False, -1, RLock()
        self._context = canonical_digest(self._fields());self._validate()

    def _fields(self) -> dict[str, Any]:
        return dict(contract=CONTRACT, phase=self._phase, issued=asdict(self._issued), binding=self._binding, draft=asdict(self._draft),
            material_reference=self._reference, directory=str(self._directory.absolute()), identity=list(self._identity),
            store=str(self._store._path.absolute()), store_key_path=str(self._store._key_path.absolute()),
            store_key_digest=hashlib.sha256(self._store._key).hexdigest(), store_parent_identity=list(self._parent_identity),
            witness_key=str(self._key_file.absolute()), checkpoint_store_ref=self._store._checkpoint_store_ref)

    def _validate(self) -> None:
        p, a, issued = self._issued.plan, self._issued.authorization, self._issued
        p.__post_init__();a.__post_init__();self._draft.__post_init__()
        for value in (issued.source_digest, issued.scope_digest, issued.parent_digest):require_digest(value, "account_source")
        if type(issued) is EmsAccountFixtureIssued:
            if self._original is not None or self._phase != "create":raise ValueError
            action, adapter = ACTION_ID, ADAPTER_REF
            parameters = parameters_digest(self._draft, self._reference, issued.parent_digest)
            current = current_digest(self._draft, self._reference, issued.parent_digest, issued.scope_digest, issued.source_digest)
            expected = expected_digest(self._draft, self._reference, issued.parent_digest, issued.scope_digest, issued.source_digest)
        elif type(issued) is EmsAccountRecoveryIssued:
            if self._original is None or not self._original._store._read_only or self._phase != "recover":raise ValueError
            owned = self._original.inspect_verified_original()
            if (owned.custody_digest != issued.original_digest or owned.parent_digest != issued.parent_digest
                    or owned.created_scope_digest != issued.scope_digest or owned.baseline_digest != issued.baseline_digest
                    or self._original._draft != self._draft or owned.material_reference != self._reference):raise ValueError
            action, adapter = RECOVERY_ACTION_ID, RECOVERY_ADAPTER_REF
            parameters, current, expected = recovery_parameters(owned), recovery_current(owned, issued.source_digest), recovery_expected(owned, issued.source_digest)
        else:raise ValueError
        if (p.action_id != action or p.adapter_ref != adapter or p.action_version != ACTION_VERSION or p.target_ref != TARGET_REF
                or p.compensation_ref is not None or p.parameters_digest != parameters
                or p.expected_current_digest != current or p.expected_state_digest != expected
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest or a.requester_digest != p.requester_digest
                or a.confirmation_digest != p.confirmation_digest or a.approval_digest != p.approval_digest
                or a.expires_at > p.expires_at or a.one_time is not True or a.execution_authorized is not True
                or self._context != canonical_digest(self._fields()) or _directory_identity(self._directory) != self._identity
                or _directory_identity(self._store._path.parent) != self._parent_identity
                or _key(self._key_file) != self._key or _key(self._store._key_path) != self._store._key
                or {p.name for p in self._directory.iterdir()} - _NAMES):raise ValueError
        if set(self._binding) != {"instance", "owner", "session", "caller_transport", "issuer"}:raise ValueError
        for value in self._binding.values():require_digest(value, "account_custody_binding")
        self._store.verify_ready()

    def _write(self, name: str, fields: dict[str, Any]) -> None:
        if name not in _NAMES | {self._reservation}:raise ValueError
        self._validate();value = dict(context_digest=self._context, **fields)
        raw = bytearray(_canonical(dict(value=value, signature=self._mac(name, value))))
        try:
            parent = self._store._path.parent if name == self._reservation else self._directory
            identity = self._parent_identity if name == self._reservation else self._identity
            _write_once(parent, identity, name, raw)
        finally:_zeroize_mutable(raw)
        if self._record(name, set(fields)) != value:raise ValueError

    def _record(self, name: str, fields: set[str]) -> dict[str, Any]:
        self._validate()
        return self._read_record(name, fields)

    def _read_record(self, name: str, fields: set[str]) -> dict[str, Any]:
        """Read a signed record within an already validated custody boundary."""
        if name not in _NAMES | {self._reservation}:raise ValueError
        parent = self._store._path.parent if name == self._reservation else self._directory
        raw = _read(parent / name, 65536)
        try:
            packet = _decode(raw)
            if type(packet) is not dict or set(packet) != {"value", "signature"}:raise ValueError
            value = packet["value"]
            if (type(value) is not dict or set(value) != fields | {"context_digest"} or value["context_digest"] != self._context
                    or type(packet["signature"]) is not str or not hmac.compare_digest(packet["signature"], self._mac(name, value))):raise ValueError
            return value
        finally:_zeroize_mutable(raw)

    def retain_before_dispatch(self) -> None:
        try:
            with self._lock:
                if self._store._read_only or self._sources is None or self._store.claim_count != 0 or any(self._directory.iterdir()):raise ValueError
                current = self._sources._current
                if current is None or current.full_scope.digest != self._issued.scope_digest:raise ValueError
                self._sources.check_current(current);self._write("binding.json", dict(fields=self._fields()))
        except Exception:self._closed = True;raise ValueError(_ERROR) from None

    @classmethod
    def open_original(cls, directory: Path, witness_key_file: Path, store: PersistentM4ExecutionStateStore) -> EmsAccountCustody:
        return cls._open(directory, witness_key_file, store, original=None)

    @classmethod
    def open_recovery(cls, directory: Path, witness_key_file: Path, store: PersistentM4ExecutionStateStore,
                      original: EmsAccountCustody) -> EmsAccountCustody:
        return cls._open(directory, witness_key_file, store, original=original)

    @classmethod
    def _open(cls, directory: Path, witness_key_file: Path, store: PersistentM4ExecutionStateStore, *,
              original: EmsAccountCustody | None) -> EmsAccountCustody:
        raw = bytearray()
        try:
            if type(store) is not PersistentM4ExecutionStateStore or not store._read_only:raise ValueError
            raw = _read(Path(directory) / "binding.json", 65536);packet = _decode(raw);value = packet["value"]
            key = _key(Path(witness_key_file))
            if (set(packet) != {"value", "signature"} or set(value) != {"context_digest", "fields"}
                    or not hmac.compare_digest(packet["signature"], cls._tag(key, "binding.json", value))):raise ValueError
            fields = value["fields"];item = fields["issued"]
            issued: EmsAccountFixtureIssued | EmsAccountRecoveryIssued
            args = (M4ExecutionPlan(**item["plan"]), M4ExecutionAuthorization(**item["authorization"]),
                item["source_digest"], item["scope_digest"], item["parent_digest"])
            if original is None:
                if fields["phase"] != "create":raise ValueError
                issued = EmsAccountFixtureIssued(*args)
            else:
                if type(original) is not EmsAccountCustody or fields["phase"] != "recover":raise ValueError
                issued = EmsAccountRecoveryIssued(*args, item["original_digest"], item["baseline_digest"])
            result = cls.__new__(cls)
            result._setup(directory, witness_key_file, store, ProspectiveEmsTagManagerAccount(**fields["draft"]),
                fields["material_reference"], issued, fields["binding"], sources=None, original=original, clock=None)
            if result._fields() != fields or result._context != value["context_digest"]:raise ValueError
            if original is None:result.inspect_verified_original()
            else:result.inspect_restoration()
            return result
        except Exception:raise ValueError(_ERROR) from None
        finally:_zeroize_mutable(raw)

    def _claim(self) -> M4Claim:
        self._validate();p, a = self._issued.plan, self._issued.authorization
        return self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest,
            context_digest=canonical_digest(dict(plan_digest=p.plan_digest, authorization_digest=a.authorization_digest, revision=p.revision)))

    def _time(self, value: object) -> int:
        if type(value) is not int or not self._issued.authorization.issued_at <= value < self._issued.authorization.expires_at:raise ValueError
        return value

    def _writing(self, *, failure: bool = False) -> int:
        self._validate()
        if self._store._read_only or self._closed and not failure:raise ValueError
        _require_m4_dispatch_ownership(self._issued.plan, self._issued.authorization, self._store)
        if self._claim().result is not None:raise ValueError
        now = self._time(self._clock())
        if now < self._last:raise ValueError
        self._last = now
        if self._record("binding.json", {"fields"})["fields"] != self._fields():raise ValueError
        return now

    def begin_send(self, scope: EmsTagIdentityScope) -> None:
        try:
            with self._lock:
                now = self._writing()
                if type(scope) is not EmsTagIdentityScope or scope.digest != self._issued.scope_digest:raise ValueError
                self._write(self._reservation, dict(reserved_at=now))
                reservation = self._record(self._reservation, {"reserved_at"})
                self._write("send.json", dict(reservation_digest=canonical_digest(reservation), claimed_at=now, scope_digest=scope.digest))
        except Exception:self._closed = True;raise ValueError(_ERROR) from None

    def _send(self) -> dict[str, Any]:
        send = self._record("send.json", {"reservation_digest", "claimed_at", "scope_digest"})
        reservation = self._record(self._reservation, {"reserved_at"})
        return self._qualify_send(send, reservation)

    def _qualify_send(self, send: dict[str, Any], reservation: dict[str, Any]) -> dict[str, Any]:
        if (send["reservation_digest"] != canonical_digest(reservation) or send["scope_digest"] != self._issued.scope_digest
                or self._time(send["claimed_at"]) < self._time(reservation["reserved_at"])):raise ValueError
        return send

    def capture_ack(self, raw: bytearray, *, status: int, content_type: str, complete: bool) -> None:
        try:
            with self._lock:
                now = self._writing();send = self._send();root = valid = False;data = None
                try:
                    payload = _decode(raw);root = type(payload) is dict;data = _ack_data(payload)
                    valid = data is None or type(data) in (int, dict)
                except Exception:pass
                reply_mac = hmac.new(self._key, _DOMAIN + b"first-response\x00", hashlib.sha256);reply_mac.update(raw)
                attempt = dict(send_digest=canonical_digest(send), attempted_at=now, http_status=status if type(status) is int and 0 <= status <= 599 else 0,
                    complete=complete is True, json_content_type=type(content_type) is str and content_type.split(";")[0].strip().lower() == "application/json",
                    root_complete=root, envelope_valid=valid, reply_digest=reply_mac.hexdigest())
                self._write("ack-attempt.json", attempt)
                if type(status) is not int or status != 200 or not all(attempt[k] for k in ("complete", "json_content_type", "root_complete", "envelope_valid")):raise ValueError
                numeric = data if type(data) is int else data.get("id") if type(data) is dict else None
                if numeric is not None:_admin_id(numeric)
                self._write("ack.json", dict(attempt_digest=canonical_digest(self._record("ack-attempt.json", _ATTEMPT)),
                    acknowledged_at=now, id_tag=self._mac("id-selector", numeric)))
        except Exception:self._closed = True;raise ValueError(_ERROR) from None
        finally:_zeroize_mutable(raw)

    def _ack(self) -> dict[str, Any]:
        send = self._send();attempt = self._record("ack-attempt.json", _ATTEMPT)
        ack = self._record("ack.json", {"attempt_digest", "acknowledged_at", "id_tag"})
        return self._qualify_ack(send, attempt, ack)

    def _qualify_ack(self, send: dict[str, Any], attempt: dict[str, Any], ack: dict[str, Any]) -> dict[str, Any]:
        if (attempt["send_digest"] != canonical_digest(send) or ack["attempt_digest"] != canonical_digest(attempt)
                or type(attempt["http_status"]) is not int or attempt["http_status"] != 200
                or any(type(attempt[k]) is not bool or not attempt[k] for k in ("complete", "json_content_type", "root_complete", "envelope_valid"))
                or self._time(ack["acknowledged_at"]) < self._time(attempt["attempted_at"])
                or self._time(attempt["attempted_at"]) < self._time(send["claimed_at"])):raise ValueError
        return ack

    def capture_effect(self, before: EmsTagIdentityScope, after: EmsTagIdentityScope) -> None:
        try:
            with self._lock:
                now = self._writing();ack = self._ack()
                self._write("effect-attempt.json", dict(ack_digest=canonical_digest(ack), attempted_at=now))
                if before.digest != self._issued.scope_digest:raise ValueError
                if self._original is None:
                    candidate = verify_account_created(before, after, self._draft)
                    numeric, digest = candidate.numeric_id, candidate.digest
                else:
                    owned = self._original.inspect_verified_original()
                    if after.digest != owned.baseline_digest:raise ValueError
                    numeric, digest = owned.account_numeric_id, owned.account_digest
                if ack["id_tag"] not in (self._mac("id-selector", None), self._mac("id-selector", numeric)):raise ValueError
                attempt = self._record("effect-attempt.json", {"ack_digest", "attempted_at"});self._writing()
                self._write("effect.json", dict(attempt_digest=canonical_digest(attempt), ack_digest=canonical_digest(ack),
                    account_numeric_id=numeric, account_digest=digest, scope_digest=after.digest, verified_at=now))
        except Exception:self._closed = True;raise ValueError(_ERROR) from None

    def inspect_effect(self, *, require_verified: bool = True) -> dict[str, Any]:
        if type(require_verified) is not bool:raise ValueError(_ERROR)
        if require_verified:
            result = self._claim().result
            if result is None or str(result.outcome) != "succeeded" or str(result.verification) != "verified" or str(result.compensation) != "not_requested":raise ValueError(_ERROR)
        else:self._validate()
        # Match the Role reader: authenticate each record once between full
        # custody/ledger checks without caching a chain across callers.
        send = self._qualify_send(
            self._read_record("send.json", {"reservation_digest", "claimed_at", "scope_digest"}),
            self._read_record(self._reservation, {"reserved_at"}))
        ack = self._qualify_ack(send, self._read_record("ack-attempt.json", _ATTEMPT),
            self._read_record("ack.json", {"attempt_digest", "acknowledged_at", "id_tag"}))
        attempt = self._read_record("effect-attempt.json", {"ack_digest", "attempted_at"})
        effect = self._read_record("effect.json", {"attempt_digest", "ack_digest", "account_numeric_id", "account_digest", "scope_digest", "verified_at"})
        _admin_id(effect["account_numeric_id"])
        for value in (effect["account_digest"], effect["scope_digest"]):require_digest(value, "account_effect")
        if (effect["attempt_digest"] != canonical_digest(attempt) or effect["ack_digest"] != canonical_digest(ack)
                or attempt["ack_digest"] != canonical_digest(ack) or self._time(effect["verified_at"]) < self._time(attempt["attempted_at"])
                or self._time(attempt["attempted_at"]) < self._time(ack["acknowledged_at"])):raise ValueError(_ERROR)
        self._validate()
        return effect

    def inspect_verified_original(self) -> EmsAccountOriginal:
        try:
            if self._phase != "create":raise ValueError
            effect = self.inspect_effect()
            result = EmsAccountOriginal(self._context, canonical_digest(effect), self._issued.scope_digest,
                effect["scope_digest"], effect["account_digest"], effect["account_numeric_id"], self._issued.parent_digest, self._reference)
            result.__post_init__();return result
        except Exception:raise ValueError(_ERROR) from None

    def inspect_restoration(self) -> EmsAccountOriginal:
        try:
            if self._phase != "recover" or self._original is None:raise ValueError
            owned = self._original.inspect_verified_original();effect = self.inspect_effect()
            if (effect["scope_digest"] != owned.baseline_digest or effect["account_numeric_id"] != owned.account_numeric_id
                    or effect["account_digest"] != owned.account_digest):raise ValueError
            return owned
        except Exception:raise ValueError(_ERROR) from None

    def require_recovery_source(self, sources: EmsTagIdentitySources, requester_digest: str) -> EmsAccountOriginal:
        try:
            if (not self._store._read_only or type(sources) is not EmsTagIdentitySources
                    or requester_digest != self._issued.plan.requester_digest):raise ValueError
            sources._pins();result = self.inspect_verified_original()
            if (sources._binding != self._binding["instance"] or self._mac("owner", sources._owner) != self._binding["owner"]
                    or sources._transport.session_binding_digest(self._key) == self._binding["session"]):raise ValueError
            return result
        except Exception:raise ValueError(_ERROR) from None

    def capture_failure(self, *, stage: str, category: str) -> None:
        try:
            with self._lock:
                now = self._writing(failure=True)
                if stage not in {"dispatch", "ack", "effect", "close"} or not category.isidentifier() or len(category) > 96:raise ValueError
                self._write("failure.json", dict(stage=stage, category=category, observed_at=now))
        except Exception:self._closed = True;raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock:self._closed = True
