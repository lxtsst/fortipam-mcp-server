"""One private pair→disabled User→User removal→pair removal lab intent.

All six mutations/observations retain their original child M4. This parent signs
ordering and exact composition only; it cannot grant a child's dispatch authority.
Login and automatic failover remain unqualified.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
from threading import RLock
from typing import Any, cast

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_ref

from .m4_execution_store import PersistentM4ExecutionStateStore
from .ldap_server_projection import _digest
from .radius_remote_user_contract import RadiusRemoteUserBinding
from .radius_remote_user_http_transport import FortiPamRadiusRemoteUserHttpTransport
from .radius_remote_user_owned_target import RadiusRemoteUserOwnedTarget
from .radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow
from .radius_remote_user_pair_handoff import retain_radius_target_handoff
from .radius_remote_user_absence_guard import RadiusRemoteUserAbsenceGuard
from .radius_remote_user_preparation import retain_radius_user_preparation, NAME as PREPARATION_FILE
from .radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport, _Connection
from .radius_server_pair_lifecycle_workflow import RadiusServerPairLifecycleWorkflow
from .radius_server_pair_m4_runtime import RadiusPairM4ExecutionBinding
from .radius_server_pair_recovery_workflow import RadiusServerPairRecoveryWorkflow

CONTRACT = "fortipam-v4-radius-pair-disabled-user-lifecycle-private-v1"
_ERROR = "The private RADIUS User lifecycle is unavailable."
_DOMAIN = b"fortipam-radius-pair-disabled-user-lifecycle-v1\x00"


@dataclass(frozen=True, slots=True, repr=False)
class _Preview(_OpaqueC3Object):
    pair_ref: str
    pair_summary_digest: str
    expires_at: int
    nonce: str
    preview_ref: str


class RadiusRemoteUserLifecycleWorkflow(_OpaqueC3Object):
    """Non-resumable fixed six-child lab flow with ordered independent recovery."""

    def __init__(self, pair: RadiusServerPairLifecycleWorkflow, binding: RadiusRemoteUserBinding, *,
            user_state_directory: Path, user_create_store: PersistentM4ExecutionStateStore,
            user_remove_store: PersistentM4ExecutionStateStore,
            user_create_authority_key: bytes, user_remove_authority_key: bytes, authority_key: bytes,
            user_create_scope_ref: str, user_remove_scope_ref: str,
            execution_enabled: bool = False,
            user_connection_factory: Callable[..., _Connection] | None = None) -> None:
        try:
            if (type(pair) is not RadiusServerPairLifecycleWorkflow or pair._retain_on_success is not True
                    or type(binding) is not RadiusRemoteUserBinding or binding.radius is not pair._create._binding
                    or type(user_create_store) is not PersistentM4ExecutionStateStore
                    or type(user_remove_store) is not PersistentM4ExecutionStateStore
                    or type(execution_enabled) is not bool
                    or user_connection_factory is not None and not callable(user_connection_factory)):
                raise ValueError
            for key in (authority_key, user_create_authority_key, user_remove_authority_key):
                if type(key) is not bytes or not 32 <= len(key) <= 4096: raise ValueError
            for scope in (user_create_scope_ref, user_remove_scope_ref): require_ref(scope, "user_scope")
            if (not isinstance(user_state_directory, Path) or not user_state_directory.is_absolute()
                    or ".." in user_state_directory.parts
                    or any(p.is_symlink() for p in (user_state_directory, *user_state_directory.parents))):
                raise ValueError
            info = user_state_directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
                raise ValueError
            self._pair, self._binding = pair, binding
            self._directory, self._directory_identity = user_state_directory, (info.st_dev, info.st_ino)
            self._user_stores = (user_create_store, user_remove_store)
            self._user_keys = (user_create_authority_key, user_remove_authority_key)
            self._scopes = (user_create_scope_ref, user_remove_scope_ref)
            self._key, self._enabled, self._initial_enabled = authority_key, execution_enabled, execution_enabled
            self._factory = user_connection_factory
            self._factory_pin = self._factory
            self._preview: _Preview | None = None
            self._authorization: tuple[str, str] | None = None
            self._radius_execution: RadiusPairM4ExecutionBinding | None = None
            self._user_create: RadiusRemoteUserLiveWorkflow | None = None
            self._user_remove: RadiusRemoteUserLiveWorkflow | None = None
            self._finished_users: set[int] = set()
            self._started = self._pair_finished = self._closed_flag = False
            self._user_prepare_started = False
            self._preparation_started = False
            self._preparation_reader: FortiPamRadiusRemoteUserHttpTransport | None = None
            self._preparation_pin: str | None = None
            self._lock = RLock()
            c, r = pair._create, pair._recovery
            ns = r._namespace
            self._pair_remove = RadiusServerPairRecoveryWorkflow(c._binding, c._config,
                expected_serial=c._serial, state_directory=c._directory, execution_store=r._store,
                authority_key=r._key, environment_ref=ns["environment_ref"], scope_ref=ns["scope_ref"],
                audience_ref=ns["audience_ref"], allowed_requester_digest=ns["requester_digest"],
                allowed_transport_digest=ns["transport_digest"], execution_enabled=execution_enabled,
                clock=c._now, connection_factory=cast(Callable[..., _Connection], c._reader._factory))
            # The parent pins this base and the complete User graph. Once owned
            # pair evidence exists, only that exact graph may narrow the child.
            self._pair_remove_base = self._pair_remove._base_composition_digest()
            self._namespace = self._bindings()
        except Exception:
            raise RuntimeError(_ERROR) from None

    def _bindings(self) -> str:
        p, c = self._pair, self._pair._create
        if self._closed_flag or self._factory is not self._factory_pin: raise ValueError
        info = self._directory.lstat()
        if (any(path.is_symlink() for path in (self._directory, *self._directory.parents))
                or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_uid != os.getuid() or (info.st_dev, info.st_ino) != self._directory_identity):
            raise ValueError
        if not self._user_prepare_started and any(self._directory.iterdir()):
            if (not self._preparation_started or set(self._directory.iterdir()) != {
                    self._directory / "operation.lock", self._directory / PREPARATION_FILE}): raise ValueError
        if self._preparation_started:
            reader = self._preparation_reader
            if (reader is None or reader._binding is not self._binding or reader._directory != self._directory
                    or reader._target._execution is not self._radius_execution
                    or _digest(reader._read_state(PREPARATION_FILE)) != self._preparation_pin): raise ValueError
        if self._pair_finished:
            if not p._closed(): raise ValueError
        elif p._bindings() != p._namespace:
            raise ValueError
        if (self._binding.radius is not c._binding or self._pair_remove._store is not p._recovery._store
                or self._pair_remove._composition_digest() != self._pair_remove._composition
                or self._pair_remove._base_composition_digest() != self._pair_remove_base
                or self._pair_remove._enabled is not self._initial_enabled
                or hashlib.sha256(self._pair_remove._key).hexdigest() != p._key_digests[3]):
            raise ValueError
        guard = self._pair_remove._user_absence
        if self._user_remove is None:
            if guard is not None: raise ValueError
        elif (type(guard) is not RadiusRemoteUserAbsenceGuard
                or guard._reader._binding is not self._binding
                or guard._reader._store is not self._user_stores[1]
                or guard._reader._original_store is not self._user_stores[0]
                or guard._reader._target is not self._user_remove._target
                or guard._reader._composition != self._user_remove._composition
                or guard._reader._namespace_pin != self._user_remove._namespace_pin):
            raise ValueError
        namespaces = [c._authority._namespace, p._primary._namespace, p._secondary._namespace, p._recovery._namespace]
        scopes = [ns["scope_ref"] for ns in namespaces] + list(self._scopes)
        if len(set(scopes)) != 6: raise ValueError
        stores = (c._execution_store, p._primary._store, p._secondary._store, p._recovery._store,
            c._material_store, c._group_store, *self._user_stores)
        paths = [path for store in stores for path in (store._path, store._key_path)]
        protected = set(paths) | {c._source._key, c._source._known_hosts}
        keys = [*p._key_digests, *(hashlib.sha256(key).hexdigest() for key in (*self._user_keys, self._key))]
        if (len(protected) != len(paths) + 2 or len(set(keys)) != 8
                or len({store._key for store in stores}) != 8
                or set(keys) & {hashlib.sha256(store._key).hexdigest() for store in stores}
                or self._directory == c._directory or self._directory in c._directory.parents
                or c._directory in self._directory.parents
                or any(self._directory == path or self._directory in path.parents for path in protected)
                or any(Path(str(path) + suffix) in protected for path in paths for suffix in ("-wal", "-shm", "-journal"))):
            raise ValueError
        for index, child in enumerate((self._user_create, self._user_remove)):
            if child is not None:
                if child._store is not self._user_stores[index] or child._binding is not self._binding:
                    raise ValueError
                if index in self._finished_users:
                    if (not child._closed or child._enabled or child._key != b"" or child._original_key is not None
                            or canonical_digest(child._namespace) != child._namespace_pin
                            or any(not t._closed or t._execution_enabled or t._recovery_enabled
                                or t._composition() != t._config_pin for t in (child._reader, child._transport))):
                        raise ValueError
                else:
                    child._gate()
        return canonical_digest({"contract": CONTRACT, "pair_namespace": p._namespace,
            "user_parameters": self._binding.parameters_digest, "user_scopes": list(self._scopes),
            "user_journal": str(self._directory), "user_directory_identity": list(self._directory_identity),
            "pair_compositions": [c._composition, p._primary._composition, p._secondary._composition, p._recovery._composition],
            "namespaces": namespaces, "store_paths": [str(path) for path in paths],
            "store_keys": [hashlib.sha256(store._key).hexdigest() for store in stores], "signing_keys": keys,
            "pair_remove_composition": self._pair_remove_base})

    def _gate(self, *, execute: bool = True) -> None:
        if not self._user_prepare_started:
            for store in self._user_stores:
                # Readiness verifies the ledger using its cached epoch key;
                # also reject a changed restart input before pair dispatch.
                if not hmac.compare_digest(store._load_key(), store._key):
                    raise ValueError
                store.verify_ready()
        if (self._closed_flag or execute and (not self._enabled or not self._initial_enabled)
                or self._bindings() != self._namespace
                or not self._user_prepare_started and any(store.claim_count for store in self._user_stores)):
            raise ValueError

    def _identity(self, identity: Mapping[str, str]) -> None:
        self._pair._identity(identity)

    def _mac(self, purpose: str, value: object) -> str:
        wire = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00" + wire, hashlib.sha256).hexdigest()

    def _context(self, p: _Preview) -> dict[str, object]:
        return {"namespace": self._namespace, "pair_ref": p.pair_ref, "pair_summary_digest": p.pair_summary_digest,
            "expires_at": p.expires_at, "nonce": p.nonce}

    def _check(self, p: _Preview, *, execute: bool = True) -> None:
        self._gate(execute=execute)
        if (self._started or self._pair._create._now() >= p.expires_at
                or p.preview_ref != "radius-user-lifecycle-preview-" + self._mac("preview", self._context(p))):
            raise ValueError

    def _summary(self, p: _Preview) -> dict[str, object]:
        return {"contract": CONTRACT, "policy_mode": "lab_auto", "summary_revision": 1,
            "preview_ref": p.preview_ref, "expires_at": p.expires_at,
            "requester_digest": self._pair._create._authority._namespace["requester_digest"],
            "Current State": {"pair_create_summary_digest": p.pair_summary_digest,
                "fresh_unclaimed_user_journal": True,
                "dependent_user_preflight": "after_owned_pair_before_user_dispatch"},
            "Proposed Changes": {"scope": "one_fresh_pair_and_one_disabled_remote_user", "child_m4_actions": 6,
                "user_status": "disable", "user_profile": "Standard", "user_wildcard": False,
                "group_association": False, "login_or_credential_probe": False},
            "Expected State": {"original_child_m4_required": True, "user_removed_before_pair": True,
                "both_final_dual_absence_required": True, "all_candidate_gates_closed": True,
                "user_authentication_qualified": False, "automatic_failover_qualified": False},
            "authorization_and_approval": {"mode": "standing_owner_lab_authority", "parent_grants_no_child_dispatch": True},
            "risk_and_effects": {"class": "C3", "effect": "one_bounded_pair_and_disabled_user_lifecycle"},
            "unresolved_gaps": ["user_enable", "user_authentication", "automatic_failover", "group_mapping", "version_1_9_1"],
            "compensation_and_stop": {"order": ["original_owned_user", "original_owned_pair"],
                "missing_ack_or_uncertain_delete": "retain_claims_read_only_reconcile_no_replay"},
            "device_write_executed": False}

    def preview(self, **identity: str) -> dict[str, object]:
        try:
            with self._lock:
                self._gate(execute=False); self._identity(identity)
                if self._authorization is not None or self._started or any(s.claim_count for s in self._user_stores):
                    raise ValueError
                pair = self._pair.preview(**identity)
                if (type(pair["preview_ref"]) is not str or type(pair["summary_digest"]) is not str
                        or type(pair["expires_at"]) is not int):
                    raise ValueError
                p = _Preview(pair["preview_ref"], pair["summary_digest"], pair["expires_at"], secrets.token_hex(24), "")
                p = _Preview(p.pair_ref, p.pair_summary_digest, p.expires_at, p.nonce,
                    "radius-user-lifecycle-preview-" + self._mac("preview", self._context(p)))
                self._check(p, execute=False); self._preview = p
                summary = self._summary(p)
                return {**summary, "summary_digest": canonical_digest(summary)}
        except Exception:
            raise RuntimeError(_ERROR) from None

    def authorize(self, preview_ref: str, **identity: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(identity)
                p = self._preview
                if p is None or self._authorization is not None or preview_ref != p.preview_ref: raise ValueError
                self._check(p)
                grant = self._pair.authorize(p.pair_ref, **identity)
                issued = self._pair._create._authority._issued
                if type(issued) is not RadiusPairM4ExecutionBinding: raise ValueError
                self._radius_execution = issued
                child_ref = str(grant["authorization_ref"])
                reference = "radius-user-lifecycle-auth-" + self._mac("authorize", {
                    **self._context(p), "pair_authorization": child_ref, "summary_digest": canonical_digest(self._summary(p))})
                self._authorization = reference, child_ref
                return {"contract": CONTRACT, "policy_mode": "lab_auto", "authorization_ref": reference, "expires_at": p.expires_at}
        except Exception:
            raise RuntimeError(_ERROR) from None

    @staticmethod
    def _success(result: Mapping[str, object]) -> bool:
        return (result.get("outcome") == "succeeded" and result.get("verification") == "verified"
            and result.get("idempotent_replay") is False)

    def _build_users(self) -> None:
        c, issued = self._pair._create, self._radius_execution
        if issued is None: raise ValueError
        self._user_prepare_started = True
        target_transport = FortiPamRadiusPairHttpTransport(c._config, c._binding, expected_serial=c._serial,
            state_directory=c._directory, clock=c._now, connection_factory=cast(Callable[..., _Connection], c._reader._factory))
        target = RadiusRemoteUserOwnedTarget(self._binding, target_transport, issued, c._execution_store)
        reader = FortiPamRadiusRemoteUserHttpTransport(c._config, self._binding, target=target,
            state_directory=self._directory, clock=c._now, connection_factory=self._factory)
        try:
            with reader._locked(): reader._namespace(preparation_digest=self._preparation_pin)
            target = retain_radius_target_handoff(reader, authority_key=self._user_keys[0])
        finally:
            reader.close()
        ns = c._authority._namespace
        common: dict[str, Any] = dict(target=target, state_directory=self._directory, environment_ref=ns["environment_ref"],
            audience_ref=ns["audience_ref"], allowed_requester_digest=ns["requester_digest"],
            allowed_transport_digest=ns["transport_digest"], clock=c._now, connection_factory=self._factory)
        self._user_create = RadiusRemoteUserLiveWorkflow(self._binding, c._config,
            execution_store=self._user_stores[0], authority_key=self._user_keys[0],
            scope_ref=self._scopes[0], execution_enabled=self._enabled, **common)
        self._user_remove = RadiusRemoteUserLiveWorkflow(self._binding, c._config, operation="remove",
            execution_store=self._user_stores[1], authority_key=self._user_keys[1], original_create_store=self._user_stores[0],
            original_create_authority_key=self._user_keys[0], scope_ref=self._scopes[1], execution_enabled=self._enabled, **common)
        original = self._pair_remove
        guard = RadiusRemoteUserAbsenceGuard(self._user_remove)
        ns = original._namespace
        try:
            narrowed = RadiusServerPairRecoveryWorkflow(original._binding, original._transport._config,
                expected_serial=original._transport._serial, state_directory=original._transport._directory,
                execution_store=original._store, authority_key=original._key,
                environment_ref=ns["environment_ref"], scope_ref=ns["scope_ref"], audience_ref=ns["audience_ref"],
                allowed_requester_digest=ns["requester_digest"], allowed_transport_digest=ns["transport_digest"],
                execution_enabled=self._enabled, clock=c._now,
                connection_factory=cast(Callable[..., _Connection], original._transport._factory),
                user_absence_guard=guard)
        except Exception:
            guard.close()
            raise
        original.close()
        self._pair_remove = narrowed

    def _uncertain_user_absent(self) -> bool:
        child = self._user_create
        if child is None: return False
        reader = FortiPamRadiusRemoteUserHttpTransport(child._reader._config, self._binding,
            target=child._target, state_directory=self._directory, clock=self._pair._create._now,
            connection_factory=cast(Callable[..., _Connection], child._reader._factory))
        try:
            return reader.inspect_uncertain_create() == "absent_observed"
        finally:
            reader.close()

    def _retain_preparation(self) -> None:
        c, e = self._pair._create, self._radius_execution
        if e is None or self._preparation_started: raise ValueError
        target_reader = FortiPamRadiusPairHttpTransport(c._config, c._binding,
            expected_serial=c._serial, state_directory=c._directory, clock=c._now,
            connection_factory=cast(Callable[..., _Connection], c._reader._factory))
        target = RadiusRemoteUserOwnedTarget(self._binding, target_reader, e, c._execution_store)
        self._preparation_reader = FortiPamRadiusRemoteUserHttpTransport(c._config, self._binding,
            target=target, state_directory=self._directory, clock=c._now, connection_factory=self._factory)
        self._preparation_started = True
        ns = c._authority._namespace
        identity = {name: ns[name] for name in ("environment_ref", "audience_ref", "requester_digest", "transport_digest")}
        identity.update(user_create_scope_ref=self._scopes[0], user_remove_scope_ref=self._scopes[1])
        self._preparation_pin = retain_radius_user_preparation(self._preparation_reader,
            authority_key=self._user_keys[0], user_stores=self._user_stores,
            user_authority_keys=self._user_keys, identity=identity)

    def execute(self, authorization_ref: str, **identity: str) -> dict[str, object]:
        with self._lock:
            try:
                self._identity(identity)
                p = self._preview
                if p is None or self._authorization is None or authorization_ref != self._authorization[0]: raise ValueError
                self._check(p)
                if self._radius_execution is not self._pair._create._authority._issued:
                    raise ValueError
                expected = "radius-user-lifecycle-auth-" + self._mac("authorize", {
                    **self._context(p), "pair_authorization": self._authorization[1], "summary_digest": canonical_digest(self._summary(p))})
                if not hmac.compare_digest(expected, authorization_ref): raise ValueError
            except Exception:
                raise RuntimeError(_ERROR) from None
            self._started = True
            pair_created = user_created = user_removed = user_absent = pair_removed = pair_absent = False
            failure: str | None = None
            stage = "pair_preparation"
            try:
                self._retain_preparation(); self._gate()
                stage = "pair_configure"
                result = self._pair.execute(self._authorization[1], **identity)
                self._pair_finished = True
                pair_created = self._success(result) and result.get("owned_entry_retained") is True
                if not pair_created:
                    if result.get("original_ack_removal_verified") is True:
                        pair_removed = self._pair_remove._transport.inspect_deleted()
                        pair_absent = pair_removed
                    raise ValueError
                self._gate()
                stage = "user_prepare"
                self._build_users(); self._gate()
                stage = "user_create"
                child = self._user_create
                if child is None: raise ValueError
                try:
                    preview = child.preview(**identity)
                    grant = child.authorize(str(preview["preview_ref"]), **identity)
                    user_created = self._success(child.execute(str(grant["authorization_ref"]), **identity))
                finally:
                    child.close(); self._finished_users.add(0)
                if not user_created: raise ValueError
            except Exception:
                failure = stage
            finally:
                # Recovery never replays a child. A fresh independent M4 may
                # reconcile an original ACK or a consumed DELETE's dual absence.
                if self._enabled and self._initial_enabled and not self._closed_flag:
                    try:
                        self._gate()
                        user = self._user_remove
                        if user is not None and user._reader._exists("create-ack.json"):
                            stage = "user_remove"
                            try:
                                preview = user.preview(**identity)
                                grant = user.authorize(str(preview["preview_ref"]), **identity)
                                user_removed = self._success(user.execute(str(grant["authorization_ref"]), **identity))
                                user_absent = user._reader.inspect_deleted()
                                if not user_removed and failure is None: failure = "user_remove"
                            finally:
                                user.close(); self._finished_users.add(1)
                        if not pair_removed:
                            self._gate()
                            if pair_created and self._pair_remove._user_absence is None:
                                # Partial User preparation cannot supply a
                                # qualified final-send dependency. Retain pair.
                                raise ValueError
                            claimed_user = os.path.lexists(self._directory / "create.claim.json")
                            if claimed_user and not user_absent:
                                user_absent = self._uncertain_user_absent()
                            if claimed_user and not user_absent:
                                # A string-valued remote-server may not be
                                # reflected by the pair's product q_ref count.
                                # Never detach a possibly surviving owned User.
                                raise ValueError
                            stage = "pair_remove"
                            # Full original pair state and q_ref=0 are checked
                            # independently; unresolved user references deny it.
                            preview = self._pair_remove.preview(**identity)
                            grant = self._pair_remove.authorize(str(preview["preview_ref"]), **identity)
                            pair_removed = self._success(self._pair_remove.execute(str(grant["authorization_ref"]), **identity))
                            pair_absent = self._pair_remove._transport.inspect_deleted()
                            if not pair_removed and failure is None: failure = "pair_remove"
                    except Exception:
                        if failure is None: failure = stage
                if stage == "pair_remove" and self._pair_remove._user_absence is not None:
                    try:
                        if not self._enabled or self._closed_flag: raise ValueError
                        self._pair_remove._user_absence.inspect()
                        user_absent = True
                    except Exception:
                        user_absent = False
                self.close()
            complete = pair_created and user_created and user_removed and user_absent and pair_removed and pair_absent
            return {"contract": CONTRACT, "outcome": "succeeded" if complete else "reconciliation_required",
                "verification": "verified" if complete else "unknown", "idempotent_replay": False,
                "pair_configure_verified": pair_created, "user_create_verified": user_created,
                "user_remove_verified": user_removed, "user_absence_verified": user_absent,
                "pair_remove_verified": pair_removed, "pair_absence_verified": pair_absent,
                "all_candidate_gates_closed": self._closed(),
                "user_authentication_qualified": False, "automatic_failover_qualified": False,
                "failure_stage": failure if failure is not None else (None if complete else "recovery")}

    def _closed(self) -> bool:
        return (self._closed_flag and not self._enabled and self._pair._closed()
            and not self._pair_remove._enabled and not self._pair_remove._transport._recovery_enabled
            and all(child is None or child._closed and not child._enabled
                for child in (self._user_create, self._user_remove)))

    def close(self) -> None:
        self._enabled = False; self._closed_flag = True
        if self._preparation_reader is not None: self._preparation_reader.close()
        for child in (self._user_create, self._user_remove):
            if child is not None:
                child._enabled = False
                child._transport.close(); child._reader.close()
        self._pair.close(); self._pair_remove.close()
        for child in (self._user_create, self._user_remove):
            if child is not None: child.close()
        self._key = b""; self._user_keys = (b"", b"")
        self._radius_execution = None
