"""One non-resumable pair configuration; every child retains original M4."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
from threading import RLock
from typing import Mapping

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport
from .radius_server_pair_live_workflow import RadiusServerPairLiveWorkflow
from .radius_server_pair_owned_connect_workflow import RadiusServerPairOwnedConnectWorkflow
from .radius_server_pair_recovery_workflow import RadiusServerPairRecoveryWorkflow

CONTRACT = "fortipam-v4-radius-pair-lifecycle-candidate-v1"
PERSISTENT_CONTRACT = "fortipam-v4-radius-pair-configure-candidate-v1"
_DOMAIN = b"fortipam-radius-pair-lifecycle-v1\x00"
_ERROR = "The private paired RADIUS lifecycle is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class _Preview(_OpaqueC3Object):
    child_ref: str
    child_summary: str
    expires_at: int
    nonce: str
    reference: str


class RadiusServerPairLifecycleWorkflow(_OpaqueC3Object):
    """Create, observe both fixed ordinals and recover under one bounded lab intent."""

    __slots__ = ("_create", "_primary", "_secondary", "_recovery", "_key", "_namespace",
        "_key_digests", "_finished", "_preview", "_authorization", "_started", "_enabled", "_lock", "_retain_on_success")
    _display_name = "RadiusServerPairLifecycleWorkflow"

    def __init__(self, create: RadiusServerPairLiveWorkflow,
            primary: RadiusServerPairOwnedConnectWorkflow, secondary: RadiusServerPairOwnedConnectWorkflow,
            recovery: RadiusServerPairRecoveryWorkflow, *, authority_key: bytes,
            execution_enabled: bool = False, retain_on_success: bool = False) -> None:
        try:
            if (type(create) is not RadiusServerPairLiveWorkflow
                    or type(primary) is not RadiusServerPairOwnedConnectWorkflow
                    or type(secondary) is not RadiusServerPairOwnedConnectWorkflow
                    or type(recovery) is not RadiusServerPairRecoveryWorkflow
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or type(execution_enabled) is not bool or type(retain_on_success) is not bool):
                raise ValueError
            self._create, self._primary, self._secondary, self._recovery = create, primary, secondary, recovery
            self._key, self._enabled = authority_key, execution_enabled
            self._retain_on_success = retain_on_success
            keys = (create._authority._key, primary._key, secondary._key, recovery._key, authority_key)
            if len(set(keys)) != 5:
                raise ValueError
            self._key_digests = [hashlib.sha256(key).hexdigest() for key in keys]
            self._finished: set[int] = set()
            self._preview: _Preview | None = None
            self._authorization: tuple[str, str] | None = None
            self._started = False
            self._lock = RLock()
            self._namespace = self._bindings()
        except Exception:
            raise ValueError(_ERROR) from None

    def _bindings(self) -> str:
        c, p, s, r = self._create, self._primary, self._secondary, self._recovery
        wires = (c._reader, p._transport, s._transport, r._transport)
        if (any(type(t) is not FortiPamRadiusPairHttpTransport for t in wires)
                or not c._binding is p._binding is s._binding is r._binding is c._source._binding
                or p._ordinal != "primary" or s._ordinal != "secondary"
                or any(t._directory != c._directory or t._serial != c._serial or t._config != c._config for t in wires)
                or c._composition_digest() != c._composition
                or any(n._composition_digest() != n._composition for n in (p, s, r))):
            raise ValueError
        namespaces = (c._authority._namespace, p._namespace, s._namespace, r._namespace)
        for name in ("environment_ref", "audience_ref", "requester_digest", "transport_digest"):
            if any(ns[name] != namespaces[0][name] for ns in namespaces):
                raise ValueError
        if len({ns["scope_ref"] for ns in namespaces}) != 4:
            raise ValueError
        stores = (c._execution_store, p._store, s._store, r._store, c._material_store, c._group_store)
        paths = [path for store in stores for path in (store._path, store._key_path)]
        protected = {*paths, c._source._key, c._source._known_hosts}
        if (len(protected) != len(paths) + 2 or len({store._key for store in stores}) != 6
                or any(c._directory == path or c._directory in path.parents for path in protected)):
            raise ValueError
        for store in stores:
            if any(type(store._path)(str(store._path) + suffix) in protected for suffix in ("-wal", "-shm", "-journal")):
                raise ValueError
        keys = (c._authority._key, p._key, s._key, r._key)
        for index, (key, enabled) in enumerate(zip(keys, (c._enabled, p._enabled, s._enabled, r._enabled))):
            if index in self._finished:
                if key != b"" or enabled:
                    raise ValueError
            elif hashlib.sha256(key).hexdigest() != self._key_digests[index]:
                raise ValueError
        if (hashlib.sha256(self._key).hexdigest() != self._key_digests[4]
                or set(self._key_digests) & {hashlib.sha256(store._key).hexdigest() for store in stores}):
            raise ValueError
        return canonical_digest({"contract": self.contract, "pair": c._binding.parameters_digest,
            "namespaces": list(namespaces), "create_composition": c._composition,
            "native_compositions": [p._composition, s._composition], "recovery_composition": r._composition,
            "paths": [str(path) for path in paths], "authority_keys": self._key_digests,
            "store_keys": [hashlib.sha256(store._key).hexdigest() for store in stores]})

    @property
    def contract(self) -> str:
        return PERSISTENT_CONTRACT if self._retain_on_success else CONTRACT

    def _gate(self, *, execute: bool = True) -> None:
        if (execute and not self._enabled or self._started or self._bindings() != self._namespace
                or any(n._store.claim_count != 0 for n in (self._primary, self._secondary, self._recovery))):
            raise ValueError

    def _identity(self, identity: Mapping[str, str]) -> None:
        if set(identity) != {"requester_digest", "transport_digest"}:
            raise ValueError
        for name, value in identity.items():
            require_digest(value, name)
        self._create._identity(identity["requester_digest"], identity["transport_digest"])

    def _mac(self, purpose: str, value: object) -> str:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00" + raw, hashlib.sha256).hexdigest()

    def _context(self, p: _Preview) -> dict[str, object]:
        return {"namespace": self._namespace, "child_ref": p.child_ref, "child_summary": p.child_summary,
            "expires_at": p.expires_at, "nonce": p.nonce}

    def _check(self, p: _Preview, *, execute: bool = True) -> None:
        self._gate(execute=execute)
        if (self._create._now() >= p.expires_at
                or not hmac.compare_digest(p.reference, "radius-pair-lifecycle-preview-" + self._mac("preview", self._context(p)))):
            raise ValueError

    def _summary(self, p: _Preview) -> dict[str, object]:
        expected = {"original_child_m4_success_required": True, "both_ordinal_observations_recorded": True,
            "full_created_state_preserved": True, "all_candidate_gates_closed": True, "connectivity_qualified": False}
        if self._retain_on_success:
            expected.update(exact_reject_only_response_required=True, owned_entry_retained=True,
                independent_original_ack_removal_available=True)
        else:
            expected["final_dual_absence_required"] = True
        return {"contract": self.contract, "policy_mode": "lab_auto", "summary_revision": 1,
            "preview_ref": p.reference, "expires_at": p.expires_at,
            "Current State": {"bound_entry_absent": True, "schema_defaults_qualified": True,
                "dual_absence_verified": True, "child_dispatches_unconsumed": True},
            "Proposed Changes": {"operation": "configure_radius_pair" if self._retain_on_success else "qualify_disposable_radius_pair",
                "fixed_sequence": ["create", "observe_primary", "observe_secondary"] if self._retain_on_success
                    else ["create", "observe_primary", "observe_secondary", "original_ack_remove"],
                "material_endpoint_acquisitions_maximum": 2, "material_pair_leases_maximum": 1,
                "user_group_associations": False},
            "Expected State": expected,
            "authorization_and_approval": {"mode": "standing_owner_lab_authority", "child_authorizations_independent": True},
            "unresolved_gaps": ["protocol_and_material_application", "automatic_failover", "user_login"],
            "compensation_and_stop": {"failure": "stop_remaining_observations_and_attempt_qualified_original_ack_recovery",
                "uncertain_result": "retain_consumed_claims_without_replay"}, "device_write_executed": False}

    def preview(self, **identity: str) -> dict[str, object]:
        try:
            with self._lock:
                self._gate(execute=False)
                self._identity(identity)
                child = self._create.preview(**identity)
                ref, summary, expires = child["preview_ref"], child["summary_digest"], child["expires_at"]
                if type(ref) is not str or type(summary) is not str or type(expires) is not int:
                    raise ValueError
                p = _Preview(ref, summary, expires, secrets.token_hex(24), "")
                p = _Preview(ref, summary, expires, p.nonce,
                    "radius-pair-lifecycle-preview-" + self._mac("preview", self._context(p)))
                self._check(p, execute=False)
                self._preview, self._authorization = p, None
                public = self._summary(p)
                return {**public, "summary_digest": canonical_digest(public)}
        except Exception:
            raise RuntimeError(_ERROR) from None

    def authorize(self, preview_ref: str, **identity: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(identity)
                require_ref(preview_ref, "preview_ref")
                p = self._preview
                if p is None or preview_ref != p.reference or self._authorization is not None:
                    raise ValueError
                self._check(p)
                auth = self._create.authorize(p.child_ref, **identity)
                ref = auth["authorization_ref"]
                if type(ref) is not str or auth["expires_at"] != p.expires_at:
                    raise ValueError
                self._check(p)
                parent_ref = "radius-pair-lifecycle-auth-" + self._mac("authorize", {
                    **self._context(p), "summary_digest": canonical_digest(self._summary(p)), "child_authorization": ref})
                self._authorization = parent_ref, ref
                return {"contract": self.contract, "policy_mode": "lab_auto", "authorization_ref": parent_ref, "expires_at": p.expires_at}
        except Exception:
            raise RuntimeError(_ERROR) from None

    @staticmethod
    def _success(result: Mapping[str, object]) -> bool:
        return result.get("outcome") == "succeeded" and result.get("verification") == "verified" and result.get("idempotent_replay") is False

    def execute(self, authorization_ref: str, **identity: str) -> dict[str, object]:
        with self._lock:
            try:
                self._identity(identity)
                require_ref(authorization_ref, "authorization_ref")
                p, auth = self._preview, self._authorization
                if p is None or auth is None or authorization_ref != auth[0]:
                    raise ValueError
                self._check(p)
                expected = "radius-pair-lifecycle-auth-" + self._mac("authorize", {
                    **self._context(p), "summary_digest": canonical_digest(self._summary(p)), "child_authorization": auth[1]})
                if not hmac.compare_digest(expected, authorization_ref):
                    raise ValueError
                self._started = True
            except Exception:
                raise RuntimeError(_ERROR) from None
            created = removed = False
            observed = {"primary": False, "secondary": False}
            reject_shapes = {"primary": False, "secondary": False}
            retention_ready = False
            retained = False
            stage, failure = "create", None
            try:
                try:
                    created = self._success(self._create.execute(auth[1], **identity))
                finally:
                    self._create.close()
                    self._finished.add(0)
                if not created:
                    raise ValueError
                for index, (ordinal, native) in enumerate((("primary", self._primary), ("secondary", self._secondary)), 1):
                    stage = "native_" + ordinal
                    if not self._enabled or self._bindings() != self._namespace:
                        raise ValueError
                    try:
                        preview = native.preview(**identity)
                        grant = native.authorize(str(preview["preview_ref"]), **identity)
                        child_result = native.execute(str(grant["authorization_ref"]), **identity)
                        observed[ordinal] = self._success(child_result)
                        if not observed[ordinal]:
                            raise ValueError
                        if self._retain_on_success:
                            stage = "retention_" + ordinal
                            proof = native._transport.inspect_owned_connect_observation()
                            reject_shapes[ordinal] = proof.reject_only_shape
                            if not proof.reject_only_shape:
                                raise ValueError
                    finally:
                        native.close()
                        self._finished.add(index)
                if self._retain_on_success:
                    stage = "retention_readback"
                    # The second observation must not invalidate the first
                    # claim/result or the pair's full-state ownership proof.
                    for native in (self._primary, self._secondary):
                        if not native._transport.inspect_owned_connect_observation().reject_only_shape:
                            raise ValueError
                    retention_ready = True
            except Exception:
                failure = stage
            finally:
                for native in (self._primary, self._secondary):
                    native.close()
                self._finished.update({1, 2})
                try:
                    retained = (self._retain_on_success and retention_ready and created and all(observed.values())
                        and all(reject_shapes.values()) and self._enabled and self._bindings() == self._namespace)
                    if (not retained and self._enabled and self._bindings() == self._namespace
                            and self._recovery._transport._exists("create-ack.json")):
                        preview = self._recovery.preview(**identity)
                        grant = self._recovery.authorize(str(preview["preview_ref"]), **identity)
                        removed = self._success(self._recovery.execute(str(grant["authorization_ref"]), **identity))
                except Exception:
                    pass
                self.close()
            complete = (created and all(observed.values()) and (retained or removed)
                and (not self._retain_on_success or retention_ready))
            result: dict[str, object] = {"contract": self.contract, "outcome": "succeeded" if complete else "reconciliation_required",
                "verification": "verified" if complete else "unknown", "idempotent_replay": False,
                "execution_scope": "persistent_pair_configure" if self._retain_on_success else "disposable_pair_lifecycle", "create_verified": created,
                "ordinal_observations_verified": observed, "original_ack_removal_verified": removed,
                "connectivity_qualified": False, "user_authentication_verified": False,
                "all_candidate_gates_closed": self._closed(),
                "failure_stage": failure if failure is not None else (None if complete else "recovery")}
            if self._retain_on_success:
                result.update(owned_entry_retained=retained, exact_reject_only_responses_verified=retention_ready)
            return result

    def _removal_identity(self, identity: Mapping[str, str]) -> None:
        # A closed configure instance cannot reopen its wire gates. Normal
        # recomposition uses the same original ACK/journals and recovery M4.
        if not self._retain_on_success or not self._enabled or self._bindings() != self._namespace:
            raise ValueError
        self._identity(identity)

    def preview_removal(self, **identity: str) -> dict[str, object]:
        with self._lock:
            self._removal_identity(identity)
            return self._recovery.preview(**identity)

    def authorize_removal(self, preview_ref: str, **identity: str) -> dict[str, object]:
        with self._lock:
            self._removal_identity(identity)
            return self._recovery.authorize(preview_ref, **identity)

    def execute_removal(self, authorization_ref: str, **identity: str) -> dict[str, object]:
        with self._lock:
            self._removal_identity(identity)
            try:
                return self._recovery.execute(authorization_ref, **identity)
            finally:
                self.close()

    def _closed(self) -> bool:
        c = self._create
        return (not self._enabled and not c._enabled and not c._source._enabled
            and all(not n._enabled and not n._transport._owned_connect_enabled for n in (self._primary, self._secondary))
            and not self._recovery._enabled and not self._recovery._transport._recovery_enabled
            and (c._runtime is None or not c._runtime._enabled and not c._runtime._transport._execution_enabled))

    def close(self) -> None:
        # Revoke the wire gates before waiting on child dispatch locks.
        self._enabled = False
        self._create._source.close()
        self._create._enabled = self._primary._enabled = self._secondary._enabled = self._recovery._enabled = False
        self._primary._transport.close_owned_connect()
        self._secondary._transport.close_owned_connect()
        self._recovery._transport._recovery_enabled = False
        if self._create._runtime is not None:
            self._create._runtime._enabled = False
            self._create._runtime._transport._execution_enabled = False
        for child in (self._create, self._primary, self._secondary, self._recovery):
            child.close()
        self._key, self._preview, self._authorization = b"", None, None
