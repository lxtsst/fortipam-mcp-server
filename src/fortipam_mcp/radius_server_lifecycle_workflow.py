"""Fixed private RADIUS primary configuration under one lab intent.

The parent reference starts one non-resumable sequence. Each child retains its
own fresh M4 authorization, durable claim and fixed readback. No parent reference
can replace child dispatch ownership or reopen consumed material/native intake.
The separately pinned persistent profile retains only complete verified success;
its original-ACK removal uses a fresh independent grant after normal composition.
"""
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

from .radius_fixture_material_loader import RadiusFixtureMaterialLoader
from .radius_server_http_transport import FortiPamRadiusServerHttpTransport
from .radius_server_live_workflow import RadiusServerLiveWorkflow
from .radius_server_owned_connect_workflow import RadiusServerOwnedConnectWorkflow
from .radius_server_recovery_workflow import RadiusServerRecoveryWorkflow

CONTRACT = "fortipam-v4-radius-primary-lifecycle-candidate-v1"
PERSISTENT_CONTRACT = "fortipam-v4-radius-primary-configure-candidate-v1"
_ERROR = "The private RADIUS lifecycle is unavailable."
_DOMAIN = b"fortipam-radius-primary-lifecycle-v1\x00"


@dataclass(frozen=True, slots=True, repr=False)
class _Preview(_OpaqueC3Object):
    child_ref: str
    expires_at: int
    nonce: str
    reference: str


class RadiusServerLifecycleWorkflow(_OpaqueC3Object):
    """One privately bound reject-only qualification or persistent primary profile."""

    __slots__ = ("_create", "_native", "_recovery", "_source", "_key", "_namespace",
                 "_preview", "_authorization", "_started", "_enabled", "_lock", "_retain_on_success")
    _display_name = "RadiusServerLifecycleWorkflow"

    def __init__(self, create: RadiusServerLiveWorkflow, native: RadiusServerOwnedConnectWorkflow,
                 recovery: RadiusServerRecoveryWorkflow, source: RadiusFixtureMaterialLoader, *,
                 authority_key: bytes, execution_enabled: bool = False,
                 retain_on_success: bool = False) -> None:
        try:
            if (type(create) is not RadiusServerLiveWorkflow
                    or type(native) is not RadiusServerOwnedConnectWorkflow
                    or type(recovery) is not RadiusServerRecoveryWorkflow
                    or type(source) is not RadiusFixtureMaterialLoader
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or type(execution_enabled) is not bool or type(retain_on_success) is not bool):
                raise ValueError
            self._create, self._native, self._recovery, self._source = create, native, recovery, source
            self._key, self._enabled = authority_key, execution_enabled
            self._retain_on_success = retain_on_success
            self._lock = RLock()
            self._preview: _Preview | None = None
            self._authorization: tuple[str, str] | None = None
            self._started = False
            self._namespace = self._bindings()
        except Exception:
            raise ValueError(_ERROR) from None

    def _bindings(self) -> str:
        c, n, r, source = self._create, self._native, self._recovery, self._source
        if (any(type(t) is not FortiPamRadiusServerHttpTransport
                for t in (c._reader, n._transport, r._transport))
                or not c._binding is n._binding is r._binding is source._binding
                or c._loader is not source
                or not c._directory == c._reader._directory == n._transport._directory == r._transport._directory
                or not c._serial == c._reader._serial == n._transport._serial == r._transport._serial
                or not c._config == c._reader._config == n._transport._config == r._transport._config):
            raise ValueError
        namespaces = (c._authority._namespace, n._namespace, r._namespace)
        common = ("environment_ref", "audience_ref", "requester_digest", "transport_digest")
        if any(any(ns[key] != namespaces[0][key] for key in common) for ns in namespaces):
            raise ValueError
        if len({ns["scope_ref"] for ns in namespaces}) != 3:
            raise ValueError
        stores = (c._execution_store, n._store, r._store)
        if len({s._path for s in stores} | {c._material_store._path}) != 4:
            raise ValueError
        require_digest(source._source_digest, "source_policy_digest")
        return canonical_digest({"contract": self.contract, "parameters": c._binding.parameters_digest,
            "source_policy": source._source_digest, "namespaces": list(namespaces),
            "serial": c._serial, "origin": c._config.base_url, "ca_file": c._config.ca_file,
            "api_identity_digest": hashlib.sha256(c._config.bearer_token.encode()).hexdigest(),
            "state_directory": str(c._directory), "execution_stores": [str(s._path) for s in stores],
            "material_store": str(c._material_store._path), "source_host": source._host,
            "source_key_file": str(source._key), "source_known_hosts_file": str(source._known_hosts)})

    @property
    def contract(self) -> str:
        return PERSISTENT_CONTRACT if self._retain_on_success else CONTRACT

    def _gate(self) -> None:
        if (self._enabled is not True or self._started or self._bindings() != self._namespace
                or self._native._store.claim_count != 0 or self._recovery._store.claim_count != 0):
            raise ValueError

    def _identity(self, identity: Mapping[str, str]) -> None:
        if set(identity) != {"requester_digest", "transport_digest"}:
            raise ValueError
        for key, value in identity.items():
            require_digest(value, key)
        self._create._identity(identity["requester_digest"], identity["transport_digest"])

    def _mac(self, purpose: str, value: object) -> str:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00" + data, hashlib.sha256).hexdigest()

    def _context(self, preview: _Preview) -> dict[str, object]:
        return {"namespace": self._namespace, "child_preview": preview.child_ref,
                "expires_at": preview.expires_at, "nonce": preview.nonce}

    def _check(self, preview: _Preview) -> None:
        self._gate()
        if (self._create._now() >= preview.expires_at
                or not hmac.compare_digest(preview.reference,
                    "radius-lifecycle-preview-" + self._mac("preview", self._context(preview)))):
            raise ValueError

    def preview(self, **identity: str) -> dict[str, object]:
        try:
            with self._lock:
                self._gate()
                self._identity(identity)
                if self._native._store.claim_count or self._recovery._store.claim_count:
                    raise ValueError
                child = self._create.preview(**identity)
                expires, child_ref = child["expires_at"], child["preview_ref"]
                if type(expires) is not int or type(child_ref) is not str:
                    raise ValueError
                p = _Preview(child_ref, expires, secrets.token_hex(24), "")
                p = _Preview(child_ref, expires, p.nonce,
                    "radius-lifecycle-preview-" + self._mac("preview", self._context(p)))
                self._check(p)
                self._preview, self._authorization = p, None
                expected = {"original_m4_success_required": True, "exact_reject_only_response_required": True,
                    "full_created_state_preserved": True, "all_candidate_gates_closed": True}
                if self._retain_on_success:
                    expected.update(owned_entry_retained=True, independent_original_ack_removal_available=True)
                else:
                    expected["final_dual_absence_required"] = True
                return {"contract": self.contract, "policy_mode": "lab_auto", "preview_ref": p.reference,
                    "expires_at": expires,
                    "Current State": {"bound_entry_absent": True, "schema_defaults_qualified": True,
                        "dual_absence_verified": True, "child_dispatches_unconsumed": True},
                    "Proposed Changes": {"operation": "configure_radius_primary" if self._retain_on_success
                            else "qualify_disposable_radius_primary",
                        "primary_only": True, "user_group_associations": False,
                        "fixed_sequence": ["create", "owned_native_connect"] if self._retain_on_success
                            else ["create", "owned_native_connect", "original_ack_remove"],
                        "material_acquisitions_maximum": 1},
                    "Expected State": expected,
                    "device_write_executed": False}
        except Exception:
            raise RuntimeError(_ERROR) from None

    def authorize(self, preview_ref: str, **identity: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(identity)
                p = self._preview
                require_ref(preview_ref, "preview_ref")
                if p is None or not hmac.compare_digest(preview_ref, p.reference) or self._authorization is not None:
                    raise ValueError
                self._check(p)
                child = self._create.authorize(p.child_ref, **identity)
                child_ref = child["authorization_ref"]
                if type(child_ref) is not str or child["expires_at"] != p.expires_at:
                    raise ValueError
                self._check(p)
                reference = "radius-lifecycle-auth-" + self._mac("authorize", {
                    **self._context(p), "child_authorization": child_ref})
                self._authorization = reference, child_ref
                return {"contract": self.contract, "policy_mode": "lab_auto",
                        "authorization_ref": reference, "expires_at": p.expires_at}
        except Exception:
            raise RuntimeError(_ERROR) from None

    @staticmethod
    def _success(result: Mapping[str, object]) -> bool:
        return (result.get("outcome") == "succeeded" and result.get("verification") == "verified"
                and result.get("idempotent_replay") is False)

    def execute(self, authorization_ref: str, **identity: str) -> dict[str, object]:
        with self._lock:
            try:
                self._identity(identity)
                require_ref(authorization_ref, "authorization_ref")
                if (self._authorization is None or self._preview is None
                        or not hmac.compare_digest(authorization_ref, self._authorization[0])):
                    raise ValueError
                self._check(self._preview)
                expected = "radius-lifecycle-auth-" + self._mac("authorize", {
                    **self._context(self._preview), "child_authorization": self._authorization[1]})
                if not hmac.compare_digest(authorization_ref, expected):
                    raise ValueError
                self._started = True
            except Exception:
                raise RuntimeError(_ERROR) from None
            created = native_verified = matched = removed = False
            stage = "create"
            failure: str | None = None
            try:
                try:
                    created = self._success(self._create.execute(self._authorization[1], **identity))
                finally:
                    self._create.close()
                    self._source.close()
                if created:
                    if not self._enabled or self._bindings() != self._namespace:
                        raise ValueError
                    stage = "native"
                    p = self._native.preview(**identity)
                    a = self._native.authorize(str(p["preview_ref"]), **identity)
                    native_verified = self._success(self._native.execute(str(a["authorization_ref"]), **identity))
                    if native_verified:
                        stage = "grammar_readback"
                        matched = self._native._transport.inspect_owned_connect_grammar()
                if not created or not native_verified or not matched:
                    failure = stage
            except Exception:
                failure = stage
            finally:
                self._native.close()
                try:
                    # This independent original-ACK recovery is allowed even if
                    # create/native failed, or the parent's intake TTL elapsed.
                    if (not (self._retain_on_success and created and native_verified and matched)
                            and self._recovery._transport._exists("create-ack.json")):
                        p = self._recovery.preview(**identity)
                        a = self._recovery.authorize(str(p["preview_ref"]), **identity)
                        removed = self._success(self._recovery.execute(str(a["authorization_ref"]), **identity))
                except Exception:
                    pass
                self.close()
            retained = self._retain_on_success and created and native_verified and matched
            complete = created and native_verified and matched and (retained or removed)
            result: dict[str, object] = {"contract": self.contract,
                "outcome": "succeeded" if complete else "reconciliation_required",
                "verification": "verified" if complete else "unknown", "idempotent_replay": False,
                "create_verified": created, "native_m4_verified": native_verified,
                "exact_reject_only_response_verified": matched, "original_ack_removal_verified": removed,
                "private_reject_only_connectivity_verified": native_verified and matched,
                "user_authentication_verified": False, "all_candidate_gates_closed": self._closed(),
                "failure_stage": failure if failure is not None else (None if complete else "recovery")}
            if self._retain_on_success:
                result["owned_entry_retained"] = retained
            return result

    def _removal_identity(self, identity: Mapping[str, str]) -> None:
        # A closed configure instance cannot reopen recovery. A newly composed
        # instance uses the same pinned original journals and independent M4.
        if (not self._retain_on_success or not self._enabled
                or self._bindings() != self._namespace):
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
        return (not self._enabled and not c._enabled and not self._source._enabled
            and not self._native._enabled and not self._native._transport._owned_connect_enabled
            and not self._recovery._enabled and not self._recovery._transport._recovery_enabled
            and (c._runtime is None or not c._runtime._enabled and not c._runtime._transport._execution_enabled))

    def close(self) -> None:
        # Revoke wire gates before waiting for any child-held dispatch lock.
        self._enabled = False
        self._source.close()
        self._create._enabled = self._native._enabled = self._recovery._enabled = False
        self._native._transport.close_owned_connect()
        self._recovery._transport._recovery_enabled = False
        if self._create._runtime is not None:
            self._create._runtime._enabled = False
            self._create._runtime._transport._execution_enabled = False
        for child in (self._create, self._native, self._recovery):
            child.close()
        self._key, self._preview, self._authorization = b"", None, None
