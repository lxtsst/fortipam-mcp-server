"""Read-only zero-claim User probe; never create missing runtime declarations."""
from __future__ import annotations

from collections.abc import Callable
import hashlib
from pathlib import Path
import time
from typing import Any
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from .ldap_server_projection import _digest
from .m4_execution_store import PersistentM4ExecutionStateStore
from .radius_remote_user_contract import RadiusRemoteUserBinding
from .radius_remote_user_http_transport import FortiPamRadiusRemoteUserHttpTransport, _MARKERS
from .radius_remote_user_live_workflow import _composition_payload, _CREATE_CONTRACT, _REMOVE_CONTRACT
from .radius_remote_user_owned_target import RadiusRemoteUserOwnedTarget
from .radius_remote_user_preparation import NAME
from .radius_remote_user_pair_handoff import _api, _store
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig

_ERROR = "The original User preparation observation is unavailable."


class RadiusRemoteUserPreparationReader(_OpaqueC3Object):
    """No User M4/signer/dispatcher exists in this preparation-only instance."""

    def __init__(self, binding: RadiusRemoteUserBinding, config: SecretMetadataHttpTransportConfig, *,
            target: RadiusRemoteUserOwnedTarget, state_directory: Path,
            user_stores: tuple[PersistentM4ExecutionStateStore, PersistentM4ExecutionStateStore],
            user_keys: tuple[bytes, bytes], identity: dict[str, str],
            connection_factory: Callable[..., Any] | None = None) -> None:
        try:
            if (type(target) is not RadiusRemoteUserOwnedTarget or not target._recovery_only
                    or target._handoff_digest is None and target._preparation_digest is None): raise ValueError
            self._binding, self._target = binding, target
            self._original_store, self._store = user_stores
            self._keys, self._identity_values = user_keys, dict(identity)
            self._enabled = self._initial_enabled = False
            self._issued = None
            self._closed = False
            self._reader = FortiPamRadiusRemoteUserHttpTransport(config, binding, target=target,
                state_directory=state_directory, connection_factory=connection_factory)
            self._namespace = {"contract": "fortipam-radius-user-preparation-reader-private-v1",
                **{name: identity[name] for name in ("environment_ref", "audience_ref", "requester_digest", "transport_digest")},
                "scope_ref": identity["user_remove_scope_ref"]}
            self._namespace_pin = canonical_digest(self._namespace)
            self._composition = self._snapshot()
        except Exception:
            raise RuntimeError(_ERROR) from None

    def _snapshot(self) -> str:
        if self._closed or self._enabled or self._initial_enabled or self._issued is not None: raise ValueError
        r = self._reader
        r._check()
        if not self._target._recovery_only or self._target._composition() != self._target._pin: raise ValueError
        for store in (self._original_store, self._store, self._target._store):
            store.verify_ready()
            if store._load_key() != store._key: raise ValueError
        if self._original_store.claim_count != 0 or self._store.claim_count != 0: raise ValueError
        original = self._target._original_execution()
        name, digest = ("radius-target.handoff.json", self._target._handoff_digest) if self._target._handoff_digest is not None else (NAME, self._target._preparation_digest)
        with r._locked(existing=True):
            if any(path.name not in {"operation.lock", NAME, "namespace.json", "radius-target.handoff.json",
                    "user-create.runtime.json", "user-remove.runtime.json", "user-create.authority.json"} for path in r._directory.iterdir()): raise ValueError
            if _digest(r._read_state(name)) != digest: raise ValueError
            if any(r._exists(item) for item in _MARKERS): raise ValueError
            # Preserve partial bytes as a drift pin, never as a signed grant or ownership proof.
            marker = r._authority_marker_digest() if r._exists("user-create.authority.json") else None
            declarations: dict[str, Any] = {}
            if r._exists("namespace.json"):
                r._namespace(existing_only=True)
                declarations["namespace.json"] = r._read_state("namespace.json")
            for ordinal, operation in enumerate(("create", "remove")):
                path = "user-" + operation + ".runtime.json"
                if not r._exists(path): continue
                stores = [self._original_store if operation == "create" else self._store, self._target._store]
                if operation == "remove": stores.append(self._original_store)
                contract = _CREATE_CONTRACT if operation == "create" else _REMOVE_CONTRACT
                expected = {"contract": contract,
                    **{key: self._namespace[key] for key in ("environment_ref", "audience_ref", "requester_digest", "transport_digest")},
                    "scope_ref": self._identity_values["user_" + operation + "_scope_ref"],
                    "policy_mode": "lab_auto", "parameters_digest": self._binding.parameters_digest,
                    "composition_digest": canonical_digest(_composition_payload(r, stores, self._keys[ordinal],
                        self._keys[0] if operation == "remove" else None, contract))}
                if r._read_state(path) != expected: raise ValueError
                declarations[path] = expected
        return canonical_digest({"namespace": self._namespace, "identity": self._identity_values,
            "proof": digest, "original_pair": original, "declarations": declarations, "unconsumed_marker": marker,
            "user_stores": [_store(self._original_store), _store(self._store)], "radius_store": _store(self._target._store),
            "parameters": self._binding.parameters_digest,
            "api": _api(r._config, r._serial), "journal": list(r._directory_identity),
            "keys": [hashlib.sha256(key).hexdigest() for key in self._keys]})

    def _gate(self, *, execute: bool = False) -> None:
        if execute or self._snapshot() != self._composition or canonical_digest(self._namespace) != self._namespace_pin:
            raise RuntimeError(_ERROR)

    def clone(self) -> RadiusRemoteUserPreparationReader:
        self._gate()
        return RadiusRemoteUserPreparationReader(self._binding, self._reader._config, target=self._target,
            state_directory=self._reader._directory, user_stores=(self._original_store, self._store),
            user_keys=self._keys, identity=self._identity_values, connection_factory=self._reader._factory)

    def inspect_cleanup_state(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            self._gate()
            if requester_digest != self._namespace["requester_digest"] or transport_digest != self._namespace["transport_digest"]:
                raise ValueError
            with self._reader._locked(existing=True):
                stop = time.monotonic() + 60
                _, draft = self._reader._components(stop)
                self._reader._absence(draft, stop)
            self._gate()
            return {"contract": "fortipam-radius-user-cleanup-observation-private-v1",
                "evidence_mode": "preparation_only_zero_claim", "observation": "absent_observed",
                "user_absence_verified": True, "mutation_executed": False, "prior_m4_outcome_unchanged": True,
                "dispatch_retry_allowed": False, "user_ownership_or_delete_authority_granted": False}
        except Exception:
            raise RuntimeError(_ERROR) from None

    def inspect_cleanup_absence(self, **identity: str) -> dict[str, object]: return self.inspect_cleanup_state(**identity)

    def revoke(self) -> None:
        self._closed = True; self._reader.close()

    def close(self) -> None:
        self.revoke(); self._keys = (b"", b"")
