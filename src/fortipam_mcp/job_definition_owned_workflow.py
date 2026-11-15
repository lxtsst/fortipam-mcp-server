"""Normal-entry composition for one disabled Job and original-only recovery."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
import hashlib
import hmac
import http.client
import os
from pathlib import Path
import secrets
import time
from typing import Any

from v4_planning import M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, canonical_digest
from v4_planning.models import require_digest

from .job_definition_ack_custody import JobDefinitionAckCustody
from .job_definition_authority import JobDefinitionM4Authority
from .job_definition_create_contract import DisabledJobCreateAckPins
from .job_definition_create_m4_adapter import JobDefinitionCreateM4Adapter
from .job_definition_recovery_m4_adapter import JobDefinitionRecoveryM4Adapter
from .job_definition_sources import JobDefinitionSources
from .ldap_server_runtime import _key, _private_directory
from .m4_execution_store import PersistentM4ExecutionStateStore
from .target_operation_records import _TargetOperationRecords

CONTRACT = "fortipam-build29-owned-disabled-job-v3"
_ERROR = "The owned disabled Job workflow is unavailable."


class _Records(_TargetOperationRecords):
    def __init__(self, root: Path, namespace: str, key_file: Path):
        _private_directory(root)
        self._directory = root
        self._identity = (root.stat().st_dev, root.stat().st_ino)
        self._namespace = namespace
        self._key_file, self._key = key_file, _key(key_file)

    def _mac(self, value: dict[str, Any]) -> str:
        if not hmac.compare_digest(_key(self._key_file), self._key):
            raise ValueError(_ERROR)
        return hmac.new(self._key, (CONTRACT+"\x00"+canonical_digest(value)).encode(), hashlib.sha256).hexdigest()

    def write(self, name: str, value: dict[str, Any]) -> None:
        packet = {**value, "namespace": self._namespace}
        with self._lock() as directory:
            self._write(directory, name, {**packet, "signature": self._mac(packet)})
            if self._read(directory, name) != {**packet, "signature": self._mac(packet)}:
                raise ValueError(_ERROR)

    def read(self, name: str) -> dict[str, Any]:
        with self._lock() as directory:
            packet = self._read(directory, name)
        signature = packet.pop("signature")
        if type(signature) is not str or not hmac.compare_digest(signature, self._mac(packet)):
            raise ValueError(_ERROR)
        packet.pop("namespace")
        return packet


class JobDefinitionOwnedWorkflow:
    """A new create or separately authorized recovery; never adopt an old Job."""

    def __init__(self, sources: JobDefinitionSources, *, root: Path, phase: str,
            source_binding_digest: str, identity: dict[str, str],
            store_factory: Callable[[str, bool], PersistentM4ExecutionStateStore],
            source_guard: Callable[[], bool], execution_enabled: bool = False,
            clock: Callable[[], int] = lambda:int(time.time()),
            connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
            publication_wait: Callable[[float], None] = time.sleep,
            publication_clock: Callable[[], float] = time.monotonic):
        if (type(sources) is not JobDefinitionSources or phase not in {"create", "recover"}
                or type(execution_enabled) is not bool or not callable(source_guard)):
            raise ValueError(_ERROR)
        require_digest(source_binding_digest, "job_source_binding")
        if set(identity) != {"environment_ref", "scope_ref", "audience_ref", "requester_digest", "transport_digest"}:
            raise ValueError(_ERROR)
        self.source, self.root, self.phase = sources, root, phase
        self._identity = dict(identity)
        self._source_digest = sources.source_context_digest
        self._source_binding = source_binding_digest
        self._store_factory, self._guard, self._clock, self._factory = store_factory, source_guard, clock, connection_factory
        self._publication_wait, self._publication_clock = publication_wait, publication_clock
        self._enabled, self._closed = execution_enabled, False
        self._authority: JobDefinitionM4Authority | None = None
        self._original: JobDefinitionAckCustody | None = None
        self._adapter: JobDefinitionCreateM4Adapter | JobDefinitionRecoveryM4Adapter | None = None
        self._preview: Any = None
        self._issued: Any = None
        self._result: dict[str, Any] | None = None
        self._namespace = canonical_digest({"contract": CONTRACT, "source_binding": source_binding_digest,
            "source_context": self._source_digest, "identity": identity})
        keys = [root/p/(k+".key") for p in ("create", "recover") for k in ("authority", "witness", "execution")]
        self._keys = {p: _key(p) for p in keys}
        if len(set(self._keys.values())) != len(keys):
            raise ValueError(_ERROR)
        self._records = {p: _Records(root/p, canonical_digest((self._namespace,p)), root/p/"witness.key")
            for p in ("create", "recover")}
        self._live()
        if phase == "create":
            if any(os.path.lexists(root/"create"/name) for name in ("constructor.json", "dispatch.json")):
                raise ValueError(_ERROR)
        else:
            self._original = self._load_original()
        if os.path.lexists(root/phase/"dispatch.json"):
            raise ValueError(_ERROR)

    def _live(self) -> None:
        if (self._closed or not self._guard() or self.source.source_context_digest != self._source_digest
                or any(not hmac.compare_digest(_key(p), key) for p,key in self._keys.items())):
            raise ValueError(_ERROR)

    def _store(self, phase: str, read_only: bool = False) -> PersistentM4ExecutionStateStore:
        store = self._store_factory(phase, read_only)
        if (type(store) is not PersistentM4ExecutionStateStore or store._read_only is not read_only
                or store._path != self.root/phase/"execution.sqlite3"
                or store._key_path != self.root/phase/"execution.key"
                or not store.monotonic_checkpoint_protocol_bound):
            raise ValueError(_ERROR)
        return store

    def _load_original(self) -> JobDefinitionAckCustody:
        packet = self._records["create"].read("constructor.json")
        if (set(packet) != {"contract", "source_binding_digest", "source_context_digest", "pins", "plan", "authorization"}
                or packet["contract"] != CONTRACT or packet["source_binding_digest"] != self._source_binding
                or packet["source_context_digest"] != self._source_digest):
            raise ValueError(_ERROR)
        original = JobDefinitionAckCustody(self.root/"create"/"native", self.root/"create"/"witness.key",
            DisabledJobCreateAckPins(**packet["pins"]), M4ExecutionPlan(**packet["plan"]),
            M4ExecutionAuthorization(**packet["authorization"]), self._store("create", True), clock=self._clock)
        original._bound_source(self.source)
        state = original.inspect_original_full_state()
        if (state.source_context_digest != self._source_digest
                or state.original_ack.original_outcome not in {"succeeded", "reconciliation_required"}
                or original._plan.requester_digest != self._identity["requester_digest"]):
            raise ValueError(_ERROR)
        return original

    def _observe(self) -> Any:
        self._live()
        return self.source.observe_absence() if self.phase == "create" else self.source.observe_candidate_presence()

    def preview(self, **identity: str) -> dict[str, Any]:
        self._live()
        if self.phase=="recover" and os.path.lexists(self.root/"execution"/"activate"/"dispatch.json"):
            raise ValueError(_ERROR)
        if identity != {k:self._identity[k] for k in ("requester_digest", "transport_digest")}:
            raise ValueError(_ERROR)
        self._authority = JobDefinitionM4Authority(self.source, phase=self.phase,
            authority_key=self._keys[self.root/self.phase/"authority.key"], original=self._original,
            execution_enabled=self._enabled, clock=self._clock, **self._identity)
        observed = self._observe()
        self._preview = self._authority.preview(observed, **identity)
        result = {"contract":CONTRACT, "phase":self.phase, "policy_mode":"lab_auto",
            "preview_ref":self._preview.preview_ref, "expires_at":self._preview.expires_at,
            "Current State":{"digest":observed.current_digest, "dependency_digest":observed.dependency_digest,
                "global_absence":observed.absent, "original_terminal_full_custody":self.phase == "recover"},
            "Proposed Changes":{"maximum_native_mutations":1,
                "operation":"create_disabled_job" if self.phase == "create" else "remove_original_owned_job",
                "activation_or_execution":False, "credential_or_policy_changes":False,
                "close_write_channel_before_readback":True, "wad_publication_delay_ms":3000},
            "Expected State":{"digest":self._authority.expected_digest,
                "complete_pristine_state_or_global_absence":True, "original_records_preserved":True},
            "recovery":"separate_fresh_m4_original_constructor_ack_full_state_only_no_replay",
            "device_write_executed":False}
        result["summary_digest"] = canonical_digest(result)
        return result

    def authorize(self, preview_ref: str, **identity: str) -> dict[str, Any]:
        self._live()
        if not self._enabled or self._authority is None or self._preview is None or preview_ref != self._preview.preview_ref:
            raise ValueError(_ERROR)
        self._issued = self._authority.issue(self._preview, self._observe(), **identity)
        return {"contract":CONTRACT, "phase":self.phase, "policy_mode":"lab_auto",
            "authorization_ref":self._issued.authorization.authorization_ref,
            "expires_at":self._issued.authorization.expires_at}

    def execute(self, authorization_ref: str, **identity: str) -> dict[str, Any]:
        self._live()
        if (not self._enabled or self._authority is None or self._issued is None
                or identity != {k:self._identity[k] for k in ("requester_digest", "transport_digest")}
                or authorization_ref != self._issued.authorization.authorization_ref):
            raise ValueError(_ERROR)
        issued, original_bytes = self._issued, {}
        try:
            store = self._store(self.phase)
            if store.claim_count != 0:
                raise ValueError(_ERROR)
            self._authority.verify(issued.plan, issued.authorization, now_epoch=self._clock())
            if self.phase == "create":
                pins = DisabledJobCreateAckPins(self.source._candidate._name, self.source._candidate._serial_digest,
                    self._identity["requester_digest"], self.source._body_digest, issued.plan.plan_digest,
                    issued.authorization.authorization_digest, secrets.token_hex(32))
                packet = {"contract":CONTRACT, "source_binding_digest":self._source_binding,
                    "source_context_digest":self._source_digest, "pins":asdict(pins),
                    "plan":asdict(issued.plan), "authorization":asdict(issued.authorization)}
                # Persist and read back every constructor pin before the first M4 reservation.
                self._records["create"].write("constructor.json", packet)
                if self._records["create"].read("constructor.json") != packet or store.claim_count != 0:
                    raise ValueError(_ERROR)
                self._original = JobDefinitionAckCustody(self.root/"create"/"native", self.root/"create"/"witness.key",
                    pins, issued.plan, issued.authorization, store, clock=self._clock)
                self._adapter = JobDefinitionCreateM4Adapter(self.source, self._original,
                    execution_enabled=True, connection_factory=self._factory, wad_publication_wait=True,
                    publication_wait=self._publication_wait,publication_clock=self._publication_clock)
            else:
                if self._original is None or not self._original._store._read_only:
                    raise ValueError(_ERROR)
                original_bytes = {p:p.read_bytes() for p in (self.root/"create").rglob("*") if p.is_file()}
                self._adapter = JobDefinitionRecoveryM4Adapter(self.source, self._original, self._authority,
                    issued, store, directory=self.root/"recover"/"native", witness_key_file=self.root/"recover"/"witness.key",
                    execution_enabled=True, connection_factory=self._factory, wad_publication_wait=True,
                    publication_wait=self._publication_wait,publication_clock=self._publication_clock)
            self._records[self.phase].write("dispatch.json", {"plan_digest":issued.plan.plan_digest,
                "authorization_digest":issued.authorization.authorization_digest, "retry_allowed":False})
            self._live()
            result = M4ExecutionKernel(self._adapter, self._authority, store, clock=self._clock).execute(issued.plan, issued.authorization)
            preserved = all(p.read_bytes() == raw for p,raw in original_bytes.items())
            complete = False
            if self.phase == "create":
                try:
                    complete = self._original is not None and bool(self._original.inspect_original_full_state().state_digest)
                except Exception:
                    pass
            else:
                complete = bool(self.source._current is not None and self.source._current.absent and preserved)
            self._result = {"contract":CONTRACT, "phase":self.phase, "outcome":str(result.outcome),
                "verification":str(result.verification), "idempotent_replay":result.idempotent_replay,
                "complete_pristine_state_or_global_absence":complete, "original_records_preserved":preserved,
                "original_store_read_only":self.phase == "recover" and bool(self._original and self._original._store._read_only),
                "activation_or_execution":False, "native_claim_count":store.claim_count,
                "write_channel_closed_before_readback":self._adapter._readback_after_channel_closure,
                "wad_publication_delay_observed":self._adapter._wad_publication_observed,
                "source_failure":self.source._failure_diagnostics()}
        finally:
            self.close()
        self._result.update(all_candidate_gates_closed=self._closed and not self._enabled,
            owner_logout_verified=self.source.logout_verified)
        return self._result

    def close(self) -> None:
        self._enabled, self._closed = False, True
        if self._adapter is not None:self._adapter.close()
        if self._authority is not None:self._authority.close()
        if self._original is not None:self._original._closed = True
        self.source.close()
