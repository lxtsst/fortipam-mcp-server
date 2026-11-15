"""Default-off initial material for exactly one source-bound fixture creation.

No credential is returned from staging. The public reference is random and
independent of material. A one-use private lease exists only inside the actual
bound original M4; later reset/login access is deliberately not provided here.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import ssl
from threading import RLock
import time
from typing import Any

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object, MaterialLease

from .ldap_server_runtime import _key, _private_directory, _read
from .local_user_reset_fixture_custody import ACTION_ID, ADAPTER_REF, ACTION_VERSION, initial_create_parameters_digest
from .local_user_reset_fixture_sources import LocalResetFixtureSources
from .local_user_reset_material_source import _directory_identity, _write_once
from .local_user_reset_policy_reader import FortiPamLocalUserResetPolicyReader, LocalUserResetPolicySnapshot
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

_ERROR = "The private initial reset-fixture material is unavailable."
_DOMAIN = b"local-reset-initial-material/v1\x00"
_PASSWORD, _MANIFEST, _USED = "initial-password", "initial-material.json", "initial-material.used.json"


def _generate(policy: LocalUserResetPolicySnapshot) -> bytearray:
    policy.__post_init__()
    groups = (b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz", b"0123456789", b"!@#%^*-_")
    minima = (policy.min_upper_case_letter, policy.min_lower_case_letter, policy.min_number, policy.min_non_alphanumeric)
    counts = tuple(max(1, count) for count in minima) if policy.status == "enable" else (1,1,1,1)
    length = max(32, policy.minimum_length if policy.status == "enable" else 0,
        policy.min_change_characters if policy.status == "enable" else 0, sum(counts))
    if length > 128: raise ValueError
    raw = bytearray()
    try:
        for alphabet, count in zip(groups, counts, strict=True):
            raw.extend(alphabet[secrets.randbelow(len(alphabet))] for _ in range(count))
        alphabet = b"".join(groups)
        raw.extend(alphabet[secrets.randbelow(len(alphabet))] for _ in range(length-len(raw)))
        for index in range(len(raw)-1,0,-1):
            other=secrets.randbelow(index+1);raw[index],raw[other]=raw[other],raw[index]
        return raw
    except BaseException:
        _zeroize_mutable(raw);raise


class LocalResetInitialLease(MaterialLease):
    def __init__(self, raw: bytearray, guard: Callable[[], None]) -> None:
        self._raw, self._guard, self._consumed, self._closed = raw, guard, False, False
        # The established private encoder requires a writable view so its
        # owner can clear rejected material. It never crosses the Tool boundary.
        self._view = memoryview(raw)

    def _consume(self) -> memoryview:
        try:
            if self._closed or self._consumed: raise ValueError
            self._consumed = True; self._guard()
            return self._view
        except Exception:
            self.close();raise ValueError(_ERROR) from None

    def close(self) -> None:
        if not self._closed:
            self._closed = True; _zeroize_mutable(self._raw); self._view.release()


class LocalResetInitialMaterialSource(_OpaqueC3Object):
    def __init__(self, sources: LocalResetFixtureSources, policy_reader: FortiPamLocalUserResetPolicyReader,
            store: PersistentM4ExecutionStateStore, *, directory: Path, witness_key_file: Path,
            execution_enabled: bool = False, clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(sources) is not LocalResetFixtureSources or type(policy_reader) is not FortiPamLocalUserResetPolicyReader
                    or type(store) is not PersistentM4ExecutionStateStore or store.monotonic_checkpoint_protocol_bound is not True
                    or policy_reader._config is not sources._config or type(execution_enabled) is not bool
                    or clock is not None and not callable(clock)): raise ValueError
            self._sources,self._policy,self._store = sources,policy_reader,store
            self._policy_factory, self._policy_context = policy_reader._factory, policy_reader._context
            self._policy_route = (policy_reader._host, policy_reader._port)
            self._directory,self._key_file = Path(directory),Path(witness_key_file)
            _private_directory(self._directory);self._identity=_directory_identity(self._directory)
            if (self._directory!=sources._state._fixture._directory or self._key_file.parent==self._directory
                    or self._key_file in (store._path,store._key_path,sources._ssh.known_hosts_file,sources._config.ca_file)):raise ValueError
            self._key=_key(self._key_file)
            if hmac.compare_digest(self._key,store._key):raise ValueError
            self._source=sources.source_context_digest
            self._context=canonical_digest(dict(contract="local-reset-initial-material/v1",source=self._source,
                body=sources._state._draft.nonmaterial_request_digest,store_path=str(store._path),
                store_key=hashlib.sha256(store._key).hexdigest(),checkpoint=store._checkpoint_store_ref))
            self._enabled,self._closed,self._consumed = execution_enabled,False,False
            self._clock=clock if clock is not None else lambda:int(time.time())
            self._last=-1;self._lease: LocalResetInitialLease|None=None;self._lock=RLock()
            self._storage()
            if execution_enabled and store.claim_count!=0:raise ValueError
        except Exception:
            raise ValueError(_ERROR) from None

    def _storage(self) -> None:
        _private_directory(self._directory)
        if (_directory_identity(self._directory)!=self._identity or self._sources.source_context_digest!=self._source
                or self._policy._config is not self._sources._config
                or self._policy._factory is not self._policy_factory or self._policy._context is not self._policy_context
                or (self._policy._host,self._policy._port) != self._policy_route
                or not self._policy._context.check_hostname or self._policy._context.verify_mode != ssl.CERT_REQUIRED
                or not hmac.compare_digest(_key(self._key_file),self._key)
                or not hmac.compare_digest(_key(self._store._key_path),self._store._key)):raise ValueError
        self._store.verify_ready()

    def _now(self) -> int:
        self._storage();now=self._clock()
        if self._closed or type(now) is not int or now<0 or now<self._last:raise ValueError
        self._last=now;return now

    def _signature(self,name: str,body: dict[str,Any]) -> str:
        return hmac.new(self._key,_DOMAIN+name.encode()+b"\x00"+
            json.dumps(body,sort_keys=True,separators=(",",":"),allow_nan=False).encode(),hashlib.sha256).hexdigest()

    def _write(self,name: str,body: dict[str,Any]) -> None:
        self._storage()
        raw=bytearray(json.dumps({**body,"signature":self._signature(name,body)},sort_keys=True,separators=(",",":"),allow_nan=False).encode())
        try:_write_once(self._directory,self._identity,name,raw)
        finally:_zeroize_mutable(raw)

    def _record(self,name: str,keys: set[str]) -> dict[str,Any]:
        from .local_user_reset_projection import _object_spans
        from . import secret_bulk_import_metadata as m
        from .secret_metadata_http_transport import _json_value_end,_skip_json_space
        self._storage();raw=_read(self._directory/name,8192)
        try:
            start=_skip_json_space(raw,0);end=_json_value_end(raw,start)
            if _skip_json_space(raw,end)!=len(raw):raise ValueError
            m._validate_json(raw,start,end,depth=0,budget=[10000]);spans=_object_spans(raw,start,end)
            if set(spans)!=keys|{"signature"}:raise ValueError
            record={key:m._scalar(raw,span) for key,span in spans.items()};signature=record.pop("signature")
            if (record["context_digest"]!=self._context or type(signature) is not str
                    or not hmac.compare_digest(signature,self._signature(name,record))):raise ValueError
            return record
        finally:_zeroize_mutable(raw)

    def _manifest(self) -> dict[str,Any]:
        from v4_planning.models import require_digest,require_ref
        body=self._record(_MANIFEST,{"context_digest","reference","policy_digest","created_at","expires_at","material_tag"})
        require_ref(body["reference"],"initial_material");require_digest(body["policy_digest"],"initial_policy")
        require_digest(body["material_tag"],"private_material_tag")
        if (type(body["created_at"]) is not int or type(body["expires_at"]) is not int
                or body["created_at"]<0 or body["expires_at"]!=body["created_at"]+1800):raise ValueError
        return body

    def stage_once(self) -> str:
        raw=bytearray()
        try:
            with self._lock:
                if not self._enabled or self._consumed or self._store.claim_count!=0 or any(self._directory.iterdir()):raise ValueError
                now=self._now();observed=self._sources._current
                if observed is None or not observed.absent:raise ValueError
                self._sources.check_current(observed)
                policy=self._policy.read_policy_snapshot();reference="reset-initial-material-"+secrets.token_hex(24)
                raw=_generate(policy)
                if self._policy.read_policy_snapshot()!=policy:raise ValueError
                self._sources.check_current(observed);self._now()
                tag=hmac.new(self._key,_DOMAIN+b"private-material\x00"+self._context.encode()+b"\x00",hashlib.sha256)
                tag.update(raw)
                _write_once(self._directory,self._identity,_PASSWORD,raw)
                self._write(_MANIFEST,dict(context_digest=self._context,reference=reference,policy_digest=policy.digest,
                    created_at=now,expires_at=now+1800,material_tag=tag.hexdigest()))
                return self.reference
        except Exception:
            self.close();raise ValueError(_ERROR) from None
        finally:_zeroize_mutable(raw)

    @property
    def reference(self) -> str:
        try:return str(self._manifest()["reference"])
        except Exception:raise ValueError(_ERROR) from None

    @property
    def parameters_digest(self) -> str:
        return initial_create_parameters_digest(self._sources._state._draft.nonmaterial_request_digest,self.reference)

    def check_staged(self) -> None:
        """Recheck the exact staged source, lifetime and current native policy."""
        now = self._now()
        manifest = self._manifest()
        observed = self._sources._current
        if (observed is None or not observed.absent
                or not manifest["created_at"] <= now < manifest["expires_at"]):
            raise ValueError(_ERROR)
        self._sources.check_current(observed)
        if self._policy.read_policy_snapshot().digest != manifest["policy_digest"]:
            raise ValueError(_ERROR)
        self._sources.check_current(observed)
        if not manifest["created_at"] <= self._now() < manifest["expires_at"]:
            raise ValueError(_ERROR)

    def _active(self,plan: M4ExecutionPlan,authorization: M4ExecutionAuthorization) -> dict[str,Any]:
        if not self._enabled:raise ValueError
        now=self._now();manifest=self._manifest()
        _require_m4_dispatch_ownership(plan,authorization,self._store)
        plan.__post_init__();authorization.__post_init__()
        observed=self._sources._current
        if (plan.action_id!=ACTION_ID or plan.adapter_ref!=ADAPTER_REF or plan.action_version!=ACTION_VERSION
                or plan.target_ref!="bound-local-reset-fixture" or plan.compensation_ref is not None
                or plan.parameters_digest!=self.parameters_digest or observed is None or not observed.absent
                or observed.current_digest!=plan.expected_current_digest
                or authorization.plan_digest!=plan.plan_digest or authorization.plan_ref!=plan.plan_ref
                or authorization.requester_digest!=plan.requester_digest
                or authorization.confirmation_digest!=plan.confirmation_digest
                or authorization.approval_digest!=plan.approval_digest
                or not authorization.issued_at<=now<authorization.expires_at
                or not manifest["created_at"]<=now<manifest["expires_at"]):raise ValueError
        self._sources.check_current(observed)
        claim=self._store.inspect_claim(plan_ref=plan.plan_ref,requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest,authorization_digest=authorization.authorization_digest,
            context_digest=canonical_digest(dict(plan_digest=plan.plan_digest,authorization_digest=authorization.authorization_digest,revision=plan.revision)))
        if claim.result is not None:raise ValueError
        return manifest

    def acquire_original(self,plan: M4ExecutionPlan,authorization: M4ExecutionAuthorization) -> LocalResetInitialLease:
        raw=bytearray()
        try:
            with self._lock:
                if self._consumed or os.path.lexists(self._directory/_USED):raise ValueError
                self._consumed=True;manifest=self._active(plan,authorization)
                self.check_staged()
                self._write(_USED,dict(context_digest=self._context,reference=manifest["reference"],
                    plan_digest=plan.plan_digest,authorization_digest=authorization.authorization_digest,claimed_at=self._now()))
                raw=_read(self._directory/_PASSWORD,256)
                tag=hmac.new(self._key,_DOMAIN+b"private-material\x00"+self._context.encode()+b"\x00",hashlib.sha256);tag.update(raw)
                if not hmac.compare_digest(tag.hexdigest(),manifest["material_tag"]):raise ValueError
                self._active(plan,authorization)
                def guard() -> None:
                    self._active(plan,authorization)
                    self.check_staged()
                    self._active(plan,authorization)
                lease=LocalResetInitialLease(raw,guard);raw=bytearray()
                self._lease=lease;return lease
        except Exception:
            self.close();raise ValueError(_ERROR) from None
        finally:_zeroize_mutable(raw)

    def close(self) -> None:
        with self._lock:
            self._enabled=False;self._closed=True
            if self._lease is not None:self._lease.close()
