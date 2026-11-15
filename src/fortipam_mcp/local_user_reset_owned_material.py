"""Default-off one-attempt reset material for successful original-owned Users.

A random reference enters the plan. Both credentials stay in private mutable
buffers and can be loaded only by the exact actual M4. A fixture-wide marker
prevents a different directory, process or ledger from reusing initial material.
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
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .ldap_server_runtime import _key, _private_directory, _read
from .local_user_reset_fixture_material import _generate, _DOMAIN as _INITIAL_DOMAIN
from .local_user_reset_http_transport import LocalUserResetBinding, LocalUserResetMaterialLease
from .local_user_reset_material_source import _directory_identity, _write_once
from .local_user_reset_owned_inspector import LocalResetFixtureOwnedInspector
from .local_user_reset_policy_reader import FortiPamLocalUserResetPolicyReader
from .local_user_reset_preview import _baseline_digest
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

ACTION_ID = "local-reset-fixture-password-change"
ADAPTER_REF = "fortipam-build29-original-owned-reset-m4-v1"
ACTION_VERSION = "1.0.0"
LOGIN_ACTION_ID = "local-reset-fixture-password-change-and-login"
LOGIN_ADAPTER_REF = "fortipam-build29-original-owned-reset-login-m4-v2"
LOGIN_ACTION_VERSION = "2.0.0"
_ERROR = "The private original-owned reset material is unavailable."
_DOMAIN = b"local-reset-owned-material/v1\x00"
_NEXT, _MANIFEST, _USED = "next-password", "next-material.json", "reset-material.used.json"
_FIXTURE_CLAIM = "original-reset.claim.json"
_CLAIM_KEYS = {"context_digest","fixture_digest","reference","plan_digest","authorization_digest","reset_context_digest","claimed_at"}


class LocalResetOwnedMaterialSource(_OpaqueC3Object):
    def __init__(self, inspector: LocalResetFixtureOwnedInspector, policy_reader: FortiPamLocalUserResetPolicyReader,
            store: PersistentM4ExecutionStateStore, *, directory: Path, witness_key_file: Path,
            execution_enabled: bool = False, verify_login: bool = False, clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(inspector) is not LocalResetFixtureOwnedInspector or type(policy_reader) is not FortiPamLocalUserResetPolicyReader
                    or type(store) is not PersistentM4ExecutionStateStore or store.monotonic_checkpoint_protocol_bound is not True
                    or store._read_only or policy_reader._config is not inspector._config or type(execution_enabled) is not bool
                    or type(verify_login) is not bool or clock is not None and not callable(clock)):raise ValueError
            self._verify_login=self._login_pinned=verify_login
            self._action_contract=(LOGIN_ACTION_ID,LOGIN_ADAPTER_REF,LOGIN_ACTION_VERSION) if verify_login else (ACTION_ID,ADAPTER_REF,ACTION_VERSION)
            self._inspector,self._policy,self._store=inspector,policy_reader,store
            self._sources,self._initial=inspector._sources,inspector._initial
            self._directory,self._key_file=Path(directory),Path(witness_key_file)
            _private_directory(self._directory);self._identity=_directory_identity(self._directory)
            self._key=_key(self._key_file)
            original=inspector._original
            if (self._directory==self._initial._directory or self._directory==original._directory
                    or self._key_file.parent in (self._directory,self._initial._directory,original._directory)
                    or self._key_file in (store._path,store._key_path,self._initial._key_file,original._key_file,
                        original._store._path,original._store._key_path,self._sources._ssh.known_hosts_file,self._sources._config.ca_file)
                    or store._path==original._store._path
                    or any(hmac.compare_digest(self._key,key) for key in (store._key,self._initial._key,original._key,original._store._key))
                    or hmac.compare_digest(store._key,original._store._key)):raise ValueError
            self._route=(policy_reader._host,policy_reader._port)
            self._factory,self._tls=policy_reader._factory,policy_reader._context
            self._source=self._sources.source_context_digest
            self._context=canonical_digest(dict(contract="original-owned-reset-login-material/v2" if verify_login else "original-owned-reset-material/v1",source=self._source,
                fixture=inspector._creation_digest,initial_material_ref=inspector._material_ref,store_path=str(store._path),
                store_key=hashlib.sha256(store._key).hexdigest(),checkpoint=store._checkpoint_store_ref))
            self._enabled,self._closed,self._consumed,self._loaded=execution_enabled,False,False,False
            self._login_loaded=False
            self._clock=clock if clock is not None else lambda:int(time.time())
            self._last=-1;self._lock=RLock();self._buffers: list[bytearray]=[]
            self._storage()
            if execution_enabled and (store.claim_count!=0 or os.path.lexists(self._initial._directory/_FIXTURE_CLAIM)):raise ValueError
        except Exception:raise ValueError(_ERROR) from None

    def _storage(self) -> None:
        _private_directory(self._directory);self._inspector._pins();self._store.verify_ready()
        expected=(LOGIN_ACTION_ID,LOGIN_ADAPTER_REF,LOGIN_ACTION_VERSION) if self._verify_login else (ACTION_ID,ADAPTER_REF,ACTION_VERSION)
        if (self._verify_login is not self._login_pinned or self._action_contract!=expected
                or _directory_identity(self._directory)!=self._identity or self._sources.source_context_digest!=self._source
                or not hmac.compare_digest(_key(self._key_file),self._key)
                or not hmac.compare_digest(_key(self._store._key_path),self._store._key)
                or self._policy._config is not self._inspector._config or self._policy._factory is not self._factory
                or self._policy._context is not self._tls or (self._policy._host,self._policy._port)!=self._route
                or not self._tls.check_hostname or self._tls.verify_mode!=ssl.CERT_REQUIRED):raise ValueError

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
        body=self._record(_MANIFEST,{"context_digest","reference","policy_digest","baseline_digest","created_at","expires_at","material_tag"})
        require_ref(body["reference"],"next_material")
        for name in ("policy_digest","baseline_digest","material_tag"):require_digest(body[name],"reset_material_binding")
        if (type(body["created_at"]) is not int or type(body["expires_at"]) is not int
                or body["created_at"]<0 or body["expires_at"]!=body["created_at"]+900):raise ValueError
        return body

    def require_unclaimed(self) -> None:
        self._now()
        if (not self._enabled or self._consumed or self._store.claim_count!=0
                or os.path.lexists(self._directory/_USED) or os.path.lexists(self._initial._directory/_FIXTURE_CLAIM)):raise ValueError(_ERROR)

    def stage_once(self) -> str:
        raw=bytearray()
        try:
            with self._lock:
                self.require_unclaimed()
                if any(self._directory.iterdir()):raise ValueError
                now=self._now();baseline=self._inspector.read_nonmaterial_baseline()
                policy=self._policy.read_policy_snapshot();reference="owned-reset-next-material-"+secrets.token_hex(24)
                raw=_generate(policy)
                if self._policy.read_policy_snapshot()!=policy or self._inspector.read_nonmaterial_baseline()!=baseline:raise ValueError
                self._now()
                tag=hmac.new(self._key,_DOMAIN+b"private-next-material\x00"+self._context.encode()+b"\x00",hashlib.sha256);tag.update(raw)
                _write_once(self._directory,self._identity,_NEXT,raw)
                self._write(_MANIFEST,dict(context_digest=self._context,reference=reference,policy_digest=policy.digest,
                    baseline_digest=_baseline_digest(baseline),created_at=now,expires_at=now+900,material_tag=tag.hexdigest()))
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
        manifest=self._manifest()
        return canonical_digest(dict(contract="original-owned-reset-login-parameters/v2" if self._verify_login else "original-owned-reset-parameters/v1",fixture=self._inspector._creation_digest,
            initial_ref=self._inspector._material_ref,next_ref=manifest["reference"],policy=manifest["policy_digest"],baseline=manifest["baseline_digest"]))

    def current_digest(self) -> str:
        observed=self._sources._current
        if observed is None or observed.absent:raise ValueError(_ERROR)
        self._sources.check_current(observed);manifest=self._manifest()
        return canonical_digest(dict(contract="original-owned-reset-login-current/v2" if self._verify_login else "original-owned-reset-current/v1",current=observed.current_digest,
            baseline=manifest["baseline_digest"],policy=manifest["policy_digest"],fixture=self._inspector._creation_digest))

    def check_staged(self) -> LocalUserResetBinding:
        now=self._now();manifest=self._manifest()
        if not manifest["created_at"]<=now<manifest["expires_at"]:raise ValueError(_ERROR)
        baseline=self._inspector.read_nonmaterial_baseline()
        if (_baseline_digest(baseline)!=manifest["baseline_digest"]
                or self._policy.read_policy_snapshot().digest!=manifest["policy_digest"]):raise ValueError(_ERROR)
        if not manifest["created_at"]<=self._now()<manifest["expires_at"]:raise ValueError(_ERROR)
        return LocalUserResetBinding(baseline)

    def _active(self,plan: M4ExecutionPlan,authorization: M4ExecutionAuthorization) -> dict[str,Any]:
        if not self._enabled:raise ValueError
        now=self._now();manifest=self._manifest();_require_m4_dispatch_ownership(plan,authorization,self._store)
        plan.__post_init__();authorization.__post_init__()
        if ((plan.action_id,plan.adapter_ref,plan.action_version)!=self._action_contract
                or plan.target_ref!="bound-local-reset-fixture" or plan.compensation_ref is not None
                or plan.parameters_digest!=self.parameters_digest or plan.expected_current_digest!=self.current_digest()
                or authorization.plan_digest!=plan.plan_digest or authorization.plan_ref!=plan.plan_ref
                or authorization.requester_digest!=plan.requester_digest or authorization.confirmation_digest!=plan.confirmation_digest
                or authorization.approval_digest!=plan.approval_digest or authorization.expires_at>plan.expires_at
                or not authorization.issued_at<=now<authorization.expires_at
                or not manifest["created_at"]<=now<manifest["expires_at"]):raise ValueError
        claim=self._store.inspect_claim(plan_ref=plan.plan_ref,requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest,authorization_digest=authorization.authorization_digest,
            context_digest=canonical_digest(dict(plan_digest=plan.plan_digest,authorization_digest=authorization.authorization_digest,revision=plan.revision)))
        if claim.result is not None:raise ValueError
        return manifest

    def acquire_original(self,plan: M4ExecutionPlan,authorization: M4ExecutionAuthorization) -> LocalUserResetMaterialLease:
        try:
            with self._lock:
                if (self._consumed or os.path.lexists(self._directory/_USED)
                        or os.path.lexists(self._initial._directory/_FIXTURE_CLAIM)):raise ValueError
                self._consumed=True;manifest=self._active(plan,authorization);self.check_staged();self._active(plan,authorization)
                claim=dict(context_digest=self._initial._context,fixture_digest=self._inspector._creation_digest,
                    reference=manifest["reference"],plan_digest=plan.plan_digest,authorization_digest=authorization.authorization_digest,
                    reset_context_digest=self._context,claimed_at=self._now())
                self._initial._write(_FIXTURE_CLAIM,claim)
                self._write(_USED,{**claim,"context_digest":self._context})
                return LocalUserResetMaterialLease(lambda:self._load(plan,authorization))
        except Exception:
            self.close();raise ValueError(_ERROR) from None

    def _load(self,plan: M4ExecutionPlan,authorization: M4ExecutionAuthorization) -> tuple[memoryview,memoryview]:
        old=new=bytearray()
        transferred=False
        try:
            with self._lock:
                if self._loaded or not self._consumed:raise ValueError
                self._loaded=True;manifest=self._active(plan,authorization);self.check_staged()
                claim=self._initial._record(_FIXTURE_CLAIM,_CLAIM_KEYS)
                local=self._record(_USED,_CLAIM_KEYS)
                if ({**claim,"context_digest":self._context}!=local or claim["reset_context_digest"]!=self._context
                        or claim["reference"]!=manifest["reference"] or claim["fixture_digest"]!=self._inspector._creation_digest
                        or claim["plan_digest"]!=plan.plan_digest or claim["authorization_digest"]!=authorization.authorization_digest
                        or type(claim["claimed_at"]) is not int
                        or not authorization.issued_at<=claim["claimed_at"]<authorization.expires_at):raise ValueError
                old=_read(self._initial._directory/"initial-password",256);new=_read(self._directory/_NEXT,256)
                tag=hmac.new(self._initial._key,_INITIAL_DOMAIN+b"private-material\x00"+self._initial._context.encode()+b"\x00",hashlib.sha256);tag.update(old)
                if not hmac.compare_digest(tag.hexdigest(),self._initial._manifest()["material_tag"]):raise ValueError
                tag=hmac.new(self._key,_DOMAIN+b"private-next-material\x00"+self._context.encode()+b"\x00",hashlib.sha256);tag.update(new)
                if not hmac.compare_digest(tag.hexdigest(),manifest["material_tag"]):raise ValueError
                self._active(plan,authorization);self._buffers.extend((old,new));transferred=True
                return memoryview(old),memoryview(new)
        except Exception:
            self.close();raise ValueError(_ERROR) from None
        finally:
            if not transferred:_zeroize_mutable(old);_zeroize_mutable(new)

    def acquire_login(self,adapter: Any) -> memoryview:
        """Reload only next material after this exact M4's original changed ACK.

        A separate durable marker is consumed before reading. This is not a
        credential-delivery or generic login interface and cannot use v1 plans.
        """
        from .local_user_reset_owned_adapter import LocalResetOwnedAdapter
        raw=bytearray();transferred=False
        try:
            with self._lock:
                if (type(adapter) is not LocalResetOwnedAdapter or adapter._material is not self
                        or not self._verify_login or self._login_loaded or not self._consumed or not self._loaded
                        or any(any(value) for value in self._buffers)
                        or os.path.lexists(self._directory/"login-material.used.json")):raise ValueError
                adapter._guard();manifest=self._active(adapter._plan,adapter._authorization);self.check_staged()
                policy,changed=adapter._record("policy-ack.json"),adapter._record("change-ack.json")
                if (policy["accepted"] is not True or changed["accepted"] is not True
                        or adapter._native_attempts!=2 or adapter._owner is None or not adapter._owner.logout_verified
                        or adapter._owner._client is not None):raise ValueError
                claim=self._record(_USED,_CLAIM_KEYS)
                original=self._initial._record(_FIXTURE_CLAIM,_CLAIM_KEYS)
                if ({**original,"context_digest":self._context}!=claim or claim["plan_digest"]!=adapter._plan.plan_digest
                        or claim["authorization_digest"]!=adapter._authorization.authorization_digest):raise ValueError
                self._login_loaded=True
                self._write("login-material.used.json",dict(context_digest=self._context,reference=manifest["reference"],
                    plan_digest=adapter._plan.plan_digest,authorization_digest=adapter._authorization.authorization_digest,
                    change_ack_digest=canonical_digest(changed),claimed_at=self._now()))
                raw=_read(self._directory/_NEXT,256)
                tag=hmac.new(self._key,_DOMAIN+b"private-next-material\x00"+self._context.encode()+b"\x00",hashlib.sha256);tag.update(raw)
                if not hmac.compare_digest(tag.hexdigest(),manifest["material_tag"]):raise ValueError
                adapter._guard();self._buffers.append(raw);transferred=True
                return memoryview(raw)
        except Exception:
            self.close();raise ValueError(_ERROR) from None
        finally:
            if not transferred:_zeroize_mutable(raw)

    def close(self) -> None:
        with self._lock:
            self._enabled=False;self._closed=True
            for raw in self._buffers:_zeroize_mutable(raw)
