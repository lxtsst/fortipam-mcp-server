"""Default-off exact inactive Policy create/recovery through persistent M4.

No public Tool is registered. One original create and one independently scoped
recovery use separate stores, keys, authorization and write-once records.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import stat
from threading import RLock
from typing import Any
from urllib.parse import urlsplit

from v4_planning import M4ExecutionKernel, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import M4AdapterDenied, M4AdapterAmbiguous, M4ExecutionResult, _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object

from .ldap_server_runtime import _key, _private_directory, _read
from .local_user_reset_projection import _object_spans
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable
from .windows_execution_policy_authority import WindowsPolicyM4Authority, WindowsPolicyPreview, WindowsPolicyIssued
from .windows_execution_policy_custody import WindowsExecutionPolicyCustody
from .windows_execution_policy_contract import consume_windows_policy_response
from .windows_execution_policy_sources import WindowsExecutionPolicySources, WindowsPolicySourceObservation

_ERROR = "The private inactive Policy lifecycle is unavailable."
_DOMAIN = b"inactive-policy-lifecycle-record/v1\x00"


class WindowsPolicyLifecycleError(ValueError):
    """No private inputs or partial native response in errors."""


class WindowsExecutionPolicyLifecycle(_OpaqueC3Object):
    def __init__(self, *, sources: WindowsExecutionPolicySources, authority: WindowsPolicyM4Authority,
            store: PersistentM4ExecutionStateStore, directory: Path, witness_key_file: Path,
            execution_enabled: bool = False, connection_factory: Callable[..., Any] = http.client.HTTPSConnection) -> None:
        try:
            if (type(sources) is not WindowsExecutionPolicySources or type(authority) is not WindowsPolicyM4Authority
                    or type(store) is not PersistentM4ExecutionStateStore or authority._sources is not sources
                    or store.monotonic_checkpoint_protocol_bound is not True
                    or type(execution_enabled) is not bool or not callable(connection_factory)):
                raise ValueError
            self._sources, self._authority, self._store = sources, authority, store
            self._directory, self._key_file = Path(directory), Path(witness_key_file)
            _private_directory(self._directory)
            info = self._directory.stat(); self._identity = (info.st_dev, info.st_ino)
            self._key = _key(self._key_file)
            if self._key_file in (store._key_path, store._path) or len({self._key, authority._key, store._key}) != 3:
                raise ValueError
            self._phase = str(authority._binding["phase"])
            self._original = authority._original
            if self._original is not None:
                if (self._directory == self._original._directory or self._store._path == self._original._store._path
                        or self._key in (self._original._key, self._original._store._key)
                        or authority._key in (self._original._key, self._original._store._key)):
                    raise ValueError
            self._context = canonical_digest({"source":sources.source_context_digest,
                "binding":authority._binding, "store_key":hashlib.sha256(store._key).hexdigest()})
            self._enabled, self._factory = execution_enabled, connection_factory
            self._lock = RLock()
            self._preview: WindowsPolicyPreview | None = None
            self._issued: WindowsPolicyIssued | None = None
            self._observation: WindowsPolicySourceObservation | None = None
            self._creation: WindowsExecutionPolicyCustody | None = None
            self._post_names: tuple[str, ...] | None = None
            self._post_observation: WindowsPolicySourceObservation | None = None
            self._pending()
        except Exception:
            raise WindowsPolicyLifecycleError(_ERROR) from None

    def _files(self) -> tuple[str, ...]:
        return (("send.claim.json", "create-ack.json", "created-state.json", "create.response.json", "create.failure.json") if self._phase == "create"
            else ("recover.claim.json", "recover.response.json", "recover.ack.json", "recover.verified.json", "recover.failure.json"))

    def _storage(self) -> None:
        _private_directory(self._directory)
        info = self._directory.stat()
        if (info.st_dev, info.st_ino) != self._identity or not hmac.compare_digest(_key(self._key_file), self._key):
            raise ValueError

    def _pending(self) -> None:
        self._storage()
        if any(os.path.lexists(self._directory/name) for name in self._files()):
            raise ValueError

    def _signature(self, name: str, record: dict[str, object]) -> str:
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + name.encode() + b"\x00" + encoded, hashlib.sha256).hexdigest()

    def _write(self, name: str, record: dict[str, object]) -> None:
        self._storage()
        if name not in self._files() or record.get("context_digest") != self._context:
            raise ValueError
        directory = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if (info.st_dev, info.st_ino) != self._identity:
                raise ValueError
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "w") as stream:
                if stat.S_IMODE(os.fstat(stream.fileno()).st_mode) != 0o600:
                    raise ValueError
                json.dump({**record,"signature":self._signature(name,record)},stream,sort_keys=True,separators=(",", ":"))
                stream.flush(); os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _record(self, name: str) -> dict[str, object]:
        self._storage()
        raw = _read(self._directory/name, 8192)
        try:
            from . import secret_bulk_import_metadata as m
            from .secret_metadata_http_transport import _json_value_end, _skip_json_space
            start = _skip_json_space(raw,0); end = _json_value_end(raw,start)
            if _skip_json_space(raw,end) != len(raw): raise ValueError
            m._validate_json(raw,start,end,depth=0,budget=[10000])
            fields = _object_spans(raw,start,end)
            record = {key:m._scalar(raw,span) for key,span in fields.items()}
            signature = record.pop("signature")
            if (record.get("context_digest") != self._context or type(signature) is not str
                    or not hmac.compare_digest(signature,self._signature(name,record))): raise ValueError
            return record
        finally:
            _zeroize_mutable(raw)

    def _refresh(self) -> WindowsPolicySourceObservation:
        observed = self._sources.observe_absence() if self._original is None else self._sources.observe_owned(self._original)
        self._observation = observed
        return observed

    def preview(self) -> WindowsPolicyPreview:
        try:
            with self._lock:
                self._pending()
                observed = self._refresh()
                preview = self._authority.preview(observed,requester_digest=str(self._authority._binding["requester_digest"]),
                    transport_digest=str(self._authority._binding["transport_digest"]))
                self._preview = preview
                return preview
        except Exception:
            raise WindowsPolicyLifecycleError(_ERROR) from None

    def issue(self, preview: WindowsPolicyPreview) -> WindowsPolicyIssued:
        try:
            with self._lock:
                self._pending()
                if preview is not self._preview: raise ValueError
                issued = self._authority.issue(preview,self._refresh(),
                    requester_digest=str(self._authority._binding["requester_digest"]),
                    transport_digest=str(self._authority._binding["transport_digest"]))
                if self._phase == "create":
                    self._creation = WindowsExecutionPolicyCustody(self._directory,self._key_file,self._sources._request,
                        issued.plan.expected_current_digest,issued.plan,issued.authorization,self._store,
                        source_context_digest=self._sources.source_context_digest,clock=self._authority._now)
                self._issued = issued
                return issued
        except Exception:
            raise WindowsPolicyLifecycleError(_ERROR) from None

    def _active(self, plan: M4ExecutionPlan) -> WindowsPolicyIssued:
        if not self._enabled or self._issued is None or plan is not self._issued.plan:
            raise ValueError
        self._storage()
        self._authority.verify(plan,self._issued.authorization,now_epoch=self._authority._now())
        return self._issued

    def _guard(self, plan: M4ExecutionPlan) -> None:
        issued = self._active(plan)
        if self._observation is None: raise ValueError
        self._authority.check_current(issued,self._observation)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            self._active(plan); self._pending(); observed = self._refresh(); self._guard(plan)
            return observed.current_digest
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        raw = bytearray(); connection = response = None; attempted = False; stage = "before_connect"
        try:
            with self._lock:
                issued = self._active(plan)
                _require_m4_dispatch_ownership(plan,issued.authorization,self._store)
                self._pending()
                origin = urlsplit(self._sources._config.base_url)
                connection = self._factory(origin.hostname,origin.port or 443,
                    timeout=min(self._sources._config.timeout_seconds,plan.expires_at-self._authority._now()),context=self._sources._tls)
                connection.connect()
                stage = "final_source"
                self._refresh(); self._guard(plan)
                if self._sources._witness is None: raise ValueError
                before_names = self._sources._witness[0]
                if self._phase == "create":
                    if self._creation is None: raise ValueError
                    self._sources.begin_original_send(self._creation)
                    claim = self._creation._record("send.claim.json",frozenset({"context_digest","absence_digest","claimed_at"}))
                    path = "/api/v2/cmdb/secret/policy?with_meta=true"
                    body: bytes | None = self._sources._request.body_json.encode("ascii")
                    method = "POST"
                else:
                    if self._original is None: raise ValueError
                    original = self._original.inspect_created_state()
                    claim = {"context_digest":self._context,"plan_digest":plan.plan_digest,
                        "authorization_digest":issued.authorization.authorization_digest,"original_digest":original.custody_digest,
                        "state_digest":original.created_state_digest,"claimed_at":self._authority._now()}
                    self._write("recover.claim.json",claim)
                    path = "/api/v2/cmdb/secret/policy/"+self._sources._request.binding.name
                    body = None; method = "DELETE"
                attempted = True
                stage = "final_guard"
                self._guard(plan)
                remaining = plan.expires_at-self._authority._now()
                if remaining <= 0: raise ValueError
                connection.timeout = min(self._sources._config.timeout_seconds,remaining)
                if getattr(connection,"sock",None) is not None: connection.sock.settimeout(connection.timeout)
                headers = {"Authorization":"Bearer "+self._sources._config.bearer_token,"Accept":"application/json",
                    "Accept-Encoding":"identity","Content-Length":str(len(body) if body is not None else 0),"Connection":"close",
                    "User-Agent":"fortipam-mcp-policy-lifecycle/1"}
                if body is not None: headers["Content-Type"]="application/json"
                stage = "native_request"
                connection.request(method,path,body,headers)
                stage = "native_response"
                response = connection.getresponse()
                status = response.status
                content_type = response.getheader("Content-Type","")
                encoding = response.getheader("Content-Encoding","identity")
                stage = "response_observation"
                self._write("create.response.json" if self._phase == "create" else "recover.response.json",
                    {"context_digest":self._context,"claim_digest":canonical_digest(claim),
                     "http_status":status if type(status) is int and 100<=status<=599 else None,
                     "json_content_type":type(content_type) is str and content_type.split(";")[0]=="application/json",
                     "identity_encoding":encoding in ("","identity"),"success_ack_qualified":False})
                if status != 200 or content_type.split(";")[0] != "application/json" or encoding not in ("","identity"):
                    raise ValueError
                stage = "bounded_response_body"
                while True:
                    self._active(plan)
                    remaining = plan.expires_at-self._authority._now()
                    if remaining <= 0: raise ValueError
                    if getattr(connection,"sock",None) is not None: connection.sock.settimeout(min(10,remaining))
                    part = response.read(min(65536,1048577-len(raw)))
                    if not part: break
                    raw.extend(part)
                    if len(raw)>1048576: raise ValueError
                response.close(); response=None; connection.close(); connection=None
                stage = "ack_qualification"
                if self._phase == "create":
                    if self._creation is None: raise ValueError
                    self._creation.capture_original_ack(raw,http_status=status,content_type=content_type)
                    stage = "created_state_readback"
                    self._post_observation = self._sources.capture_creation(self._creation)
                    expected_names = tuple(sorted((*before_names,self._sources._request.binding.name)))
                else:
                    digest = consume_windows_policy_response(raw,binding=self._sources._request.binding,phase="delete",http_status=status)
                    self._write("recover.ack.json",{"context_digest":self._context,"claim_digest":canonical_digest(claim),
                        "acknowledgement_digest":digest})
                    stage = "absence_readback"
                    self._post_observation = self._sources.observe_absence()
                    expected_names = tuple(name for name in before_names if name != self._sources._request.binding.name)
                self._active(plan)
                if self._sources._witness is None or self._sources._witness[0] != expected_names: raise ValueError
                self._post_names = expected_names
        except Exception as error:
            if attempted:
                # Forward diagnostic only. It cannot qualify an ACK, replace
                # original custody or make a consumed operation replayable.
                known = {"RemoteDisconnected", "SSLEOFError", "SSLError", "TimeoutError", "ConnectionResetError",
                    "BrokenPipeError", "OSError", "ValueError", "M4AuthorizationDenied", "WindowsPolicySourceError",
                    "WindowsExecutionPolicyCustodyError"}
                try:
                    self._write("create.failure.json" if self._phase == "create" else "recover.failure.json",
                        {"context_digest":self._context,"claim_digest":canonical_digest(claim),"stage":stage,
                         "error_class":type(error).__name__ if type(error).__name__ in known else "unclassified",
                         "success_ack_qualified":False})
                except Exception:
                    pass
                raise M4AdapterAmbiguous(_ERROR) from None
            raise M4AdapterDenied(_ERROR) from None
        finally:
            _zeroize_mutable(raw)
            for resource in (response,connection):
                if resource is not None: resource.close()

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            self._active(plan)
            if self._post_names is None or self._post_observation is None: raise ValueError
            observed = self._post_observation
            self._sources.check_current(observed)
            if self._phase == "create":
                if self._creation is None: raise ValueError
                original = self._creation.inspect_created_state()
                if observed.absent or original.created_state_digest != observed.state_digest: raise ValueError
            elif not observed.absent:
                raise ValueError
            if self._sources._witness is None or self._sources._witness[0] != self._post_names: raise ValueError
            self._sources.check_current(observed)
            self._active(plan)
            return self._authority.expected_digest
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def execute(self) -> M4ExecutionResult:
        try:
            with self._lock:
                if self._issued is None: raise ValueError
                self._active(self._issued.plan); self._pending()
                result = M4ExecutionKernel(self,self._authority,self._store,clock=self._authority._now).execute(
                    self._issued.plan,self._issued.authorization)
                if self._phase == "recover" and str(result.outcome) == "succeeded" and str(result.verification) == "verified":
                    self._write("recover.verified.json",{"context_digest":self._context,
                        "ack_digest":canonical_digest(self._record("recover.ack.json")),
                        "expected_absence_digest":self._authority.expected_digest})
                return result
        except Exception:
            raise WindowsPolicyLifecycleError(_ERROR) from None

    def original_creation(self) -> WindowsExecutionPolicyCustody:
        try:
            if self._creation is None: raise ValueError
            self._creation.inspect_created_state()
            return self._creation
        except Exception:
            raise WindowsPolicyLifecycleError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled = False
            self._authority.close()
            if self._creation is not None: self._creation.close()
