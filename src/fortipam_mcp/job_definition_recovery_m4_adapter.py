"""Default-off independent recovery of one original full-custody disabled Job."""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import ssl
import stat
from threading import RLock
import time
from typing import Any
from urllib.parse import quote, urlsplit

from v4_planning import M4AdapterAmbiguous, M4AdapterDenied, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object

from .job_definition_ack_custody import JobDefinitionAckCustody
from .job_definition_authority import JobDefinitionIssued, JobDefinitionM4Authority, RECOVER_ACTION, RECOVER_ADAPTER
from .job_definition_create_contract import _observe_disabled_job_ack_shape
from .job_definition_create_m4_adapter import _wait_for_job_wad_publication
from .job_definition_recovery_ack import consume_disabled_job_delete_ack
from .job_definition_sources import JobDefinitionSources, JobDefinitionSourceObservation
from .job_namespace_ssh_reader import CONTRACT as _NAMESPACE
from .ldap_server_runtime import _key, _private_directory, _read
from .local_user_reset_projection import _object_spans
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

_ERROR = "The private original Job recovery is unavailable."
_DOMAIN = b"disabled-job-independent-recovery/v1\x00"
_CLAIM, _RESPONSE, _BODY, _ACK, _ABSENCE, _FAILURE = (
    "recover.claim.json", "recover.response.json", "recover.body-shape.json", "recover.ack.json",
    "recover.absence.json", "recover.failure.json")


class JobDefinitionRecoveryM4Adapter(_OpaqueC3Object):
    """One original DELETE, new M4/store/key and fixed global-absence readback.

    Original creation records remain read-only. No activation, execution,
    credential handling, generic write or automatic rollback is available.
    """

    def __init__(self, sources: JobDefinitionSources, original: JobDefinitionAckCustody,
            authority: JobDefinitionM4Authority, issued: JobDefinitionIssued,
            store: PersistentM4ExecutionStateStore, *, directory: Path, witness_key_file: Path,
            execution_enabled: bool = False, connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
            wad_publication_wait: bool = False, publication_wait: Callable[[float], None] = time.sleep,
            publication_clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(sources) is not JobDefinitionSources or type(original) is not JobDefinitionAckCustody
                    or type(authority) is not JobDefinitionM4Authority or type(issued) is not JobDefinitionIssued
                    or type(store) is not PersistentM4ExecutionStateStore or store.monotonic_checkpoint_protocol_bound is not True
                    or type(execution_enabled) is not bool or not callable(connection_factory)
                    or type(wad_publication_wait) is not bool or not callable(publication_wait) or not callable(publication_clock)
                    or authority._sources is not sources or authority._original is not original
                    or authority._binding["phase"] != "recover" or authority._issued is not issued
                    or store._path == original._store._path or hmac.compare_digest(store._key, original._store._key)):
                raise ValueError
            self._sources, self._original, self._authority, self._issued, self._store = sources, original, authority, issued, store
            self._directory, self._key_file = Path(directory), Path(witness_key_file)
            if (self._directory == original._directory or original._directory in self._directory.parents
                    or self._directory in original._directory.parents
                    or self._key_file in (store._path, store._key_path, original._key_file,
                        *(self._directory / name for name in (_CLAIM, _RESPONSE, _BODY, _ACK, _ABSENCE, _FAILURE)))):
                raise ValueError
            _private_directory(self._directory)
            info = self._directory.stat(); self._identity = (info.st_dev, info.st_ino)
            self._key = _key(self._key_file)
            if any(hmac.compare_digest(self._key, value) for value in (store._key, original._key, original._store._key)):
                raise ValueError
            self._sealed = original.inspect_original_full_state()
            self._source = sources.source_context_digest
            self._context = canonical_digest({"contract": "disabled-job-independent-recovery/v1", "source": self._source,
                "original": self._sealed.custody_digest, "original_state": self._sealed.state_digest,
                "plan": issued.plan.plan_digest, "authorization": issued.authorization.authorization_digest,
                "store_key": hashlib.sha256(store._key).hexdigest()})
            self._plan, self._authorization = issued.plan, issued.authorization
            self._enabled, self._closed, self._resources_closed = execution_enabled, False, True
            self._readback_after_channel_closure = False
            self._wad_wait = wad_publication_wait
            self._publication_wait, self._publication_clock = publication_wait, publication_clock
            self._wad_publication_observed = False
            self._factory = connection_factory
            self._current: JobDefinitionSourceObservation | None = None
            self._absence: JobDefinitionSourceObservation | None = None
            self._lock = RLock()
            self._storage(); self._pending()
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def _storage(self) -> None:
        _private_directory(self._directory)
        info = self._directory.stat()
        if ((info.st_dev, info.st_ino) != self._identity or not hmac.compare_digest(_key(self._key_file), self._key)
                or self._original.inspect_original_full_state() != self._sealed
                or self._sources._source != self._source
                or not hmac.compare_digest(_key(self._store._key_path), self._store._key)
                or self._authority._original is not self._original or self._authority._sources is not self._sources
                or self._authority._issued is not self._issued or self._plan is not self._issued.plan
                or self._authorization is not self._issued.authorization
                or self._plan.action_id != RECOVER_ACTION or self._plan.adapter_ref != RECOVER_ADAPTER
                or self._plan.action_version != "1.0.0" or self._plan.target_ref != "bound-disabled-job"
                or self._plan.compensation_ref is not None or self._sealed.source_context_digest != self._source):
            raise ValueError

    def _pending(self) -> None:
        self._storage()
        if any(os.path.lexists(self._directory / name) for name in (_CLAIM, _RESPONSE, _BODY, _ACK, _ABSENCE, _FAILURE)):
            raise ValueError

    def _signature(self, name: str, record: dict[str, Any]) -> str:
        raw = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, _DOMAIN + name.encode() + b"\x00" + raw, hashlib.sha256).hexdigest()

    def _write(self, name: str, record: dict[str, Any]) -> None:
        self._storage()
        record = {"context_digest": self._context, **record}
        directory = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if ((info.st_dev, info.st_ino) != self._identity or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "w") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                    raise ValueError
                json.dump({**record, "signature": self._signature(name, record)}, stream,
                    sort_keys=True, separators=(",", ":"), allow_nan=False)
                stream.flush(); os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _record(self, name: str) -> dict[str, Any]:
        from . import secret_bulk_import_metadata as m
        from .secret_metadata_http_transport import _json_value_end, _skip_json_space
        self._storage()
        raw = _read(self._directory / name, 8192)
        try:
            left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
            if _skip_json_space(raw, right) != len(raw): raise ValueError
            m._validate_json(raw, left, right, depth=0, budget=[10000])
            record = {key: m._scalar(raw, span) for key, span in _object_spans(raw, left, right).items()}
            signature = record.pop("signature")
            if (record.get("context_digest") != self._context or type(signature) is not str
                    or not hmac.compare_digest(signature, self._signature(name, record))):
                raise ValueError
            return record
        finally:
            _zeroize_mutable(raw)

    def _active(self, plan: M4ExecutionPlan) -> None:
        if not self._enabled or self._closed or plan is not self._plan: raise ValueError
        self._storage()
        self._authority.verify(plan, self._authorization, now_epoch=self._authority._now())
        claim = self._store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest, authorization_digest=self._authorization.authorization_digest,
            context_digest=canonical_digest({"plan_digest": plan.plan_digest,
                "authorization_digest": self._authorization.authorization_digest, "revision": plan.revision}))
        if claim.result is not None:
            raise ValueError

    def _refresh(self) -> JobDefinitionSourceObservation:
        observed = self._sources.observe_candidate_presence()
        self._authority.check_current(self._issued, observed)
        self._current = observed
        return observed

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._active(plan); self._pending()
                return self._refresh().current_digest
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        raw = bytearray(); connection = response = active_socket = None
        attempted = False; stage = "before_connect"
        try:
            with self._lock:
                self._active(plan); self._pending()
                _require_m4_dispatch_ownership(plan, self._authorization, self._store)
                config, tls = self._sources._config, self._sources._tls
                if not tls.check_hostname or tls.verify_mode != ssl.CERT_REQUIRED: raise ValueError

                def guard(*, current: bool = True) -> float:
                    self._active(plan)
                    _require_m4_dispatch_ownership(plan, self._authorization, self._store)
                    if current:
                        if self._current is None: raise ValueError
                        self._authority.check_current(self._issued, self._current)
                    remaining = self._authorization.expires_at - self._authority._now()
                    if remaining <= 0: raise ValueError
                    timeout = min(float(config.timeout_seconds), float(remaining))
                    if active_socket is not None and active_socket.fileno() >= 0: active_socket.settimeout(timeout)
                    return timeout

                url = urlsplit(config.base_url)
                connection = self._factory(url.hostname, url.port or 443, timeout=guard(), context=tls)
                connection.connect(); active_socket = getattr(connection, "sock", None)
                guard()
                stage = "fresh_source_after_tls"; observed = self._refresh(); guard()
                claim = dict(current_digest=observed.current_digest, namespace_digest=observed.namespace_digest,
                    original_state_digest=self._sealed.state_digest, claimed_at=self._authority._now())
                stage = "original_recovery_claim"; self._write(_CLAIM, claim); guard()
                stage = "original_delete"
                if self._wad_wait and guard() <= 3:raise ValueError
                attempted = True
                connection.request("DELETE", "/api/v2/cmdb/secret/job/" + quote(self._original._pins.job_name, safe="") + "?vdom=root", None,
                    {"Authorization": "Bearer " + config.bearer_token, "Accept": "application/json", "Accept-Encoding": "identity",
                     "Content-Length": "0", "Connection": "close", "Cache-Control": "no-store",
                     "User-Agent": "fortipam-mcp-disabled-job-recover/1"})
                guard(); stage = "original_response"; response = connection.getresponse(); guard()
                status, content_type, encoding = response.status, response.getheader("Content-Type", ""), response.getheader("Content-Encoding", "identity")
                if type(status) is not int or not 100 <= status <= 599: raise ValueError
                self._write(_RESPONSE, dict(http_status=status, exact_json=content_type.split(";", 1)[0].strip().lower() == "application/json",
                    identity_encoding=encoding in ("", "identity"), raw_values_stored=False))
                if encoding not in ("", "identity") or content_type.split(";", 1)[0].strip().lower() != "application/json": raise ValueError
                while True:
                    guard(); chunk = response.read(min(16385 - len(raw), 4096)); guard()
                    if not chunk: break
                    raw.extend(chunk)
                    if len(raw) > 16384: raise ValueError
                self._write(_BODY, _observe_disabled_job_ack_shape(raw, self._original._pins.job_name))
                stage = "original_ack"
                ack = consume_disabled_job_delete_ack(raw, job_name=self._original._pins.job_name,
                    serial_digest=self._original._pins.serial_digest, context_digest=self._context,
                    http_status=status, content_type=content_type, witness_key=self._key)
                guard()
                self._write(_ACK, dict(claim_digest=canonical_digest(self._record(_CLAIM)), acknowledgement_digest=ack,
                    acknowledged_at=self._authority._now()))
                guard(); stage = "original_channel_closure"
                response.close(); response = None
                connection.close(); connection = None; active_socket = None
                self._readback_after_channel_closure = True
                if self._wad_wait:
                    stage = "wad_publication"
                    _wait_for_job_wad_publication(guard,self._publication_wait,self._publication_clock)
                    self._wad_publication_observed = True
                guard(); stage = "global_absence"
                self._absence = self._sources.observe_absence(); guard(current=False)
                self._sources.check_current(self._absence)
                before = canonical_digest({"contract": _NAMESPACE, "names": sorted((*self._sources._names, self._original._pins.job_name))})
                if (not self._absence.absent or self._absence.state_digest is not None
                        or before != self._record(_CLAIM)["namespace_digest"]):
                    raise ValueError
                self._write(_ABSENCE, dict(ack_digest=canonical_digest(self._record(_ACK)),
                    current_digest=self._absence.current_digest, namespace_digest=self._absence.namespace_digest,
                    verified_at=self._authority._now()))
        except Exception as error:
            if attempted:
                try:
                    self._write(_FAILURE, dict(stage=stage, error_class=type(error).__name__ if type(error).__name__ in {
                        "ValueError", "OSError", "RemoteDisconnected", "TimeoutError", "IncompleteRead"} else "unavailable",
                        original_request_replayable=False))
                except Exception: pass
                raise M4AdapterAmbiguous(_ERROR) from None
            raise M4AdapterDenied(_ERROR) from None
        finally:
            _zeroize_mutable(raw)
            for resource in (response, connection):
                if resource is not None:
                    try: resource.close()
                    except Exception: self._resources_closed = False

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._active(plan)
                if not self._resources_closed or self._absence is None: raise ValueError
                self._sources.check_current(self._absence)
                claim, ack, absence = self._record(_CLAIM), self._record(_ACK), self._record(_ABSENCE)
                if (ack["claim_digest"] != canonical_digest(claim) or absence["ack_digest"] != canonical_digest(ack)
                        or absence["current_digest"] != self._absence.current_digest
                        or absence["namespace_digest"] != self._absence.namespace_digest
                        or claim["current_digest"] != plan.expected_current_digest
                        or claim["original_state_digest"] != self._sealed.state_digest
                        or not self._authorization.issued_at <= claim["claimed_at"] <= ack["acknowledged_at"]
                            <= absence["verified_at"] < self._authorization.expires_at
                        or not self._absence.absent or self._absence.state_digest is not None):
                    raise ValueError
                return plan.expected_state_digest
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled, self._closed = False, True
