"""Default-off original-HTTP M4 adapter for one source-bound disabled Job.

Trusted composition must separately qualify the referenced Secret and supply
server authorization and independent recovery before any native write.
No authority issuer, Tool registration, activation or execution exists here.
"""
from __future__ import annotations

from collections.abc import Callable
import http.client
import json
import math
import os
import ssl
from threading import RLock
import time
from typing import Any
from urllib.parse import urlsplit

from v4_planning import M4AdapterAmbiguous, M4AdapterDenied, M4ExecutionPlan
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object

from .job_definition_ack_custody import JobDefinitionAckCustody, _SEND, _ACK, _SOURCE_ABSENCE, _STATE
from .job_definition_create_contract import _observe_disabled_job_ack_shape
from .job_definition_sources import JobDefinitionSources, JobDefinitionSourceObservation
from .secret_metadata_http_transport import _zeroize_mutable

_ERROR = "The private disabled Job original HTTP adapter is unavailable."
_POST = "/api/v2/cmdb/secret/job?with_meta=true&vdom=root"
_RESPONSE = "create-response.json"
_FAILURE = "create-failure.json"
_BODY_SHAPE = "create-body-shape.json"


def _wait_for_job_wad_publication(guard: Callable[[], float], wait: Callable[[float], None],
        clock: Callable[[], float]) -> None:
    """Pinned native Job model44294 -> CMDB20916 waits 3s after WAD writes."""
    start = clock()
    if not math.isfinite(start) or start < 0 or guard() <= 3:
        raise ValueError(_ERROR)
    wait(3.0)
    end = clock()
    if not math.isfinite(end) or end < start+3:
        raise ValueError(_ERROR)
    guard()


class JobDefinitionCreateM4Adapter(_OpaqueC3Object):
    """At most one POST inside actual original M4; retain ACK/full-state UNKNOWNs."""

    def __init__(self, sources: JobDefinitionSources, custody: JobDefinitionAckCustody, *,
            execution_enabled: bool = False,
            connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
            wad_publication_wait: bool = False, publication_wait: Callable[[float], None] = time.sleep,
            publication_clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(sources) is not JobDefinitionSources or type(custody) is not JobDefinitionAckCustody
                    or type(execution_enabled) is not bool or not callable(connection_factory)
                    or type(wad_publication_wait) is not bool or not callable(publication_wait) or not callable(publication_clock)):
                raise ValueError
            custody._validate()
            custody._bound_source(sources)
            self._sources, self._custody = sources, custody
            self._source = sources.source_context_digest
            self._plan, self._authorization, self._store = custody._plan, custody._authorization, custody._store
            self._enabled, self._closed = execution_enabled, False
            self._last_epoch = -1
            self._resources_closed = True
            self._readback_after_channel_closure = False
            self._wad_wait = wad_publication_wait
            self._publication_wait, self._publication_clock = publication_wait, publication_clock
            self._wad_publication_observed = False
            self._factory = connection_factory
            self._absence: JobDefinitionSourceObservation | None = None
            self._lock = RLock()
            self._pending()
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def _pending(self) -> None:
        self._custody._validate()
        if any(os.path.lexists(self._custody._directory / name)
                for name in (_SOURCE_ABSENCE, _SEND, _ACK, _STATE, _RESPONSE, _FAILURE, _BODY_SHAPE)):
            raise ValueError

    def _active(self, plan: M4ExecutionPlan) -> None:
        self._custody._validate()
        self._custody._bound_source(self._sources)
        now = self._custody._clock()
        if (not self._enabled or self._closed or plan is not self._plan
                or type(now) is not int or now < self._last_epoch
                or not self._authorization.issued_at <= now < self._authorization.expires_at
                or self._sources.source_context_digest != self._source
                or self._plan is not self._custody._plan or self._authorization is not self._custody._authorization
                or self._store is not self._custody._store):
            raise ValueError
        self._last_epoch = now

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._active(plan)
                self._pending()
                observed = self._sources.observe_absence()
                self._sources.check_current(observed)
                if observed.current_digest != plan.expected_current_digest:
                    raise ValueError
                self._absence = observed
                return observed.current_digest
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        body = raw = bytearray()
        connection = response = view = active_socket = None
        attempted = False
        stage = "before_connect"
        try:
            with self._lock:
                self._active(plan)
                _require_m4_dispatch_ownership(plan, self._authorization, self._store)
                self._pending()
                config = self._sources._config
                tls = self._sources._tls
                if not tls.check_hostname or tls.verify_mode != ssl.CERT_REQUIRED:
                    raise ValueError
                url = urlsplit(config.base_url)

                def guard(*, absence: bool = False) -> float:
                    self._active(plan)
                    _require_m4_dispatch_ownership(plan, self._authorization, self._store)
                    remaining = self._authorization.expires_at - self._custody._clock()
                    if remaining <= 0:
                        raise ValueError
                    if absence:
                        if self._absence is None:
                            raise ValueError
                        self._sources.check_current(self._absence)
                    timeout = min(float(config.timeout_seconds), float(remaining))
                    if active_socket is not None and active_socket.fileno() >= 0:
                        active_socket.settimeout(timeout)
                    return timeout

                connection = self._factory(url.hostname, url.port or 443, timeout=guard(absence=True), context=tls)
                connection.connect()
                active_socket = getattr(connection, "sock", None)
                stage = "fresh_source_after_tls"
                self._absence = self._sources.observe_absence()
                guard(absence=True)
                if self._absence.current_digest != plan.expected_current_digest:
                    raise ValueError
                body = bytearray(json.dumps(self._sources._body, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=True, allow_nan=False).encode("ascii"))
                stage = "original_send_claim"
                self._custody.begin_original_send_from_sources(self._sources)
                guard(absence=True)
                stage = "original_post"
                if self._wad_wait and guard(absence=True) <= 3:raise ValueError
                view = memoryview(body).toreadonly()
                attempted = True
                connection.request("POST", _POST, view, {"Authorization": "Bearer " + config.bearer_token,
                    "Accept": "application/json", "Content-Type": "application/json", "Content-Length": str(len(body)),
                    "Accept-Encoding": "identity", "Cache-Control": "no-store", "Connection": "close",
                    "User-Agent": "fortipam-mcp-disabled-job-create/1"})
                guard()
                stage = "original_response"
                response = connection.getresponse()
                guard()
                status = response.status
                content_type = response.getheader("Content-Type", "")
                encoding = response.getheader("Content-Encoding", "identity")
                if type(status) is not int or not 100 <= status <= 599:
                    raise ValueError
                self._custody._write(_RESPONSE, {"context_digest": self._custody._context,
                    "http_status": status, "exact_json": content_type.split(";", 1)[0].strip().lower() == "application/json",
                    "identity_encoding": encoding in ("", "identity"), "raw_values_stored": False})
                if encoding not in ("", "identity") or content_type.split(";", 1)[0].strip().lower() != "application/json":
                    raise ValueError
                raw = bytearray()
                while True:
                    guard()
                    chunk = response.read(min(16385 - len(raw), 4096))
                    guard()
                    if not chunk:
                        break
                    raw.extend(chunk)
                    if len(raw) > 16384:
                        raise ValueError
                self._custody._write(_BODY_SHAPE, {"context_digest": self._custody._context,
                    **_observe_disabled_job_ack_shape(raw, self._sources._candidate._name)})
                if status != 200:
                    raise ValueError
                stage = "original_ack"
                self._custody.capture_original_ack(raw, http_status=status, content_type=content_type)
                guard()
                stage = "original_channel_closure"
                response.close(); response = None
                connection.close(); connection = None; active_socket = None
                self._readback_after_channel_closure = True
                guard()
                if self._wad_wait:
                    stage = "wad_publication"
                    _wait_for_job_wad_publication(guard,self._publication_wait,self._publication_clock)
                    self._wad_publication_observed = True
                stage = "original_full_state"
                self._sources.observe_candidate_presence()
                guard()
                self._custody.capture_original_full_state(self._sources)
                guard()
        except Exception as error:
            if attempted:
                try:
                    self._custody._write(_FAILURE, {"context_digest": self._custody._context,
                        "stage": stage, "error_class": type(error).__name__ if type(error).__name__ in {
                            "ValueError", "OSError", "RemoteDisconnected", "TimeoutError", "IncompleteRead"} else "unavailable",
                        **(self._sources._failure_diagnostics() if stage == "original_full_state" else {
                            "source_reader_phase": None, "reader_failure_stage": None}),
                        "original_request_replayable": False})
                except Exception:
                    pass
                raise M4AdapterAmbiguous(_ERROR) from None
            raise M4AdapterDenied(_ERROR) from None
        finally:
            if view is not None:
                view.release()
            _zeroize_mutable(body)
            _zeroize_mutable(raw)
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        self._resources_closed = False

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._active(plan)
                original = self._custody.inspect_original_full_state()
                observed = self._sources._current
                if observed is None:
                    raise ValueError
                self._sources.check_current(observed)
                if (not self._resources_closed or observed.absent or observed.state_digest != original.state_digest
                        or original.source_context_digest != self._source):
                    raise ValueError
                return plan.expected_state_digest
        except Exception:
            raise M4AdapterAmbiguous(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled, self._closed = False, True
