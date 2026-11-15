"""Default-closed fixed EMS Tag create adapter with original-M4 custody.

This private candidate exposes no Tool or recovery writer. The protected owner
channel, independent EMS authority, durable store and exact draft are joined
before one POST. Every prior full state must survive the original birth read.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import http.client
import json
import os
import stat
from threading import RLock

from v4_planning import M4AdapterAmbiguous, M4AdapterDenied, M4ExecutionPlan
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object

from .ems_tag_authority import EmsTagCreateAuthority, EmsTagIssued
from .ems_tag_contract import _canonical
from .ems_tag_custody import EmsTagOriginalCustody
from .ems_tag_http_transport import NativeEmsTagHttpTransport
from .ems_tag_sources import EmsTagSourceObservation, EmsTagSources
from .ldap_server_runtime import _private_directory
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

_CREATE = "/api/v1/tags/zero_trust/create"
_ERROR = "The private original EMS tag create is unavailable."


class NativeEmsTagCreateM4Adapter(_OpaqueC3Object):
    def __init__(self, *, transport: NativeEmsTagHttpTransport, sources: EmsTagSources,
                 authority: EmsTagCreateAuthority, issued: EmsTagIssued,
                 store: PersistentM4ExecutionStateStore, custody: EmsTagOriginalCustody,
                 execution_enabled: bool = False, check_request: Callable[[], None] | None = None) -> None:
        try:
            if (type(transport) is not NativeEmsTagHttpTransport or type(sources) is not EmsTagSources
                    or type(authority) is not EmsTagCreateAuthority or type(issued) is not EmsTagIssued
                    or type(store) is not PersistentM4ExecutionStateStore
                    or type(custody) is not EmsTagOriginalCustody or type(execution_enabled) is not bool
                    or check_request is not None and not callable(check_request)
                    or getattr(sources._get, "__self__", None) is not transport
                    or getattr(sources._get, "__func__", None) is not NativeEmsTagHttpTransport.get_json
                    or sources._instance != transport._binding or sources._owner != transport._owner
                    or authority._sources is not sources or authority._issued is not issued
                    or custody._store is not store or custody._plan is not issued.plan
                    or custody._authorization is not issued.authorization or custody._draft is not sources._draft
                    or custody._source != sources.source_context_digest
                    or custody._actor_binding.owner_session_digest != transport.session_binding_digest(sources._key)
                    or custody._actor_binding.caller_transport_digest != authority._binding["transport_digest"]
                    or custody._actor_binding.issuer_key_digest != hashlib.sha256(authority._key).hexdigest()
                    or len({sources._key, authority._key, store._key, custody._key}) != 4):
                raise ValueError
            if (authority._fpa_admission is not None and bytes(authority._fpa_admission.source._key)
                    in {sources._key, authority._key, store._key, custody._key}):
                raise ValueError
            self._transport, self._sources, self._authority = transport, sources, authority
            self._issued, self._store, self._custody = issued, store, custody
            self._source = sources.source_context_digest
            self._enabled, self._sent, self._resources_closed = execution_enabled, False, True
            self._post: EmsTagSourceObservation | None = None
            self._stage, self._status, self._complete = "not_started", 0, False
            self._response_error: str | None = None
            self._failure_name = store._path.name + ".ems-create-failure." + issued.plan.plan_digest + ".json"
            self._lock = RLock()
            self._check_request = check_request
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def _active(self, plan: M4ExecutionPlan) -> None:
        reader_owner = getattr(self._sources._get, "__self__", None)
        if type(reader_owner) is not NativeEmsTagHttpTransport:
            raise ValueError
        if (not self._enabled or plan is not self._issued.plan or self._transport._live is not True
                or self._transport._failed or self._sources.source_context_digest != self._source
                or reader_owner is not self._transport
                or getattr(self._sources._get, "__func__", None) is not NativeEmsTagHttpTransport.get_json
                or self._sources._instance != self._transport._binding
                or self._sources._owner != self._transport._owner
                or self._custody._actor_binding.owner_session_digest != self._transport.session_binding_digest(self._sources._key)
                or self._custody._actor_binding.caller_transport_digest != self._authority._binding["transport_digest"]
                or self._custody._actor_binding.issuer_key_digest != hashlib.sha256(self._authority._key).hexdigest()):
            raise ValueError
        self._transport._pins()
        self._authority.verify(plan, self._issued.authorization, now_epoch=self._authority._now())
        if self._check_request is not None:
            self._check_request()

    def _fresh(self) -> EmsTagSourceObservation:
        observed = self._sources.observe()
        self._authority.check_current(self._issued, observed)
        if observed.full_scope.digest != self._custody._baseline or not self._transport._connections_closed:
            raise ValueError
        return observed

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._active(plan)
                if self._sent:
                    raise ValueError
                return self._sources.current_digest(self._fresh())
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def _failure(self, error: BaseException) -> None:
        """Write the bounded original failure before returning UNKNOWN to M4."""
        self._custody._validate()
        if self._custody._claim().result is not None:
            raise ValueError
        attempt = None
        try:
            attempt = self._custody.inspect_ack_attempt()
        except Exception:
            pass
        kind = type(error).__name__
        record = {"context_digest": self._custody._context, "plan_digest": self._issued.plan.plan_digest,
            "source_context_digest": self._source, "stage": self._stage,
            "error_type": kind if kind in {"ValueError", "EmsTagCustodyError", "EmsTagSourceError",
                "EmsTagHttpError", "M4AuthorizationDenied", "IncompleteRead", "RemoteDisconnected",
                "TimeoutError", "OSError"} else "unavailable",
            "http_status": self._status, "framing_complete": self._complete,
            "response_error_type": self._response_error,
            "original_ack_attempt": attempt, "request_replayable": False}
        if self._stage == "fpa_postcondition" and self._authority._fpa_admission is not None:
            source = self._authority._fpa_admission.source
            stage = source.failure_stage or source._stage
            record["fpa_source_stage"] = stage if stage in {
                "constructed", "source_pins", "owner_factory", "actor_before", "connectors_before",
                "status_before", "complete_mapping_before", "selected_root_scope", "reference_type",
                "candidate_usage", "complete_mapping_after", "status_after", "connectors_after",
                "actor_after", "owner_closure", "source_complete",
            } else "unavailable"
            record["fpa_observation_completed"] = source.failure_stage is None and source._stage == "source_complete"
            record["fpa_connector_configuration_unchanged"] = source.connector_configuration_unchanged
            record["fpa_connector_counter_unchanged"] = source.connector_counter_unchanged
            record["fpa_read_stage"] = source.last_read_stage
            record["fpa_http_status"] = source.last_http_status
            record["fpa_mapping_diagnostic"] = source.mapping_diagnostic
        raw = _canonical(record)
        signature = hmac.new(self._custody._key, b"ems-tag-original-create-diagnostic/v1\x00" + raw,
                             hashlib.sha256).hexdigest()
        parent = self._store._path.parent
        _private_directory(parent)
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) != self._custody._store_parent_identity:
                raise ValueError
            fd = os.open(self._failure_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=descriptor)
            with os.fdopen(fd, "w") as stream:
                if stat.S_IMODE(os.fstat(stream.fileno()).st_mode) != 0o600:
                    raise ValueError
                json.dump({**record, "signature": signature}, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        raw, body = bytearray(), bytearray()
        connection = response = None
        try:
            with self._lock:
                self._active(plan)
                _require_m4_dispatch_ownership(plan, self._issued.authorization, self._store)
                if self._sent:
                    raise ValueError
                self._stage = "before_connect"
                connection = self._transport._connect()
                self._resources_closed = False
                self._stage = "final_full_source"
                before = self._fresh()
                self._active(plan)
                if self._authority._fpa_admission is not None:
                    self._stage = "final_fpa_scope"
                    self._authority._fpa_admission.check(refresh=True)
                    self._active(plan)
                body = bytearray(_canonical(self._sources._draft._body))
                request = self._transport._headers("POST", _CREATE, body)
                self._stage = "durable_send_reservation"
                self._custody.begin_original_send(before.full_scope)
                self._sent = True
                try:
                    self._stage = "request_dispatch"
                    connection.request("POST", _CREATE, body=body, headers=dict(request.header_items()))
                    self._stage = "original_response_headers"
                    response = connection.getresponse()
                    self._status = response.status
                    self._stage = "original_response_framing"
                    try:
                        self._transport._consume(response, raw, 65536)
                        self._complete = True
                    except http.client.IncompleteRead as error:
                        if type(error.partial) is bytes and len(raw) + len(error.partial) <= 65536:
                            raw.extend(error.partial)
                        raise
                except Exception as error:
                    kind = type(error).__name__
                    self._response_error = kind if kind in {"ValueError", "IncompleteRead", "RemoteDisconnected",
                        "TimeoutError", "OSError"} else "unavailable"
                    raise
                finally:
                    content_type = response.getheader("Content-Type", "") if response is not None else ""
                    if self._complete:
                        self._stage = "original_ack_qualification"
                    self._custody.capture_original_ack(raw, http_status=self._status,
                        content_type=content_type, complete=self._complete)
                self._stage = "original_full_birth_source"
                post = self._sources.observe()
                if not self._transport._connections_closed:
                    raise ValueError
                self._stage = "original_full_birth_seal"
                self._custody.capture_created_scope(before.full_scope, post.full_scope)
                self._post = post
                self._stage = "dispatch_complete"
        except Exception as error:
            if self._sent:
                try:
                    self._failure(error)
                except Exception:
                    pass
                raise M4AdapterAmbiguous(_ERROR) from None
            raise M4AdapterDenied(_ERROR) from None
        finally:
            _zeroize_mutable(raw)
            _zeroize_mutable(body)
            closed = True
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        closed = False
            self._resources_closed = closed
        if not self._resources_closed:
            self._stage = "original_resource_close"
            try:
                self._failure(ValueError())
            except Exception:
                pass
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._active(plan)
                if not self._sent or self._post is None or not self._resources_closed:
                    raise ValueError
                self._sources.check_current(self._post)
                original = self._custody.inspect_created_scope(require_verified_original=False)
                if (original.source_context_digest != self._source
                        or original.created_scope_digest != self._post.full_scope.digest
                        or original.created_state_digest != self._post.full_scope._candidate(self._sources._draft).digest):
                    raise ValueError
                if self._authority._fpa_admission is not None:
                    self._stage = "fpa_postcondition"
                    self._authority._fpa_admission.check(refresh=True, after_effect=True)
                    self._active(plan)
                    self._sources.check_current(self._post)
                return plan.expected_state_digest
        except Exception as error:
            if self._sent:
                try:
                    self._failure(error)
                except Exception:
                    pass
            raise M4AdapterAmbiguous(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled = False
