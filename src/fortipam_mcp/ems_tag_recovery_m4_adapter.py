"""Default-closed one-Tag recovery POST through independent persistent M4.

Only the original sealed disabled Tag ID is compiled. Complete API restoration
and original recovery custody are required. Pending unused FPA mappings receive
bounded reads within the original authority/source lifetime; no delete replay,
normal Tool or general synchronization guarantee is provided.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import http.client
from threading import RLock
from time import sleep as _wait_for_fpa

from v4_planning import M4AdapterAmbiguous, M4AdapterDenied, M4ExecutionPlan
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object

from .ems_tag_authority import EmsTagIssued
from .ems_tag_contract import _canonical
from .ems_tag_recovery_authority import EmsTagRecoveryAuthority
from .ems_tag_recovery_contract import EmsTagOwnedRecoveryScope, EmsTagRecoveryObservation
from .ems_tag_recovery_custody import EmsTagRecoveryCustody
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

_DELETE = "/api/v1/tags/zero_trust/delete"
_ERROR = "The private independent EMS tag recovery is unavailable."
_FPA_PROPAGATION_CHECKS = 6
_FPA_PROPAGATION_DELAY_SECONDS = 5


class NativeEmsTagRecoveryM4Adapter(_OpaqueC3Object):
    def __init__(self, *, scope: EmsTagOwnedRecoveryScope, authority: EmsTagRecoveryAuthority,
                 issued: EmsTagIssued, store: PersistentM4ExecutionStateStore,
                 custody: EmsTagRecoveryCustody, execution_enabled: bool = False,
                 check_request: Callable[[], None] | None = None) -> None:
        try:
            if (type(scope) is not EmsTagOwnedRecoveryScope or type(authority) is not EmsTagRecoveryAuthority
                    or type(issued) is not EmsTagIssued or type(store) is not PersistentM4ExecutionStateStore
                    or type(custody) is not EmsTagRecoveryCustody or type(execution_enabled) is not bool
                    or check_request is not None and not callable(check_request)
                    or authority._scope is not scope or authority._issued is not issued
                    or custody._store is not store or custody._original is not scope._original
                    or custody._plan is not issued.plan or custody._authorization is not issued.authorization
                    or custody._binding != scope._context or custody._actor.owner_session_digest != scope._session
                    or custody._actor.caller_transport_digest != scope._caller_transport
                    or custody._actor.issuer_key_digest != hashlib.sha256(authority._key).hexdigest()
                    or len({scope._sources._key, authority._key, store._key, custody._key}) != 4):
                raise ValueError
            if (authority._fpa_admission is not None and bytes(authority._fpa_admission.source._key)
                    in {scope._sources._key, authority._key, store._key, custody._key}):
                raise ValueError
            scope._pins();custody._validate()
            self._scope, self._authority, self._issued, self._store, self._custody = scope, authority, issued, store, custody
            self._enabled, self._sent, self._restored, self._resources_closed = execution_enabled, False, False, True
            self._stage = "not_started"
            self._response_error: str | None = None
            self._lock = RLock()
            self._check_request = check_request
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def _active(self, plan: M4ExecutionPlan) -> None:
        if not self._enabled or plan is not self._issued.plan or self._scope is not self._authority._scope:
            raise ValueError
        self._custody._validate()
        # Authority verification checks this exact scope's live pins once.
        self._authority.verify(plan, self._issued.authorization, now_epoch=self._authority._now())
        if self._check_request is not None:
            self._check_request()

    def _fresh(self) -> EmsTagRecoveryObservation:
        observed = self._scope.observe_owned()
        self._authority.check_current(self._issued, observed)
        if not self._scope._transport._connections_closed:
            raise ValueError
        return observed

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._active(plan)
                if self._sent:
                    raise ValueError
                return self._fresh().current_digest
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def _failure(self, error: BaseException) -> None:
        try:
            self._custody.capture_failure(stage=self._stage, error_type=type(error).__name__,
                response_error_type=self._response_error)
        except Exception:
            pass

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        raw, body = bytearray(), bytearray()
        connection = response = None
        status, complete = 0, False
        reserved = False
        try:
            with self._lock:
                self._active(plan)
                _require_m4_dispatch_ownership(plan, self._issued.authorization, self._store)
                if self._sent:
                    raise ValueError
                self._stage = "before_connect"
                transport = self._scope._transport
                connection = transport._connect();self._resources_closed = False
                self._stage = "final_full_source"
                observed = self._fresh();self._active(plan)
                if self._authority._fpa_admission is not None:
                    self._stage = "final_fpa_scope"
                    self._authority._fpa_admission.check(refresh=True)
                    self._active(plan)
                candidate = observed.full_scope._candidate(self._scope._sources._draft)
                body = bytearray(_canonical({"ids": [candidate._id]}))
                request = transport._headers("POST", _DELETE, body)
                self._stage = "durable_original_object_reservation"
                reserved = True
                self._custody.reserve(self._scope, observed)
                self._sent = True
                try:
                    self._stage = "request_dispatch"
                    connection.request("POST", _DELETE, body=body, headers=dict(request.header_items()))
                    self._stage = "original_response_headers"
                    response = connection.getresponse();status = response.status
                    self._stage = "original_response_framing"
                    try:
                        transport._consume(response, raw, 65536);complete = True
                    except http.client.IncompleteRead as error:
                        if type(error.partial) is bytes and len(raw) + len(error.partial) <= 65536:
                            raw.extend(error.partial)
                        raise
                except Exception as error:
                    kind = type(error).__name__
                    self._response_error = kind if kind in {"ValueError", "RemoteDisconnected", "IncompleteRead",
                        "TimeoutError", "OSError"} else "unavailable"
                    raise
                finally:
                    if complete:
                        self._stage = "original_ack_qualification"
                    content_type = response.getheader("Content-Type", "") if response is not None else ""
                    self._custody.capture_ack(raw, http_status=status, content_type=content_type, complete=complete)
                self._stage = "original_restored_api_source"
                if self._scope.observe_restored_api_graph() != plan.expected_state_digest:
                    raise ValueError
                if not transport._connections_closed:
                    raise ValueError
                self._stage = "original_restoration_seal"
                self._custody.capture_restored(self._scope)
                self._restored = True
                self._stage = "dispatch_complete"
        except Exception as error:
            if self._sent or reserved:
                self._failure(error)
            if self._sent:
                raise M4AdapterAmbiguous(_ERROR) from None
            raise M4AdapterDenied(_ERROR) from None
        finally:
            _zeroize_mutable(raw);_zeroize_mutable(body)
            closed = True
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        closed = False
            self._resources_closed = closed
        if not self._resources_closed:
            self._stage = "original_resource_close";self._failure(ValueError())
            raise M4AdapterAmbiguous(_ERROR) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._stage = "postcondition"
                self._active(plan)
                if not self._sent or not self._restored or not self._resources_closed:
                    raise ValueError
                observed = self._scope._sources._current
                if observed is None:
                    raise ValueError
                self._scope._sources.check_current(observed)
                seal = self._custody.inspect_restored(require_verified_recovery=False)
                if (seal.restored_api_scope_digest != observed.full_scope.digest
                        or seal.original_custody_digest != self._scope._birth.custody_digest):
                    raise ValueError
                if self._authority._fpa_admission is not None:
                    admission = self._authority._fpa_admission
                    for attempt in range(_FPA_PROPAGATION_CHECKS):
                        self._active(plan)
                        self._scope._sources.check_current(observed)
                        self._stage = "fpa_postcondition"
                        # Only unchanged, unused pending mappings may be observed again.
                        current = admission.check(refresh=True)
                        self._active(plan)
                        self._scope._sources.check_current(observed)
                        if current.mapping.candidate_absent:
                            admission.source.require_original_scope(current, admission.binding, absent=True)
                            break
                        self._stage = "fpa_sync_pending"
                        if attempt + 1 == _FPA_PROPAGATION_CHECKS:
                            raise ValueError
                        _wait_for_fpa(_FPA_PROPAGATION_DELAY_SECONDS)
                return plan.expected_state_digest
        except Exception as error:
            if self._sent:
                try:
                    self._custody.capture_postcondition_failure(stage=self._stage, error_type=type(error).__name__)
                except Exception:
                    pass
            raise M4AdapterAmbiguous(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled = False
