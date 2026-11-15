"""Default-closed M4 adapter for two fixed original Role fixture phases."""
from __future__ import annotations

import hashlib
import http.client
from threading import RLock

from v4_planning import M4AdapterAmbiguous, M4AdapterDenied, M4ExecutionPlan
from v4_planning.material_provider import _OpaqueC3Object

from .ems_tag_contract import _canonical
from .ems_tag_identity_sources import EmsTagIdentityObservation, EmsTagIdentitySources, NativeEmsIdentityHttpTransport
from .ems_tag_role_fixture_authority import EmsRoleFixtureAuthority
from .ems_tag_role_fixture_custody import EmsRoleFixtureCustody
from .secret_metadata_http_transport import _zeroize_mutable

_ERROR = "The private original EMS role fixture dispatch is unavailable."


class NativeEmsRoleFixtureM4Adapter(_OpaqueC3Object):
    def __init__(self, authority: EmsRoleFixtureAuthority, custody: EmsRoleFixtureCustody, *,
                 execution_enabled: bool = False) -> None:
        try:
            if (type(authority) is not EmsRoleFixtureAuthority or type(custody) is not EmsRoleFixtureCustody
                    or type(execution_enabled) is not bool or authority._issued is None
                    or type(authority._sources) is not EmsTagIdentitySources
                    or type(authority._sources._transport) is not NativeEmsIdentityHttpTransport
                    or custody._issued is not authority._issued or custody._sources is not authority._sources
                    or custody._original is not authority._original
                    or custody._binding["issuer"] != hashlib.sha256(authority._key).hexdigest()
                    or custody._binding["caller_transport"] != authority._binding["transport_digest"]):raise ValueError
            keys = {authority._key, authority._sources._key, custody._key, custody._store._key}
            if len(keys) != 4:raise ValueError
            if authority._original is not None:
                keys.update((authority._original._key, authority._original._store._key))
                if len(keys) != 6:raise ValueError
            self._authority, self._custody, self._sources = authority, custody, authority._sources
            self._transport, self._issued = self._sources._transport, authority._issued
            self._enabled, self._sent, self._resources_closed = execution_enabled, False, True
            self._post: EmsTagIdentityObservation | None = None
            self._stage, self._status, self._complete = "dispatch", 0, False
            self._lock = RLock()
        except Exception:raise M4AdapterDenied(_ERROR) from None

    def _active(self, plan: M4ExecutionPlan) -> None:
        if (not self._enabled or plan is not self._issued.plan
                or self._authority._issued is not self._issued
                or self._custody._sources is not self._sources or self._custody._store._read_only
                or self._custody._binding["instance"] != self._sources._binding
                or self._custody._mac("owner", self._sources._owner) != self._custody._binding["owner"]
                or self._transport.session_binding_digest(self._custody._key) != self._custody._binding["session"]):raise ValueError
        self._authority.verify(plan, self._issued.authorization, now_epoch=self._authority._now())
        self._custody._validate()

    def _fresh(self) -> EmsTagIdentityObservation:
        observed = self._sources.observe()
        self._authority.check_current(observed)
        return observed

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._active(plan)
                if self._sent:raise ValueError
                self._fresh()
                return plan.expected_current_digest
        except Exception:raise M4AdapterDenied(_ERROR) from None

    def _failure(self, error: BaseException) -> None:
        try:self._custody.capture_failure(stage=self._stage, category=type(error).__name__)
        except Exception:pass

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        raw, body = bytearray(), bytearray()
        connection = response = None
        try:
            with self._lock:
                self._active(plan)
                if self._sent:raise ValueError
                connection = self._transport._connect();self._resources_closed = False
                before = self._fresh();self._active(plan)
                if self._issued.phase == "create":
                    method, path = "POST", "/api/v1/roles/create"
                    body.extend(_canonical(self._authority._draft._body))
                else:
                    owned = self._authority._owned
                    if owned is None:raise ValueError
                    method, path = "DELETE", "/api/v1/roles/" + owned.role_uid + "/delete"
                request = self._transport._headers(method, path, body if body else None)
                self._custody.begin_send(before.full_scope);self._sent = True
                self._stage = "dispatch"
                try:
                    connection.request(method, path, body=body if body else None, headers=dict(request.header_items()))
                    response = connection.getresponse();self._status = response.status;self._stage = "ack"
                    try:
                        self._transport._consume(response, raw, 65536);self._complete = True
                    except http.client.IncompleteRead as error:
                        if type(error.partial) is bytes and len(raw) + len(error.partial) <= 65536:raw.extend(error.partial)
                        raise
                finally:
                    self._custody.capture_ack(raw, status=self._status,
                        content_type=response.getheader("Content-Type", "") if response is not None else "", complete=self._complete)
                self._stage = "effect"
                post = self._sources.observe()
                self._active(plan)
                self._custody.capture_effect(before.full_scope, post.full_scope)
                self._post = post
        except Exception as error:
            if self._sent:
                self._failure(error);raise M4AdapterAmbiguous(_ERROR) from None
            raise M4AdapterDenied(_ERROR) from None
        finally:
            _zeroize_mutable(raw);_zeroize_mutable(body)
            closed = True
            for resource in (response, connection):
                if resource is not None:
                    try:resource.close()
                    except Exception:closed = False
            self._resources_closed = closed
        if not self._resources_closed:
            self._stage = "close";self._failure(ValueError());raise M4AdapterAmbiguous(_ERROR)

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._active(plan)
                if (not self._sent or self._post is None or not self._resources_closed
                        or self._custody._claim().result is not None):raise ValueError
                self._sources.check_current(self._post)
                effect = self._custody.inspect_effect(require_verified=False)
                if effect["scope_digest"] != self._post.full_scope.digest:raise ValueError
                return plan.expected_state_digest
        except Exception:raise M4AdapterAmbiguous(_ERROR) from None

    def close(self) -> None:
        with self._lock:self._enabled = False
