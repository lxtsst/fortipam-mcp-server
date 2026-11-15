"""Private original-ACK creation projection with qualified namespace sources.

Trusted composition supplies concrete owned-dependency and API/SSH prototypes.
Fresh phase readers retain their own clocks and source pins. No caller witness,
route, permission grant, material acquisition, Tool or activation is provided.
"""
from __future__ import annotations

import os
from threading import RLock
from urllib.parse import quote

from v4_planning import M4ExecutionPlan, M4AdapterFailure
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .secret_bulk_import_namespace_source import ImportSecretNamespaceSourceReader, ImportSecretNamespaceSourceObservation
from .target_api_dependency_reader import _private_http_logs
from .windows_execution_secret_ack import WindowsExecutionSecretAckCustody, _SEND, _ACK, _METADATA
from .windows_execution_secret_authority import windows_execution_secret_state_digest
from .windows_execution_secret_contract import (
    WindowsExecutionSecretDefaults, REQUEST_UUID, _proposed_metadata,
    consume_windows_execution_secret_metadata,
)
from .windows_execution_secret_material import ADAPTER_REF, TARGET_REF, windows_execution_secret_parameters_digest
from .windows_execution_secret_preflight import WindowsExecutionOwnedDependencies, WindowsExecutionOwnedDependencyObservation
from .secret_metadata_http_transport import _zeroize_mutable

_ERROR = "The private Windows execution Secret creation projection is unavailable."


class WindowsExecutionProjectionError(M4AdapterFailure):
    """No raw metadata, credential values or partial authority in failures."""


class WindowsExecutionSecretProjection(_OpaqueC3Object):
    """One preview, one fresh M4 current read and one independent postcondition."""

    def __init__(self, owned: WindowsExecutionOwnedDependencies,
            namespace: ImportSecretNamespaceSourceReader, defaults: WindowsExecutionSecretDefaults) -> None:
        try:
            if (type(owned) is not WindowsExecutionOwnedDependencies
                    or type(namespace) is not ImportSecretNamespaceSourceReader
                    or type(defaults) is not WindowsExecutionSecretDefaults
                    or owned._used or owned._closed or owned._failed
                    or namespace._used or namespace._closed or namespace._failed
                    or namespace._config is not owned._creator._config
                    or namespace._source != owned._source
                    or namespace._guard.serial_digest != owned._profile.serial_digest
                    or namespace._owner_name != owned._folder_binding.owner_name):
                raise ValueError
            self._owned_proto, self._namespace_proto = owned, namespace
            self._profile, self._defaults = owned._profile, defaults
            self._parameters = windows_execution_secret_parameters_digest(self._profile, defaults, create_uuid=REQUEST_UUID)
            self._source, self._binding = owned._source, owned._binding
            self._ssh_source, self._actor_pin = namespace._ssh_source, namespace._actor_pin
            self._factories = (owned._api._factory, namespace._factory, namespace._guard._factory)
            self._owned: WindowsExecutionOwnedDependencies | None = None
            self._namespace: ImportSecretNamespaceSourceReader | None = None
            self._owned_observation: WindowsExecutionOwnedDependencyObservation | None = None
            self._namespace_observation: ImportSecretNamespaceSourceObservation | None = None
            self._custody: WindowsExecutionSecretAckCustody | None = None
            self._phase: str | None = None
            self._preview_started = self._current_started = self._post_started = False
            self._failed = self._closed = False
            self._lock = RLock()
            self._pins()
        except Exception:
            raise WindowsExecutionProjectionError(_ERROR) from None

    @property
    def source_context_digest(self) -> str:
        self._pins()
        return self._source

    def _pins(self) -> None:
        o, n = self._owned_proto, self._namespace_proto
        o._local()
        n._require_pins()
        if (self._failed or self._closed or o._used or o._closed or o._failed
                or n._used or n._closed or n._failed or o._binding != self._binding
                or o._source != self._source or n._source != self._source
                or n._config is not o._creator._config or n._owner_name != o._folder_binding.owner_name
                or n._ssh_source != self._ssh_source or n._actor_pin != self._actor_pin
                or (o._api._factory, n._factory, n._guard._factory) != self._factories
                or windows_execution_secret_parameters_digest(self._profile, self._defaults, create_uuid=REQUEST_UUID) != self._parameters):
            raise ValueError
        if self._custody is not None:
            self._custody._validate()

    def _close_phase(self) -> None:
        self._phase = None
        if self._owned is not None:
            self._owned.close()
        if self._namespace is not None:
            self._namespace.close()
        self._owned_observation = self._namespace_observation = None

    def _fresh(self, *, present: bool) -> None:
        self._pins()
        self._close_phase()
        o, n = self._owned_proto, self._namespace_proto
        self._owned = WindowsExecutionOwnedDependencies(self._profile, creator=o._creator,
            folder_workflow=o._workflow, folder_preview_ref=o._preview_ref,
            requester_digest=o._requester, api=o._api,
            created_secret=self._custody if present else None, clock=o._clock)
        self._namespace = ImportSecretNamespaceSourceReader(n._config, n._ssh_config, n._binding,
            connection_factory=n._guard._factory, client_factory=n._factory, clock=n._clock)
        if self._namespace._source != self._source or self._namespace._ssh_source != self._ssh_source:
            raise ValueError
        self._owned_observation = self._owned.read_once()
        self._namespace_observation = self._namespace.read_once()
        self._phase = "present" if present else "absent"
        self._check_current()
        view = self._namespace_observation
        matches = [name for name in view.namespace.names if name.casefold() == self._profile.secret_name.casefold()]
        visible = [row for row in view.api_view.rows
            if type(row) is m.ImportMetadataSecret and row.name.casefold() == self._profile.secret_name.casefold()]
        if not present:
            if matches or visible:
                raise ValueError
        else:
            if self._custody is None:
                raise ValueError
            original = self._custody.inspect_original_creation()
            if (matches != [self._profile.secret_name] or len(visible) != 1
                    or visible[0].name != self._profile.secret_name
                    or visible[0].identifier != original.native_secret_id or original.native_uuid is None):
                raise ValueError

    def _check_current(self) -> None:
        self._pins()
        if (self._phase not in {"absent", "present"} or self._owned is None or self._namespace is None
                or self._owned_observation is None or self._namespace_observation is None):
            raise ValueError
        self._owned.check_current(self._owned_observation)
        self._namespace.check_current(self._namespace_observation)
        self._pins()

    def check_source(self) -> bool:
        """Metadata/custody-only local checks, never renew a source window."""
        try:
            with self._lock:
                self._check_current()
                return True
        except Exception:
            self._failed = True
            return False

    def require_create_ready(self) -> bool:
        with self._lock:
            return self._custody is not None and self._phase == "absent" and self.check_source()

    def inspect_onboarding_binding_digest(self) -> str:
        self._pins()
        return self._profile.parameters_digest

    def preview_current(self) -> str:
        try:
            with self._lock:
                if self._preview_started or self._custody is not None:
                    raise ValueError
                self._preview_started = True
                self._fresh(present=False)
                return windows_execution_secret_state_digest(self._profile, exists=False)
        except BaseException as error:
            self._failed = True
            self._close_phase()
            if isinstance(error, Exception):
                raise WindowsExecutionProjectionError(_ERROR) from None
            raise

    def bind_original_creation(self, custody: WindowsExecutionSecretAckCustody) -> None:
        try:
            with self._lock:
                self._check_current()
                if (self._custody is not None or self._phase != "absent"
                        or type(custody) is not WindowsExecutionSecretAckCustody
                        or custody._config is not self._owned_proto._creator._config
                        or custody._profile != self._profile or custody._defaults != self._defaults
                        or custody._execution_store.claim_count or custody._material_store.claim_count
                        or custody._closed or any(os.path.lexists(custody._directory / name) for name in (_SEND, _ACK, _METADATA))):
                    raise ValueError
                custody._validate()
                self._custody = custody
                self._plan(custody._plan)
        except Exception:
            self._failed = True
            raise WindowsExecutionProjectionError(_ERROR) from None

    def _plan(self, plan: M4ExecutionPlan) -> None:
        self._pins()
        if self._custody is None or plan is not self._custody._plan:
            raise ValueError
        plan.__post_init__()
        now = self._custody._guard.clock()
        if (plan.action_id != "secret-create-from-reference" or plan.action_version != "1.0.0"
                or plan.adapter_ref != ADAPTER_REF or plan.target_ref != TARGET_REF
                or plan.compensation_ref is not None or plan.parameters_digest != self._parameters
                or plan.requester_digest != self._owned_proto._requester
                or plan.expected_current_digest != windows_execution_secret_state_digest(self._profile, exists=False)
                or plan.expected_state_digest != windows_execution_secret_state_digest(self._profile, exists=True)
                or type(now) is not int or now < 0 or now >= plan.expires_at):
            raise ValueError

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._plan(plan)
                if self._current_started or self._post_started:
                    raise ValueError
                self._current_started = True
                self._fresh(present=False)
                return plan.expected_current_digest
        except BaseException as error:
            self._failed = True
            self._close_phase()
            if isinstance(error, Exception):
                raise WindowsExecutionProjectionError(_ERROR) from None
            raise

    def _read_original_metadata(self) -> None:
        raw = bytearray()
        try:
            if self._custody is None or self._owned is None or self._owned_observation is None:
                raise ValueError
            original = self._custody.inspect_original_creation()
            if original.native_uuid is None or original.state_digest is None:
                raise ValueError
            fields = sorted(set(_proposed_metadata(self._profile, REQUEST_UUID)) | {"q_ref", "q_static", "target-info"})
            path = "/api/v2/cmdb/secret/database/" + str(original.native_secret_id)
            path += "?format=" + quote("|".join(fields), safe="") + "&with_meta=true&vdom=root"
            api = self._owned_proto._api
            self._check_current()
            with _private_http_logs(), api._factory(verify=api._context,
                    timeout=min(10.0, api._config.timeout_seconds), follow_redirects=False, trust_env=False) as client:
                try:
                    client.cookies.clear()
                    with client.stream("GET", api._config.base_url + path, headers={
                            "Authorization":"Bearer " + api._config.bearer_token, "Accept":"application/json",
                            "Accept-Encoding":"identity", "Cache-Control":"no-store"}) as response:
                        if (response.status_code != 200
                                or response.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json"
                                or response.headers.get("content-encoding", "identity") != "identity"):
                            raise ValueError
                        for chunk in response.iter_raw():
                            self._check_current()
                            if len(raw) + len(chunk) > 1048576:
                                raise ValueError
                            raw.extend(chunk)
                finally:
                    client.cookies.clear()
            if not client.is_closed:
                raise ValueError
            observed = consume_windows_execution_secret_metadata(raw, self._profile,
                expected_secret_id=original.native_secret_id, create_uuid=REQUEST_UUID,
                expected_native_uuid=original.native_uuid)
            current = self._custody.inspect_original_creation()
            if (current.custody_digest != original.custody_digest or observed.state_digest != original.state_digest):
                raise ValueError
            self._check_current()
        finally:
            _zeroize_mutable(raw)

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            with self._lock:
                self._plan(plan)
                if not self._current_started or self._post_started:
                    raise ValueError
                self._post_started = True
                self._fresh(present=True)
                self._read_original_metadata()
                return plan.expected_state_digest
        except BaseException as error:
            self._failed = True
            self._close_phase()
            if isinstance(error, Exception):
                raise WindowsExecutionProjectionError(_ERROR) from None
            raise

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._close_phase()
