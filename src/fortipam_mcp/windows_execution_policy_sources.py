"""Fixed API/Owner/CLI source join for the inactive Policy lab candidate.

No configuration writer, permission issuer or Tool is provided. Saved proof
files, caller name tuples and hashes cannot replace these live source windows.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import re
import ssl
from threading import RLock
import time
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .isolated_folder_creation_ownership import ownership_payload
from .isolated_folder_live_workflow import IsolatedFolderLiveWorkflow
from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_projection import _object_spans
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, FortiPamSecretMetadataHttpTransport, _ssl_context, _zeroize_mutable,
)
from .target_api_dependency_reader import _private_http_logs
from .target_lifecycle_dependencies import _envelope, _one, _spans
from .target_preservation_contract import _api_source_context, _digest, _token_digest
from .target_ssh_transport import TargetSshTransportConfig
from .windows_execution_policy_cli_source import WindowsPolicyCliSource, WindowsPolicyCliObservation, _names
from .windows_execution_policy_contract import (
    WindowsExecutionPolicyRequest, compile_windows_execution_policy,
    consume_windows_policy_response, consume_windows_policy_state,
)
from .windows_execution_policy_custody import WindowsExecutionPolicyCustody

_CONTRACT = "fortipam-build29-inactive-policy-live-source-v1"
_ERROR = "The private inactive Policy live source is unavailable."
_MONITOR = "/api/v2/monitor/web-ui/state"
_POLICY = "/api/v2/cmdb/secret/policy"
_API_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}\Z")
_PROFILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class WindowsPolicySourceError(ValueError):
    """Non-disclosing refusal without partial source or native responses."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsPolicySourceObservation(_OpaqueC3Object):
    source_context_digest: str
    current_digest: str
    dependency_digest: str
    state_digest: str | None
    absent: bool
    observed_at: float
    expires_at: float


class WindowsExecutionPolicySources(_OpaqueC3Object):
    """Pin the writer and original Folder control; never adopt existing Policies."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, *, request: WindowsExecutionPolicyRequest,
            folder_workflow: IsolatedFolderLiveWorkflow, folder_preview_ref: str, folder_requester_digest: str,
            ssh: TargetSshTransportConfig, owner_credentials: Callable[[], tuple[str, str]],
            client_factory: Callable[..., Any] = httpx.Client, clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(request) is not WindowsExecutionPolicyRequest
                    or type(folder_workflow) is not IsolatedFolderLiveWorkflow or type(ssh) is not TargetSshTransportConfig
                    or not callable(owner_credentials) or not callable(client_factory) or not callable(clock)):
                raise ValueError
            config.__post_init__(); request.validate(); ssh.__post_init__()
            origin = urlsplit(config.base_url)
            if origin.username is not None or origin.password is not None:
                raise ValueError
            self._config, self._request, self._folder = config, request, folder_workflow
            self._folder_ref, self._requester = folder_preview_ref, folder_requester_digest
            self._original = folder_workflow.read_creation_ownership(folder_preview_ref, folder_requester_digest)
            control = self._original.snapshot.folder["secret-policy"]
            if type(control) is not str:
                raise ValueError
            self._control = control
            if (hashlib.sha256(self._original.serial.encode()).hexdigest() != request.binding.serial_digest
                    or folder_workflow._binding.owner_name != ssh.username):
                raise ValueError
            self._cli = WindowsPolicyCliSource(ssh, request=request, control_policy_name=self._control, clock=clock)
            self._credentials, self._owner = owner_credentials, ssh.username
            self._clock, self._factory = clock, client_factory
            self._tls = _ssl_context(config)
            if not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError
            self._tls.minimum_version = ssl.TLSVersion.TLSv1_2
            self._source = self._context()
            self._last = -1.0
            self._closed = self._failed = False
            self._current: WindowsPolicySourceObservation | None = None
            self._cli_observed: WindowsPolicyCliObservation | None = None
            self._witness: tuple[tuple[str, ...], int, int | None] | None = None
            self._raw = bytearray()
            self._lock = RLock()
            self.logout_verified = False
        except Exception:
            raise WindowsPolicySourceError(_ERROR) from None

    def _context(self) -> str:
        self._config.__post_init__(); self._request.validate()
        original = self._folder.read_creation_ownership(self._folder_ref, self._requester)
        if original != self._original or self._control != original.snapshot.folder["secret-policy"]:
            raise ValueError
        ca = None
        if self._config.ca_file is not None:
            value = Path(self._config.ca_file).read_bytes()
            if not 0 < len(value) <= 1048576:
                raise ValueError
            ca = hashlib.sha256(value).hexdigest()
        return _digest((_CONTRACT, self._request.request_digest, _api_source_context(self._config.base_url,
            hashlib.sha256(self._config.bearer_token.encode()).hexdigest(), ca, self._request.binding.serial_digest),
            hashlib.sha256(ownership_payload(original).encode()).hexdigest(), self._cli._context(), self._owner))

    @property
    def source_context_digest(self) -> str:
        try:
            self._now()
            return self._source
        except Exception:
            raise WindowsPolicySourceError(_ERROR) from None

    def _now(self) -> float:
        try:
            value = self._clock()
            if (self._closed or self._failed or type(value) not in (int, float) or not math.isfinite(value)
                    or value < 0 or value < self._last or self._context() != self._source):
                raise ValueError
            self._last = float(value)
            return float(value)
        except Exception:
            self._failed = True
            raise ValueError from None

    def _get(self, client: httpx.Client, path: str, deadline: float, *, owner: bool = False,
            absent: bool = False) -> bytearray:
        raw = bytearray()
        try:
            headers = {"Accept":"application/json", "Accept-Encoding":"identity", "Cache-Control":"no-store"}
            if not owner:
                headers["Authorization"] = "Bearer " + self._config.bearer_token
            remaining = deadline - self._now()
            if remaining <= 0:
                raise ValueError
            with client.stream("GET", path if owner else self._config.base_url + path,
                    headers=headers, timeout=min(10.0, remaining)) as response:
                if (response.status_code != (404 if absent else 200)
                        or response.headers.get("content-type", "").split(";")[0] != "application/json"
                        or response.headers.get("content-encoding", "identity") not in ("", "identity")):
                    raise ValueError
                for part in response.iter_raw():
                    if self._now() >= deadline or len(raw) + len(part) > 1048576:
                        raise ValueError
                    raw.extend(part)
            if self._now() >= deadline:
                raise ValueError
            _spans(raw)
            if "schema_errors" in _object_spans(raw, 0, len(raw)):
                raise ValueError
            result, raw = raw, bytearray()
            return result
        finally:
            _zeroize_mutable(raw)

    def _actor(self, raw: bytearray, *, expected: str | None = None) -> tuple[str, str, str]:
        span = _envelope(raw, path="web-ui", name="state", serial_digest=self._request.binding.serial_digest, monitor=True)
        fields = m._object_spans(raw, *span, frozenset({"admin", "vdom_mode", "maintenance_mode"}))
        admin = m._object_spans(raw, *fields["admin"], frozenset({"name", "profile", "global_admin"}))
        name = m._scalar(raw, admin["name"])
        if type(name) is not str or _API_NAME.fullmatch(name) is None or expected is not None and expected != name:
            raise ValueError
        identity = _actor_context(raw, expected_name=name)
        profile = m._scalar(raw, m._object_spans(raw, *admin["profile"], frozenset({"name"}))["name"])
        maintenance = m._object_spans(raw, *fields["maintenance_mode"], frozenset({"mode"}))
        if (type(profile) is not str or _PROFILE.fullmatch(profile) is None
                or m._scalar(raw, fields["vdom_mode"]) != ""
                or m._scalar(raw, maintenance["mode"]) != "disable"
                or m._scalar(raw, admin["global_admin"]) is not True):
            raise ValueError
        return name, profile, _digest((identity, profile, "global-root", "maintenance-disabled"))

    def _api_role(self, client: httpx.Client, deadline: float) -> str:
        buffers: list[bytearray] = []
        try:
            raw = self._get(client, _MONITOR, deadline); buffers.append(raw)
            name, profile, actor = self._actor(raw)
            raw = self._get(client, "/api/v2/cmdb/system/api-user/" + quote(name, safe="") +
                "?format=name%7Caccprofile&with_meta=true&vdom=root", deadline); buffers.append(raw)
            row = _one(raw, _envelope(raw, path="system", name="api-user", serial_digest=self._request.binding.serial_digest))
            fields = m._object_spans(raw, *row, frozenset({"name", "accprofile"}))
            if m._scalar(raw, fields["name"]) != name or m._scalar(raw, fields["accprofile"]) != profile:
                raise ValueError
            user = _token_digest(raw, row)
            raw = self._get(client, "/api/v2/cmdb/system/accprofile/" + quote(profile, safe="") +
                "?format=name%7Csecretgrp%7Csecretgrp-permission&with_meta=true&vdom=root", deadline); buffers.append(raw)
            row = _one(raw, _envelope(raw, path="system", name="accprofile", serial_digest=self._request.binding.serial_digest))
            fields = m._object_spans(raw, *row, frozenset({"name", "secretgrp", "secretgrp-permission"}))
            rights = m._object_spans(raw, *fields["secretgrp-permission"], frozenset({"secret-policy"}))
            if (m._scalar(raw, fields["name"]) != profile or m._scalar(raw, fields["secretgrp"]) != "custom"
                    or m._scalar(raw, rights["secret-policy"]) != "read-write"):
                raise ValueError
            return _digest((actor, user, _token_digest(raw, row)))
        finally:
            for raw in buffers: _zeroize_mutable(raw)

    def _owner_role(self, session: OwnerSessionMetadataTransport, deadline: float) -> str:
        buffers: list[bytearray] = []
        try:
            if session._client is None or session._clock() >= session._expires_at:
                raise ValueError
            raw = self._get(session._client, _MONITOR, deadline, owner=True); buffers.append(raw)
            _, profile, actor = self._actor(raw, expected=self._owner)
            state = _envelope(raw, path="web-ui", name="state", serial_digest=self._request.binding.serial_digest, monitor=True)
            root = m._object_spans(raw, *state, frozenset({"admin"}))
            admin = m._object_spans(raw, *root["admin"], frozenset({"super_admin"}))
            if profile != "super_admin" or m._scalar(raw, admin["super_admin"]) is not True:
                raise ValueError
            raw = self._get(session._client, "/api/v2/cmdb/system/admin/" + quote(self._owner, safe="") +
                "?format=name%7Caccprofile%7Cstatus%7Cremote-auth%7Cwildcard&with_meta=true&vdom=root", deadline, owner=True)
            buffers.append(raw)
            row = _one(raw, _envelope(raw, path="system", name="admin", serial_digest=self._request.binding.serial_digest))
            fields = m._object_spans(raw, *row, frozenset({"name", "accprofile", "status", "remote-auth", "wildcard"}))
            expected = {"name":self._owner, "accprofile":"super_admin", "status":"enable", "remote-auth":"disable", "wildcard":"disable"}
            if {key:m._scalar(raw, value) for key, value in fields.items()} != expected:
                raise ValueError
            return _digest((actor, expected))
        finally:
            for raw in buffers: _zeroize_mutable(raw)

    def _namespace(self, client: httpx.Client, deadline: float) -> tuple[str, ...]:
        raw = self._get(client, _POLICY + "?format=name&with_meta=true&vdom=root", deadline)
        try:
            span = _envelope(raw, path="secret", name="policy", serial_digest=self._request.binding.serial_digest)
            rows = m._array(raw, span, 128)
            fields = _spans(raw)
            if "limit_reached" in fields and m._scalar(raw, fields["limit_reached"]) is not False:
                raise ValueError
            if "size" in fields:
                size = m._scalar(raw, fields["size"])
                if type(size) is not int or size != len(rows):
                    raise ValueError
            return _names(tuple(m._text(m._scalar(raw, m._object_spans(raw, *row, frozenset({"name"}))["name"]), maximum=255)
                for row in rows))
        finally:
            _zeroize_mutable(raw)

    def _control_count(self, client: httpx.Client, deadline: float) -> int:
        raw = self._get(client, _POLICY + "/" + quote(self._control, safe="") +
            "?format=name%7Cq_ref&with_meta=true&vdom=root", deadline)
        try:
            row = _one(raw, _envelope(raw, path="secret", name="policy", serial_digest=self._request.binding.serial_digest))
            fields = m._object_spans(raw, *row, frozenset({"name", "q_ref"}))
            count = m._scalar(raw, fields["q_ref"])
            if m._scalar(raw, fields["name"]) != self._control or type(count) is not int or not 0 < count <= 128:
                raise ValueError
            return count
        finally:
            _zeroize_mutable(raw)

    def _candidate(self, client: httpx.Client, deadline: float, present: bool) -> tuple[str | None, bytearray]:
        raw = self._get(client, _POLICY + "/" + quote(self._request.binding.name, safe="") +
            "?with_meta=true&vdom=root", deadline, absent=not present)
        kept = bytearray(raw)
        try:
            if present:
                state = consume_windows_policy_state(raw, request=self._request)
            else:
                consume_windows_policy_response(raw, binding=self._request.binding, phase="absent", http_status=404)
                state = None
            return state, kept
        except Exception:
            _zeroize_mutable(kept)
            raise
        finally:
            _zeroize_mutable(raw)

    def _observe(self, present: bool) -> WindowsPolicySourceObservation:
        with self._lock:
            self._current = None
            _zeroize_mutable(self._raw)
            kept = bytearray(); schema = bytearray(); defaults = bytearray()
            session = None
            try:
                started = self._now(); deadline = started + 60.0
                with _private_http_logs(), self._factory(verify=self._tls, timeout=10,
                        trust_env=False, follow_redirects=False) as client:
                    try:
                        before = self._api_role(client, deadline)
                        schema = self._get(client, _POLICY + "?action=schema&with_meta=true&vdom=root", deadline)
                        defaults = self._get(client, _POLICY + "?action=default&vdom=root", deadline)
                        if compile_windows_execution_policy(schema, defaults, binding=self._request.binding,
                                profile=self._request.profile) != self._request:
                            raise ValueError
                        control = self._control_count(client, deadline)
                        state_before, discarded = self._candidate(client, deadline, present); _zeroize_mutable(discarded)
                        names = self._namespace(client, deadline)
                        if (self._request.binding.name in names) is not present:
                            raise ValueError
                        session = OwnerSessionMetadataTransport(self._config, owner_name=self._owner,
                            credentials=self._credentials, folder_path="policy-source", secret_name="policy-source", target_name="policy-source",
                            witness=FortiPamSecretMetadataHttpTransport(self._config), client_factory=self._factory, clock=self._clock)
                        self.logout_verified = False
                        with session.authenticated():
                            owner = self._owner_role(session, deadline)
                            def guard() -> None:
                                if self._now() >= deadline or session._client is None or session._clock() >= session._expires_at:
                                    raise ValueError
                            self._cli_observed = self._cli.observe(api_names=names, control_reference_count=control,
                                candidate_reference_count=0 if present else None, before_send=guard)
                            if self._owner_role(session, deadline) != owner:
                                raise ValueError
                        self.logout_verified = session.logout_verified
                        if not self.logout_verified:
                            raise ValueError
                        state, kept = self._candidate(client, deadline, present)
                        if state != state_before or self._namespace(client, deadline) != names or self._api_role(client, deadline) != before:
                            raise ValueError
                    finally:
                        client.cookies.clear()
                if not client.is_closed or self._now() >= deadline or self._cli_observed is None:
                    raise ValueError
                self._witness = (names, control, 0 if present else None)
                self._cli.check_current(self._cli_observed, api_names=names, control_reference_count=control,
                    candidate_reference_count=0 if present else None)
                dependency = _digest((_CONTRACT, self._source, before, owner, self._cli_observed.witness_digest,
                    self._cli_observed.namespace_digest, self._request.request_digest))
                current = _digest((_CONTRACT, "present" if present else "absent", dependency, state))
                result = WindowsPolicySourceObservation(self._source, current, dependency, state, not present,
                    started, min(deadline, self._cli_observed.expires_at))
                self._current, self._raw = result, kept
                kept = bytearray()
                self.check_current(result)
                return result
            except Exception:
                self._failed = True
                self._current = None
                _zeroize_mutable(self._raw)
                raise WindowsPolicySourceError(_ERROR) from None
            finally:
                for raw in (kept, schema, defaults): _zeroize_mutable(raw)
                if session is not None:
                    self.logout_verified = session.logout_verified

    def observe_absence(self) -> WindowsPolicySourceObservation:
        return self._observe(False)

    def observe_candidate_presence(self) -> WindowsPolicySourceObservation:
        """Reconcile this fixed nonmaterial candidate without creating ownership.

        This observation cannot replace the original M4 ACK/state seal required
        by capture_creation, observe_owned and the recovery authority.
        """
        return self._observe(True)

    def check_current(self, observed: WindowsPolicySourceObservation) -> None:
        try:
            with self._lock:
                if (type(observed) is not WindowsPolicySourceObservation or observed is not self._current
                        or self._witness is None or self._cli_observed is None
                        or not observed.observed_at <= self._now() < observed.expires_at
                        or observed.source_context_digest != self._source):
                    raise ValueError
                names, control, count = self._witness
                self._cli.check_current(self._cli_observed, api_names=names,
                    control_reference_count=control, candidate_reference_count=count)
        except Exception:
            raise WindowsPolicySourceError(_ERROR) from None

    def _custody(self, custody: WindowsExecutionPolicyCustody, *, created: bool) -> str | None:
        if type(custody) is not WindowsExecutionPolicyCustody or custody._request != self._request:
            raise ValueError
        original = custody.inspect_created_state() if created else custody.inspect_original_ack()
        if original.source_context_digest != self._source:
            raise ValueError
        return original.created_state_digest

    def begin_original_send(self, custody: WindowsExecutionPolicyCustody) -> None:
        """Consume fresh absence only under its exact original M4 dispatch."""
        try:
            with self._lock:
                observed = self._current
                if (observed is None or not observed.absent or type(custody) is not WindowsExecutionPolicyCustody
                        or custody._request != self._request or custody._source_context != self._source
                        or custody._preflight != observed.current_digest):
                    raise ValueError
                self.check_current(observed)
                custody.begin_original_send(self._raw, http_status=404)
        except Exception:
            raise WindowsPolicySourceError(_ERROR) from None
        finally:
            _zeroize_mutable(self._raw)

    def capture_creation(self, custody: WindowsExecutionPolicyCustody) -> WindowsPolicySourceObservation:
        try:
            self._custody(custody, created=False)
            observed = self._observe(True)
            self.check_current(observed)
            self._custody(custody, created=False)
            custody.capture_created_state(self._raw)
            if self._custody(custody, created=True) != observed.state_digest:
                raise ValueError
            return observed
        except Exception:
            self._failed = True
            raise WindowsPolicySourceError(_ERROR) from None
        finally:
            _zeroize_mutable(self._raw)

    def observe_owned(self, custody: WindowsExecutionPolicyCustody) -> WindowsPolicySourceObservation:
        try:
            original = self._custody(custody, created=True)
            observed = self._observe(True)
            if original is None or observed.state_digest != original or self._custody(custody, created=True) != original:
                raise ValueError
            return observed
        except Exception:
            self._failed = True
            self._current = None
            raise WindowsPolicySourceError(_ERROR) from None
        finally:
            _zeroize_mutable(self._raw)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current = None
            _zeroize_mutable(self._raw)
            self._cli.close()
