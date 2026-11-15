"""Concrete read-only sources for one new explicit-Policy Windows Folder.

Borrow the original Policy's fixed API/Owner bindings, not a saved proof or
caller-provided digest. This module cannot issue authority, write configuration,
establish Folder ownership or relax the inherited Folder/Secret contracts.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
from threading import RLock
import unicodedata
from urllib.parse import quote

import httpx
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .folder_archive_reference_ssh_transport import FortiPamFolderArchiveReferenceSshTransport
from .folder_namespace_ssh_reader import FortiPamFolderNamespaceSshReader, FolderNamespaceColumns
from .isolated_folder_http_transport import IsolatedFolderHttpTransport
from .local_user_reset_projection import _object_spans
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .target_lifecycle_dependencies import _envelope, _one, _spans
from .target_preservation_contract import _digest, _token_digest
from .windows_execution_folder_contract import (
    FIELDS, WindowsExecutionFolderRequest, compile_windows_execution_folder,
    consume_windows_execution_folder_state, consume_windows_execution_policy_link, _folder_detail_columns,
)
from .windows_execution_policy_cli_source import WindowsPolicyCliSource, WindowsPolicyCliObservation, FOLDER_LINK_PROFILE
from .windows_execution_policy_contract import compile_windows_execution_policy
from .windows_execution_policy_custody import WindowsExecutionPolicyCustody
from .windows_execution_policy_sources import WindowsExecutionPolicySources

_CONTRACT = "fortipam-build29-explicit-windows-folder-live-source-v1"
_ERROR = "The private explicit-Policy Folder live source is unavailable."
_FOLDER = "/api/v2/cmdb/secret/folder"
_POLICY = "/api/v2/cmdb/secret/policy"
_COLLECTION = _FOLDER + "?format=" + quote("|".join(sorted(FIELDS)), safe="") + "&with_meta=true&vdom=root&count=512&start=0"


class WindowsFolderSourceError(ValueError):
    """No raw identity, response or partial ownership proof in diagnostics."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsFolderSourceObservation(_OpaqueC3Object):
    source_context_digest: str
    current_digest: str
    absent: bool
    native_folder_id: int | None
    state_digest: str | None
    policy_reference_count: int
    folder_namespace_digest: str
    global_namespace_digest: str
    global_folder_count: int
    observed_at: float
    expires_at: float


class WindowsExecutionFolderSources(_OpaqueC3Object):
    """One fixed fresh window; caller owns the borrowed Policy source lifetime."""

    def __init__(self, *, request: WindowsExecutionFolderRequest,
            policy_sources: WindowsExecutionPolicySources,
            original_policy: WindowsExecutionPolicyCustody) -> None:
        try:
            if (type(request) is not WindowsExecutionFolderRequest
                    or type(policy_sources) is not WindowsExecutionPolicySources
                    or type(original_policy) is not WindowsExecutionPolicyCustody):
                raise ValueError
            request.validate()
            self._request, self._policy, self._original = request, policy_sources, original_policy
            binding = request.binding
            parent = policy_sources._folder._binding
            if (binding.policy_request != policy_sources._request
                    or binding.policy_request != original_policy._request
                    or binding.parent_folder_id != parent.parent_folder_id
                    or binding.parent_digest != parent.parent_digest
                    or binding.owner_name != parent.owner_name or binding.owner_name != policy_sources._owner):
                raise ValueError
            transport: object = policy_sources._folder._transport
            if type(transport) is not IsolatedFolderHttpTransport or transport._metadata._config is not policy_sources._config:
                raise ValueError
            self._folder_transport = transport
            self._path = transport._parent_path
            self._parent_name = self._path.split("/")[-1]
            witness = policy_sources._original.snapshot.folder
            self._witness = (witness["id"], witness["name"], witness["parent-folder"])
            if self._witness[0] == binding.parent_folder_id or self._witness[1] == self._parent_name:
                raise ValueError
            config = policy_sources._cli._config
            self._folder_cli = FortiPamFolderNamespaceSshReader(config, candidate_name=binding.name,
                positive_witness_names=(self._parent_name, str(self._witness[1])),
                expected_device_serial=policy_sources._original.serial)
            self._references = FortiPamFolderArchiveReferenceSshTransport(config)
            self._policy_cli = WindowsPolicyCliSource(config, request=binding.policy_request,
                control_policy_name=policy_sources._control, clock=policy_sources._clock,
                reference_profile=FOLDER_LINK_PROFILE)
            self._clock = policy_sources._clock
            self._source = self._context()
            self._last = -1.0
            self._closed = self._failed = False
            self._lock = RLock()
            self._current: WindowsFolderSourceObservation | None = None
            self._current_seal: str | None = None
            self._cli_observed: WindowsPolicyCliObservation | None = None
            self._policy_witness: tuple[tuple[str, ...], int, int] | None = None
            self._names: tuple[tuple[int, str, int], ...] = ()
            self._columns: FolderNamespaceColumns | None = None
            self._raw = bytearray()
            self.logout_verified = False
            self._last_failure_stage: str | None = None
        except Exception:
            raise WindowsFolderSourceError(_ERROR) from None

    def _context(self) -> str:
        self._request.validate()
        binding = self._request.binding
        original = self._original.inspect_created_state()
        parent = self._policy._folder._binding
        transport: object = self._policy._folder._transport
        ssh = self._policy._cli._config
        if (original.original_outcome != "succeeded" or original.original_verification != "verified"
                or original.custody_digest != binding.policy_custody_digest
                or original.created_state_digest != binding.policy_state_digest
                or original.source_context_digest != binding.policy_source_context_digest
                or self._policy.source_context_digest != binding.policy_source_context_digest
                or binding.policy_request != self._original._request or binding.policy_request != self._policy._request
                or parent.parent_folder_id != binding.parent_folder_id or parent.parent_digest != binding.parent_digest
                or parent.owner_name != binding.owner_name
                or transport is not self._folder_transport
                or self._folder_transport._metadata._config is not self._policy._config
                or self._folder_transport._parent_path != self._path
                or self._folder_cli._candidate_name != binding.name
                or self._folder_cli._witness_names != (self._parent_name, str(self._witness[1]))
                or self._folder_cli._device_serial != self._policy._original.serial
                or self._folder_cli._ssh._config is not ssh
                or self._references._ssh._config is not ssh
                or self._policy_cli._ssh._config is not ssh):
            raise ValueError
        return _digest((_CONTRACT, self._request.request_digest, original.context_digest,
            original.custody_digest, self._policy.source_context_digest, self._policy_cli._context(),
            self._path, self._witness, "native-full-fourteen-field-collection-v1", _COLLECTION))

    @property
    def source_context_digest(self) -> str:
        try:
            self._now()
            return self._source
        except Exception:
            raise WindowsFolderSourceError(_ERROR) from None

    def _now(self) -> float:
        try:
            value = self._clock()
            if (self._closed or self._failed or type(value) not in (int, float) or not math.isfinite(value)
                    or value < self._last or value < 0 or self._context() != self._source):
                raise ValueError
            self._last = float(value)
            return float(value)
        except Exception:
            self._failed = True
            raise ValueError from None

    def _folder_rights(self, client: httpx.Client, deadline: float) -> str:
        raw = bytearray()
        try:
            raw = self._policy._get(client, "/api/v2/monitor/web-ui/state", deadline)
            _, profile, actor = self._policy._actor(raw)
            _zeroize_mutable(raw)
            raw = self._policy._get(client, "/api/v2/cmdb/system/accprofile/" + quote(profile, safe="") +
                "?format=name%7Csecretgrp%7Csecretgrp-permission&with_meta=true&vdom=root", deadline)
            row = _one(raw, _envelope(raw, path="system", name="accprofile",
                serial_digest=self._request.binding.policy_request.binding.serial_digest))
            fields = m._object_spans(raw, *row, frozenset({"name", "secretgrp", "secretgrp-permission"}))
            rights = m._object_spans(raw, *fields["secretgrp-permission"], frozenset({"folder-table"}))
            if (m._scalar(raw, fields["name"]) != profile or m._scalar(raw, fields["secretgrp"]) != "custom"
                    or m._scalar(raw, rights["folder-table"]) != "read-write"):
                raise ValueError
            return _digest((actor, _token_digest(raw, row)))
        finally:
            _zeroize_mutable(raw)

    def _namespace(self, client: httpx.Client, deadline: float) -> tuple[tuple[int, str, int], ...]:
        raw = self._policy._get(client, _COLLECTION, deadline, owner=True)
        try:
            fields = _spans(raw)
            wanted = {"version":"v7.0.0", "build":29, "http_method":"GET", "http_status":200,
                "status":"OK", "path":"secret", "name":"folder", "vdom":"root"}
            for key, value in wanted.items():
                actual = m._scalar(raw, fields[key])
                if type(actual) is not type(value) or actual != value:
                    raise ValueError
            serial = m._scalar(raw, fields["serial"])
            if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != self._request.binding.policy_request.binding.serial_digest:
                raise ValueError
            outer = _object_spans(raw, 0, len(raw))
            if ("schema_errors" in outer or any(key in outer for key in ("next_idx", "next_index", "total", "total_count"))
                    or "action" in outer and m._scalar(raw, outer["action"]) != ""
                    or "limit_reached" in fields and m._scalar(raw, fields["limit_reached"]) is not False
                    or "error" in fields and (type(m._scalar(raw, fields["error"])) is not int or m._scalar(raw, fields["error"]) != 0)):
                raise ValueError
            rows = m._array(raw, fields["results"], 512)
            count = m._scalar(raw, outer["matched_count"])
            if type(count) is not int or count != len(rows) or not 2 <= count < 512:
                raise ValueError
            result: list[tuple[int, str, int]] = []
            ids: set[int] = set()
            for span in rows:
                props = _object_spans(raw, *span)
                if set(props) != FIELDS | {"q_origin_key", "permissions"}:
                    raise ValueError
                identifier, name, parent = (m._scalar(raw, props[key]) for key in ("id", "name", "parent-folder"))
                if (type(identifier) is not int or not 0 < identifier <= 2147483647 or identifier in ids
                        or type(parent) is not int or not 0 <= parent <= 2147483647
                        or type(name) is not str or not 0 < len(name) <= 64
                        or any(unicodedata.category(ch).startswith("C") or ch in '\\"' for ch in name)):
                    raise ValueError
                if "q_origin_key" in props:
                    origin = m._scalar(raw, props["q_origin_key"])
                    if type(origin) is not int or origin != identifier:
                        raise ValueError
                ids.add(identifier)
                result.append((identifier, name, parent))
            return tuple(sorted(result))
        finally:
            _zeroize_mutable(raw)

    def _parent(self, client: httpx.Client, deadline: float) -> str:
        binding = self._request.binding
        raw = self._policy._get(client, _FOLDER + "/" + str(binding.parent_folder_id) +
            "?with_meta=true&vdom=root", deadline, owner=True)
        try:
            columns = _folder_detail_columns(raw, native_folder_id=binding.parent_folder_id,
                serial_digest=binding.policy_request.binding.serial_digest)
            values = {key:json.loads(raw[slice(*span)]) for key, span in columns.items()}
            if (values["name"] != self._parent_name or values["folder-type"] != "public"
                    or canonical_digest({key:values[key] for key in FIELDS}) != binding.parent_digest):
                raise ValueError
            return _digest(values)
        finally:
            _zeroize_mutable(raw)

    def _policy_link(self, client: httpx.Client, deadline: float, references: int) -> str:
        raw = self._policy._get(client, _POLICY + "/" + quote(self._request.binding.policy_request.binding.name, safe="") +
            "?with_meta=true&vdom=root", deadline)
        return consume_windows_execution_policy_link(raw, binding=self._request.binding, expected_references=references)

    def _candidate(self, client: httpx.Client, deadline: float, native_id: int) -> tuple[str, bytearray]:
        raw = self._policy._get(client, _FOLDER + "/" + str(native_id) + "?with_meta=true&vdom=root", deadline, owner=True)
        kept = bytearray()
        try:
            kept = bytearray(raw)
            digest = consume_windows_execution_folder_state(raw, request=self._request, native_folder_id=native_id)
            return digest, kept
        except Exception:
            _zeroize_mutable(kept)
            raise
        finally:
            _zeroize_mutable(raw)

    def _observe(self, present: bool, native_id: int | None) -> WindowsFolderSourceObservation:
        with self._lock:
            self._current = None
            self._current_seal = None
            self.logout_verified = False
            self._cli_observed = None
            self._policy_witness = None
            self._names = ()
            self._columns = None
            _zeroize_mutable(self._raw)
            kept = bytearray()
            buffers: list[bytearray] = []
            session = None
            stage = "source_context"
            try:
                if type(present) is not bool or (present and (type(native_id) is not int or not 0 < native_id <= 2147483647)
                        or not present and native_id is not None):
                    raise ValueError
                started = self._now(); deadline = started + 60
                references = 1 if present else 0
                with _private_http_logs(), self._policy._factory(verify=self._policy._tls, timeout=10,
                        trust_env=False, follow_redirects=False) as client:
                    try:
                        stage = "api_role"
                        role = self._policy._api_role(client, deadline)
                        stage = "folder_permissions"
                        folder_rights = self._folder_rights(client, deadline)
                        stage = "policy_metadata"
                        schema = self._policy._get(client, _POLICY + "?action=schema&with_meta=true&vdom=root", deadline); buffers.append(schema)
                        defaults = self._policy._get(client, _POLICY + "?action=default&vdom=root", deadline); buffers.append(defaults)
                        if compile_windows_execution_policy(schema, defaults, binding=self._policy._request.binding,
                                profile=self._policy._request.profile) != self._policy._request:
                            raise ValueError
                        stage = "folder_metadata"
                        schema = self._policy._get(client, _FOLDER + "?action=schema&with_meta=true&vdom=root", deadline); buffers.append(schema)
                        defaults = self._policy._get(client, _FOLDER + "?action=default&vdom=root", deadline); buffers.append(defaults)
                        if compile_windows_execution_folder(schema, defaults, binding=self._request.binding) != self._request:
                            raise ValueError
                        stage = "policy_namespace"
                        control = self._policy._control_count(client, deadline)
                        names = self._policy._namespace(client, deadline)
                        stage = "original_policy_link_before"
                        link = self._policy_link(client, deadline, references)
                        session = OwnerSessionMetadataTransport(self._policy._config, owner_name=self._policy._owner,
                            credentials=self._policy._credentials, folder_path="explicit-folder-source",
                            secret_name="explicit-folder-source", target_name="explicit-folder-source",
                            witness=FortiPamSecretMetadataHttpTransport(self._policy._config),
                            client_factory=self._policy._factory, clock=self._clock)
                        stage = "owner_login"
                        with session.authenticated():
                            if session._client is None:
                                raise ValueError
                            stage = "owner_identity_before"
                            owner = self._policy._owner_role(session, deadline)
                            stage = "folder_namespace_before"
                            namespace = self._namespace(session._client, deadline)
                            binding = self._request.binding
                            stage = "parent_before"
                            parent = self._parent(session._client, deadline)
                            stage = "candidate_scope"
                            if (self._witness not in namespace
                                    or not any(row[0] == binding.parent_folder_id and row[1] == self._parent_name for row in namespace)):
                                raise ValueError
                            matches = tuple(row for row in namespace if row[1] == binding.name)
                            if matches != (((native_id, binding.name, binding.parent_folder_id),) if present else ()):
                                raise ValueError
                            state = None
                            if present:
                                assert native_id is not None
                                stage = "candidate_before"
                                state, raw = self._candidate(session._client, deadline, native_id); _zeroize_mutable(raw)
                            stage = "global_folder_namespace"
                            folder_started = self._now()
                            columns = self._folder_cli.read_complete_namespace()
                            observed = columns.observation
                            if (observed.global_name_absent is not (not present)
                                    or columns.names.count(binding.name) != int(present)
                                    or observed.folder_count != len(columns.names)
                                    or len(columns.names) != len(columns.parent_values)
                                    or observed.folder_count < len(namespace)
                                    or observed.namespace_digest != canonical_digest({
                                        "contract":"fortipam-700-build29-folder-name-namespace-candidate-v1",
                                        "names":list(columns.names), "parent_values":list(columns.parent_values)})):
                                raise ValueError
                            if present:
                                assert native_id is not None
                                stage = "folder_references"
                                if not self._references.verify_no_references(native_id, binding.parent_folder_id, self._policy._original.serial):
                                    raise ValueError
                            def guard() -> None:
                                if self._now() >= min(deadline, folder_started + min(30, self._policy._cli._config.timeout_seconds)):
                                    raise ValueError
                            guard()
                            stage = "policy_global_reference"
                            cli = self._policy_cli.observe(api_names=names, control_reference_count=control,
                                candidate_reference_count=references, before_send=guard)
                            if present:
                                assert native_id is not None
                                stage = "candidate_after"
                                after, kept = self._candidate(session._client, deadline, native_id)
                                if state != after:
                                    raise ValueError
                            stage = "parent_namespace_owner_after"
                            if (self._parent(session._client, deadline) != parent
                                    or self._namespace(session._client, deadline) != namespace
                                    or self._policy._owner_role(session, deadline) != owner):
                                raise ValueError
                        stage = "owner_logout_and_api_after"
                        self.logout_verified = session.logout_verified
                        if (not self.logout_verified or self._policy_link(client, deadline, references) != link
                                or self._policy._namespace(client, deadline) != names
                                or self._policy._control_count(client, deadline) != control
                                or self._folder_rights(client, deadline) != folder_rights
                                or self._policy._api_role(client, deadline) != role):
                            raise ValueError
                    finally:
                        client.cookies.clear()
                stage = "source_freshness"
                expires = min(deadline, folder_started + min(30, self._policy._cli._config.timeout_seconds), cli.expires_at)
                if self._now() >= expires:
                    raise ValueError
                namespace_digest = _digest(namespace)
                current = _digest((_CONTRACT, self._source, role, folder_rights, owner, parent, namespace_digest,
                    observed.namespace_digest, link, cli.namespace_digest, cli.witness_digest, state, native_id, present))
                result = WindowsFolderSourceObservation(self._source, current, not present, native_id, state,
                    references, namespace_digest, observed.namespace_digest, observed.folder_count, started, expires)
                self._current, self._current_seal = result, _digest(asdict(result))
                self._cli_observed, self._policy_witness = cli, (names, control, references)
                self._names, self._columns = namespace, columns
                self._raw, kept = kept, bytearray()
                self._last_failure_stage = None
                return result
            except Exception:
                self._failed = True
                self._current = None
                self._last_failure_stage = stage
                raise WindowsFolderSourceError(_ERROR) from None
            finally:
                for raw in (*buffers, kept):
                    _zeroize_mutable(raw)

    def observe_absence(self) -> WindowsFolderSourceObservation:
        return self._observe(False, None)

    def observe_candidate_presence(self, native_folder_id: int) -> WindowsFolderSourceObservation:
        """Read-only qualification cannot establish the candidate's ownership."""
        return self._observe(True, native_folder_id)

    def observe_owned(self, original: object) -> WindowsFolderSourceObservation:
        """Require the actual original Folder seal before recovery readback."""
        from .windows_execution_folder_custody import WindowsExecutionFolderCustody
        try:
            if type(original) is not WindowsExecutionFolderCustody or original._request != self._request:
                raise ValueError
            owned = original.inspect_created_state()
            if owned.source_context_digest != self.source_context_digest:
                raise ValueError
            observed = self._observe(True, owned.native_folder_id)
            self.check_current(observed)
            if (observed.state_digest != owned.created_state_digest
                    or original.inspect_created_state() != owned):
                raise ValueError
            return observed
        except Exception:
            self._failed = True
            self._current = None
            raise WindowsFolderSourceError(_ERROR) from None
        finally:
            _zeroize_mutable(self._raw)

    def check_current(self, observed: WindowsFolderSourceObservation) -> None:
        try:
            with self._lock:
                if (type(observed) is not WindowsFolderSourceObservation or observed is not self._current
                        or self._current_seal != _digest(asdict(observed))
                        or not observed.observed_at <= self._now() < observed.expires_at
                        or observed.source_context_digest != self._source
                        or self._cli_observed is None or self._policy_witness is None):
                    raise ValueError
                names, control, count = self._policy_witness
                self._policy_cli.check_current(self._cli_observed, api_names=names,
                    control_reference_count=control, candidate_reference_count=count)
        except Exception:
            raise WindowsFolderSourceError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current = None
            self._current_seal = None
            _zeroize_mutable(self._raw)
            self._policy_cli.close()
