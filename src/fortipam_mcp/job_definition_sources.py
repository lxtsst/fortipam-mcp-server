"""Fresh fixed writer/Owner/default/namespace sources for one disabled Job.

No authority, original receipt, mutation, activation or execution is supplied.
The protected composition owns both exact readers and their shared Owner.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import re
from threading import RLock
import time
from urllib.parse import quote

import httpx
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .job_definition_create_contract import compile_disabled_job_create_body
from .job_definition_reference_reader import read_job_reference_control, CONTRACT as _REFERENCE_CONTRACT
from .job_definition_detail_reader import (
    JobDefinitionDetailReader, _READ_FAILURE_STAGES,
    _require_token, _token,
)
from .job_definition_http_transport import _SOURCE, _digest as _body_digest
from .job_namespace_ssh_reader import FortiPamJobNamespaceSshReader, CONTRACT as _NAMESPACE_CONTRACT
from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable, _redact_json_field_values,
)
from .target_api_dependency_reader import _private_http_logs
from .target_lifecycle_dependencies import _envelope, _one, _spans
from .target_preservation_contract import _api_source_context, _digest, _token_digest
from .target_ssh_transport import TargetSshTransportConfig

CONTRACT = "fortipam-build29-disabled-job-live-source-v2"
_ERROR = "The private disabled Job live source is unavailable."
_JOB = "/api/v2/cmdb/secret/job"
_MONITOR = "/api/v2/monitor/web-ui/state"
_SECRET_KEYS = ("id", "folder", "template", "need-approval-job", "approval-profile")


class JobDefinitionSourceError(ValueError):
    """No private selector, native output or partial authorization in errors."""


@dataclass(frozen=True, slots=True, repr=False)
class JobDefinitionSourceObservation(_OpaqueC3Object):
    source_context_digest: str
    current_digest: str
    dependency_digest: str
    namespace_digest: str
    state_digest: str | None
    absent: bool
    job_count: int
    observed_at: float
    expires_at: float


class JobDefinitionSources(_OpaqueC3Object):
    """Fresh role-bound C/P/E sources; existing Jobs remain read-only controls."""

    def __init__(self, *, candidate: JobDefinitionDetailReader, anchor: JobDefinitionDetailReader,
            ssh: TargetSshTransportConfig, client_factory: Callable[..., httpx.Client] = httpx.Client,
            clock: Callable[[], float] = time.monotonic, source_secret_id: int | None = None) -> None:
        try:
            if (type(candidate) is not JobDefinitionDetailReader or type(anchor) is not JobDefinitionDetailReader
                    or type(ssh) is not TargetSshTransportConfig or not callable(clock) or not callable(client_factory)
                    or candidate._owner is not anchor._owner or candidate._name in (anchor._name, _SOURCE)
                    or anchor._name == _SOURCE or candidate._serial_digest != anchor._serial_digest
                    or candidate._owner._owner_name != ssh.username
                    or type(candidate._owner._config) is not SecretMetadataHttpTransportConfig):
                raise ValueError
            self._candidate, self._anchor, self._owner, self._ssh = candidate, anchor, candidate._owner, ssh
            self._config = candidate._owner._config
            self._tls = _ssl_context(self._config)
            self._serial = json.loads(candidate._serial_token)
            self._body = {key: json.loads(value) for key, value in candidate._expected_tokens.items()
                if key not in {"approval-status", "max-timeout"}}
            self._body["$originalName"] = ""
            if type(self._body["secret"]) is not int or not 0 < self._body["secret"] <= 2147483647:
                raise ValueError
            self._retarget = source_secret_id is not None
            self._source_secret_id = self._body["secret"] if source_secret_id is None else source_secret_id
            if type(self._source_secret_id) is not int or not 0 < self._source_secret_id <= 2147483647:raise ValueError
            self._secret_path = self._secret_metadata_path()
            self._writer = self._body["user"]
            self._body_digest = _body_digest(self._body)
            self._provider = self._owner._credentials
            self._owner_factory = self._owner._session_factory
            self._factory, self._clock = client_factory, clock
            self._namespace_proto = self._namespace()
            self._namespace_source = self._namespace_proto._source
            self._source = self._context()
            self._closed = self._failed = False
            self._last = -1.0
            self._current: JobDefinitionSourceObservation | None = None
            self._seal: str | None = None
            self._names: tuple[str, ...] = ()
            self._last_failure_stage: str | None = None
            self._last_reader_failure_stage: str | None = None
            self.logout_verified = False
            self._lock = RLock()
        except Exception:
            raise JobDefinitionSourceError(_ERROR) from None

    def _namespace(self) -> FortiPamJobNamespaceSshReader:
        return FortiPamJobNamespaceSshReader(self._ssh, candidate_name=self._candidate._name,
            positive_witness_names=(_SOURCE, self._anchor._name), expected_device_serial=self._serial)

    def _secret_metadata_path(self) -> str:
        return "/api/v2/cmdb/secret/database/" + str(self._body["secret"]) + "?format=" + quote(
            "|".join(_SECRET_KEYS), safe="") + "&with_meta=true&vdom=root"

    def _context(self) -> str:
        c, a, o = self._candidate, self._anchor, self._owner
        binding, anchor_binding = c._bound_definition_digests(), a._bound_definition_digests()
        source = {key: value for key, value in self._body.items() if key != "$originalName"}
        source.update(name=_SOURCE, user="admin", **{"approval-status": "approved"})
        compiled = compile_disabled_job_create_body({"status": "success", "version": "v7.0.0", "build": 29,
            "results": source}, source_name=_SOURCE, target_name=c._name,
            target_requester=str(self._writer), expected_secret_id=self._body["secret"])
        if (a._expected_tokens["secret"] != _token(self._source_secret_id)
                or c._owner is not o or a._owner is not o or o._config is not self._config
                or o._owner_name != self._ssh.username or o._credentials is not self._provider
                or o._session_factory is not self._owner_factory or o._allow_secret_create
                or o._allow_collector_credential_repair or self._body != compiled
                or _body_digest(compiled) != self._body_digest or binding[0] != self._body_digest
                or c._serial_digest != a._serial_digest or binding[1] != hashlib.sha256(self._serial.encode()).hexdigest()
                or self._namespace_proto._config is not self._ssh
                or self._namespace_proto._candidate != c._name
                or self._namespace_proto._witnesses != (_SOURCE, a._name)
                or self._namespace_proto._serial != self._serial
                or self._secret_path != self._secret_metadata_path()
                or self._namespace_proto._context() != self._namespace_source):
            raise ValueError
        self._config.__post_init__()
        ca = None
        if self._config.ca_file is not None:
            with Path(self._config.ca_file).open("rb") as stream:
                data = stream.read(1048577)
            if not 0 < len(data) <= 1048576:
                raise ValueError
            ca = hashlib.sha256(data).hexdigest()
        api = _api_source_context(self._config.base_url, hashlib.sha256(self._config.bearer_token.encode()).hexdigest(),
            ca, binding[1])
        context = (CONTRACT, api, binding, anchor_binding, self._namespace_source, o._owner_name,
            "exact-source-clone-disabled", "full-pristine-row-v1", self._secret_path,
            "metadata-field-redaction-v1", "effective-job-approval-disabled-v1", _REFERENCE_CONTRACT)
        # Preserve every accepted v3 source/constructor digest byte-for-byte.
        return _digest(context if not self._retarget else (*context,"fixed-selected-secret-v1",self._source_secret_id))

    def _now(self) -> float:
        value = self._clock()
        if (self._closed or self._failed or type(value) not in (int, float) or not math.isfinite(value)
                or value < 0 or value < self._last or self._context() != self._source):
            raise ValueError
        self._last = float(value)
        return float(value)

    @property
    def source_context_digest(self) -> str:
        try:
            self._now()
            return self._source
        except Exception:
            raise JobDefinitionSourceError(_ERROR) from None

    def _get(self, client: httpx.Client, path: str, deadline: float, *, owner: bool = False) -> bytearray:
        raw = bytearray()
        try:
            headers = {"Accept": "application/json", "Accept-Encoding": "identity", "Cache-Control": "no-store"}
            if not owner:
                headers["Authorization"] = "Bearer " + self._config.bearer_token
            remaining = deadline - self._now()
            if remaining <= 0:
                raise ValueError
            with client.stream("GET", path if owner else self._config.base_url + path, headers=headers,
                    timeout=min(10.0, remaining)) as response:
                if (response.status_code != 200
                        or response.headers.get("content-type", "").split(";")[0] != "application/json"
                        or response.headers.get("content-encoding", "identity") not in ("", "identity")):
                    raise ValueError
                for chunk in response.iter_raw():
                    if self._now() >= deadline or len(raw) + len(chunk) > 1048576:
                        raise ValueError
                    raw.extend(chunk)
            if self._now() >= deadline:
                raise ValueError
            if path == self._secret_path:
                # Native Secret detail can include field despite format. Erase
                # it before the existing generic JSON framing or projection.
                _redact_json_field_values(raw)
            _spans(raw)
            if "schema_errors" in _object_spans(raw, 0, len(raw)):
                raise ValueError
            result, raw = raw, bytearray()
            return result
        finally:
            _zeroize_mutable(raw)

    def _actor(self, raw: bytearray, expected: str) -> tuple[str, str]:
        row = _envelope(raw, path="web-ui", name="state", serial_digest=self._candidate._serial_digest, monitor=True)
        root = m._object_spans(raw, *row, frozenset({"admin", "vdom_mode", "maintenance_mode"}))
        admin = m._object_spans(raw, *root["admin"], frozenset({"profile", "global_admin"}))
        role = m._scalar(raw, m._object_spans(raw, *admin["profile"], frozenset({"name"}))["name"])
        maintenance = m._object_spans(raw, *root["maintenance_mode"], frozenset({"mode"}))
        if (type(role) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", role) is None
                or m._scalar(raw, admin["global_admin"]) is not True
                or m._scalar(raw, root["vdom_mode"]) != ""
                or m._scalar(raw, maintenance["mode"]) != "disable"):
            raise ValueError
        return role, _actor_context(raw, expected_name=expected)

    def _writer_role(self, client: httpx.Client, deadline: float) -> str:
        buffers: list[bytearray] = []
        try:
            expected = str(self._writer)
            raw = self._get(client, _MONITOR, deadline); buffers.append(raw)
            role, actor = self._actor(raw, expected)
            raw = self._get(client, "/api/v2/cmdb/system/api-user/" + quote(expected, safe="") +
                "?format=name%7Caccprofile&with_meta=true&vdom=root", deadline); buffers.append(raw)
            row = _one(raw, _envelope(raw, path="system", name="api-user", serial_digest=self._candidate._serial_digest))
            fields = m._object_spans(raw, *row, frozenset({"name", "accprofile"}))
            if m._scalar(raw, fields["name"]) != expected or m._scalar(raw, fields["accprofile"]) != role:
                raise ValueError
            user = _token_digest(raw, row)
            raw = self._get(client, "/api/v2/cmdb/system/accprofile/" + quote(role, safe="") +
                "?format=name%7Csecretgrp%7Csecretgrp-permission&with_meta=true&vdom=root", deadline); buffers.append(raw)
            row = _one(raw, _envelope(raw, path="system", name="accprofile", serial_digest=self._candidate._serial_digest))
            fields = m._object_spans(raw, *row, frozenset({"name", "secretgrp", "secretgrp-permission"}))
            rights = m._object_spans(raw, *fields["secretgrp-permission"], frozenset({"secret-job"}))
            if (m._scalar(raw, fields["name"]) != role or m._scalar(raw, fields["secretgrp"]) != "custom"
                    or m._scalar(raw, rights["secret-job"]) != "read-write"):
                raise ValueError
            return _digest((actor, user, _token_digest(raw, row)))
        finally:
            for raw in buffers:
                _zeroize_mutable(raw)

    def _owner_role(self, deadline: float) -> str:
        client = self._owner._client
        if client is None:
            raise ValueError
        raw = self._get(client, _MONITOR, deadline, owner=True)
        try:
            role, actor = self._actor(raw, self._ssh.username)
            row = _envelope(raw, path="web-ui", name="state", serial_digest=self._candidate._serial_digest, monitor=True)
            root = m._object_spans(raw, *row, frozenset({"admin"}))
            admin = m._object_spans(raw, *root["admin"], frozenset({"super_admin"}))
            if role != "super_admin" or m._scalar(raw, admin["super_admin"]) is not True:
                raise ValueError
        finally:
            _zeroize_mutable(raw)
        raw = self._get(client, "/api/v2/cmdb/system/admin/" + quote(self._ssh.username, safe="") +
            "?format=name%7Caccprofile%7Cstatus%7Cremote-auth%7Cwildcard&with_meta=true&vdom=root", deadline, owner=True)
        try:
            row = _one(raw, _envelope(raw, path="system", name="admin", serial_digest=self._candidate._serial_digest))
            fields = m._object_spans(raw, *row, frozenset({"name", "accprofile", "status", "remote-auth", "wildcard"}))
            expected = {"name": self._ssh.username, "accprofile": "super_admin", "status": "enable",
                "remote-auth": "disable", "wildcard": "disable"}
            if {key: m._scalar(raw, value) for key, value in fields.items()} != expected:
                raise ValueError
            return _digest((actor, expected))
        finally:
            _zeroize_mutable(raw)

    def _clone_source(self, client: httpx.Client, deadline: float) -> str:
        raw = self._get(client, _JOB + "/" + _SOURCE + "?vdom=root", deadline)
        try:
            row = _one(raw, _envelope(raw, path="secret", name="job", serial_digest=self._candidate._serial_digest))
            fields = _object_spans(raw, *row)
            for key, value in self._body.items():
                if key != "$originalName":
                    _require_token(raw, fields[key], _token(_SOURCE if key == "name" else "admin" if key == "user" else self._source_secret_id if key == "secret" else value))
            _require_token(raw, fields["approval-status"], _token("approved"))
            return _digest({key: _token_digest(raw, fields[key]) for key in self._body if key != "$originalName"})
        finally:
            _zeroize_mutable(raw)

    def _defaults(self, client: httpx.Client, deadline: float) -> str:
        raw = self._get(client, _JOB + "?action=default&with_meta=true&vdom=root", deadline)
        try:
            row = _one(raw, _envelope(raw, path="secret", name="job", serial_digest=self._candidate._serial_digest, action="default"))
            fields = _object_spans(raw, *row)
            _require_token(raw, fields["status"], _token("disable"))
            _require_token(raw, fields["max-timeout"], self._candidate._expected_tokens["max-timeout"])
            if not (set(self._body) - {"$originalName"}) <= fields.keys():
                raise ValueError
            return _digest({key: _token_digest(raw, span) for key, span in fields.items()})
        finally:
            _zeroize_mutable(raw)

    def _metadata_row(self, path: str, table: str, keys: tuple[str, ...], deadline: float
            ) -> tuple[dict[str, object], str]:
        if self._owner._client is None:
            raise ValueError
        raw = self._get(self._owner._client, path, deadline, owner=True)
        try:
            envelope = _spans(raw)
            expected = dict(version="v7.0.0", build=29, http_method="GET", http_status=200,
                path="secret", name=table, vdom="root", serial=self._serial,
                status="OK" if table in ("database", "folder") else "success")
            for key, value in expected.items():
                actual = m._scalar(raw, envelope[key])
                if type(actual) is not type(value) or actual != value:
                    raise ValueError
            if "error" in envelope:
                error = m._scalar(raw, envelope["error"])
                if error is not None and (type(error) is not int or error != 0):
                    raise ValueError
            row = _one(raw, envelope["results"])
            fields = m._object_spans(raw, *row, frozenset(keys) | {"field"})
            if "field" in fields and m._scalar(raw, fields["field"]) is not None:
                raise ValueError
            return ({key: m._scalar(raw, fields[key]) for key in keys},
                _digest({key: _token_digest(raw, fields[key]) for key in keys}))
        finally:
            _zeroize_mutable(raw)

    def _secret_dependency(self, deadline: float) -> str:
        secret, state = self._metadata_row(self._secret_path, "database", _SECRET_KEYS, deadline)
        folder_id, template = secret["folder"], secret["template"]
        if (type(secret["id"]) is not int or secret["id"] != self._body["secret"]
                or type(folder_id) is not int or not 0 < folder_id <= 2147483647
                or type(template) is not str or not 0 < len(template) <= 79
                or any(ord(character) < 32 or ord(character) == 127 for character in template)
                or secret["need-approval-job"] not in ("enable", "disable")
                or type(secret["approval-profile"]) is not str):
            raise ValueError
        seen: set[int] = set()
        parents: list[str] = []
        for _ in range(8):
            if folder_id in seen:
                raise ValueError
            seen.add(folder_id)
            keys = ("id", "parent-folder", "inherit-policy", "secret-policy")
            folder, fingerprint = self._metadata_row("/api/v2/cmdb/secret/folder/" + str(folder_id) +
                "?format=" + quote("|".join(keys), safe="") + "&with_meta=true&vdom=root", "folder", keys, deadline)
            parent = folder["parent-folder"]
            if (type(folder["id"]) is not int or folder["id"] != folder_id
                    or type(parent) is not int or not 0 <= parent <= 2147483647
                    or folder["inherit-policy"] not in ("enable", "disable")):
                raise ValueError
            parents.append(fingerprint)
            if folder["inherit-policy"] == "disable":
                policy_name = folder["secret-policy"]
                if type(policy_name) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,78}", policy_name) is None:
                    raise ValueError
                policy, fingerprint = self._metadata_row("/api/v2/cmdb/secret/policy/" + quote(policy_name, safe="") +
                    "?format=name%7Cneed-approval-job&with_meta=true&vdom=root", "policy", ("name", "need-approval-job"), deadline)
                flag = policy["need-approval-job"]
                if policy["name"] != policy_name or flag not in ("enable", "disable", "not-set"):
                    raise ValueError
                effective = secret["need-approval-job"] if flag == "not-set" else flag
                if effective != "disable":
                    raise ValueError
                return _digest((state, parents, fingerprint, "effective-job-approval-disabled"))
            if parent == 0:
                raise ValueError
            folder_id = parent
        raise ValueError

    def _observe(self, present: bool) -> JobDefinitionSourceObservation:
        with self._lock:
            if self._failed or self._closed:
                raise JobDefinitionSourceError(_ERROR) from None
            self._current, self._seal, self._names = None, None, ()
            self._last_reader_failure_stage = None
            self.logout_verified = False
            namespace = None
            stage = "source_binding"
            try:
                started = self._now(); deadline = started + 60
                with _private_http_logs(), self._factory(verify=self._tls, timeout=10, trust_env=False,
                        follow_redirects=False) as client:
                    try:
                        stage = "writer_role_before"; writer = self._writer_role(client, deadline)
                        stage = "defaults"; defaults = self._defaults(client, deadline)
                        stage = "clone_source"; source = self._clone_source(client, deadline)
                        with self._owner.authenticated():
                            stage = "owner_before"; owner = self._owner_role(deadline)
                            stage = "secret_dependency_before"; secret = self._secret_dependency(deadline)
                            stage = "positive_pristine"; anchor, anchor_state = self._anchor._pristine_in_session()
                            if not anchor.verified:
                                raise ValueError
                            stage = "candidate_before"
                            before = None
                            if present:
                                result, before = self._candidate._pristine_in_session()
                                if not result.verified:
                                    raise ValueError
                            stage = "global_namespace"; namespace = self._namespace()
                            names_started = self._now()
                            observed = namespace.read_namespace()
                            if (observed.global_name_absent is not (not present)
                                    or namespace._names.count(self._candidate._name) != int(present)
                                    or observed.source_context_digest != self._namespace_source):
                                raise ValueError
                            stage = "reference_controls"
                            def guard() -> None:
                                if self._now() >= min(deadline, names_started + min(30, self._ssh.timeout_seconds)):
                                    raise ValueError
                            references = read_job_reference_control(self._ssh, candidate_name=self._candidate._name,
                                anchor_name=self._anchor._name, secret_id=self._source_secret_id, serial=self._serial,
                                before_send=guard)
                            if not references.candidate_unreferenced or not references.anchor_unreferenced:
                                raise ValueError
                            state = None
                            if present:
                                stage = "candidate_after"
                                result, state = self._candidate._pristine_in_session()
                                if not result.verified or state != before:
                                    raise ValueError
                            stage = "owner_after"
                            if self._secret_dependency(deadline) != secret or self._owner_role(deadline) != owner:
                                raise ValueError
                        self.logout_verified = self._owner.logout_verified
                        stage = "writer_source_after"
                        if (not self.logout_verified or self._writer_role(client, deadline) != writer
                                or self._defaults(client, deadline) != defaults or self._clone_source(client, deadline) != source):
                            raise ValueError
                    finally:
                        client.cookies.clear()
                expires = min(deadline, names_started + min(30, self._ssh.timeout_seconds))
                if self._now() >= expires:
                    raise ValueError
                dependency = _digest((CONTRACT, writer, owner, defaults, source, anchor_state, secret, references.snapshot_digest))
                current = _digest((CONTRACT, self._source, dependency, observed.namespace_digest, present, state))
                observation = JobDefinitionSourceObservation(self._source, current, dependency,
                    observed.namespace_digest, state, not present, observed.job_count, started, expires)
                self._current, self._seal, self._names = observation, _digest(asdict(observation)), namespace._names
                self._last_failure_stage = None
                return observation
            except Exception:
                self._failed = True
                self._current, self._seal, self._names = None, None, ()
                self._last_failure_stage = stage
                reader = self._anchor if stage == "positive_pristine" else self._candidate
                reader_stage = reader._last_failure_stage
                if (stage in {"positive_pristine", "candidate_before", "candidate_after"}
                        and type(reader_stage) is str and reader_stage in _READ_FAILURE_STAGES):
                    self._last_reader_failure_stage = reader_stage
                raise JobDefinitionSourceError(_ERROR) from None
            finally:
                if namespace is not None:
                    namespace.close()

    def _failure_diagnostics(self) -> dict[str, str | None]:
        """Return only fixed reader categories, never an upstream error or value."""
        phase = self._last_failure_stage
        stage = self._last_reader_failure_stage
        return {
            "source_reader_phase": phase if type(phase) is str and phase in {
                "positive_pristine", "candidate_before", "candidate_after"} else None,
            "reader_failure_stage": stage if type(stage) is str and stage in _READ_FAILURE_STAGES else None,
        }

    def observe_absence(self) -> JobDefinitionSourceObservation:
        return self._observe(False)

    def observe_candidate_presence(self) -> JobDefinitionSourceObservation:
        """Current full/pristine state is not original ownership or recovery."""
        return self._observe(True)

    def check_current(self, observed: JobDefinitionSourceObservation) -> None:
        try:
            with self._lock:
                if (type(observed) is not JobDefinitionSourceObservation or observed is not self._current
                        or _digest(asdict(observed)) != self._seal
                        or not observed.observed_at <= self._now() < observed.expires_at
                        or observed.job_count != len(self._names)
                        or observed.namespace_digest != canonical_digest({
                            "contract": _NAMESPACE_CONTRACT, "names": sorted(self._names)})):
                    raise ValueError
        except Exception:
            self._failed = True
            self._current, self._seal, self._names = None, None, ()
            raise JobDefinitionSourceError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current, self._seal, self._names = None, None, ()
            self._namespace_proto.close()
