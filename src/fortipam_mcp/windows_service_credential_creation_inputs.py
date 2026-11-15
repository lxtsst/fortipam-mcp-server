"""Bounded defaults/Schema/Template reads on an existing service Target source.

Borrow its exact authenticated origin, actor, TLS, physical client factory and
remaining lifetime. These metadata observations do not establish Secret-name
absence, Folder custody, material, association, activity or dispatch authority.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
from threading import RLock

import httpx
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from . import target_preservation_contract as c
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .target_lifecycle_dependencies import _one, _spans
from .windows_execution_secret_contract import WindowsExecutionSecretDefaults, consume_windows_execution_defaults
from .windows_privileged_secret_birth import _row_field_set_digest
from .windows_service_credential_contract import WindowsServiceCredentialBinding, _metadata
from .windows_service_credential_target_sources import (
    WindowsServiceCredentialTargetSources, WindowsServiceCredentialTargetObservation, _ACTOR,
)

_CONTRACT = "fortipam-build29-service-credential-creation-input-source-v1"
_ERROR = "The private service credential creation inputs are unavailable."
_DEFAULTS = "/api/v2/cmdb/secret/database?action=default&with_meta=true&vdom=root"
_SCHEMA = "/api/v2/cmdb/secret/database?action=schema&with_meta=true&vdom=root"
_TEMPLATE = "/api/v2/cmdb/secret/template?format=name%7Cfield%7Cpermissions&with_meta=true&vdom=root"
_BUILTIN = "Windows Machine"
_REQUIRED_SCHEMA = frozenset({"id", "name", "folder", "target", "template", "field", "dependency",
    "target-privilege-account", "totp-setting", "instruction-profile", "password-changer", "auto-association"})
_RUNTIME_FIELDS = frozenset({"field", "subscriber", "target-info", "totp-setting", "instruction-profile"})
_KINDS = {"Host": "target-address", "Username": "username", "Password": "password"}
_ROLE_REQUIREMENTS = (("folder-table", "read"), ("secret-table", "read-write"),
    ("target", "read"), ("template", "read"))
_ROLE_RIGHTS = tuple(name for name, _ in _ROLE_REQUIREMENTS)
_PAGING = frozenset({"has_more", "next_index", "offset", "start", "limit", "total", "total_count"})


class WindowsServiceCredentialCreationInputError(ValueError):
    """No private selectors, schema definitions or partial eligibility in errors."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceCredentialCreationInputObservation(_OpaqueC3Object):
    source_context_digest: str
    target_reference_context_digest: str
    inputs_digest: str
    defaults: WindowsExecutionSecretDefaults
    full_row_fields: frozenset[str]
    schema_digest: str
    builtin_template_digest: str
    target_template_digest: str
    observed_at: float
    expires_at: float


def _observation_digest(value: WindowsServiceCredentialCreationInputObservation) -> str:
    fields = asdict(value)
    fields["full_row_fields"] = sorted(value.full_row_fields)
    return c._digest(fields)


class WindowsServiceCredentialCreationInputs(_OpaqueC3Object):
    """One 8/10-read bracket; the caller owns the borrowed Target source."""

    def __init__(self, *, target_sources: WindowsServiceCredentialTargetSources,
            target_observation: WindowsServiceCredentialTargetObservation) -> None:
        try:
            if (type(target_sources) is not WindowsServiceCredentialTargetSources
                    or type(target_observation) is not WindowsServiceCredentialTargetObservation):
                raise ValueError
            target_sources.check_current(target_observation)
            self._target, self._target_observed = target_sources, target_observation
            self._config = target_sources._config
            self._factory, self._tls = target_sources._factory, target_sources._tls
            self._template = target_observation.configuration.coordinates.template
            self._identities = (self._target, self._target_observed, self._config, self._factory, self._tls)
            self._binding = self._context()
            self._used = self._failed = self._closed = False
            self._current: WindowsServiceCredentialCreationInputObservation | None = None
            self._seal: str | None = None
            self._schema_fields: frozenset[str] | None = None
            self._default_fields: frozenset[str] | None = None
            self._lock = RLock()
        except Exception:
            raise WindowsServiceCredentialCreationInputError(_ERROR) from None

    def _context(self) -> str:
        return canonical_digest({"contract": _CONTRACT,
            "source": self._target_observed.source_context_digest,
            "target": self._target_observed.target_reference_context_digest,
            "template": hashlib.sha256(self._template.encode()).hexdigest(),
            "declared_role_requirements": _ROLE_REQUIREMENTS})

    def _guard(self) -> float:
        if (self._closed or self._failed
                or self._context() != self._binding
                or self._template != self._target_observed.configuration.coordinates.template
                or any(a is not b for a, b in zip(self._identities,
                    (self._target, self._target_observed, self._config, self._factory, self._tls)))
                or any(a is not b for a, b in zip(self._identities[2:],
                    (self._target._config, self._target._factory, self._target._tls)))):
            raise ValueError
        self._target.check_current(self._target_observed)
        return self._target._guard()

    def _receive(self, client: httpx.Client, path: str, *, template_name: str | None = None) -> bytearray:
        if path == _ACTOR and template_name is None:
            return self._target._receive(client, _ACTOR)
        raw = bytearray()
        transfer = False
        try:
            if (path not in (_DEFAULTS, _SCHEMA, _TEMPLATE)
                    or (path == _TEMPLATE) != (template_name is not None)
                    or template_name is not None and template_name not in {_BUILTIN, self._template}):
                raise ValueError
            headers = {"Authorization": "Bearer " + self._config.bearer_token,
                "Accept": "application/json", "Accept-Encoding": "identity", "Cache-Control": "no-store"}
            body = None
            if template_name is not None:
                headers.update({"X-HTTP-Method-Override": "GET", "Content-Type": "application/json"})
                body = json.dumps({"json_filter": [{"logic": "or", "filters": [{
                    "key": "name", "type": "string", "operator": "exact", "negate": False,
                    "pattern": template_name}]}]}, ensure_ascii=True, separators=(",", ":")).encode("ascii")
            maximum = 1048576 if path == _SCHEMA else 262144
            now = self._guard()
            client.cookies.clear()
            with client.stream("POST" if template_name is not None else "GET",
                    self._config.base_url.rstrip("/") + path, headers=headers, content=body,
                    timeout=min(float(self._config.timeout_seconds), self._target_observed.expires_at - now)) as response:
                self._guard()
                lengths = response.headers.get_list("content-length")
                if (response.status_code != 200
                        or response.headers.get("content-type", "").split(";")[0].lower() != "application/json"
                        or response.headers.get("content-encoding", "identity") not in ("", "identity")
                        or len(lengths) > 1
                        or lengths and (not lengths[0].isascii() or not lengths[0].isdigit())
                        or lengths and "transfer-encoding" in response.headers):
                    raise ValueError
                expected_length = int(lengths[0]) if lengths else None
                if expected_length is not None and not 0 < expected_length <= maximum:
                    raise ValueError
                iterator = response.iter_raw()
                while True:
                    self._guard()
                    try:
                        chunk = next(iterator)
                    except StopIteration:
                        self._guard()
                        break
                    self._guard()
                    if len(raw) + len(chunk) > maximum:
                        raise ValueError
                    raw.extend(chunk)
                if expected_length is not None and len(raw) != expected_length:
                    raise ValueError
            client.cookies.clear()
            self._guard()
            _spans(raw)
            transfer = True
            return raw
        finally:
            if not transfer:
                _zeroize_mutable(raw)

    def _envelope(self, raw: bytearray, *, action: str = "", template: bool = False) -> dict[str, tuple[int, int]]:
        _spans(raw)
        start = _skip_json_space(raw, 0)
        top = _object_spans(raw, start, _json_value_end(raw, start))
        expected: dict[str, object] = dict(version="v7.0.0", build=29, path="secret",
            name="template" if template else "database", http_method="POST" if template else "GET",
            http_status=200, status="OK" if template else "success", vdom="root")
        if "action" in top:
            expected["action"] = action
        for name, value in expected.items():
            actual = m._scalar(raw, top[name])
            if type(actual) is not type(value) or actual != value:
                raise ValueError
        serial = m._text(m._scalar(raw, top["serial"]), maximum=128)
        if not hmac.compare_digest(hashlib.sha256(serial.encode()).hexdigest(), self._target._serial):
            raise ValueError
        if "schema_errors" in top or _PAGING & top.keys():
            raise ValueError
        if "error" in top:
            error = m._scalar(raw, top["error"])
            if error is not None and (type(error) is not int or error != 0):
                raise ValueError
        if "limit_reached" in top and m._scalar(raw, top["limit_reached"]) is not False:
            raise ValueError
        if "next_idx" in top:
            cursor = m._scalar(raw, top["next_idx"])
            if type(cursor) is not int or cursor not in (0, 1):
                raise ValueError
        if "size" in top:
            size = m._scalar(raw, top["size"])
            if type(size) is not int or size != 1:
                raise ValueError
        return top

    def _defaults(self, raw: bytearray) -> tuple[WindowsExecutionSecretDefaults, frozenset[str]]:
        top = self._envelope(raw, action="default")
        names = frozenset(_object_spans(raw, *_one(raw, top["results"])))
        if not _REQUIRED_SCHEMA <= names:
            raise ValueError
        serial = m._text(m._scalar(raw, top["serial"]), maximum=128)
        return consume_windows_execution_defaults(raw, expected_serial=serial), names

    def _schema(self, raw: bytearray) -> tuple[str, frozenset[str]]:
        top = self._envelope(raw, action="schema")
        root = _object_spans(raw, *_one(raw, top["results"]))
        children = _object_spans(raw, *root["children"])
        names = frozenset(children)
        if not _REQUIRED_SCHEMA <= names:
            raise ValueError
        _row_field_set_digest(names | _RUNTIME_FIELDS)
        return c._token_digest(raw, top["results"]), names

    def _read_template(self, raw: bytearray, *, expected_name: str, builtin: bool) -> str:
        top = self._envelope(raw, template=True)
        rows = m._array(raw, top["results"], 1)
        if len(rows) != 1:
            raise ValueError
        value = m._row(raw, rows[0], "template")
        if (type(value) is not m.ImportMetadataTemplate or value.name != expected_name
                or value.permission not in {"owner", "create-secret"}
                or {field.name: field.kind for field in value.fields} != _KINDS):
            raise ValueError
        if builtin and {field.name: field.mandatory for field in value.fields} != {
                "Host": True, "Username": False, "Password": False}:
            raise ValueError
        return c._token_digest(raw, rows[0])

    def _state_seal(self, observed: WindowsServiceCredentialCreationInputObservation) -> str:
        if self._schema_fields is None or self._default_fields is None:
            raise ValueError
        return canonical_digest((_observation_digest(observed),
            _row_field_set_digest(self._schema_fields), _row_field_set_digest(self._default_fields)))

    def _read_actor(self, raw: bytearray) -> str:
        """Check active declaration bits for the fixed read/create inputs.

        Build29's native role projection gives the group precedence over its
        granular fields. Secret creation needs declared Secret-table RW; the
        existing Folder/Target/Template references need declared read access.
        This is neither object ACL nor backend enforcement qualification.
        """
        actor = self._target._read_actor(raw)
        root = _object_spans(raw, *_spans(raw)["results"])
        admin = _object_spans(raw, *root["admin"])
        role = _object_spans(raw, *admin["profile"])
        group = m._scalar(raw, role["secretgrp"])
        selected = _object_spans(raw, *role["secretgrp-permission"])
        rights = tuple(m._scalar(raw, selected[name]) for name in _ROLE_RIGHTS)
        if (type(group) is not str or group not in {"none", "read", "read-write", "custom"}
                or any(type(value) is not str or value not in {"none", "read", "read-write"} for value in rights)):
            raise ValueError
        for (_, minimum), value in zip(_ROLE_REQUIREMENTS, rights, strict=True):
            effective = value if group == "custom" else group
            if not (effective == "read-write" or minimum == "read" and effective == "read"):
                raise ValueError
        return actor

    def read_once(self) -> WindowsServiceCredentialCreationInputObservation:
        buffers: list[bytearray] = []
        try:
            with self._lock, self._target._lock:
                started = self._guard()
                if self._used:
                    raise ValueError
                self._used = True
                with _private_http_logs(), ExitStack() as stack:
                    client = self._factory(verify=self._tls, follow_redirects=False, trust_env=False)
                    stack.callback(client.close)
                    stack.callback(client.cookies.clear)
                    stack.enter_context(client)
                    def read(path: str, name: str | None = None) -> bytearray:
                        value = self._receive(client, path, template_name=name)
                        buffers.append(value)
                        return value
                    actor = self._read_actor(read(_ACTOR))
                    if actor != self._target_observed.actor_context_digest:
                        raise ValueError
                    defaults, default_names = self._defaults(read(_DEFAULTS))
                    schema_digest, schema_names = self._schema(read(_SCHEMA))
                    builtin = self._read_template(read(_TEMPLATE, _BUILTIN), expected_name=_BUILTIN, builtin=True)
                    target_template = builtin if self._template == _BUILTIN else self._read_template(
                        read(_TEMPLATE, self._template), expected_name=self._template, builtin=False)
                    if self._template != _BUILTIN and self._read_template(read(_TEMPLATE, self._template),
                            expected_name=self._template, builtin=False) != target_template:
                        raise ValueError
                    if self._read_template(read(_TEMPLATE, _BUILTIN), expected_name=_BUILTIN, builtin=True) != builtin:
                        raise ValueError
                    if self._schema(read(_SCHEMA)) != (schema_digest, schema_names):
                        raise ValueError
                    if self._defaults(read(_DEFAULTS)) != (defaults, default_names):
                        raise ValueError
                    if self._read_actor(read(_ACTOR)) != actor:
                        raise ValueError
                self._guard()
                full_fields = schema_names | _RUNTIME_FIELDS
                context = canonical_digest({"binding": self._binding, "guards": defaults.guards_digest,
                    "default_fields": _row_field_set_digest(default_names), "schema": schema_digest,
                    "full_fields": _row_field_set_digest(full_fields), "builtin": builtin, "target_template": target_template})
                observed = WindowsServiceCredentialCreationInputObservation(self._target_observed.source_context_digest,
                    self._target_observed.target_reference_context_digest, context, defaults, full_fields,
                    schema_digest, builtin, target_template, started, self._target_observed.expires_at)
                self._schema_fields, self._default_fields = schema_names, default_names
                self._current, self._seal = observed, self._state_seal(observed)
                return observed
        except BaseException as error:
            self._failed, self._current, self._seal = True, None, None
            if isinstance(error, Exception):
                raise WindowsServiceCredentialCreationInputError(_ERROR) from None
            raise
        finally:
            for value in buffers:
                _zeroize_mutable(value)

    def check_current(self, observed: WindowsServiceCredentialCreationInputObservation) -> None:
        try:
            with self._lock:
                now = self._guard()
                if (type(observed) is not WindowsServiceCredentialCreationInputObservation
                        or observed is not self._current or self._seal != self._state_seal(observed)
                        or not observed.observed_at <= now < observed.expires_at):
                    raise ValueError
        except Exception:
            self._failed, self._current, self._seal = True, None, None
            raise WindowsServiceCredentialCreationInputError(_ERROR) from None

    def check_profile(self, observed: WindowsServiceCredentialCreationInputObservation,
            profile: WindowsServiceCredentialBinding) -> None:
        try:
            self.check_current(observed)
            self._target.check_profile(self._target_observed, profile)
            if (self._schema_fields is None or self._default_fields is None
                    or not _metadata(profile).keys() <= self._schema_fields
                    or not _metadata(profile).keys() <= self._default_fields):
                raise ValueError
        except Exception:
            self._failed, self._current, self._seal = True, None, None
            raise WindowsServiceCredentialCreationInputError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current, self._seal, self._schema_fields, self._default_fields = None, None, None, None
