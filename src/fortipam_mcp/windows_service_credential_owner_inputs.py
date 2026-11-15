"""Fixed Owner creation inputs, distinct from the borrowed Bearer observer.

Reuse genuine current source objects and their unchanged byte consumers. No
Secret instance, material, write, association/activity or ownership authority
is supplied. The caller owns both borrowed sources and authenticated session.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import asdict, dataclass
import hashlib
import json
from threading import RLock

import httpx
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from . import target_preservation_contract as c
from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .target_lifecycle_dependencies import _spans
from .windows_execution_secret_contract import WindowsExecutionSecretDefaults
from .windows_privileged_secret_birth import _row_field_set_digest
from .windows_service_credential_contract import WindowsServiceCredentialBinding, _metadata
from .windows_service_credential_creation_inputs import (
    WindowsServiceCredentialCreationInputs, WindowsServiceCredentialCreationInputObservation,
    _DEFAULTS, _SCHEMA, _TEMPLATE, _BUILTIN, _RUNTIME_FIELDS,
)
from .windows_service_credential_owner_auth import WindowsServiceCredentialOwnerSession
from .windows_service_credential_target_sources import _ACTOR, _RUNTIME

_CONTRACT = "fortipam-build29-service-credential-owner-creation-input-source-v1"
_ERROR = "The private Windows service credential Owner inputs are unavailable."


class WindowsServiceCredentialOwnerInputError(ValueError):
    """No selectors, schema, cookie or partial eligibility in errors."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceCredentialOwnerInputObservation(_OpaqueC3Object):
    metadata_source_context_digest: str
    owner_binding_digest: str
    actor_context_digest: str
    target_reference_context_digest: str
    inputs_digest: str
    configuration: c.TargetState
    runtime_digest: str
    runtime_field_count: int
    defaults: WindowsExecutionSecretDefaults
    full_row_fields: frozenset[str]
    schema_digest: str
    builtin_template_digest: str
    target_template_digest: str
    observed_at: float
    expires_at: float


def _seal(value: WindowsServiceCredentialOwnerInputObservation) -> str:
    fields = asdict(value)
    fields["full_row_fields"] = sorted(value.full_row_fields)
    return c._digest(fields)


class WindowsServiceCredentialOwnerInputs(_OpaqueC3Object):
    """One 12/14-read Owner bracket against an independently observed Target."""
    def __init__(self, *, metadata_sources: WindowsServiceCredentialCreationInputs,
            metadata_observation: WindowsServiceCredentialCreationInputObservation,
            owner_session: WindowsServiceCredentialOwnerSession) -> None:
        try:
            if (type(metadata_sources) is not WindowsServiceCredentialCreationInputs
                    or type(metadata_observation) is not WindowsServiceCredentialCreationInputObservation
                    or type(owner_session) is not WindowsServiceCredentialOwnerSession):
                raise ValueError
            metadata_sources.check_current(metadata_observation)
            self._metadata, self._observed, self._owner = metadata_sources, metadata_observation, owner_session
            self._target = metadata_sources._target
            self._config, self._factory, self._tls = metadata_sources._config, metadata_sources._factory, metadata_sources._tls
            self._owner_binding = owner_session.binding
            if self._owner_binding.serial_digest != self._target._serial:
                raise ValueError
            self._template = metadata_sources._template
            self._identities = (metadata_sources, metadata_observation, owner_session, self._config, self._factory, self._tls, self._target)
            self._binding = self._context()
            self._used = self._closed = self._failed = False
            self._count = 0
            self._deadline: float | None = None
            self._current: WindowsServiceCredentialOwnerInputObservation | None = None
            self._seal: str | None = None
            self._schema_fields: frozenset[str] | None = None
            self._default_fields: frozenset[str] | None = None
            self._lock = RLock()
            self._guard()
        except Exception:
            raise WindowsServiceCredentialOwnerInputError(_ERROR) from None

    def _context(self) -> str:
        return canonical_digest(dict(contract=_CONTRACT, metadata=self._observed.inputs_digest,
            metadata_source=self._observed.source_context_digest, owner=self._owner.binding.binding_digest,
            selected_target=self._observed.target_reference_context_digest,
            template=hashlib.sha256(self._template.encode()).hexdigest()))

    def _guard(self) -> float:
        if (self._closed or self._failed or self._context() != self._binding
                or self._owner.binding != self._owner_binding or self._template != self._metadata._template
                or any(a is not b for a,b in zip(self._identities,
                    (self._metadata,self._observed,self._owner,self._config,self._factory,self._tls,self._target)))
                or any(a is not b for a,b in zip(self._identities[3:],
                    (self._metadata._config,self._metadata._factory,self._metadata._tls,self._metadata._target)))):
            raise ValueError
        self._metadata.check_current(self._observed)
        self._owner.require_binding(self._owner_binding, config=self._config, purpose="create")
        now = self._target._guard()
        if self._deadline is not None and now >= self._deadline:
            raise ValueError
        return now

    def _receive(self, client: httpx.Client, path: str, *, selected_name: str | None = None) -> bytearray:
        raw = bytearray()
        transferred = False
        try:
            if path not in (_ACTOR,self._target._detail,_RUNTIME,_DEFAULTS,_SCHEMA,_TEMPLATE):
                raise ValueError
            filtered = path in (_RUNTIME,_TEMPLATE)
            expected_names = {self._target._name} if path == _RUNTIME else {_BUILTIN,self._template} if path == _TEMPLATE else {None}
            if selected_name not in expected_names or filtered != (selected_name is not None):
                raise ValueError
            body = json.dumps({"json_filter":[{"logic":"or","filters":[{"key":"name","type":"string",
                "operator":"exact","negate":False,"pattern":selected_name}]}]},ensure_ascii=True,separators=(",",":")).encode("ascii") if filtered else None
            now = self._guard()
            if self._deadline is None or "authorization" in client.headers:
                raise ValueError
            cookie, csrf = self._owner._validated_cookie("POST" if filtered else "GET", path)
            headers = {"Cookie":cookie,"Accept":"application/json","Accept-Encoding":"identity",
                "Cache-Control":"no-store","User-Agent":"fortipam-mcp-service-credential/1"}
            if filtered:
                headers.update({"X-CSRFTOKEN":csrf,"X-HTTP-Method-Override":"GET","Content-Type":"application/json"})
            maximum = 1048576 if path == _SCHEMA else 262144
            self._count += 1
            if self._count > 14:
                raise ValueError
            client.cookies.clear()
            with client.stream("POST" if filtered else "GET",self._config.base_url.rstrip("/")+path,
                    headers=headers,content=body,timeout=min(float(self._config.timeout_seconds),self._deadline-now)) as response:
                self._guard()
                lengths = response.headers.get_list("content-length")
                if (response.status_code != 200 or response.headers.get("content-type","").split(";")[0].lower() != "application/json"
                        or response.headers.get("content-encoding","identity") not in ("","identity")
                        or len(lengths)>1 or lengths and (not lengths[0].isascii() or not lengths[0].isdigit())
                        or lengths and "transfer-encoding" in response.headers):
                    raise ValueError
                length = int(lengths[0]) if lengths else None
                if length is not None and not 0 < length <= maximum:
                    raise ValueError
                iterator=response.iter_raw()
                while True:
                    self._guard()
                    try:chunk=next(iterator)
                    except StopIteration:
                        self._guard();break
                    self._guard()
                    if len(raw)+len(chunk)>maximum:raise ValueError
                    raw.extend(chunk)
                if length is not None and len(raw)!=length:raise ValueError
            client.cookies.clear()
            self._guard();_spans(raw)
            transferred=True
            return raw
        finally:
            if not transferred:_zeroize_mutable(raw)

    def _actor(self, raw: bytearray) -> str:
        top=self._target._envelope(raw,actor=True)
        root=_object_spans(raw,*top["results"]);admin=_object_spans(raw,*root["admin"])
        profile=_object_spans(raw,*admin["profile"]);maintenance=_object_spans(raw,*root["maintenance_mode"])
        identity=_actor_context(raw,expected_name=self._owner._owner)
        if (m._scalar(raw,profile["name"])!="super_admin" or m._scalar(raw,admin["super_admin"]) is not True
                or m._scalar(raw,admin["global_admin"]) is not True or m._scalar(raw,root["vdom_mode"])!=""
                or m._scalar(raw,maintenance["mode"])!="disable"):
            raise ValueError
        return canonical_digest(dict(identity=identity,profile=c._token_digest(raw,admin["profile"])))

    def read_once(self) -> WindowsServiceCredentialOwnerInputObservation:
        buffers:list[bytearray]=[]
        try:
            with self._lock,self._metadata._lock,self._target._lock:
                started=self._guard()
                if self._used:raise ValueError
                self._used=True
                self._deadline=min(started+30.0,self._observed.expires_at)
                with _private_http_logs(),ExitStack() as stack:
                    client=self._factory(verify=self._tls,follow_redirects=False,trust_env=False)
                    stack.callback(client.close);stack.callback(client.cookies.clear);stack.enter_context(client)
                    def read(path:str,name:str|None=None)->bytearray:
                        raw=self._receive(client,path,selected_name=name);buffers.append(raw);return raw
                    actor=self._actor(read(_ACTOR))
                    state=self._target._read_configuration(read(self._target._detail))
                    if state!=self._metadata._target_observed.configuration:raise ValueError
                    runtime,count=self._target._read_runtime(read(_RUNTIME,self._target._name),state)
                    defaults,default_names=self._metadata._defaults(read(_DEFAULTS))
                    schema,schema_names=self._metadata._schema(read(_SCHEMA))
                    if self._metadata._schema_fields is None or not self._metadata._schema_fields<=schema_names:raise ValueError
                    builtin=self._metadata._read_template(read(_TEMPLATE,_BUILTIN),expected_name=_BUILTIN,builtin=True)
                    template=builtin if self._template==_BUILTIN else self._metadata._read_template(
                        read(_TEMPLATE,self._template),expected_name=self._template,builtin=False)
                    if self._template!=_BUILTIN and self._metadata._read_template(read(_TEMPLATE,self._template),expected_name=self._template,builtin=False)!=template:raise ValueError
                    if self._metadata._read_template(read(_TEMPLATE,_BUILTIN),expected_name=_BUILTIN,builtin=True)!=builtin:raise ValueError
                    if self._metadata._schema(read(_SCHEMA))!=(schema,schema_names):raise ValueError
                    if self._metadata._defaults(read(_DEFAULTS))!=(defaults,default_names):raise ValueError
                    if self._target._read_runtime(read(_RUNTIME,self._target._name),state)!=(runtime,count):raise ValueError
                    if self._target._read_configuration(read(self._target._detail))!=state:raise ValueError
                    if self._actor(read(_ACTOR))!=actor:raise ValueError
                self._guard()
                fields=schema_names|_RUNTIME_FIELDS
                reference=canonical_digest(dict(contract=_CONTRACT,binding=self._binding,actor=actor,state=state.state_digest,runtime=runtime))
                context=canonical_digest(dict(binding=self._binding,target=reference,guards=defaults.guards_digest,
                    defaults=_row_field_set_digest(default_names),schema=schema,fields=_row_field_set_digest(fields),builtin=builtin,template=template))
                value=WindowsServiceCredentialOwnerInputObservation(self._observed.source_context_digest,
                    self._owner_binding.binding_digest,actor,reference,context,state,runtime,count,defaults,fields,
                    schema,builtin,template,started,self._deadline)
                self._schema_fields,self._default_fields=schema_names,default_names
                self._current,self._seal=value,self._state_seal(value)
                return value
        except BaseException as error:
            self._failed,self._current,self._seal=True,None,None
            if isinstance(error,Exception):raise WindowsServiceCredentialOwnerInputError(_ERROR) from None
            raise
        finally:
            for raw in buffers:_zeroize_mutable(raw)

    def _state_seal(self, observed: WindowsServiceCredentialOwnerInputObservation) -> str:
        if self._schema_fields is None or self._default_fields is None:raise ValueError
        return canonical_digest((_seal(observed),_row_field_set_digest(self._schema_fields),_row_field_set_digest(self._default_fields)))

    def check_current(self, observed: WindowsServiceCredentialOwnerInputObservation) -> None:
        try:
            with self._lock:
                now=self._guard()
                if (type(observed) is not WindowsServiceCredentialOwnerInputObservation or observed is not self._current
                        or self._state_seal(observed)!=self._seal or not observed.observed_at<=now<observed.expires_at):raise ValueError
        except Exception:
            self._failed,self._current,self._seal=True,None,None
            raise WindowsServiceCredentialOwnerInputError(_ERROR) from None

    def check_profile(self, observed: WindowsServiceCredentialOwnerInputObservation, profile: WindowsServiceCredentialBinding) -> None:
        try:
            self.check_current(observed)
            if type(profile) is not WindowsServiceCredentialBinding:raise ValueError
            profile.__post_init__()
            if (profile.serial_digest!=self._target._serial or profile.target_name!=self._target._name
                    or profile.target_address!=self._target._address
                    or profile.folder_context_digest!=self._owner_binding.folder_context_digest
                    or profile.target_reference_context_digest!=observed.target_reference_context_digest
                    or self._schema_fields is None or self._default_fields is None
                    or not _metadata(profile).keys()<=self._schema_fields or not _metadata(profile).keys()<=self._default_fields):raise ValueError
        except Exception:
            self._failed,self._current,self._seal=True,None,None
            raise WindowsServiceCredentialOwnerInputError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed=True
            self._current,self._seal,self._schema_fields,self._default_fields=None,None,None,None
