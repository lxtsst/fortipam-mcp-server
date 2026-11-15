"""Complete private build29 outbound SMTP schema/current observation.

Two fixed reads classify every native field and validate option values against
this device's schema. Neither credential token is decoded or retained. This
source grants no write, SMTP contact, credential-safe rollback or tool binding.
"""
from __future__ import annotations

from collections.abc import Callable,Mapping
from dataclasses import dataclass
import http.client
import hashlib
import json
import ipaddress
import ssl
from typing import Any,cast
from urllib.parse import urlsplit

from v4_planning.material_provider import _OpaqueC3Object

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from . import secret_bulk_import_metadata as m
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,_ssl_context,_zeroize_mutable,_json_value_end,_skip_json_space,
)
from .target_api_dependency_reader import _private_http_logs
from .system_email_configuration_contract import (
    SystemEmailEmptyAuthDraft, prepare_empty_auth_system_email,
)

CONTRACT="fortipam-build29-outbound-smtp-readonly-source/v2"
SOURCE_PAYLOAD_CONTRACT="fortipam-build29-email-server-source-bound-empty-auth/v1"
_PATH="/api/v2/cmdb/system/email-server"
_SCHEMA=_PATH+"?action=schema"
_TYPES={"type":"option","server":"string","port":"integer","security":"option","authenticate":"option",
    "username":"string","password":"password","source-ip":"ipv4-address","source-ip6":"ipv6-address",
    "interface-select-method":"option","interface":"string","sender":"string","reply-to":"string",
    "validate-server":"option","ssl-min-proto-version":"option"}
_FIELDS=set(_TYPES)
_TOP={"http_method","results","vdom","revision","serial","version","build","http_status","status","path","name","mkey","action"}
_ERROR="The private outbound SMTP source is unavailable."


def _validate_nonmaterial_values(values: Mapping[str,Any],specs: dict[str,dict[str,Any]]) -> dict[str,Any]:
    if set(values)!=_FIELDS-{"username","password"}:raise ValueError
    selected=dict(values)
    for name,value in selected.items():
        spec=specs[name];kind=spec["type"]
        if kind=="integer":
            if type(value) is not int or not spec.get("min-value",1)<=value<=spec.get("max-value",65535):raise ValueError
        else:
            if type(value) is not str or len(value.encode("utf-8"))>spec.get("size",4096):raise ValueError
            if kind=="option" and value not in spec["options"]:raise ValueError
            if kind in ("ipv4-address","ipv6-address") and value:
                if ipaddress.ip_address(value).version!=(4 if kind=="ipv4-address" else 6):raise ValueError
    return selected


@dataclass(frozen=True,slots=True,repr=False)
class SystemEmailNativeObservation(_OpaqueC3Object):
    service_type: str
    security_mode: str
    authentication: str
    server_present: bool
    username_empty: bool
    password_empty: bool
    nonmaterial_digest: str
    schema_field_count: int=15


@dataclass(frozen=True,slots=True,repr=False)
class SystemEmailSourceBoundDraft(_OpaqueC3Object):
    """One complete read joined to its SDK payload; never dispatch authority."""
    observation: SystemEmailNativeObservation
    draft: SystemEmailEmptyAuthDraft
    source_serial_digest: str
    source_schema_digest: str
    _schema: bytes

    def prepare_proposal(self,values: Mapping[str,Any]) -> SystemEmailEmptyAuthDraft:
        """Validate new input against the immutable constraints of this source."""
        try:
            selected=_validate_nonmaterial_values(values,json.loads(self._schema))
            return prepare_empty_auth_system_email(selected,
                username_empty=self.observation.username_empty,
                password_empty=self.observation.password_empty)
        except Exception:raise ValueError(_ERROR) from None

    def summary(self) -> dict[str,object]:
        return dict(contract=SOURCE_PAYLOAD_CONTRACT,source_field_count=15,
            request_field_count=12,unforwarded_preservation_field_count=3,
            empty_disabled_authentication=True,configuration_write_authorized=False,
            backend_type_conversion_qualified=False,credential_safe_rollback_qualified=False,
            smtp_contacted=False,protected_values_returned=False)


class SystemEmailNativeSource(_OpaqueC3Object):
    def __init__(self,config: SecretMetadataHttpTransportConfig,*,expected_serial: str,
            connection_factory: Callable[...,Any]=http.client.HTTPSConnection) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(expected_serial) is not str
                    or not 1<=len(expected_serial)<=128 or not callable(connection_factory)):raise ValueError
            url=urlsplit(config.base_url)
            if (url.scheme!="https" or not url.hostname or url.username or url.password or url.query or url.fragment
                    or url.path not in ("","/")):raise ValueError
            self._config,self._serial=config,expected_serial;self._host,self._port=url.hostname,url.port or 443
            self._context=_ssl_context(config)
            if not self._context.check_hostname or self._context.verify_mode!=ssl.CERT_REQUIRED:raise ValueError
            self._factory=connection_factory;self._closed=False;self._last_failure_stage: str|None=None
        except Exception:raise ValueError(_ERROR) from None

    def _fetch(self,path: str) -> bytearray:
        raw = bytearray()
        try:
            connection=response=None;raw=bytearray();transferred=False
            try:
                if path not in (_PATH,_SCHEMA) or self._closed:raise ValueError
                if not self._context.check_hostname or self._context.verify_mode!=ssl.CERT_REQUIRED:raise ValueError
                self._last_failure_stage="connection"
                connection=self._factory(self._host,self._port,context=self._context,timeout=self._config.timeout_seconds)
                self._last_failure_stage="request"
                connection.request("GET",path,headers={"Authorization":"Bearer "+self._config.bearer_token,
                    "Accept":"application/json","Accept-Encoding":"identity","Cache-Control":"no-cache,no-store",
                    "Connection":"close","User-Agent":"fortipam-mcp-system-email-source/2"})
                self._last_failure_stage="response_headers";response=connection.getresponse()
                if (type(response.status) is not int or response.status!=200
                        or response.getheader("content-type","").split(";",1)[0].strip().lower()!="application/json"
                        or response.getheader("content-encoding","identity").lower()!="identity"):raise ValueError
                self._last_failure_stage="response_payload";raw=bytearray(131073);offset=0
                while offset<len(raw):
                    view=memoryview(raw)[offset:]
                    try:count=response.readinto(view)
                    finally:view.release()
                    if type(count) is not int or not 0<=count<=len(raw)-offset:raise ValueError
                    if not count:break
                    offset+=count
                if not 0<offset<=131072:raise ValueError
                raw = _take_mutable_prefix(raw, offset);transferred=True;return raw
            finally:
                failed=False
                for resource in (response,connection):
                    if resource is not None:
                        try:resource.close()
                        except Exception:failed=True
                if failed or not transferred:_zeroize_mutable(raw)
                if failed:self._last_failure_stage="resource_cleanup";raise ValueError
        except BaseException:
            _erase_transfer_storage(raw)
            raise

    def _envelope(self,raw: bytearray,*,schema: bool) -> tuple[int,int]:
        left=_skip_json_space(raw,0);right=_json_value_end(raw,left)
        if _skip_json_space(raw,right)!=len(raw):raise ValueError
        m._validate_json(raw,left,right,depth=0,budget=[20000]);root=_object_spans(raw,left,right)
        if not set(root)<=_TOP:raise ValueError
        for field,value in dict(http_method="GET",version="v7.0.0",build=29,http_status=200,
                path="system",name="email-server",serial=self._serial).items():
            actual=m._scalar(raw,root[field])
            if type(actual) is not type(value) or actual!=value:raise ValueError
        if m._scalar(raw,root["status"]) not in ("success","OK"):raise ValueError
        if "action" in root and m._scalar(raw,root["action"])!=("schema" if schema else ""):raise ValueError
        return root["results"]

    def _schema(self,raw: bytearray) -> dict[str,dict[str,Any]]:
        result=_object_spans(raw,*self._envelope(raw,schema=True))
        fields=_object_spans(raw,*result["children"])
        if set(fields)!=_FIELDS:raise ValueError
        specs={}
        for name,expected in _TYPES.items():
            descriptor=_object_spans(raw,*fields[name])
            if m._scalar(raw,descriptor["type"])!=expected:raise ValueError
            spec: dict[str,Any]={"type":expected}
            if expected=="option":
                choices=[m._scalar(raw,_object_spans(raw,*item)["name"]) for item in m._array(raw,descriptor["options"],16)]
                if (not choices or any(type(v) is not str or not 1<=len(v)<=64 for v in choices)
                        or len(set(choices))!=len(choices)):raise ValueError
                spec["options"]=sorted(choices)
            if name not in ("username","password"):
                for key in ("size","min-value","max-value"):
                    if key in descriptor:
                        value=m._scalar(raw,descriptor[key])
                        if type(value) is not int:raise ValueError
                        spec[key]=value
            specs[name]=spec
        return specs

    def read(self) -> SystemEmailNativeObservation:
        observation,_=self._read(prepare_payload=False)
        return observation

    def read_empty_auth_payload(self) -> SystemEmailSourceBoundDraft:
        """Derive a private payload from this exact read, with no caller DTO.

        All HTTP resources close and raw buffers clear before the joined result
        is published. Shared-relay isolation, permissions, backend ACK semantics
        and restoration remain separate, unqualified execution requirements.
        """
        _,draft=self._read(prepare_payload=True)
        assert draft is not None
        return draft

    def _read(self,*,prepare_payload: bool) -> tuple[SystemEmailNativeObservation,SystemEmailSourceBoundDraft|None]:
        schema=current=bytearray();stage="source_binding"
        try:
            with _private_http_logs():
                schema=self._fetch(_SCHEMA);self._last_failure_stage=None;stage="complete_schema";specs=self._schema(schema)
                current=self._fetch(_PATH);self._last_failure_stage=None;stage="current_envelope";span=self._envelope(current,schema=False)
                fields=_object_spans(current,*span);stage="complete_current_fields"
                if set(fields)!=_FIELDS:raise ValueError
                stage="credential_types";empty={}
                for name in ("username","password"):
                    left,right=fields[name]
                    if current[left]!=34 or current[right-1]!=34:raise ValueError
                    empty[name]=right-left==2
                stage="schema_value_validation"
                values=_validate_nonmaterial_values({name:m._scalar(current,fields[name])
                    for name in sorted(_FIELDS-{"username","password"})},specs)
                stage="nonmaterial_fingerprint"
                # Private device DTOs legitimately contain empty strings; the
                # C0-C2 planner normalizer intentionally rejects those values.
                digest=hashlib.sha256(json.dumps(dict(contract=CONTRACT,configuration=values,schema=specs),
                    sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()).hexdigest()
                observation=SystemEmailNativeObservation(cast(str,values["type"]),cast(str,values["security"]),cast(str,values["authenticate"]),bool(values["server"]),
                    empty["username"],empty["password"],digest)
                draft=None
                if prepare_payload:
                    stage="empty_auth_payload"
                    payload=prepare_empty_auth_system_email(values,
                        username_empty=empty["username"],password_empty=empty["password"])
                    schema_bytes=json.dumps(specs,sort_keys=True,separators=(",",":"),
                        ensure_ascii=True,allow_nan=False).encode()
                    schema_digest=hashlib.sha256(SOURCE_PAYLOAD_CONTRACT.encode()+b'\x00'+schema_bytes).hexdigest()
                    draft=SystemEmailSourceBoundDraft(observation,payload,
                        hashlib.sha256(self._serial.encode()).hexdigest(),schema_digest,schema_bytes)
                self._last_failure_stage=None
                return observation,draft
        except Exception:
            if self._last_failure_stage not in {"connection","request","response_headers","response_payload","resource_cleanup"}:
                self._last_failure_stage=stage
            raise ValueError(_ERROR) from None
        finally:_zeroize_mutable(schema);_zeroize_mutable(current)

    def close(self) -> None:self._closed=True
