"""One borrowed EMS source window, fixed GETs and value-free response metadata.

No response contract is inferred from the request export. Unknown values are
byte-validated and skipped, never decoded or hashed. This source cannot prove
complete Rule Set state, child ownership, linkage, effects or cleanup rights.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hmac
import math
import re
import ssl
from threading import RLock,get_ident
import time

from v4_planning.material_provider import _OpaqueC3Object
from . import secret_bulk_import_metadata as metadata
from .email_alert_general_source import _read_alert_response
from .ems_rule_set_contract import INDEX_PATH,MAX_RULE_SETS,rule_set_detail_path
from .ems_tag_http_transport import NativeEmsTagHttpTransport
from .ems_tag_sources import EmsTagSources,EmsTagSourceObservation
from .secret_metadata_http_transport import _json_string_end,_json_value_end,_skip_json_space,_zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

CONTRACT='ems-7.4.8-rule-set-borrowed-metadata-source-local/v1'
_ERROR='The private EMS rule-set metadata source is unavailable.'
_KEY=re.compile(rb'"[A-Za-z_][A-Za-z0-9_-]{0,63}"\Z')
_FIELDS=frozenset({'id','tag','status','comments','rules','use_custom_logic','logic','rule_sets','total'})
MAX_RESPONSE_BYTES=262144


def _members(raw: bytearray, span: tuple[int,int], selected: frozenset[str]) -> tuple[dict[str,tuple[int,int]],int]:
    """Only compiled field names may be decoded; duplicate used-frame keys refuse."""
    start,end=span
    if raw[start]!=123 or raw[end-1]!=125: raise ValueError
    cursor=_skip_json_space(raw,start+1); keys: list[tuple[int,int]]=[]; count=0
    while cursor<end-1:
        right=_json_string_end(raw,cursor)+1
        with memoryview(raw)[cursor:right] as key:
            if _KEY.fullmatch(key) is None: raise ValueError
            for first,last in keys:
                with memoryview(raw)[first:last] as previous:
                    if key==previous: raise ValueError
        keys.append((cursor,right)); count+=1
        if count>512: raise ValueError
        separator=_skip_json_space(raw,right)
        if raw[separator]!=58: raise ValueError
        first=_skip_json_space(raw,separator+1); last=_json_value_end(raw,first)
        cursor=_skip_json_space(raw,last)
        if cursor==end-1: break
        if raw[cursor]!=44: raise ValueError
        cursor=_skip_json_space(raw,cursor+1)
    return metadata._object_spans(raw,start,end,selected),count


def _kind(raw: bytearray, span: tuple[int,int]) -> str:
    first=raw[span[0]]
    if first in (123,91,34,110): return {123:'object',91:'array',34:'string',110:'null'}[first]
    if first in (116,102): return 'boolean'
    with memoryview(raw)[slice(*span)] as token:
        return 'integer' if re.fullmatch(rb'-?(?:0|[1-9][0-9]*)',token) else 'number'


@dataclass(frozen=True,slots=True,repr=False)
class RuleSetResponseMetadata(_OpaqueC3Object):
    data_kind: str
    selected_types: tuple[tuple[str,str],...]
    unclassified_member_occurrences: int
    observed_array_length: int | None

    def summary(self) -> dict[str,object]:
        return dict(data_kind=self.data_kind,selected_types=dict(self.selected_types),
            unclassified_member_occurrences=self.unclassified_member_occurrences,
            observed_array_length=self.observed_array_length,response_contract_verified=False,
            local_catalog_bound_exceeded=self.observed_array_length is not None and self.observed_array_length>MAX_RULE_SETS,
            complete_or_unfiltered_state_verified=False,identity_or_relation_verified=False)


def consume_rule_set_response_metadata(raw: bytearray) -> RuleSetResponseMetadata:
    """Observe one common-envelope candidate; clear even on control interruption."""
    try:
        if type(raw) is not bytearray or not 0<len(raw)<=MAX_RESPONSE_BYTES: raise ValueError
        start=_skip_json_space(raw,0); end=_json_value_end(raw,start)
        if _skip_json_space(raw,end)!=len(raw): raise ValueError
        metadata._validate_json(raw,start,end,depth=0,budget=[20000])
        root,count=_members(raw,(start,end),frozenset({'data','result'}))
        if count!=2 or set(root)!={'data','result'}: raise ValueError
        result,count=_members(raw,root['result'],frozenset({'retval','message'}))
        if count!=2 or set(result)!={'retval','message'}: raise ValueError
        with memoryview(raw)[slice(*result['retval'])] as status:
            if not hmac.compare_digest(status,b'1'): raise ValueError
        if _kind(raw,result['message']) not in ('string','null'): raise ValueError
        kind=_kind(raw,root['data']); fields: dict[str,tuple[int,int]]={}; unknown=0; length=None
        if kind=='object':
            fields,count=_members(raw,root['data'],_FIELDS); unknown=count-len(fields)
            if 'rule_sets' in fields and _kind(raw,fields['rule_sets'])=='array':
                length=len(metadata._array(raw,fields['rule_sets'],MAX_RULE_SETS+1))
        elif kind=='array': length=len(metadata._array(raw,root['data'],MAX_RULE_SETS+1))
        elif kind!='null': raise ValueError
        return RuleSetResponseMetadata(kind,tuple((name,_kind(raw,span)) for name,span in sorted(fields.items())),unknown,length)
    except Exception: raise ValueError(_ERROR) from None
    finally:
        if type(raw) is bytearray: _zeroize_mutable(raw)


class EmsRuleSetMetadataSource(_OpaqueC3Object):
    """One attempt using IDs from one original physical Tag-source observation.

    The producer owns login, logout and the underlying channel. This object
    clears only its own volatile Cookie copy and cannot renew that observation.
    """
    def __init__(self,owner: NativeEmsTagHttpTransport,source: EmsTagSources,current: EmsTagSourceObservation,*,
            source_guard: Callable[[],bool] | None=None,http_clock: Callable[[],float]=time.monotonic) -> None:
        cookie=bytearray()
        try:
            if (type(owner) is not NativeEmsTagHttpTransport or type(source) is not EmsTagSources
                    or type(current) is not EmsTagSourceObservation or not callable(http_clock)
                    or source_guard is not None and not callable(source_guard)): raise ValueError
            with source._lock,owner._lock:
                if (not owner._live or owner._closed or owner._failed or owner._owner is None
                        or source._original_account is not None
                        or getattr(source._get,'__self__',None) is not owner
                        or getattr(source._get,'__func__',None) is not NativeEmsTagHttpTransport.get_json
                        or source._instance!=owner._binding or source._owner!=owner._owner
                        or getattr(owner,'_rule_set_metadata_source',None) is not None): raise ValueError
                source.check_current(current); owner._pins()
                identifiers=tuple(sorted({value for value in current.full_scope._rule_sets().values() if value is not None}))
                if len(identifiers)>MAX_RULE_SETS: raise ValueError
                self._owner=self._owner_pin=owner; self._source=self._source_pin=source; self._current=current
                self._config,self._jar,self._tls=owner._config,owner._jar,owner._tls
                self._instance,self._actor=owner._binding,owner._owner
                self._source_get,self._source_clock=source._get,source._clock
                self._headers=owner._headers
                self._paths=(INDEX_PATH,*(rule_set_detail_path(value) for value in identifiers))
                self._connect=owner._connect; self._guard=self._guard_pin=source_guard
                self._http_clock=self._clock_pin=http_clock; self._last_time=-1.0
                self._closed=self._used=False; self._lock=RLock()
                self._reading_thread: int | None=None; self._fetch_active=False; self._attempted_paths: set[str]=set()
                cookie=self._cookie_header(); self._cookie=cookie
                owner._rule_set_metadata_source=self
        except BaseException as error:
            _zeroize_mutable(cookie)
            if isinstance(error,Exception): raise ValueError(_ERROR) from None
            raise

    def _cookie_header(self) -> bytearray:
        sessions=[cookie for cookie in self._owner._jar if cookie.name=='sessionid']
        if len(sessions)!=1 or not sessions[0].value: raise ValueError
        value=self._headers('GET',INDEX_PATH,None).get_header('Cookie')
        if type(value) is not str or not value.isascii() or not 0<len(value)<=8192 or any(ord(c)<32 or ord(c)==127 for c in value): raise ValueError
        return bytearray(value.encode('ascii'))

    def _available(self) -> None:
        owner=self._owner
        if (self._closed or owner is not self._owner_pin or self._source is not self._source_pin
                or owner._config is not self._config or owner._binding!=self._instance or owner._owner!=self._actor
                or owner._jar is not self._jar or owner._tls is not self._tls or owner._connect!=self._connect
                or owner._headers!=self._headers or self._source._get!=self._source_get
                or self._source._clock is not self._source_clock or self._source._original_account is not None
                or self._source._instance!=self._instance or self._source._owner!=self._actor
                or getattr(owner,'_rule_set_metadata_source',None) is not self
                or not owner._live or owner._closed or owner._failed or self._http_clock is not self._clock_pin
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True
                or self._tls.check_hostname is not True or self._tls.verify_mode!=ssl.CERT_REQUIRED
                or self._tls.minimum_version<ssl.TLSVersion.TLSv1_2): raise ValueError
        owner._pins(); self._source.check_current(self._current)
        ids=tuple(sorted({value for value in self._current.full_scope._rule_sets().values() if value is not None}))
        if self._paths!=(INDEX_PATH,*(rule_set_detail_path(value) for value in ids)): raise ValueError
        cookie=self._cookie_header()
        try:
            if not hmac.compare_digest(cookie,self._cookie): raise ValueError
        finally: _zeroize_mutable(cookie)

    def _now(self) -> float:
        now=self._http_clock()
        if type(now) not in (int,float) or not math.isfinite(now) or now<0 or now<self._last_time:
            self.close(); raise ValueError
        self._last_time=float(now); return float(now)

    def _remaining(self,deadline: float) -> float:
        self._available(); remaining=deadline-self._now()
        if remaining<=0: raise ValueError
        return min(10.0,remaining)

    def _fetch(self,path: str,deadline: float) -> bytearray:
        if self._reading_thread!=get_ident() or not self._used or self._fetch_active: raise ValueError
        self._fetch_active=True
        raw=bytearray(); connection=response=handle=None; transferred=False
        try:
            if path not in self._paths or path in self._attempted_paths: raise ValueError
            self._attempted_paths.add(path)
            try:
                connection=self._connect(timeout_seconds=self._remaining(deadline)); handle=connection.sock
                if handle is None: raise ValueError
                handle.settimeout(self._remaining(deadline))
                headers=dict(self._headers('GET',path,None).header_items())
                connection.request('GET',path,body=None,headers=headers)
                handle.settimeout(self._remaining(deadline)); response=connection.getresponse()
                if connection.sock is not None and connection.sock is not handle: raise ValueError
                raw=_read_alert_response(self,response,handle,deadline,MAX_RESPONSE_BYTES)
            finally:
                try:
                    if response is not None: response.close()
                finally:
                    try:
                        if connection is not None: connection.close()
                    finally:
                        if handle is not None: handle.close()
            self._remaining(deadline); transferred=True; return raw
        finally:
            self._fetch_active=False
            if not transferred: _zeroize_mutable(raw)

    def read_once(self) -> dict[str,object]:
        try:
            with self._lock,self._source._lock,self._owner._lock,_private_http_logs():
                if self._used: raise ValueError
                self._used=True; self._available()
                self._reading_thread=get_ident()
                remaining_epoch=self._current.expires_at-self._source._now()
                deadline=self._now()+min(20.0,remaining_epoch); observations=[]
                for path in self._paths:
                    raw=self._fetch(path,deadline); observations.append(consume_rule_set_response_metadata(raw).summary())
                self._remaining(deadline)
                return dict(contract=CONTRACT,tag_reference_selectors_bound=True,metadata_read_count=len(observations),
                    index=observations[0],details=observations[1:],native_response_contract_verified=False,
                    complete_rule_set_scope_verified=False,original_child_custody_verified=False,
                    current_permission_or_usage_verified=False,cleanup_authorized=False,device_write_dispatched=False,
                    login_or_logout_performed=False)
        except BaseException as error:
            self.close()
            if isinstance(error,Exception): raise ValueError(_ERROR) from None
            raise
        finally:
            self._reading_thread=None; self.close()

    def close(self) -> None:
        with self._lock:
            self._closed=True; _zeroize_mutable(self._cookie)
