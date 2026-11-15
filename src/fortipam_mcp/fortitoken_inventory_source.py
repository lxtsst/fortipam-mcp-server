"""Fixed private build29 inventory aggregates, without token or license claims.

Retained native evidence qualifies the monitor route, keyed rows, type and
status.name. License values and unselected fields remain opaque. Visible
counts never establish global ownership, license validity or MFA readiness.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hmac
import json
import re

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as metadata
from .fortitoken_user_contract import _validate_token
from .fortitoken_user_source import FortitokenUserSource
from .local_user_reset_http_transport import _members
from .secret_metadata_http_transport import _json_string_end, _json_value_end, _skip_json_space, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

CONTRACT = 'fortipam-build29-fortitoken-inventory-aggregate-local/v1'
INVENTORY_PATH = '/api/v2/monitor/user/fortitoken/?vdom=*'
_ERROR = 'The private FortiToken inventory source is unavailable.'
_TOP = {b'"'+name+b'"' for name in (b'build',b'http_method',b'http_status',b'name',b'path',b'status',b'version',
    b'vdom',b'serial',b'results',b'error',b'limit_reached',b'size',b'matched_count',b'filtered_count',b'next_idx',b'revision')}


@dataclass(frozen=True, slots=True, repr=False)
class FortitokenInventoryObservation(_OpaqueC3Object):
    source_digest: str
    view_count: int
    type_counts: tuple[int,int,int]
    status_counts: tuple[int,int,int]
    license_field_count: int
    counts_reported_for_each_view: bool
    no_truncation_reported_for_each_view: bool
    observed_at: int
    expires_at: int

    def public(self) -> dict[str,object]:
        return dict(contract=CONTRACT,view_count=self.view_count,token_count=sum(self.type_counts),
            token_type_counts=dict(zip(('hard','mobile','other'),self.type_counts)),
            native_status_counts=dict(zip(('available','pending','other'),self.status_counts)),
            license_field_count=self.license_field_count,counts_reported_for_each_view=self.counts_reported_for_each_view,
            no_truncation_reported_for_each_view=self.no_truncation_reported_for_each_view,
            observed_at=self.observed_at,expires_at=self.expires_at,inventory_observed_locally=True,
            complete_inventory_qualified=False,license_validity_verified=False,token_ownership_verified=False,
            material_continuity_verified=False,configuration_write_authorized=False,mfa_login_verified=False)


def _rows(raw: bytearray, span: tuple[int,int]) -> list[tuple[int,int]]:
    start,end = span
    if raw[start] != 123 or raw[end-1] != 125: raise ValueError
    cursor = _skip_json_space(raw,start+1); keys: list[tuple[int,int]] = []; rows = []
    while cursor < end-1:
        key_end = _json_string_end(raw,cursor)+1
        with memoryview(raw)[cursor:key_end] as key:
            if not 2 < len(key) <= 258 or 92 in key: raise ValueError
            for previous in keys:
                with memoryview(raw)[slice(*previous)] as other:
                    if hmac.compare_digest(key,other): raise ValueError
        keys.append((cursor,key_end))
        colon = _skip_json_space(raw,key_end)
        if raw[colon] != 58: raise ValueError
        left = _skip_json_space(raw,colon+1); right = _json_value_end(raw,left)
        rows.append((left,right))
        if len(rows)>128: raise ValueError
        cursor = _skip_json_space(raw,right)
        if cursor == end-1: break
        if raw[cursor] != 44: raise ValueError
        cursor = _skip_json_space(raw,cursor+1)
    return rows


def _category(raw: bytearray, span: tuple[int,int], categories: tuple[bytes,bytes]) -> int:
    with memoryview(raw)[slice(*span)] as value:
        if not 2 < len(value) <= 258 or value[0] != 34 or value[-1] != 34: raise ValueError
        for index,candidate in enumerate(categories):
            if hmac.compare_digest(value,candidate): return index
    return 2


def _inspect_inventory(raw: bytearray, *, expected_serial: str, source_digest: str,
        observed_at: int) -> tuple[FortitokenInventoryObservation,tuple[tuple[int,int],...]]:
    """Validate private bytes and spans; the caller retains cleanup ownership."""
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= 1048576 or type(expected_serial) is not str
                or re.fullmatch(r'[A-Za-z0-9_-]{1,128}',expected_serial) is None
                or type(observed_at) is not int or observed_at < 0): raise ValueError
        require_digest(source_digest,'FortiToken inventory source')
        left = _skip_json_space(raw,0); right = _json_value_end(raw,left)
        if _skip_json_space(raw,right) != len(raw): raise ValueError
        metadata._validate_json(raw,left,right,depth=0,budget=[50000])
        envelopes = metadata._array(raw,(left,right),31) if raw[left] == 91 else [(left,right)]
        if not envelopes: raise ValueError
        types = [0,0,0]; statuses = [0,0,0]; licensed = 0; count_disclosed = truncation_disclosed = True
        selectors: list[tuple[int,int]] = []
        for span in envelopes:
            fields = _members(raw,*span,_TOP)
            expected = dict(build=29,http_method='GET',name='fortitoken',path='user',status='success',
                version='v7.0.0',serial=expected_serial)
            for name,value in expected.items():
                with memoryview(raw)[slice(*fields[b'"'+name.encode()+b'"'])] as actual:
                    if not hmac.compare_digest(actual,json.dumps(value,separators=(',',':')).encode()): raise ValueError
            for option,required_value in ((b'"http_status"',200),(b'"error"',0),(b'"next_idx"',0)):
                if option in fields:
                    actual_value = metadata._scalar(raw,fields[option])
                    if type(actual_value) is not int or actual_value != required_value: raise ValueError
            if b'"limit_reached"' in fields:
                if metadata._scalar(raw,fields[b'"limit_reached"']) is not False: raise ValueError
            else: truncation_disclosed = False
            rows = _rows(raw,fields[b'"results"'])
            counts = [fields[name] for name in (b'"size"',b'"matched_count"',b'"filtered_count"') if name in fields]
            if not counts: count_disclosed = False
            for count_span in counts:
                count = metadata._scalar(raw,count_span)
                if type(count) is not int or count != len(rows): raise ValueError
            for row_span in rows:
                row = metadata._object_spans(raw,*row_span,frozenset({'serial_number','type','status','license'}))
                start,end = row['serial_number']
                if raw[start] != 34 or raw[end-1] != 34: raise ValueError
                with memoryview(raw)[start+1:end-1] as selector:
                    _validate_token(selector)
                    for previous in selectors:
                        with memoryview(raw)[slice(*previous)] as other:
                            if hmac.compare_digest(selector,other): raise ValueError
                selectors.append((start+1,end-1))
                if len(selectors)>128: raise ValueError
                types[_category(raw,row['type'],(b'"hard"',b'"mobile"'))] += 1
                status = metadata._object_spans(raw,*row['status'],frozenset({'name'}))
                statuses[_category(raw,status['name'],(b'"available"',b'"pending"'))] += 1
                licensed += 'license' in row
        observation = FortitokenInventoryObservation(source_digest,len(envelopes),(types[0],types[1],types[2]),
            (statuses[0],statuses[1],statuses[2]),licensed,count_disclosed,truncation_disclosed,observed_at,observed_at+10)
        return observation,tuple(selectors)
    except Exception: raise ValueError(_ERROR) from None


def project_fortitoken_inventory(raw: bytearray, *, expected_serial: str, source_digest: str,
        observed_at: int) -> FortitokenInventoryObservation:
    """Consume raw bytes; no inventory key, selector or license value is decoded."""
    try:
        observation,_ = _inspect_inventory(raw,expected_serial=expected_serial,source_digest=source_digest,observed_at=observed_at)
        return observation
    finally:
        if type(raw) is bytearray: _zeroize_mutable(raw)


class FortitokenInventorySource(_OpaqueC3Object):
    def __init__(self, source: FortitokenUserSource, *, source_digest: str,
            source_guard: Callable[[],bool] | None = None) -> None:
        if (type(source) is not FortitokenUserSource or source_guard is not None and not callable(source_guard)):
            raise ValueError(_ERROR)
        require_digest(source_digest,'FortiToken inventory source')
        if source_digest == source._source: raise ValueError(_ERROR)
        self._source,self._digest,self._guard,self._guard_pin = source,source_digest,source_guard,source_guard
        self._closed = False

    def _available(self) -> None:
        self._source._available()
        if self._closed or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True: raise ValueError

    def _fetch(self, deadline: float) -> bytearray:
        """One fixed private GET; internal consumers own the returned buffer."""
        connection = None; raw = bytearray(); transferred = False
        try:
            source = self._source; self._available()
            connection = source._factory(source._host,source._port,context=source._tls,timeout=source._remaining(deadline))
            connection.set_debuglevel(0); connection.connect(); self._available()
            connection.sock.settimeout(source._remaining(deadline))
            connection.request('GET',INVENTORY_PATH,headers={'Authorization':'Bearer '+source._config.bearer_token,
                'Accept':'application/json','Accept-Encoding':'identity','Cache-Control':'no-cache,no-store','Connection':'close'})
            raw = source._receive(connection,deadline,1048576); transferred = True
            return raw
        finally:
            failed = False
            if connection is not None:
                try: connection.close()
                except Exception: failed = True
            if failed or not transferred: _zeroize_mutable(raw)
            if failed: raise ValueError

    def read(self) -> FortitokenInventoryObservation:
        raw = bytearray()
        try:
            with self._source._lock, _private_http_logs():
                source = self._source; self._available(); started = source._epoch(); deadline = source._now()+source._config.timeout_seconds
                raw = self._fetch(deadline)
                observation = project_fortitoken_inventory(raw,expected_serial=source._serial,
                    source_digest=self._digest,observed_at=started)
                self._available(); source._remaining(deadline)
                if not observation.observed_at <= source._epoch() < observation.expires_at: raise ValueError
                return observation
        except Exception: raise ValueError(_ERROR) from None
        finally: _zeroize_mutable(raw)

    def close(self) -> None:
        with self._source._lock: self._closed = True
