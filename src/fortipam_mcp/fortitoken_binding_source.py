"""Private visible-User/inventory join; no actor, custody or global authority.

The retained Owner-session projection supplies a fixed read shape, not authority
for the current API actor. Response usernames and selectors stay in byte views;
only counts survive. Separate GETs cannot establish an atomic or global view.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hmac
import json

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as metadata
from .fortitoken_inventory_source import FortitokenInventoryObservation, FortitokenInventorySource, _inspect_inventory
from .fortitoken_user_contract import _validate_token
from .fortitoken_user_source import FortitokenUserObservation
from .local_user_reset_http_transport import _members
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

CONTRACT = 'fortipam-build29-fortitoken-visible-binding-aggregate-local/v1'
USER_BINDINGS_PATH = '/api/v2/cmdb/system/admin?format=name%7Ctwo-factor%7Cfortitoken'
_ERROR = 'The private FortiToken binding source is unavailable.'
_TOP = {b'"'+name+b'"' for name in (b'build',b'http_method',b'http_status',b'name',b'path',b'status',b'version',
    b'vdom',b'serial',b'results',b'error',b'limit_reached',b'size',b'matched_count',b'filtered_count',b'next_idx',b'revision')}
_ROW = {b'"name"',b'"two-factor"',b'"fortitoken"',b'"q_origin_key"'}


@dataclass(frozen=True, slots=True, repr=False)
class FortitokenBindingObservation(_OpaqueC3Object):
    source_digest: str
    inventory: FortitokenInventoryObservation
    visible_user_count: int
    fortitoken_mfa_user_count: int
    nonempty_selector_count: int
    bindings_to_observed_inventory_count: int
    unmatched_selector_count: int
    inventory_tokens_with_multiple_visible_bindings_count: int
    fortitoken_mfa_without_selector_count: int
    selector_with_other_mfa_count: int
    no_truncation_reported: bool
    observed_at: int
    expires_at: int

    def public(self) -> dict[str,object]:
        return dict(contract=CONTRACT,visible_user_count=self.visible_user_count,
            fortitoken_mfa_user_count=self.fortitoken_mfa_user_count,nonempty_selector_count=self.nonempty_selector_count,
            bindings_to_observed_inventory_count=self.bindings_to_observed_inventory_count,
            unmatched_selector_count=self.unmatched_selector_count,
            inventory_tokens_with_multiple_visible_bindings_count=self.inventory_tokens_with_multiple_visible_bindings_count,
            fortitoken_mfa_without_selector_count=self.fortitoken_mfa_without_selector_count,
            selector_with_other_mfa_count=self.selector_with_other_mfa_count,
            reported_user_counts_match_rows=True,no_truncation_reported=self.no_truncation_reported,
            selected_user_mfa_projection_matches_detail=True,bindings_observed_locally=True,
            product_actor_verified=False,global_unassigned_ownership_verified=False,atomic_snapshot_qualified=False,
            exact_selected_selector_continuity_verified=False,configuration_write_authorized=False,mfa_login_verified=False,
            observed_at=self.observed_at,expires_at=self.expires_at)


def project_fortitoken_bindings(users: bytearray, tokens: bytearray, *, expected_serial: str,
        source_digest: str, inventory_source_digest: str, current: FortitokenUserObservation,
        observed_at: int) -> FortitokenBindingObservation:
    """Consume both responses; join private selectors without decoded copies."""
    try:
        require_digest(source_digest,'FortiToken binding source')
        if (type(users) is not bytearray or not 0 < len(users) <= 524288
                or type(current) is not FortitokenUserObservation or type(observed_at) is not int
                or not current.observed_at <= observed_at < current.expires_at): raise ValueError
        inventory,selectors = _inspect_inventory(tokens,expected_serial=expected_serial,
            source_digest=inventory_source_digest,observed_at=observed_at)
        left = _skip_json_space(users,0); right = _json_value_end(users,left)
        if _skip_json_space(users,right) != len(users): raise ValueError
        metadata._validate_json(users,left,right,depth=0,budget=[30000]); fields = _members(users,left,right,_TOP)
        for field_name,value in dict(build=29,http_method='GET',http_status=200,name='admin',path='system',
                status='success',version='v7.0.0',serial=expected_serial).items():
            with memoryview(users)[slice(*fields[b'"'+field_name.encode()+b'"'])] as actual:
                if not hmac.compare_digest(actual,json.dumps(value,separators=(',',':')).encode()): raise ValueError
        for option,required in ((b'"vdom"','root'),(b'"error"',0),(b'"next_idx"',0),(b'"limit_reached"',False)):
            if option in fields:
                value = metadata._scalar(users,fields[option])
                if type(value) is not type(required) or value != required: raise ValueError
        rows = metadata._array(users,fields[b'"results"'],255)
        for count_name in (b'"size"',b'"matched_count"',b'"filtered_count"'):
            if count_name in fields or count_name != b'"filtered_count"':
                count = metadata._scalar(users,fields[count_name])
                if type(count) is not int or count != len(rows): raise ValueError
        expected_name = json.dumps(current.state.binding.username).encode()
        expected_mfa = json.dumps(json.loads(current.state._encoded)['two-factor']).encode()
        names: list[tuple[int,int]] = []; joins = [0]*len(selectors)
        mfa_users = nonempty = joined = unmatched = empty_mfa = other_mfa = selected = 0
        for row_span in rows:
            row = _members(users,*row_span,_ROW)
            for key in (b'"name"',b'"two-factor"'):
                with memoryview(users)[slice(*row[key])] as text:
                    if not 2 < len(text) <= 514 or text[0] != 34 or text[-1] != 34 or 92 in text: raise ValueError
            name_span = row[b'"name"']
            with memoryview(users)[slice(*name_span)] as name:
                for previous in names:
                    with memoryview(users)[slice(*previous)] as other:
                        if hmac.compare_digest(name,other): raise ValueError
                if b'"q_origin_key"' in row:
                    with memoryview(users)[slice(*row[b'"q_origin_key"'])] as origin:
                        if not hmac.compare_digest(name,origin): raise ValueError
                is_selected = hmac.compare_digest(name,expected_name)
            names.append(name_span)
            with memoryview(users)[slice(*row[b'"two-factor"'])] as mfa:
                fortitoken_mfa = hmac.compare_digest(mfa,b'"fortitoken"')
                if is_selected and not hmac.compare_digest(mfa,expected_mfa): raise ValueError
            start,end = row[b'"fortitoken"']
            if users[start] != 34 or users[end-1] != 34: raise ValueError
            present = end-start > 2; mfa_users += fortitoken_mfa; nonempty += present
            empty_mfa += fortitoken_mfa and not present; other_mfa += present and not fortitoken_mfa
            if is_selected:
                selected += 1
                if present is not current.state.token_present: raise ValueError
            if present:
                matched = False
                with memoryview(users)[start+1:end-1] as selector:
                    _validate_token(selector)
                    for index,token_span in enumerate(selectors):
                        with memoryview(tokens)[slice(*token_span)] as token:
                            if hmac.compare_digest(selector,token): joins[index] += 1; matched = True
                joined += matched; unmatched += not matched
        if selected != 1: raise ValueError
        return FortitokenBindingObservation(source_digest,inventory,len(rows),mfa_users,nonempty,joined,unmatched,
            sum(count>1 for count in joins),empty_mfa,other_mfa,b'"limit_reached"' in fields,
            observed_at,min(current.expires_at,inventory.expires_at))
    except Exception: raise ValueError(_ERROR) from None
    finally:
        for raw in (users,tokens):
            if type(raw) is bytearray: _zeroize_mutable(raw)


class FortitokenBindingSource(_OpaqueC3Object):
    def __init__(self, inventory: FortitokenInventorySource, *, source_digest: str,
            source_guard: Callable[[],bool] | None = None) -> None:
        if (type(inventory) is not FortitokenInventorySource or source_guard is not None and not callable(source_guard)):
            raise ValueError(_ERROR)
        require_digest(source_digest,'FortiToken binding source')
        if source_digest in (inventory._digest,inventory._source._source): raise ValueError(_ERROR)
        self._inventory,self._source,self._digest = inventory,inventory._source,source_digest
        self._guard = self._guard_pin = source_guard; self._closed = False

    def _available(self) -> None:
        self._inventory._available()
        if self._closed or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True: raise ValueError

    def _fetch_users(self, deadline: float) -> bytearray:
        connection = None; raw = bytearray(); transferred = False
        try:
            source = self._source; self._available()
            connection = source._factory(source._host,source._port,context=source._tls,timeout=source._remaining(deadline))
            connection.set_debuglevel(0); connection.connect(); self._available()
            connection.sock.settimeout(source._remaining(deadline))
            connection.request('GET',USER_BINDINGS_PATH,headers={'Authorization':'Bearer '+source._config.bearer_token,
                'Accept':'application/json','Accept-Encoding':'identity','Cache-Control':'no-cache,no-store','Connection':'close'})
            raw = source._receive(connection,deadline,524288); transferred = True
            return raw
        finally:
            failed = False
            if connection is not None:
                try: connection.close()
                except Exception: failed = True
            if failed or not transferred: _zeroize_mutable(raw)
            if failed: raise ValueError

    def read(self) -> FortitokenBindingObservation:
        users = bytearray(); tokens = bytearray()
        try:
            with self._source._lock, _private_http_logs():
                source = self._source; self._available(); started = source._epoch(); current = source._latest
                if current is None or not current.observed_at <= started < current.expires_at: raise ValueError
                deadline = source._now()+source._config.timeout_seconds
                with source._bounded_by(deadline):
                    users = self._fetch_users(deadline); tokens = self._inventory._fetch(deadline)
                    observed = project_fortitoken_bindings(users,tokens,expected_serial=source._serial,source_digest=self._digest,
                        inventory_source_digest=self._inventory._digest,current=current,observed_at=started)
                    self._available(); source._remaining(deadline)
                    if source._latest is not current or not observed.observed_at <= source._epoch() < observed.expires_at: raise ValueError
                    return observed
        except Exception: raise ValueError(_ERROR) from None
        finally:
            _zeroize_mutable(users); _zeroize_mutable(tokens)

    def close(self) -> None:
        with self._source._lock: self._closed = True
