"""Sixteen fixed GETs for an existing alert graph; private forward drafts only.

Sequential observations do not prove an atomic snapshot, native graph authority,
certificate merge semantics, per-object ACKs, recovery custody or mail delivery.
"""
from __future__ import annotations

from collections.abc import Callable,Iterator,Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from .email_alert_compound_contract import (Kind,Slot,Step,SLOTS,STEPS,_TABLES,_identity,
    EmailAlertFrame,EmailAlertCompoundState,EmailAlertCompoundPlan,
    email_alert_frame_schema_digest,project_email_alert_frame)
from .email_alert_general_source import (EmailAlertGeneralObservation,EmailAlertGeneralSource,
    _fetch_fixed_alert,_project_alert_schema)
from .secret_metadata_http_transport import _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

CONTRACT = 'fortipam-build29-email-alert-compound-source-local/v1'
KINDS: tuple[Kind,...] = ('action','stitch','trigger','settings')
SCHEMA_PATHS = {kind:'/api/v2/cmdb/'+path+'/'+table+'?action=schema&vdom=root'
    for kind,(path,table) in _TABLES.items()}


def _detail(kind: Kind, slot: Slot | None) -> str:
    path,table,name = _identity(kind,slot)
    return '/api/v2/cmdb/'+path+'/'+table+('/'+quote(name,safe='') if name else '')+'?with_meta=true&vdom=root'


DETAILS = tuple((kind,slot,_detail(kind,slot)) for kind in KINDS
    for slot in ((None,) if kind == 'settings' else SLOTS))
_PATHS = (*SCHEMA_PATHS.values(),*(path for _,_,path in DETAILS))
_ERROR = 'The private compound email-alert source is unavailable.'


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertCompoundObservation(_OpaqueC3Object):
    source_digest: str
    general: EmailAlertGeneralObservation
    state: EmailAlertCompoundState
    observed_at: int
    expires_at: int


class EmailAlertCompoundSource(_OpaqueC3Object):
    def __init__(self, general: EmailAlertGeneralSource, *, expected_schema_digests: Mapping[Kind,str],
            source_digest: str, source_guard: Callable[[],bool] | None = None) -> None:
        try:
            if (type(general) is not EmailAlertGeneralSource or set(expected_schema_digests) != set(KINDS)
                    or source_guard is not None and not callable(source_guard)): raise ValueError
            for value in (*expected_schema_digests.values(),source_digest): require_digest(value,'compound alert source')
            if source_digest == general._source: raise ValueError
            self._general = self._general_pin = general
            self._schema_pins = dict(expected_schema_digests); self._source = source_digest
            self._guard = self._guard_pin = source_guard
            self._pins = (tuple(self._schema_pins[kind] for kind in KINDS),source_digest)
            self._closed = False
            self._latest: EmailAlertCompoundObservation | None = None
            self._plan: EmailAlertCompoundPlan | None = None
            self._origin: EmailAlertCompoundObservation | None = None
            self._m4_session: object | None = None
            self._deadline_cap: float | None = None
        except Exception: raise ValueError(_ERROR) from None

    def _available(self) -> None:
        self._general._available()
        if (self._closed or self._general is not self._general_pin or self._guard is None
                or self._guard is not self._guard_pin or self._guard() is not True
                or (tuple(self._schema_pins[kind] for kind in KINDS),self._source) != self._pins): raise ValueError

    def _fetch(self, path: str, deadline: float) -> bytearray:
        self._available()
        raw = _fetch_fixed_alert(self._general,path,deadline,_PATHS,additional_guard=self._available)
        try:
            self._available(); return raw
        except Exception:
            _zeroize_mutable(raw); raise

    def read(self) -> EmailAlertCompoundObservation:
        return self._read(None)

    @contextmanager
    def _bounded_by(self, deadline: float) -> Iterator[None]:
        with self._general._lock:
            previous = self._deadline_cap
            self._deadline_cap = deadline if previous is None else min(previous,deadline)
            try: yield
            finally: self._deadline_cap = previous

    def _read(self, budget_deadline: float | None) -> EmailAlertCompoundObservation:
        buffers: list[bytearray] = []
        try:
            with self._general._lock, _private_http_logs():
                source = self._general; self._available(); started = source._epoch()
                deadline = source._now()+source._config.timeout_seconds
                if budget_deadline is not None: deadline = min(deadline,budget_deadline)
                if self._deadline_cap is not None: deadline = min(deadline,self._deadline_cap)
                general = source._read(deadline); schemas: dict[Kind,dict[str,Any]] = {}
                for kind in KINDS:
                    raw = self._fetch(SCHEMA_PATHS[kind],deadline); buffers.append(raw)
                    path,table = _TABLES[kind]; schema = _project_alert_schema(raw,path=path,table=table,serial=source._serial)
                    if email_alert_frame_schema_digest(schema,kind,expected_serial=source._serial) != self._schema_pins[kind]: raise ValueError
                    schemas[kind] = schema; _zeroize_mutable(raw)
                frames: dict[Kind,list[EmailAlertFrame]] = {kind:[] for kind in KINDS}
                for kind,slot,path in DETAILS:
                    raw = self._fetch(path,deadline); buffers.append(raw)
                    frames[kind].append(project_email_alert_frame(raw,schemas[kind],kind,slot,
                        expected_serial=source._serial,expected_schema_digest=self._schema_pins[kind]))
                state = EmailAlertCompoundState(general.state,tuple(frames['action']),tuple(frames['stitch']),
                    tuple(frames['trigger']),frames['settings'][0])
                observed = EmailAlertCompoundObservation(self._source,general,state,started,min(started+10,general.expires_at))
                for buffer in buffers: _zeroize_mutable(buffer)
                self._available(); source._remaining(deadline)
                if source._latest is not general or not started <= source._epoch() < observed.expires_at: raise ValueError
                self._latest = observed; return observed
        except Exception: raise ValueError(_ERROR) from None
        finally:
            for buffer in buffers: _zeroize_mutable(buffer)

    def prepare_plan(self) -> EmailAlertCompoundPlan:
        return self._prepare_plan(None)

    def _prepare_plan(self, budget_deadline: float | None) -> EmailAlertCompoundPlan:
        try:
            with self._general._lock:
                source = self._general; self._available(); deadline = source._now()+source._config.timeout_seconds
                if budget_deadline is not None: deadline = min(deadline,budget_deadline)
                observed = self._read(deadline); plan = EmailAlertCompoundPlan(observed.state,source._scope)
                if not plan.changed_steps: raise ValueError
                self._available(); source._remaining(deadline)
                if not source._epoch() < observed.expires_at: raise ValueError
                self._plan,self._origin = plan,observed; return plan
        except Exception: raise ValueError(_ERROR) from None

    def compile(self, plan: EmailAlertCompoundPlan, step: Step) -> bytearray:
        """Re-read the full graph for a forward draft; never supplies inverse custody."""
        body = bytearray()
        try:
            with self._general._lock:
                self._available(); source = self._general; origin = self._origin
                if (plan is not self._plan or origin is None or step not in STEPS
                        or not origin.observed_at <= source._epoch() < origin.expires_at): raise ValueError
                deadline = source._now()+source._config.timeout_seconds; observed = self._read(deadline)
                if not source._epoch() < origin.expires_at: raise ValueError
                body = plan.compile(step,observed.state); self._available(); source._remaining(deadline)
                if not source._epoch() < origin.expires_at: raise ValueError
                transferred = body; body = bytearray(); return transferred
        except Exception: raise ValueError(_ERROR) from None
        finally: _zeroize_mutable(body)

    def preview(self) -> dict[str,object]:
        try:
            with self._general._lock:
                source = self._general; deadline = source._now()+source._config.timeout_seconds
                plan = self._prepare_plan(deadline); origin = self._origin
                if origin is None: raise ValueError
                public = plan.preview()
                public.update(read_source_contract=CONTRACT,fixed_get_count=16,existing_graph_observed_locally=True,
                    schema_pins_matched_locally=True,atomic_snapshot_verified=False,product_actor_verified=False,
                    native_complete_schema_qualified=False,configuration_written=False,mail_contacted=False)
                self._available(); source._remaining(deadline)
                if not source._epoch() < origin.expires_at: raise ValueError
                return public
        except Exception: raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._general._lock: self._closed = True
