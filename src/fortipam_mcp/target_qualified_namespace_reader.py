"""Bounded same-device Target name namespace; trusted caller supplies API witnesses.

No write/ownership authority. API names must come from a fresh source-qualified
reader in the consuming composition; arbitrary caller tuples do not prove that.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import math
import re
from threading import RLock
import time
from collections.abc import Callable

from v4_planning.material_provider import _OpaqueC3Object
from . import target_preservation_contract as c
from . import target_qualified_reference_reader as r
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport, _target_name
from .cli_safety import _complete_pre_login
from .target_ssh_transport import TargetSshTransportConfig, _send_and_read_dynamic_prompt, _send_and_read

_NAMES = 'show full-configuration | grep "^    edit "'
_ERROR = 'Protected Target name namespace unavailable.'


class TargetQualifiedNamespaceError(ValueError):
    """No private names, device identifiers or raw CLI in errors."""


def _names(values: object) -> tuple[str,...]:
    if (type(values) is not tuple or not 2 <= len(values) <= 128
        or any(type(x) is not str or not 0 < len(x.encode('utf-8')) <= 255
               or any(ord(ch)<32 or ord(ch)==127 or ch in '\\"' for ch in x) for x in values)
        or len(set(values)) != len(values)):
        raise ValueError
    return values


def _project(raw: bytes, prompt: bytes) -> tuple[str,...]:
    names: list[str]=[]
    for line in r._lines(raw,_NAMES,prompt):
        match=re.fullmatch(rb'    edit "([^"\\\r\n]+)"',line)
        if match is None or len(names)>=128: raise ValueError
        names.append(match[1].decode('utf-8'))
    return _names(tuple(names))


@dataclass(frozen=True,slots=True,repr=False)
class TargetNameNamespaceObservation(_OpaqueC3Object):
    candidate_digest: str
    namespace_digest: str
    api_witness_digest: str
    target_count: int
    candidate_absent: bool
    observed_at: float
    expires_at: float


class FortiPamTargetQualifiedNamespaceReader(_OpaqueC3Object):
    def __init__(self, config: TargetSshTransportConfig, *, serial_digest: str,
                 clock: Callable[[],float] = time.monotonic) -> None:
        try:
            if (type(config) is not TargetSshTransportConfig or type(serial_digest) is not str
                or c._DIGEST.fullmatch(serial_digest) is None or not callable(clock)): raise ValueError
            config.__post_init__()
            self._ssh=FortiPamTargetReferenceSshTransport(config)
            self._serial=serial_digest
            self._timeout=config.timeout_seconds
            self._clock=clock
            self._lock=RLock()
            self._last: float | None=None
            self._closed=False
            self._failed=False
            self._current: TargetNameNamespaceObservation | None=None
        except Exception:
            raise TargetQualifiedNamespaceError(_ERROR) from None

    def _now(self) -> float:
        try: value=self._clock()
        except Exception:
            self._failed=True
            raise ValueError from None
        if (type(value) not in (int,float) or not math.isfinite(value) or value<0
            or self._closed or self._failed or self._last is not None and value<self._last):
            self._failed=True
            raise ValueError
        self._last=float(value)
        return float(value)

    def read_namespace(self, candidate_name: str, *, api_names: tuple[str,...]) -> TargetNameNamespaceObservation:
        with self._lock:
            self._current=None
            try:
                if type(candidate_name) is not str: raise ValueError
                candidate=_target_name(candidate_name);witnesses=_names(api_names)
                started=self._now();expires=started+self._timeout
                names=asyncio.run(self._bounded_read(witnesses))
                if not started <= self._now()<expires: raise ValueError
                result=TargetNameNamespaceObservation(c._digest((self._serial,candidate)),
                    c._digest((self._serial,tuple(sorted(names)))),c._digest(tuple(sorted(witnesses))),
                    len(names),candidate.casefold() not in {name.casefold() for name in names},started,expires)
                self._current=result
                return result
            except Exception:
                raise TargetQualifiedNamespaceError(_ERROR) from None

    def check_current(self, observation: TargetNameNamespaceObservation, *, candidate_name: str,
                      api_names: tuple[str,...]) -> None:
        with self._lock:
            try:
                if (type(observation) is not TargetNameNamespaceObservation or observation is not self._current
                    or not observation.observed_at<=self._now()<observation.expires_at
                    or observation.candidate_digest!=c._digest((self._serial,_target_name(candidate_name)))
                    or observation.api_witness_digest!=c._digest(tuple(sorted(_names(api_names))))): raise ValueError
            except Exception:
                raise TargetQualifiedNamespaceError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed=True;self._current=None

    async def _bounded_read(self, witnesses: tuple[str,...]) -> tuple[str,...]:
        async with asyncio.timeout(self._timeout):
            deadline=time.monotonic()+self._timeout
            connection=await self._ssh._connection()
            try:
                process=await connection.create_process(term_type='vt100',term_size=(200,24),encoding=None)
                try:
                    root=await _complete_pre_login(process.stdout,process.stdin,deadline,r._LIMIT,
                        accept_pre_login_banner=False)
                    if re.fullmatch(rb'[A-Za-z0-9._-]{1,63} #',root) is None: raise ValueError
                    async def identity() -> None:
                        raw=await _send_and_read(process,r._SERIAL,root,deadline)
                        lines=r._lines(raw,r._SERIAL,root)
                        if len(lines)!=1: raise ValueError
                        match=re.fullmatch(rb'Serial-Number: ([A-Za-z0-9_-]{1,128})',lines[0])
                        if match is None or hashlib.sha256(match[1]).hexdigest()!=self._serial: raise ValueError
                        r._version(r._lines(await _send_and_read(process,r._VERSION,root,deadline),r._VERSION,root))
                    await identity()
                    context=await _send_and_read_dynamic_prompt(process,'config secret target',root,deadline)
                    if context!=root[:-2]+b' (target) #': raise ValueError
                    first=await _send_and_read(process,_NAMES,context,deadline)
                    names=_project(first,context)
                    second=await _send_and_read(process,_NAMES,context,deadline)
                    _project(second,context)
                    if first!=second or not set(witnesses)<=set(names): raise ValueError
                    returned=await _send_and_read_dynamic_prompt(process,'end',root,deadline)
                    if returned!=root: raise ValueError
                    await identity()
                    return names
                finally:
                    process.close()
                    async with asyncio.timeout(1):await process.wait_closed()
            finally:connection.abort()
