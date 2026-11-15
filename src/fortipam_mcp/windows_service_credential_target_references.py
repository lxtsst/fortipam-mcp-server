"""Private current global Target-reference evidence, never Secret/activity authority.

Borrow an actual Target observation and an explicitly authenticated Owner. Two
bounded Owner catalogs bracket one fixed CLI window with a same-table positive
control. No names, addresses, raw references or credentials leave this boundary.
The caller still owns and must separately qualify complete Secret associations,
activity, original custody, permissions and M4/C3 admission.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
import math
import re
import secrets
from threading import RLock
import time
from typing import Any

import httpx
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from . import target_qualified_namespace_reader as names
from . import target_qualified_reference_reader as frames
from .cli_safety import _complete_pre_login
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .target_contract import DEFAULT_TEMPLATE
from .target_preservation_contract import _digest
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport
from .target_ssh_transport import TargetSshTransportConfig, _send_and_read, _send_and_read_dynamic_prompt
from .windows_service_credential_owner_auth import WindowsServiceCredentialOwnerSession, service_credential_owner_binding
from .windows_service_credential_target_sources import WindowsServiceCredentialTargetObservation, WindowsServiceCredentialTargetSources

_ERROR = "The private service Target reference source is unavailable."
_CONTRACT = "fortipam-build29-service-target-global-reference-source-v1"
_CATALOG = "/api/v2/cmdb/secret/target?format=name%7Caddress%7Cdomain%7Curl%7Ctemplate%7Cpermissions%7Cpriv_acct%7Cq_ref&with_meta=true&vdom=root"
_BODY = b'{"json_filter":[]}'
_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ ()-]{0,126}\Z")
_PAGING = frozenset({"has_more", "next_index", "offset", "start", "limit", "total", "total_count"})


class WindowsServiceTargetReferenceError(ValueError):
    """Categorical refusal; a consumed window is never replayed."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceTargetReferenceObservation(_OpaqueC3Object):
    source_context_digest: str
    target_reference_context_digest: str
    reference_scope_digest: str
    global_target_count: int
    positive_reference_count: int
    selected_reference_count: int
    observed_at: float
    expires_at: float


@dataclass(frozen=True, slots=True, repr=False)
class _Row(_OpaqueC3Object):
    name: str
    address: str
    template: str
    references: int
    privilege: int | None


class WindowsServiceCredentialTargetReferences(_OpaqueC3Object):
    """One bounded read; closing never closes borrowed sources or Owner session."""

    def __init__(self, target_source: WindowsServiceCredentialTargetSources, *,
            target_observation: WindowsServiceCredentialTargetObservation,
            owner_session: WindowsServiceCredentialOwnerSession, ssh: TargetSshTransportConfig,
            read_enabled: bool = False, client_factory: Callable[..., httpx.Client] = httpx.Client,
            clock: Callable[[], float] = time.monotonic) -> None:
        self._key = bytearray()
        try:
            if (type(target_source) is not WindowsServiceCredentialTargetSources
                    or type(target_observation) is not WindowsServiceCredentialTargetObservation
                    or type(owner_session) is not WindowsServiceCredentialOwnerSession
                    or type(ssh) is not TargetSshTransportConfig or type(read_enabled) is not bool
                    or not callable(client_factory) or not callable(clock)):
                raise ValueError
            target_source.check_current(target_observation)
            ssh.__post_init__()
            if _SAFE.fullmatch(target_source._name) is None:
                raise ValueError
            self._target, self._observed, self._owner, self._ssh = target_source, target_observation, owner_session, ssh
            self._config, self._serial = target_source._config, target_source._serial
            self._owner_binding = owner_session.binding
            self._factory, self._clock, self._enabled = client_factory, clock, read_enabled
            self._factory_pin, self._clock_pin = client_factory, clock
            self._borrowed = (target_source, target_observation, owner_session, ssh, self._config, target_source._tls)
            self._transport = FortiPamTargetReferenceSshTransport(ssh)
            self._connect = self._transport._connection
            self._helpers = (_complete_pre_login, _send_and_read, _send_and_read_dynamic_prompt)
            self._key.extend(secrets.token_bytes(32))
            self._closed = self._failed = self._used = False
            self._last = -1.0
            self._deadline: float | None = None
            self._current: WindowsServiceTargetReferenceObservation | None = None
            self._seal: str | None = None
            self._failure_stage: str | None = None
            self._lock = RLock()
            self._source = self._context()
        except Exception:
            _zeroize_mutable(self._key)
            raise WindowsServiceTargetReferenceError(_ERROR) from None

    def _context(self) -> str:
        self._target.check_current(self._observed)
        self._ssh.__post_init__()
        binding = service_credential_owner_binding(self._config, owner_name=self._ssh.username,
            serial_digest=self._serial, folder_context_digest=self._owner_binding.folder_context_digest)
        if (binding != self._owner_binding or self._owner.binding != binding
                or self._owner._config != self._config
                or any(current is not pinned for current, pinned in zip(
                    (self._target, self._observed, self._owner, self._ssh, self._config, self._target._tls), self._borrowed, strict=True))):
            raise ValueError
        return canonical_digest(dict(contract=_CONTRACT, target=self._observed.target_reference_context_digest,
            source=self._observed.source_context_digest, owner=binding.binding_digest,
            ssh_host=self._ssh.host, ssh_port=self._ssh.port, ssh_user=self._ssh.username,
            ssh_credential=hashlib.sha256(self._ssh.password.encode()).hexdigest(),
            trust=hashlib.sha256(self._ssh.known_hosts_file.read_bytes()).hexdigest(),
            ssh_timeout=str(self._ssh.timeout_seconds)))

    def _now(self) -> float:
        value = self._clock()
        if (self._closed or self._failed or self._clock is not self._clock_pin
                or type(value) not in (float, int) or not math.isfinite(value) or value < 0 or value < self._last):
            raise ValueError
        self._last = float(value)
        return float(value)

    def _guard(self) -> float:
        now = self._now()
        if (self._enabled is not True or self._factory is not self._factory_pin
                or self._transport._config is not self._ssh
                or self._transport._connection != self._connect
                or self._helpers != (_complete_pre_login, _send_and_read, _send_and_read_dynamic_prompt)
                or self._context() != self._source or self._deadline is not None and now >= self._deadline):
            raise ValueError
        self._owner.require_binding(self._owner_binding, config=self._config, purpose="create")
        return now

    def _remaining(self) -> float:
        now = self._guard()
        if self._deadline is None or self._deadline <= now:
            raise ValueError
        return min(10.0, self._deadline-now)

    def _catalog(self) -> tuple[_Row, ...]:
        raw, consumed = bytearray(), bytearray()
        client: httpx.Client | None = None
        try:
            self._guard()
            cookie, csrf = self._owner._validated_cookie("POST", _CATALOG)
            with _private_http_logs():
                client = self._factory(verify=self._target._tls, timeout=self._remaining(), trust_env=False, follow_redirects=False)
                with client:
                    with client.stream("POST", self._config.base_url+_CATALOG, headers={"Cookie": cookie, "X-CSRFTOKEN": csrf,
                            "X-HTTP-Method-Override": "GET", "Content-Type": "application/json", "Accept": "application/json",
                            "Accept-Encoding": "identity", "Cache-Control": "no-store"}, content=_BODY) as response:
                        self._guard()
                        length = response.headers.get("content-length")
                        if (response.status_code != 200 or response.headers.get("content-type", "").split(";", 1)[0] != "application/json"
                                or response.headers.get("content-encoding", "identity") != "identity"
                                or "transfer-encoding" in response.headers
                                or length is not None and (re.fullmatch(r"[0-9]{1,7}", length) is None or not 0 < int(length) <= 262144)):
                            raise ValueError
                        for chunk in response.iter_raw():
                            self._guard()
                            if len(raw)+len(chunk) > 262144:
                                raise ValueError
                            raw.extend(chunk)
                        if length is not None and len(raw) != int(length):
                            raise ValueError
                    self._guard()
                    client.cookies.clear()
                self._guard()
            consumed.extend(raw)
            projected = metadata.project_native_import_metadata(consumed, table="target", expected_serial_digest=self._serial)
            if not 2 <= len(projected.rows) <= 128:
                raise ValueError
            start = _skip_json_space(raw, 0)
            top = _object_spans(raw, start, _json_value_end(raw, start))
            if _PAGING & top.keys() or "action" in top and metadata._scalar(raw, top["action"]) != "":
                raise ValueError
            for name in ("size", "matched_count", "filtered_count"):
                if name in top:
                    value = metadata._scalar(raw, top[name])
                    if type(value) is not int or value != len(projected.rows):
                        raise ValueError
            rows = []
            for view, span in zip(projected.rows, metadata._array(raw, top["results"], 128), strict=True):
                if type(view) is not metadata.ImportMetadataTarget:
                    raise ValueError
                fields = _object_spans(raw, *span)
                count = metadata._scalar(raw, fields["q_ref"])
                privilege = metadata._scalar(raw, fields["priv_acct"]) if "priv_acct" in fields else None
                if type(count) is not int or not 0 <= count <= 65536 or privilege is not None and (type(privilege) is not int or not 0 <= privilege <= 2147483647):
                    raise ValueError
                rows.append(_Row(view.name, view.address, view.template, count, privilege))
            result = tuple(rows)
            selected = [row for row in result if row.name == self._target._name]
            if (len(selected) != 1 or selected[0].address != self._target._address
                    or selected[0].references != 0 or type(selected[0].privilege) is not int or selected[0].privilege != 0
                    or sum(row.address == self._target._address for row in result) != 1):
                raise ValueError
            self._guard()
            return result
        finally:
            _zeroize_mutable(raw); _zeroize_mutable(consumed)
            if client is not None:
                client.cookies.clear(); client.close()

    async def _cli(self, rows: tuple[_Row, ...], control: _Row) -> tuple[int, int]:
        connection: Any = None
        process: Any = None
        commands = 0
        try:
            now = self._guard()
            if self._deadline is None:
                raise ValueError
            deadline = self._deadline
            async with asyncio.timeout(deadline-now):
                connection = await self._connect()
                self._guard()
                process = await connection.create_process(term_type="vt100", term_size=(200, 24), encoding=None)
                root = await _complete_pre_login(process.stdout, process.stdin, deadline, 65536, accept_pre_login_banner=False)
                if re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", root) is None:
                    raise ValueError
                async def command(text: str, prompt: bytes) -> bytes:
                    nonlocal commands
                    self._guard(); commands += 1
                    if commands > 11:
                        raise ValueError
                    result = await _send_and_read(process, text, prompt, deadline)
                    self._guard()
                    return result
                async def identity() -> None:
                    lines = frames._lines(await command(frames._SERIAL, root), frames._SERIAL, root)
                    match = re.fullmatch(rb"Serial-Number: ([A-Za-z0-9_-]{1,128})", lines[0]) if len(lines) == 1 else None
                    if match is None or not hmac.compare_digest(hashlib.sha256(match[1]).hexdigest(), self._serial):
                        raise ValueError
                    frames._version(frames._lines(await command(frames._VERSION, root), frames._VERSION, root))
                await identity()
                self._guard(); commands += 1
                context = await _send_and_read_dynamic_prompt(process, "config secret target", root, deadline)
                if context != root[:-2]+b" (target) #":
                    raise ValueError
                first = await command(names._NAMES, context)
                global_names = names._project(first, context)
                second = await command(names._NAMES, context)
                if second != first or set(names._project(second, context)) != {row.name for row in rows} or set(global_names) != {row.name for row in rows}:
                    raise ValueError
                self._guard(); commands += 1
                if await _send_and_read_dynamic_prompt(process, "end", root, deadline) != root:
                    raise ValueError
                counts = []
                for name in (control.name, self._target._name, control.name):
                    if _SAFE.fullmatch(name) is None:
                        raise ValueError
                    text = frames._REFERENCE+'"'+name+'"'
                    lines = frames._lines(await command(text, root), text, root)
                    if any(b"entry used by" not in line.lower() for line in lines):
                        raise ValueError
                    counts.append(len(lines))
                if not counts[0] == counts[2] > 0 or counts[1] != 0:
                    raise ValueError
                await identity()
                if commands != 11:
                    raise ValueError
                self._guard()
                return len(global_names), counts[0]
        finally:
            try:
                if process is not None:
                    process.close()
                    async with asyncio.timeout(1):
                        await process.wait_closed()
            finally:
                if connection is not None:
                    connection.abort()
                    async with asyncio.timeout(1):
                        await connection.wait_closed()

    def read_once(self) -> WindowsServiceTargetReferenceObservation:
        phase = "admission"
        try:
            with self._lock:
                if self._used:
                    raise ValueError
                self._used = True
                started = self._guard()
                self._deadline = min(started+30.0, started+self._ssh.timeout_seconds, self._observed.expires_at)
                phase = "catalog-before"
                before = self._catalog()
                controls = sorted((row for row in before if row.name != self._target._name and row.address != self._target._address
                    and row.template == DEFAULT_TEMPLATE and row.references > 0 and _SAFE.fullmatch(row.name)
                    and not row.name.casefold().startswith(("mcp", "b47"))), key=lambda row: (row.references, row.name))
                if not controls:
                    raise ValueError
                phase = "global-cli-window"
                count, positive = asyncio.run(self._cli(before, controls[0]))
                phase = "catalog-after"
                if self._catalog() != before:
                    raise ValueError
                phase = "private-reference-seal"
                scope = hmac.new(self._key, _digest(dict(source=self._source,
                    catalog=[asdict(row) for row in before], positive=asdict(controls[0]), references=positive)).encode(), hashlib.sha256).hexdigest()
                current = WindowsServiceTargetReferenceObservation(self._source, self._observed.target_reference_context_digest,
                    scope, count, positive, 0, started, self._deadline)
                self._guard()
                self._current, self._seal = current, _digest(asdict(current))
                return current
        except BaseException as error:
            self._failed, self._current, self._seal = True, None, None
            self._failure_stage = phase
            if isinstance(error, Exception):
                raise WindowsServiceTargetReferenceError(_ERROR) from None
            raise

    def check_current(self, observation: WindowsServiceTargetReferenceObservation) -> None:
        try:
            with self._lock:
                now = self._guard()
                if (type(observation) is not WindowsServiceTargetReferenceObservation or observation is not self._current
                        or self._seal != _digest(asdict(observation))
                        or not observation.observed_at <= now < observation.expires_at):
                    raise ValueError
        except Exception:
            self._failed, self._current, self._seal = True, None, None
            raise WindowsServiceTargetReferenceError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current, self._seal = None, None
            _zeroize_mutable(self._key)
