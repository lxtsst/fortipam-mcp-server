"""Fixed global User/API User names for one prospective reset fixture.

The caller must bracket this read with fresh same-Owner global/Super evidence
and API-qualified positive witnesses. No current-state observation grants a
create, reset, adoption or recovery authority.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
import re
from threading import RLock

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from .folder_namespace_ssh_reader import _SERIAL_COMMAND, _VERSION_COMMAND, _frame_lines, _qualified_version_metadata, _safe_observed_name
from .local_user_reset_http_transport import _NAME
from .target_namespace_ssh_reader import _NAME_PROJECTION, _target_names
from .target_preservation_contract import _digest
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport
from .target_ssh_transport import TargetSshTransportConfig, _close_cli, _require_root_prompt, _send_and_read, _send_and_read_dynamic_prompt

CONTRACT = "fortipam-build29-local-reset-global-names-v1"
_ERROR = "The private reset-fixture namespace is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class LocalResetNamespaceObservation(_OpaqueC3Object):
    admin_count: int
    api_user_count: int
    candidate_admin_occurrences: int
    candidate_api_occurrences: int
    global_name_absent: bool
    namespace_digest: str
    source_context_digest: str


class LocalResetNamespaceReader(_OpaqueC3Object):
    """One bounded two-table name projection; raw names remain private."""

    def __init__(self, config: TargetSshTransportConfig, *, candidate_name: str,
            admin_witness: str, api_witness: str, expected_serial: str,
            before_send: Callable[[], None]) -> None:
        try:
            if (type(config) is not TargetSshTransportConfig or type(candidate_name) is not str
                    or len(candidate_name) > 64 or _NAME.fullmatch(candidate_name) is None
                    or not all(_safe_observed_name(name) for name in (admin_witness, api_witness))
                    or candidate_name.casefold() in {admin_witness.casefold(), api_witness.casefold()}
                    or type(expected_serial) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_serial) is None
                    or not callable(before_send)):
                raise ValueError
            self._config, self._candidate = config, candidate_name
            self._admin_witness, self._api_witness, self._serial = admin_witness, api_witness, expected_serial
            self._before_send = before_send
            self._ssh = FortiPamTargetReferenceSshTransport(config)
            self._source = self._context()
            self._used = self._closed = False
            self._admin_names: tuple[str, ...] = ()
            self._api_names: tuple[str, ...] = ()
            self._lock = RLock()
        except Exception:
            raise ValueError(_ERROR) from None

    def _context(self) -> str:
        config = self._config
        config.__post_init__()
        with Path(config.known_hosts_file).open("rb") as stream: known_hosts = stream.read(1048577)
        if not 0 < len(known_hosts) <= 1048576 or self._ssh._config is not config: raise ValueError
        return _digest((CONTRACT, config.host, config.port, config.username,
            hashlib.sha256(config.password.encode()).hexdigest(), config.timeout_seconds,
            str(config.known_hosts_file), hashlib.sha256(known_hosts).hexdigest(), self._candidate,
            self._admin_witness, self._api_witness, self._serial))

    def _guard(self) -> None:
        if self._closed or self._context() != self._source: raise ValueError
        self._before_send()

    def read_namespace(self) -> LocalResetNamespaceObservation:
        with self._lock:
            try:
                self._guard()
                if self._used: raise ValueError
                self._used = True
                return asyncio.run(self._read())
            except Exception:
                self.close()
                raise ValueError(_ERROR) from None

    async def _read(self) -> LocalResetNamespaceObservation:
        self._guard()
        async with self._ssh._connection() as connection:
            process, prompt, deadline = await self._ssh._open_cli(connection)
            try:
                if re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", prompt) is None: raise ValueError
                self._guard()
                raw = await _send_and_read(process, _SERIAL_COMMAND, prompt, deadline)
                lines = tuple(line for line in _frame_lines(raw, _SERIAL_COMMAND, prompt) if line.strip(b" \t"))
                if lines != (b"Serial-Number: " + self._serial.encode("ascii"),): raise ValueError
                self._guard()
                raw = await _send_and_read(process, _VERSION_COMMAND, prompt, deadline)
                if not _qualified_version_metadata(tuple(line for line in _frame_lines(raw, _VERSION_COMMAND, prompt) if line.strip(b" \t"))):
                    raise ValueError
                names = []
                for table, witness in (("admin", self._admin_witness), ("api-user", self._api_witness)):
                    self._guard()
                    context = await _send_and_read_dynamic_prompt(process, "config system " + table, prompt, deadline)
                    if context != prompt[:-2] + b" (" + table.encode() + b") #": raise ValueError
                    self._guard()
                    first = await _send_and_read(process, _NAME_PROJECTION, context, deadline)
                    selected = _target_names(first, context)
                    self._guard()
                    second = await _send_and_read(process, _NAME_PROJECTION, context, deadline)
                    if (not hmac.compare_digest(first, second) or _target_names(second, context) != selected
                            or witness not in selected or len(selected) != len({name.casefold() for name in selected})):
                        raise ValueError
                    self._guard()
                    returned = await _send_and_read_dynamic_prompt(process, "end", prompt, deadline)
                    _require_root_prompt(prompt, returned)
                    if returned != prompt: raise ValueError
                    names.append(selected)
                self._guard()
                self._admin_names, self._api_names = names
                admin = sum(name.casefold() == self._candidate.casefold() for name in self._admin_names)
                api = sum(name.casefold() == self._candidate.casefold() for name in self._api_names)
                return LocalResetNamespaceObservation(len(self._admin_names), len(self._api_names), admin, api,
                    admin == api == 0, canonical_digest(dict(contract=CONTRACT,
                        admin_names=sorted(self._admin_names), api_names=sorted(self._api_names))), self._source)
            finally:
                await _close_cli(process)

    def close(self) -> None:
        with self._lock:
            self._closed, self._admin_names, self._api_names = True, (), ()
