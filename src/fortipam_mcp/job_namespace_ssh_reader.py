"""Private build29 global Job names; no scripts, mutation or ownership authority."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
import re
from threading import RLock

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from .folder_namespace_ssh_reader import (
    _SERIAL_COMMAND, _VERSION_COMMAND, _frame_lines, _qualified_version_metadata,
)
from .job_definition_create_contract import _JOB_NAME
from .target_namespace_ssh_reader import _NAME_PROJECTION, _qualified_names, _target_names
from .target_preservation_contract import _digest
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport
from .target_ssh_transport import (
    TargetSshTransportConfig, _close_cli, _require_root_prompt,
    _send_and_read, _send_and_read_dynamic_prompt,
)

CONTRACT = "fortipam-700-build29-job-name-namespace-v1"
_ERROR = "The private global Job namespace is unavailable."


class JobNamespaceSshReaderError(RuntimeError):
    """Categorical refusal without names, native output or private identity."""


@dataclass(frozen=True, slots=True, repr=False)
class JobNamespaceObservation(_OpaqueC3Object):
    status: str
    job_count: int
    positive_witness_count: int
    namespace_digest: str
    global_name_absent: bool
    source_context_digest: str


class FortiPamJobNamespaceSshReader(_OpaqueC3Object):
    """One fixed read; caller must bracket the same global Owner/API witnesses.

    Two positive names must be freshly qualified by the caller's fixed API
    reads. The CLI namespace may contain more rows than that actor-visible view.
    This observation cannot qualify API write rights, original custody or M4.
    """

    def __init__(self, config: TargetSshTransportConfig, *, candidate_name: str,
            positive_witness_names: tuple[str, ...], expected_device_serial: str) -> None:
        try:
            if (type(config) is not TargetSshTransportConfig
                    or type(candidate_name) is not str or len(candidate_name) > 64
                    or _JOB_NAME.fullmatch(candidate_name) is None
                    or not _qualified_names(positive_witness_names) or len(positive_witness_names) < 2
                    or candidate_name.casefold() in {name.casefold() for name in positive_witness_names}
                    or len(positive_witness_names) != len({name.casefold() for name in positive_witness_names})
                    or type(expected_device_serial) is not str
                    or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_device_serial) is None):
                raise ValueError
            self._config = config
            self._candidate, self._witnesses, self._serial = candidate_name, positive_witness_names, expected_device_serial
            self._ssh = FortiPamTargetReferenceSshTransport(config)
            self._source = self._context()
            self._used = self._closed = False
            self._names: tuple[str, ...] = ()
            self._lock = RLock()
        except Exception:
            raise JobNamespaceSshReaderError(_ERROR) from None

    def _context(self) -> str:
        config = self._config
        config.__post_init__()
        with Path(config.known_hosts_file).open("rb") as stream:
            known_hosts = stream.read(1048577)
        if not 0 < len(known_hosts) <= 1048576 or self._ssh._config is not config:
            raise ValueError
        return _digest((CONTRACT, config.host, config.port, config.username,
            hashlib.sha256(config.password.encode()).hexdigest(), config.timeout_seconds,
            str(config.known_hosts_file), hashlib.sha256(known_hosts).hexdigest(),
            self._candidate, self._witnesses, self._serial))

    def _guard(self) -> None:
        if self._closed or self._context() != self._source:
            raise ValueError

    def read_namespace(self) -> JobNamespaceObservation:
        with self._lock:
            try:
                self._guard()
                if self._used:
                    raise ValueError
                self._used = True
                return asyncio.run(self._read_namespace())
            except Exception:
                self._names = ()
                self._closed = True
                raise JobNamespaceSshReaderError(_ERROR) from None

    async def _read_namespace(self) -> JobNamespaceObservation:
        self._guard()
        async with self._ssh._connection() as connection:
            process, prompt, deadline = await self._ssh._open_cli(connection)
            try:
                if re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", prompt) is None:
                    raise ValueError
                serial = await _send_and_read(process, _SERIAL_COMMAND, prompt, deadline)
                lines = tuple(line for line in _frame_lines(serial, _SERIAL_COMMAND, prompt) if line.strip(b" \t"))
                if lines != (b"Serial-Number: " + self._serial.encode("ascii"),):
                    raise ValueError
                version = await _send_and_read(process, _VERSION_COMMAND, prompt, deadline)
                if not _qualified_version_metadata(tuple(
                        line for line in _frame_lines(version, _VERSION_COMMAND, prompt) if line.strip(b" \t"))):
                    raise ValueError
                self._guard()
                context = await _send_and_read_dynamic_prompt(process, "config secret job", prompt, deadline)
                if context != prompt[:-2] + b" (job) #":
                    raise ValueError
                first = await _send_and_read(process, _NAME_PROJECTION, context, deadline)
                names = _target_names(first, context)
                second = await _send_and_read(process, _NAME_PROJECTION, context, deadline)
                if (not hmac.compare_digest(first, second) or _target_names(second, context) != names
                        or not set(self._witnesses) <= set(names)
                        or len(names) != len({name.casefold() for name in names})):
                    raise ValueError
                returned = await _send_and_read_dynamic_prompt(process, "end", prompt, deadline)
                _require_root_prompt(prompt, returned)
                if returned != prompt:
                    raise ValueError
                self._guard()
                absent = self._candidate.casefold() not in {name.casefold() for name in names}
                self._names = names
                return JobNamespaceObservation("name_absent" if absent else "name_present",
                    len(names), len(self._witnesses), canonical_digest({"contract": CONTRACT, "names": sorted(names)}),
                    absent, self._source)
            finally:
                await _close_cli(process)

    def close(self) -> None:
        with self._lock:
            self._closed, self._names = True, ()
