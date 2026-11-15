"""One calibrated global User reference read, never ownership or absence."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
import re
from threading import RLock

from v4_planning.material_provider import _OpaqueC3Object

from .folder_namespace_ssh_reader import _SERIAL_COMMAND, _VERSION_COMMAND, _frame_lines, _qualified_version_metadata
from .local_user_reset_http_transport import _NAME
from .target_preservation_contract import _digest
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport, _strict_reference_count
from .target_ssh_transport import TargetSshTransportConfig, _close_cli, _send_and_read

CONTRACT = "fortipam-build29-local-reset-reference-control-v2"
_ERROR = "The private reset-fixture references are unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class LocalResetReferenceObservation(_OpaqueC3Object):
    candidate_reference_count: int
    candidate_unreferenced: bool
    positive_reference_count: int
    api_positive_count: int
    snapshot_digest: str
    source_context_digest: str


class LocalResetReferenceReader(_OpaqueC3Object):
    """Same global Owner must bracket a fresh API-positive reference count."""

    def __init__(self, config: TargetSshTransportConfig, *, candidate_name: str, positive_name: str,
            api_positive_count: int, expected_serial: str, before_send: Callable[[], None]) -> None:
        try:
            if (type(config) is not TargetSshTransportConfig or type(candidate_name) is not str
                    or len(candidate_name) > 64 or _NAME.fullmatch(candidate_name) is None
                    or type(positive_name) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", positive_name) is None
                    or candidate_name.casefold() == positive_name.casefold()
                    or type(api_positive_count) is not int or not 1 <= api_positive_count <= 4096
                    or type(expected_serial) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_serial) is None
                    or not callable(before_send)):
                raise ValueError
            self._config, self._candidate, self._positive = config, candidate_name, positive_name
            self._api_count, self._serial, self._before_send = api_positive_count, expected_serial, before_send
            self._ssh = FortiPamTargetReferenceSshTransport(config)
            self._source = self._context()
            self._used = self._closed = False
            self._stage = "source_binding"
            self._last_failure_stage: str | None = None
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
            str(config.known_hosts_file), hashlib.sha256(known_hosts).hexdigest(),
            self._candidate, self._positive, self._api_count, self._serial))

    def _guard(self) -> None:
        if self._closed or self._context() != self._source: raise ValueError
        self._before_send()

    def read_references(self) -> LocalResetReferenceObservation:
        with self._lock:
            try:
                self._guard()
                if self._used: raise ValueError
                self._used = True
                return asyncio.run(self._read())
            except Exception:
                if self._last_failure_stage is None: self._last_failure_stage = self._stage
                self.close()
                raise ValueError(_ERROR) from None

    async def _read(self) -> LocalResetReferenceObservation:
        self._guard()
        async with self._ssh._connection() as connection:
            process, prompt, deadline = await self._ssh._open_cli(connection)
            try:
                self._stage = "root_prompt"
                if re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", prompt) is None: raise ValueError
                self._stage = "serial"
                self._guard()
                raw = await _send_and_read(process, _SERIAL_COMMAND, prompt, deadline)
                lines = tuple(line for line in _frame_lines(raw, _SERIAL_COMMAND, prompt) if line.strip(b" \t"))
                if lines != (b"Serial-Number: " + self._serial.encode("ascii"),): raise ValueError
                self._stage = "version"
                self._guard()
                raw = await _send_and_read(process, _VERSION_COMMAND, prompt, deadline)
                if not _qualified_version_metadata(tuple(line for line in _frame_lines(raw, _VERSION_COMMAND, prompt) if line.strip(b" \t"))):
                    raise ValueError
                positive = "diagnose sys cmdb refcnt show system.admin.name " + self._positive
                self._stage = "positive_before"
                self._guard()
                before = await _send_and_read(process, positive, prompt, deadline)
                positive_count = _strict_reference_count(before, positive, prompt)
                if not 1 <= positive_count <= 4096: raise ValueError
                candidate = "diagnose sys cmdb refcnt show system.admin.name " + self._candidate
                self._stage = "candidate"
                self._guard()
                raw = await _send_and_read(process, candidate, prompt, deadline)
                count = _strict_reference_count(raw, candidate, prompt)
                if not 0 <= count <= 4096: raise ValueError
                self._stage = "positive_after"
                self._guard()
                after = await _send_and_read(process, positive, prompt, deadline)
                if _strict_reference_count(after, positive, prompt) != positive_count or not hmac.compare_digest(before, after):
                    raise ValueError
                self._guard()
                return LocalResetReferenceObservation(count, count == 0, positive_count, self._api_count,
                    _digest((CONTRACT, self._source, hashlib.sha256(before).hexdigest(), hashlib.sha256(raw).hexdigest(), count)), self._source)
            except Exception:
                self._last_failure_stage = self._stage
                raise
            finally:
                self._stage = "resource_close"
                await _close_cli(process)

    def close(self) -> None:
        with self._lock:
            self._closed = True
