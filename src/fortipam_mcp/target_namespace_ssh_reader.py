"""Private build-29 Target name namespace evidence; no write authority."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hmac
import re
from typing import cast

from v4_planning import canonical_digest

from .folder_namespace_ssh_reader import (
    _SERIAL_COMMAND, _VERSION_COMMAND, _frame_lines, _projection_lines,
    _qualified_version_metadata, _safe_observed_name,
)
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport
from .target_ssh_transport import (
    TargetSshTransportConfig, _close_cli, _require_root_prompt,
    _send_and_read, _send_and_read_dynamic_prompt,
)


CONTRACT = "fortipam-700-build29-target-name-namespace-candidate-v1"
_UNAVAILABLE = "FortiPAM Target namespace evidence is unavailable."
_NAME_PROJECTION = 'show full-configuration | grep "^    edit "'
_MAX_NAMES = 128
_WEB_NAME = re.compile(r"mcp-v4-target-web-[0-9]{8}-r[0-9]+\Z")


class TargetNamespaceSshReaderError(RuntimeError):
    """Stable failure without native output or private selectors."""


@dataclass(frozen=True, slots=True, repr=False)
class TargetNamespaceObservation:
    status: str
    target_count: int
    positive_witness_count: int
    namespace_digest: str
    global_name_absent: bool
    _candidate_digest: str = field(repr=False)

    def matches_candidate(self, name: str) -> bool:
        return (isinstance(name, str) and _WEB_NAME.fullmatch(name) is not None
                and hmac.compare_digest(self._candidate_digest, _candidate_digest(name)))


def _candidate_digest(name: str) -> str:
    return cast(str, canonical_digest({"contract": CONTRACT, "candidate_name": name}))


class FortiPamTargetNamespaceSshReader:
    """Read only one fixed candidate against fresh Owner/API-qualified names."""

    def __init__(self, config: TargetSshTransportConfig, *, candidate_name: str,
                 positive_witness_names: tuple[str, ...], expected_device_serial: str,
                 expected_api_names: tuple[str, ...]) -> None:
        if (not isinstance(config, TargetSshTransportConfig)
            or not isinstance(candidate_name, str) or _WEB_NAME.fullmatch(candidate_name) is None
            or len(candidate_name) > 64
            or not _qualified_names(expected_api_names)
            or not _qualified_names(positive_witness_names) or len(positive_witness_names) < 2
            or candidate_name in positive_witness_names
            or not set(positive_witness_names) <= set(expected_api_names)
            or not isinstance(expected_device_serial, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_device_serial) is None):
            raise ValueError(_UNAVAILABLE)
        self._ssh = FortiPamTargetReferenceSshTransport(config)
        self._candidate_name = candidate_name
        self._witness_names = positive_witness_names
        self._api_names = expected_api_names
        self._serial = expected_device_serial

    def read_namespace(self) -> TargetNamespaceObservation:
        try:
            return asyncio.run(self._read_namespace())
        except Exception:
            raise TargetNamespaceSshReaderError(_UNAVAILABLE) from None

    async def _read_namespace(self) -> TargetNamespaceObservation:
        async with self._ssh._connection() as connection:
            process, prompt, deadline = await self._ssh._open_cli(connection)
            try:
                if re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", prompt) is None:
                    raise ValueError
                serial = await _send_and_read(process, _SERIAL_COMMAND, prompt, deadline)
                lines = tuple(line for line in _frame_lines(serial, _SERIAL_COMMAND, prompt) if line.strip(b" \t"))
                if len(lines) != 1 or not hmac.compare_digest(
                    lines[0], b"Serial-Number: " + self._serial.encode("ascii"),
                ):
                    raise ValueError
                version = await _send_and_read(process, _VERSION_COMMAND, prompt, deadline)
                if not _qualified_version_metadata(tuple(
                    line for line in _frame_lines(version, _VERSION_COMMAND, prompt) if line.strip(b" \t")
                )):
                    raise ValueError
                context = await _send_and_read_dynamic_prompt(process, "config secret target", prompt, deadline)
                if context != prompt[:-2] + b" (target) #":
                    raise ValueError
                first = await _send_and_read(process, _NAME_PROJECTION, context, deadline)
                names = _target_names(first, context)
                second = await _send_and_read(process, _NAME_PROJECTION, context, deadline)
                _target_names(second, context)
                if (not hmac.compare_digest(first, second) or set(names) != set(self._api_names)
                    or not set(self._witness_names) <= set(names)):
                    raise ValueError
                returned = await _send_and_read_dynamic_prompt(process, "end", prompt, deadline)
                _require_root_prompt(prompt, returned)
                if returned != prompt:
                    raise ValueError
                absent = self._candidate_name not in names
                return TargetNamespaceObservation(
                    "name_absent" if absent else "name_present", len(names), len(self._witness_names),
                    canonical_digest({"contract": CONTRACT, "names": sorted(names)}), absent,
                    _candidate_digest(self._candidate_name),
                )
            finally:
                await _close_cli(process)


def _qualified_names(names: object) -> bool:
    return (isinstance(names, tuple) and 0 < len(names) <= _MAX_NAMES
            and all(_safe_observed_name(name) for name in names) and len(set(names)) == len(names))


def _target_names(output: bytes, prompt: bytes) -> tuple[str, ...]:
    names: list[str] = []
    for line in _projection_lines(_frame_lines(output, _NAME_PROJECTION, prompt)):
        match = re.fullmatch(rb'    edit "([^"\\\r\n]+)"', line)
        if match is None:
            raise ValueError(_UNAVAILABLE)
        names.append(match[1].decode("utf-8"))
        if len(names) > _MAX_NAMES:
            raise ValueError(_UNAVAILABLE)
    if not _qualified_names(tuple(names)):
        raise ValueError(_UNAVAILABLE)
    return tuple(names)
