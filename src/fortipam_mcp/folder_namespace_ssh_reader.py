"""Private build-29 global Folder name observation; never grants write authority."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hmac
import re
import unicodedata

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from .folder_archive_reference_ssh_transport import _PARENT_PROJECTION, _folder_parent_ids
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport
from .target_ssh_transport import (
    TargetSshTransportConfig,
    _close_cli,
    _require_root_prompt,
    _send_and_read,
    _send_and_read_dynamic_prompt,
)


_UNAVAILABLE = "FortiPAM Folder namespace evidence is unavailable."
_SERIAL_COMMAND = 'get system status | grep "Serial-Number"'
_VERSION_COMMAND = 'get system status | grep "Version"'
_NAME_PROJECTION = 'show full-configuration | grep "set name"'
_MAX_OUTPUT_BYTES = 64 * 1024


class FolderNamespaceSshReaderError(RuntimeError):
    """Non-disclosing rejection of an incomplete or unqualified observation."""


@dataclass(frozen=True, slots=True)
class FolderNamespaceObservation:
    status: str
    folder_count: int
    positive_witness_count: int
    namespace_digest: str
    global_name_absent: bool


@dataclass(frozen=True, slots=True, repr=False)
class FolderNamespaceColumns(_OpaqueC3Object):
    """Private complete projections; columns do not associate IDs with names."""

    observation: FolderNamespaceObservation
    names: tuple[str, ...]
    parent_values: tuple[int, ...]


class FortiPamFolderNamespaceSshReader:
    """One compiled readonly candidate, with fresh caller-owned role qualification.

    The caller must separately establish the same Owner's enabled local
    super_admin role and API device/version binding. This reader does not
    qualify ACLs, associate independent projection columns, or permit CREATE.
    """

    def __init__(self, config: TargetSshTransportConfig, *, candidate_name: str,
                 positive_witness_names: tuple[str, ...], expected_device_serial: str) -> None:
        if (not isinstance(config, TargetSshTransportConfig)
            or not isinstance(candidate_name, str) or len(candidate_name) > 64
            or re.fullmatch(r"mcp-v4-[A-Za-z0-9][A-Za-z0-9._-]*", candidate_name) is None
            or not isinstance(positive_witness_names, tuple)
            or len(positive_witness_names) < 2
            or any(not _safe_observed_name(name) for name in positive_witness_names)
            or len(set(positive_witness_names)) != len(positive_witness_names)
            or not isinstance(expected_device_serial, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_device_serial) is None):
            raise ValueError(_UNAVAILABLE)
        self._ssh = FortiPamTargetReferenceSshTransport(config)
        self._candidate_name = candidate_name
        self._witness_names = positive_witness_names
        self._device_serial = expected_device_serial

    def read_namespace(self) -> FolderNamespaceObservation:
        return self.read_complete_namespace().observation

    def read_complete_namespace(self) -> FolderNamespaceColumns:
        """Keep the fixed bounded projections inside a trusted local consumer."""
        try:
            return asyncio.run(self._read_namespace())
        except Exception:
            raise FolderNamespaceSshReaderError(_UNAVAILABLE) from None

    async def _read_namespace(self) -> FolderNamespaceColumns:
        async with self._ssh._connection() as connection:
            process, prompt, deadline = await self._ssh._open_cli(connection)
            try:
                if re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", prompt) is None:
                    raise ValueError(_UNAVAILABLE)
                serial_output = await _send_and_read(process, _SERIAL_COMMAND, prompt, deadline)
                serial_lines = tuple(line for line in _frame_lines(serial_output, _SERIAL_COMMAND, prompt)
                                     if line.strip(b" \t"))
                if (len(serial_lines) != 1
                    or not hmac.compare_digest(
                        serial_lines[0], b"Serial-Number: " + self._device_serial.encode("ascii"))):
                    raise ValueError(_UNAVAILABLE)
                version_output = await _send_and_read(process, _VERSION_COMMAND, prompt, deadline)
                version_lines = tuple(line for line in _frame_lines(version_output, _VERSION_COMMAND, prompt)
                                      if line.strip(b" \t"))
                if not _qualified_version_metadata(version_lines):
                    raise ValueError(_UNAVAILABLE)
                folder_prompt = await _send_and_read_dynamic_prompt(
                    process, "config secret folder", prompt, deadline,
                )
                if folder_prompt != prompt[:-2] + b" (folder) #":
                    raise ValueError(_UNAVAILABLE)
                first_names = await _send_and_read(process, _NAME_PROJECTION, folder_prompt, deadline)
                names = _folder_names(first_names, folder_prompt)
                parent_output = await _send_and_read(process, _PARENT_PROJECTION, folder_prompt, deadline)
                parent_lines = _projection_lines(_frame_lines(parent_output, _PARENT_PROJECTION, folder_prompt))
                if any(re.fullmatch(rb"[ \t]*set parent-folder (0|[1-9][0-9]*)[ \t]*", line) is None
                       for line in parent_lines):
                    raise ValueError(_UNAVAILABLE)
                parents = _folder_parent_ids(parent_output, folder_prompt)
                second_names = await _send_and_read(process, _NAME_PROJECTION, folder_prompt, deadline)
                _folder_names(second_names, folder_prompt)
                if not hmac.compare_digest(first_names, second_names) or len(names) != len(parents):
                    raise ValueError(_UNAVAILABLE)
                if any(witness not in names for witness in self._witness_names):
                    raise ValueError(_UNAVAILABLE)
                returned = await _send_and_read_dynamic_prompt(process, "end", prompt, deadline)
                _require_root_prompt(prompt, returned)
                if returned != prompt:
                    raise ValueError(_UNAVAILABLE)
                absent = self._candidate_name not in names
                observed = FolderNamespaceObservation(
                    status="name_absent" if absent else "name_present",
                    folder_count=len(names), positive_witness_count=len(self._witness_names),
                    namespace_digest=canonical_digest({
                        "contract": "fortipam-700-build29-folder-name-namespace-candidate-v1",
                        "names": list(names), "parent_values": list(parents),
                    }),
                    global_name_absent=absent,
                )
                return FolderNamespaceColumns(observed, names, parents)
            finally:
                await _close_cli(process)


def _frame_lines(output: bytes, command: str, prompt: bytes) -> tuple[bytes, ...]:
    """Only explicit qualified CRCRLF echo and CRLF line terminators are accepted."""
    if len(output) > _MAX_OUTPUT_BYTES or any(
        byte < 32 and byte not in {9, 10, 13} or byte == 127 for byte in output
    ):
        raise ValueError(_UNAVAILABLE)
    echo = command.encode("ascii")
    prefixes = (echo + b"\r\r\n", echo + b"\r\n")
    prefix = next((value for value in prefixes if output.startswith(value)), None)
    if output.endswith(prompt + b" "):
        terminal_prompt = prompt + b" "
    elif output.endswith(prompt):
        terminal_prompt = prompt
    else:
        raise ValueError(_UNAVAILABLE)
    if prefix is None:
        raise ValueError(_UNAVAILABLE)
    body = output[len(prefix):-len(terminal_prompt)]
    if not body or not body.endswith(b"\r\n"):
        raise ValueError(_UNAVAILABLE)
    lines = tuple(body[:-2].split(b"\r\n"))
    if any(b"\r" in line or b"\n" in line for line in lines):
        raise ValueError(_UNAVAILABLE)
    return lines


def _projection_lines(lines: tuple[bytes, ...]) -> tuple[bytes, ...]:
    """Accept exactly one optional empty footer, never internal/whitespace rows."""
    if lines and lines[-1] == b"":
        lines = lines[:-1]
    if not lines or any(not line for line in lines):
        raise ValueError(_UNAVAILABLE)
    return lines


def _safe_observed_name(value: object) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= 64
            and not any(character in {'"', "\\"} or unicodedata.category(character).startswith("C")
                        for character in value))


def _folder_names(output: bytes, prompt: bytes) -> tuple[str, ...]:
    names: list[str] = []
    for line in _projection_lines(_frame_lines(output, _NAME_PROJECTION, prompt)):
        match = re.fullmatch(rb'[ \t]*set name "([^"\\\r\n]*)"[ \t]*', line)
        if match is None:
            raise ValueError(_UNAVAILABLE)
        value = match[1].decode("utf-8")
        if not _safe_observed_name(value):
            raise ValueError(_UNAVAILABLE)
        names.append(value)
    return tuple(names)


def _build29_version(line: bytes) -> bool:
    return (line.startswith(b"Version:") and b"FortiPAM" in line
            and all(32 <= byte <= 126 for byte in line)
            and re.search(rb"\bv7\.0\.0,\s*build0*29\b", line) is not None)


def _qualified_version_metadata(lines: tuple[bytes, ...]) -> bool:
    """An optional qualified release label supplies no version/role evidence."""
    versions = tuple(line for line in lines if line.startswith(b"Version:"))
    auxiliary = tuple(line for line in lines if not line.startswith(b"Version:"))
    if len(versions) != 1 or not _build29_version(versions[0]) or len(auxiliary) > 1:
        return False
    release_prefix = b"Release Version Information:"
    return all(
        line.startswith(release_prefix) and len(line) <= 256
        and bool(line[len(release_prefix):].strip(b" "))
        and all(32 <= byte <= 126 for byte in line)
        for line in auxiliary
    )
