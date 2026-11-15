"""Private build-29 top-level Secret namespace observation; no write authority."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import unicodedata

from v4_planning import canonical_digest

from .folder_namespace_ssh_reader import (
    _SERIAL_COMMAND, _VERSION_COMMAND, _frame_lines, _projection_lines, _qualified_version_metadata,
)
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport
from .target_ssh_transport import (
    TargetSshTransportConfig, _close_cli, _require_root_prompt, _send_and_read, _send_and_read_dynamic_prompt,
)


_UNAVAILABLE = "FortiPAM Secret namespace evidence is unavailable."
_NAME_PROJECTION = 'show full-configuration | grep "^        set name "'
_FOLDER_PROJECTION = 'show full-configuration | grep "^        set folder "'


class SecretNamespaceSshReaderError(RuntimeError):
    """Stable non-disclosing failure for unqualified or incomplete evidence."""


@dataclass(frozen=True, slots=True)
class SecretNamespaceObservation:
    status: str
    secret_count: int
    positive_witness_count: int
    namespace_digest: str
    global_name_absent: bool


class FortiPamSecretNamespaceSshReader:
    """Read one compiled candidate with caller-qualified Owner/API witnesses.

    The caller must freshly bind an enabled local nonwildcard super_admin
    Owner, API build/serial and two exact existing Secret witnesses. Separate
    CLI columns are not associated; any occurrence of the name denies absence.
    """

    def __init__(self, config: TargetSshTransportConfig, *, candidate_name: str,
                 positive_witness_names: tuple[str, ...], expected_device_serial: str) -> None:
        if (not isinstance(config, TargetSshTransportConfig)
            or not isinstance(candidate_name, str) or len(candidate_name) > 64
            or re.fullmatch(r"mcp-v4-[A-Za-z0-9][A-Za-z0-9._-]*", candidate_name) is None
            or not isinstance(positive_witness_names, tuple) or len(positive_witness_names) < 2
            or any(not _safe_secret_name(value) for value in positive_witness_names)
            or len(set(positive_witness_names)) != len(positive_witness_names)
            or not isinstance(expected_device_serial, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_device_serial) is None):
            raise ValueError(_UNAVAILABLE)
        self._ssh = FortiPamTargetReferenceSshTransport(config)
        self._candidate_name = candidate_name
        self._witness_names = positive_witness_names
        self._device_serial = expected_device_serial

    def read_namespace(self) -> SecretNamespaceObservation:
        try:
            return asyncio.run(self._read_namespace())
        except Exception:
            raise SecretNamespaceSshReaderError(_UNAVAILABLE) from None

    async def _read_namespace(self) -> SecretNamespaceObservation:
        async with self._ssh._connection() as connection:
            process, prompt, deadline = await self._ssh._open_cli(connection)
            try:
                if re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", prompt) is None:
                    raise ValueError(_UNAVAILABLE)
                serial_output = await _send_and_read(process, _SERIAL_COMMAND, prompt, deadline)
                serial_lines = tuple(line for line in _frame_lines(serial_output, _SERIAL_COMMAND, prompt)
                                     if line.strip(b" \t"))
                if (len(serial_lines) != 1 or not hmac.compare_digest(
                    serial_lines[0], b"Serial-Number: " + self._device_serial.encode("ascii"),
                )):
                    raise ValueError(_UNAVAILABLE)
                version_output = await _send_and_read(process, _VERSION_COMMAND, prompt, deadline)
                version_lines = tuple(line for line in _frame_lines(version_output, _VERSION_COMMAND, prompt)
                                      if line.strip(b" \t"))
                if not _qualified_version_metadata(version_lines):
                    raise ValueError(_UNAVAILABLE)
                database_prompt = await _send_and_read_dynamic_prompt(
                    process, "config secret database", prompt, deadline,
                )
                if database_prompt != prompt[:-2] + b" (database) #":
                    raise ValueError(_UNAVAILABLE)
                first_names = await _send_and_read(process, _NAME_PROJECTION, database_prompt, deadline)
                names = _secret_names(first_names, database_prompt)
                folder_output = await _send_and_read(process, _FOLDER_PROJECTION, database_prompt, deadline)
                folders = _secret_folder_values(folder_output, database_prompt)
                second_names = await _send_and_read(process, _NAME_PROJECTION, database_prompt, deadline)
                _secret_names(second_names, database_prompt)
                if not hmac.compare_digest(first_names, second_names) or len(names) != len(folders):
                    raise ValueError(_UNAVAILABLE)
                if any(witness not in names for witness in self._witness_names):
                    raise ValueError(_UNAVAILABLE)
                returned = await _send_and_read_dynamic_prompt(process, "end", prompt, deadline)
                _require_root_prompt(prompt, returned)
                if returned != prompt:
                    raise ValueError(_UNAVAILABLE)
                absent = self._candidate_name not in names
                return SecretNamespaceObservation(
                    status="name_absent" if absent else "name_present", secret_count=len(names),
                    positive_witness_count=len(self._witness_names), global_name_absent=absent,
                    namespace_digest=_namespace_digest(names, folders),
                )
            finally:
                await _close_cli(process)


def _namespace_digest(names: tuple[str, ...], folders: tuple[int, ...]) -> str:
    # Keep all retained v1 fingerprints exactly as issued. Larger qualified
    # private columns do not belong in the frozen M2 64-item value envelope.
    if len(names) <= 64:
        return canonical_digest({
            "contract": "fortipam-700-build29-secret-name-namespace-candidate-v1",
            "names": list(names), "folder_values": list(folders),
        })
    def column_digest(values: tuple[str, ...] | tuple[int, ...]) -> str:
        return hashlib.sha256(json.dumps(values, ensure_ascii=True,
            separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()
    # Columns stay separate: the digest does not assert row association.
    # Both complete frames have already passed their native 64-KiB bounds.
    return canonical_digest({
        "contract": "fortipam-700-build29-secret-name-namespace-columns-v2",
        "column_count": len(names), "names_digest": column_digest(names),
        "folder_values_digest": column_digest(folders),
    })


def _safe_secret_name(value: object) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= 255
            and not any(character in {'"', "\\"} or unicodedata.category(character).startswith("C")
                        for character in value))


def _secret_names(output: bytes, prompt: bytes) -> tuple[str, ...]:
    values: list[str] = []
    for line in _projection_lines(_frame_lines(output, _NAME_PROJECTION, prompt)):
        match = re.fullmatch(rb'        set name "([^"\\\r\n]*)"', line)
        if match is None:
            raise ValueError(_UNAVAILABLE)
        value = match[1].decode("utf-8")
        if not _safe_secret_name(value):
            raise ValueError(_UNAVAILABLE)
        values.append(value)
    return tuple(values)


def _secret_folder_values(output: bytes, prompt: bytes) -> tuple[int, ...]:
    values: list[int] = []
    for line in _projection_lines(_frame_lines(output, _FOLDER_PROJECTION, prompt)):
        match = re.fullmatch(rb"        set folder (0|[1-9][0-9]*)", line)
        if match is None or int(match[1]) > 2_147_483_647:
            raise ValueError(_UNAVAILABLE)
        values.append(int(match[1]))
    return tuple(values)
