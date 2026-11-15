"""Fixed read-only Job reference controls; no object or recovery authority."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
import hmac
import re

from v4_planning.material_provider import _OpaqueC3Object

from .folder_namespace_ssh_reader import (
    _SERIAL_COMMAND, _VERSION_COMMAND, _frame_lines, _qualified_version_metadata,
)
from .job_definition_create_contract import _JOB_NAME
from .job_definition_http_transport import _SOURCE
from .target_preservation_contract import _digest
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport, _strict_reference_count
from .target_ssh_transport import TargetSshTransportConfig, _close_cli, _send_and_read

CONTRACT = "fortipam-build29-job-reference-control-v1"
_ERROR = "The private Job reference control is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class JobReferenceObservation(_OpaqueC3Object):
    candidate_unreferenced: bool
    anchor_unreferenced: bool
    positive_reference_count: int
    snapshot_digest: str


def read_job_reference_control(config: TargetSshTransportConfig, *, candidate_name: str,
        anchor_name: str, secret_id: int, serial: str, before_send: Callable[[], None]) -> JobReferenceObservation:
    """Calibrate two known Job links before accepting either empty reference read.

    The caller must separately qualify the same global Owner, device and actual
    API relationships. These counts neither prove absence nor original custody.
    """
    try:
        if (type(config) is not TargetSshTransportConfig or not callable(before_send)
                or type(secret_id) is not int or not 0 < secret_id <= 2147483647
                or any(type(name) is not str or len(name) > 64 or _JOB_NAME.fullmatch(name) is None
                    for name in (candidate_name, anchor_name))
                or len({candidate_name, anchor_name, _SOURCE}) != 3
                or type(serial) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", serial) is None):
            raise ValueError
        config.__post_init__()
        return asyncio.run(_read(config, candidate_name, anchor_name, secret_id, serial, before_send))
    except Exception:
        raise RuntimeError(_ERROR) from None


async def _read(config: TargetSshTransportConfig, candidate: str, anchor: str,
        secret_id: int, serial: str, guard: Callable[[], None]) -> JobReferenceObservation:
    transport = FortiPamTargetReferenceSshTransport(config)
    guard()
    async with transport._connection() as connection:
        process, prompt, deadline = await transport._open_cli(connection)
        try:
            if re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", prompt) is None:
                raise ValueError
            guard()
            raw = await _send_and_read(process, _SERIAL_COMMAND, prompt, deadline)
            lines = tuple(line for line in _frame_lines(raw, _SERIAL_COMMAND, prompt) if line.strip(b" \t"))
            if len(lines) != 1 or not hmac.compare_digest(lines[0], b"Serial-Number: " + serial.encode("ascii")):
                raise ValueError
            raw = await _send_and_read(process, _VERSION_COMMAND, prompt, deadline)
            if not _qualified_version_metadata(tuple(
                    line for line in _frame_lines(raw, _VERSION_COMMAND, prompt) if line.strip(b" \t"))):
                raise ValueError
            guard()
            command = "diagnose sys cmdb refcnt show secret.database.id " + str(secret_id)
            raw = await _send_and_read(process, command, prompt, deadline)
            positive = _strict_reference_count(raw, command, prompt)
            lines = tuple(line for line in raw.replace(b"\r", b"").split(b"\n")[1:-1] if line.strip())
            if positive <= 0 or not all(any(b"secret.job" in line and re.search(
                    rb"(?<![A-Za-z0-9_.-])" + re.escape(name.encode("ascii")) + rb"(?![A-Za-z0-9_.-])", line)
                    for line in lines) for name in (_SOURCE, anchor)):
                raise ValueError
            guard()
            for name in (anchor, candidate):
                command = "diagnose sys cmdb refcnt show secret.job.name " + name
                raw = await _send_and_read(process, command, prompt, deadline)
                if _strict_reference_count(raw, command, prompt) != 0:
                    raise ValueError
                guard()
            return JobReferenceObservation(True, True, positive,
                _digest((CONTRACT, candidate, anchor, secret_id, serial, positive, "zero-zero")))
        finally:
            await _close_cli(process)
