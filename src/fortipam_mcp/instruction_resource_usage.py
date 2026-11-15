"""Inactive build-29 Instruction storage-usage source; no mutation authority.

The five native byte counts remain opaque. Unknown or malformed capacity is
rejected instead of using the frontend's zero-valued error fallback. A snapshot
does not establish quota headroom, upload permission, ownership, or cleanup.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import math
import ssl
import time
from typing import cast
from urllib.parse import urlsplit

import httpx

from v4_planning.material_provider import _OpaqueC3Object
from . import secret_bulk_import_metadata as m
from . import target_lifecycle_dependencies as d
from .instruction_feature_contract import _digest
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable,
)
from .target_api_dependency_reader import _private_http_logs

CONTRACT = "fortipam-700-build29-instruction-resource-usage-private-v1"
_PATH = "/api/v2/monitor/log/current-disk-usage"
_FIELDS = ("video_disk_total_bytes", "video_used_bytes", "sec_file_used_bytes",
           "software_package_used_bytes", "sec_instruction_used_bytes")
_LIMIT = 524288
_ERROR = "The private Instruction resource usage source is unavailable."


class InstructionResourceUsageError(ValueError):
    """A categorical refusal without raw inventory, response, or partial usage."""


@dataclass(frozen=True, slots=True, repr=False, init=False)
class InstructionResourceUsage(_OpaqueC3Object):
    """Private device-bound counts; neither a reservation nor a quota plan."""

    _serial: str
    _bytes: tuple[int, int, int, int, int]
    _state: str

    def __init__(self) -> None:
        raise InstructionResourceUsageError(_ERROR)

    @property
    def instruction_usage_zero(self) -> bool:
        return self._bytes[4] == 0


def project_instruction_resource_usage(raw: bytearray, *, serial_digest: str) -> InstructionResourceUsage:
    """Consume one strict native monitor envelope and wipe the input on all exits."""
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= _LIMIT
                or type(serial_digest) is not str or m._DIGEST.fullmatch(serial_digest) is None):
            raise ValueError
        envelope = d._spans(raw)
        serial = m._scalar(raw, envelope["serial"])
        if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != serial_digest:
            raise ValueError
        span = d._envelope(raw, path="log", name="current-disk-usage",
                           serial_digest=serial_digest, monitor=True)
        fields = m._object_spans(raw, *span, frozenset(_FIELDS))
        if set(fields) != set(_FIELDS):
            raise ValueError
        selected = tuple(m._scalar(raw, fields[key]) for key in _FIELDS)
        if any(type(value) is not int or not 0 <= value <= 2**53 - 1 for value in selected):
            raise ValueError
        values = cast(tuple[int, int, int, int, int], selected)
        total, *used = values
        if total <= 0 or any(value > total for value in used) or sum(used) > total:
            raise ValueError
        state = object.__new__(InstructionResourceUsage)
        object.__setattr__(state, "_serial", serial_digest)
        object.__setattr__(state, "_bytes", values)
        object.__setattr__(state, "_state", _digest([CONTRACT, serial_digest, values]))
        return state
    except Exception:
        raise InstructionResourceUsageError(_ERROR) from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)


def read_instruction_resource_usage(config: SecretMetadataHttpTransportConfig, *,
        serial_digest: str, client_factory: Callable[..., httpx.Client] = httpx.Client,
        clock: Callable[[], float] = time.monotonic) -> InstructionResourceUsage:
    """One strict-TLS GET, bounded by body size and one deadline, with no retry."""
    raw = bytearray()
    client = response = None
    previous: float | None = None
    try:
        if type(config) is not SecretMetadataHttpTransportConfig:
            raise ValueError
        config.__post_init__()
        origin = urlsplit(config.base_url)
        if (not origin.hostname or origin.username is not None or origin.password is not None
                or type(serial_digest) is not str or m._DIGEST.fullmatch(serial_digest) is None):
            raise ValueError
        context = _ssl_context(config)
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        def now() -> float:
            nonlocal previous
            value = clock()
            if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                    or previous is not None and value < previous):
                raise ValueError
            previous = value
            return value

        deadline = now() + min(30.0, config.timeout_seconds)

        def remaining() -> float:
            value = deadline - now()
            if value <= 0:
                raise ValueError
            return min(10.0, value)

        with _private_http_logs(), client_factory(verify=context, timeout=remaining(),
                follow_redirects=False, trust_env=False) as client:
            try:
                with client.stream("GET", config.base_url.rstrip("/") + _PATH,
                        headers={"Authorization": "Bearer " + config.bearer_token,
                            "Accept": "application/json", "Accept-Encoding": "identity",
                            "Cache-Control": "no-store", "Connection": "close",
                            "User-Agent": "fortipam-mcp-target-lifecycle/1"},
                        timeout=remaining()) as response:
                    remaining()
                    if (response.status_code != 200
                            or response.headers.get("content-type", "").split(";")[0].lower() != "application/json"
                            or response.headers.get("content-encoding", "identity") not in ("", "identity")):
                        raise ValueError
                    for chunk in response.iter_raw():
                        remaining()
                        if len(raw) + len(chunk) > _LIMIT:
                            raise ValueError
                        raw.extend(chunk)
                    remaining()
                result = project_instruction_resource_usage(raw, serial_digest=serial_digest)
                remaining()
            finally:
                client.cookies.clear()
        remaining()
        if not client.is_closed or len(client.cookies) or response is None or not response.is_closed:
            raise ValueError
        return result
    except Exception:
        raise InstructionResourceUsageError(_ERROR) from None
    finally:
        _zeroize_mutable(raw)
