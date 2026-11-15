"""Opt-in private build29 Web creation acknowledgement, never material readback.

Success-status qualification remains a trusted source prerequisite. Only fixed
envelope metadata is decoded; unknown members/material are validated as bytes,
wiped and never returned. A numeric ACK is provenance, not cleanup authority.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import math
import re
import time
from typing import Literal, Protocol

from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

_ERROR = "The private Web creation acknowledgement is unavailable."
_MAX = 16_384
_FIELDS = frozenset({"version", "build", "http_method", "http_status", "status", "path", "name",
                     "vdom", "serial", "mkey", "error", "action", "schema_errors"})
_REQUIRED = _FIELDS - {"error", "action", "schema_errors"}


class WebSecretCreateAckError(ValueError):
    """Categorical refusal without response, device or material values."""

    def __init__(self) -> None:
        super().__init__(_ERROR)


@dataclass(frozen=True, slots=True, repr=False)
class WebSecretCreateAckCapture:
    """Private, explicitly supplied source pins; never default activation."""

    serial_digest: str
    success_status: Literal["OK", "success"] | None
    observe_source: bool = False

    def __post_init__(self) -> None:
        if (type(self.serial_digest) is not str or re.fullmatch(r"[a-f0-9]{64}", self.serial_digest) is None
                or type(self.observe_source) is not bool
                or (self.success_status is None) != self.observe_source
                or not self.observe_source and (type(self.success_status) is not str
                                                or self.success_status not in {"OK", "success"})):
            raise WebSecretCreateAckError()

    def __repr__(self) -> str:
        return "<WebSecretCreateAckCapture redacted>"

    __str__ = __repr__

    @property
    def source_digest(self) -> str:
        if self.observe_source:
            return hashlib.sha256(b"web-create-ack-source-observation/v1\0"
                                  + self.serial_digest.encode("ascii")).hexdigest()
        if self.success_status is None:
            raise WebSecretCreateAckError()
        return hashlib.sha256(b"web-create-ack-source/v1\0" + self.serial_digest.encode("ascii")
                              + b"\0" + self.success_status.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class WebSecretCreateAcknowledgement:
    """Private original response metadata; its type alone is not provenance."""

    native_secret_id: int
    serial_digest: str
    acknowledgement_digest: str
    observed_status: Literal["OK", "success"] | None = None

    def __repr__(self) -> str:
        return "<WebSecretCreateAcknowledgement redacted>"

    __str__ = __repr__


def _ack_digest(native_id: int, capture: WebSecretCreateAckCapture,
                observed_status: Literal["OK", "success"] | None = None) -> str:
    if capture.observe_source:
        if observed_status not in {"OK", "success"}:
            raise WebSecretCreateAckError()
        return hashlib.sha256(b"web-create-native-source-ack/v1\0" + capture.source_digest.encode("ascii")
            + b"\0" + str(native_id).encode("ascii") + b"\0" + str(observed_status).encode("ascii")).hexdigest()
    if observed_status is not None:
        raise WebSecretCreateAckError()
    return hashlib.sha256(b"web-create-native-ack/v1\0" + capture.source_digest.encode("ascii")
                          + b"\0" + str(native_id).encode("ascii")).hexdigest()


def _consume_database_create_ack_metadata(raw: bytearray, *, serial_digest: str,
        accepted_statuses: frozenset[str]) -> tuple[int, str]:
    """Shared byte-only CMDB envelope grammar; no profile provenance or authority."""
    # The existing byte parser imports this transport's UTF-8 validator. Resolve
    # it after module initialization instead of introducing a new parser/cycle.
    from . import secret_bulk_import_metadata as metadata
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= _MAX
                or type(serial_digest) is not str or re.fullmatch(r"[a-f0-9]{64}", serial_digest) is None
                or type(accepted_statuses) is not frozenset or not accepted_statuses
                or not accepted_statuses <= {"OK", "success"}):
            raise ValueError
        left = _skip_json_space(raw, 0)
        right = _json_value_end(raw, left)
        if _skip_json_space(raw, right) != len(raw):
            raise ValueError
        metadata._validate_json(raw, left, right, depth=0, budget=[50_000])
        spans = metadata._object_spans(raw, left, right, _FIELDS)
        if not _REQUIRED <= spans.keys() or {"action", "schema_errors"} & spans.keys():
            raise ValueError
        status = metadata._scalar(raw, spans["status"])
        if type(status) is not str or status not in {"OK", "success"}:
            raise ValueError
        if status not in accepted_statuses:
            raise ValueError
        expected: dict[str, str | int] = {"version": "v7.0.0", "build": 29, "http_method": "POST",
            "http_status": 200, "path": "secret", "name": "database", "vdom": "root"}
        for name, value in expected.items():
            actual = metadata._scalar(raw, spans[name])
            if type(actual) is not type(value) or actual != value:
                raise ValueError
        if "error" in spans:
            error = metadata._scalar(raw, spans["error"])
            if type(error) is not int or error != 0:
                raise ValueError
        serial = metadata._text(metadata._scalar(raw, spans["serial"]), maximum=128)
        if hashlib.sha256(serial.encode()).hexdigest() != serial_digest:
            raise ValueError
        identifier = metadata._integer(metadata._scalar(raw, spans["mkey"]))
        return identifier, status
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)


def consume_web_secret_create_ack(raw: bytearray, *, capture: WebSecretCreateAckCapture
        ) -> WebSecretCreateAcknowledgement:
    """Retain the existing Web source pins, digest domains and closed result."""
    try:
        if type(capture) is not WebSecretCreateAckCapture:
            raise ValueError
        capture.__post_init__()
        identifier, status = _consume_database_create_ack_metadata(raw,
            serial_digest=capture.serial_digest,
            accepted_statuses=frozenset({"OK", "success"}) if capture.observe_source
            else frozenset({str(capture.success_status)}))
        observed: Literal["OK", "success"] | None = (
            "OK" if status == "OK" else "success") if capture.observe_source else None
        return WebSecretCreateAcknowledgement(identifier, capture.serial_digest,
            _ack_digest(identifier, capture, observed), observed)
    except Exception:
        raise WebSecretCreateAckError() from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)


class _AckResponse(Protocol):
    def getheader(self, name: str) -> str | None: ...

    def readinto1(self, buffer: memoryview) -> int: ...


def read_web_secret_create_ack(response: _AckResponse, *, capture: WebSecretCreateAckCapture,
        timeout_seconds: float, clock: Callable[[], float] = time.monotonic) -> WebSecretCreateAcknowledgement:
    """Read a bounded original response; transport owns response/connection close.

    Transfer-encoded responses refuse before body reads: HTTPResponse's chunked
    readinto1 can loop through framing/trailers internally. The remaining fixed
    framing uses at most one underlying buffered read per iteration. The opt-in
    socket timeout is capped at ten seconds, with a total min(30, configured
    timeout) check before and after every read.
    """
    raw, chunk = bytearray(), bytearray(4096)
    previous: float | None = None
    try:
        if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or not 1 <= timeout_seconds <= 60:
            raise ValueError

        def now() -> float:
            nonlocal previous
            value = clock()
            if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                    or previous is not None and value < previous):
                raise ValueError
            previous = value
            return value

        deadline = now() + min(30.0, timeout_seconds)

        def check() -> None:
            if now() >= deadline:
                raise ValueError

        content_type = response.getheader("Content-Type")
        encoding = response.getheader("Content-Encoding")
        transfer_encoding = response.getheader("Transfer-Encoding")
        if (type(content_type) is not str or content_type.split(";", 1)[0].strip().lower() != "application/json"
                or encoding not in (None, "", "identity") or transfer_encoding not in (None, "")):
            raise ValueError
        while True:
            check()
            with memoryview(chunk)[:min(len(chunk), _MAX - len(raw) + 1)] as view:
                count = response.readinto1(view)
                check()
                if type(count) is not int or not 0 <= count <= len(view) or len(raw) + count > _MAX:
                    raise ValueError
                if count:
                    raw.extend(view[:count])
            for offset in range(len(chunk)):
                chunk[offset] = 0
            if not count:
                break
        result = consume_web_secret_create_ack(raw, capture=capture)
        check()
        return result
    except Exception:
        raise WebSecretCreateAckError() from None
    finally:
        _zeroize_mutable(raw)
        _zeroize_mutable(chunk)
