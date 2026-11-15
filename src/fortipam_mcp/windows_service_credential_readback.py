"""Default-closed full rows and private material brackets for one service Secret.

Only an original signed ACK selects the native ID. Seven fixed requests keep
values inside consuming byte parsers. The declared source guard and fixture must
be independently qualified; a successful callback is not source/permission proof.
No configuration write, authorization issuer, recovery action or Tool is added.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import http.client
import math
import os
import re
import ssl
from threading import RLock
import time
from typing import Any, Literal
from urllib.parse import urlsplit

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as parser
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space, _ssl_context, _zeroize_mutable,
)
from .secret_instruction_build29_api_preservation import consume_secret_instruction_build29_credential_response
from .secret_approval_build29_totp_boundary import consume_secret_approval_build29_totp_response
from .windows_service_credential_birth import WindowsServiceCredentialBirthCustody, WindowsServiceCredentialOriginalCreation
from .windows_privileged_secret_birth import WindowsReferenceSecretPristineState, _FRAME, _FRAME_FIELDS
from .windows_target_owner_source import _ca_digest
from .windows_service_credential_owner_auth import WindowsServiceCredentialOwnerSession, check_owner_session_binding

_ERROR = "The private Windows service credential full readback is unavailable."
_PHASES = frozenset({"original", "recovery-preview", "recovery-dispatch"})
_CLEAR = "/api/v2/internal/secret-clear-text"


class WindowsServiceCredentialReadbackError(RuntimeError):
    """Fixed non-disclosing failure; a consumed read never authorizes replay."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceCredentialReadbackObservation(_OpaqueC3Object):
    """Private supplied-state/source binding, not source or recovery admission."""
    original: WindowsServiceCredentialOriginalCreation
    current_state_digest: str
    original_material_seal_present: bool
    source_context_digest: str
    observed_at: float
    expires_at: float


def _receive_fixed_json(response: Any, maximum: int, *, guard: Callable[[], None],
        remaining: Callable[[], float]) -> bytearray:
    """Shared complete-stream boundary for the fixed create/readback paths."""
    raw, chunk = bytearray(), bytearray(4096)
    transferred = False
    try:
        content_type = response.getheader("Content-Type")
        if (type(response.status) is not int or response.status != 200
                or type(content_type) is not str or content_type.split(";", 1)[0].strip().lower() != "application/json"
                or response.getheader("Content-Encoding") not in (None, "", "identity")
                or response.getheader("Transfer-Encoding") not in (None, "")):
            raise ValueError
        length = response.getheader("Content-Length")
        if length is not None and (type(length) is not str or re.fullmatch(r"[0-9]{1,7}", length) is None
                or not 0 < int(length) <= maximum):
            raise ValueError
        while True:
            guard(); remaining()
            with memoryview(chunk)[:min(len(chunk), maximum-len(raw)+1)] as view:
                count = response.readinto1(view)
                guard(); remaining()
                if type(count) is not int or not 0 <= count <= len(view) or len(raw)+count > maximum:
                    raise ValueError
                if count: raw.extend(view[:count])
            for offset in range(len(chunk)): chunk[offset] = 0
            if count == 0: break
        if length is not None and len(raw) != int(length):
            raise ValueError
        transferred = True
        return raw
    finally:
        _zeroize_mutable(chunk)
        if not transferred: _zeroize_mutable(raw)


class WindowsServiceCredentialFullReader(_OpaqueC3Object):
    def __init__(self, custody: WindowsServiceCredentialBirthCustody, *,
            phase: Literal["original", "recovery-preview", "recovery-dispatch"],
            config: SecretMetadataHttpTransportConfig | None = None,
            read_enabled: bool = False, source_guard: Callable[[], bool] | None = None,
            owner_session: WindowsServiceCredentialOwnerSession | None = None,
            connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
            http_clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(custody) is not WindowsServiceCredentialBirthCustody or type(phase) is not str
                    or phase not in _PHASES or type(read_enabled) is not bool
                    or source_guard is not None and not callable(source_guard)
                    or not callable(connection_factory) or not callable(http_clock)):
                raise ValueError
            custody._validate()
            original = custody.inspect_original_creation()
            if phase == "original":
                custody._writing_now()
                if original.native_uuid is not None or original.original_outcome != "in_progress":
                    raise ValueError
            elif original.original_outcome == "in_progress" or original.native_uuid is None:
                raise ValueError
            config = custody._config if config is None else config
            if (type(config) is not SecretMetadataHttpTransportConfig
                    or config.base_url != custody._config.base_url
                    or _ca_digest(config) != _ca_digest(custody._config)
                    or phase == "original" and config != custody._config):
                raise ValueError
            config.__post_init__()
            check_owner_session_binding(config, custody._owner_binding, owner_session,
                purpose="create" if phase == "original" else "recovery")
            origin = urlsplit(config.base_url)
            if origin.hostname is None or origin.username is not None or origin.password is not None:
                raise ValueError
            context = _ssl_context(config)
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._custody: WindowsServiceCredentialBirthCustody = custody
            self._config: SecretMetadataHttpTransportConfig = config
            self._owner_session: WindowsServiceCredentialOwnerSession | None = owner_session
            self._owner_session_pin: WindowsServiceCredentialOwnerSession | None = owner_session
            self._source: str = self._source_digest()
            self._original: WindowsServiceCredentialOriginalCreation = original
            self._sealed_result: WindowsServiceCredentialOriginalCreation | None = None
            self._phase: str = phase
            self._phase_pin: str = phase
            self._context: str = custody._context
            self._parameters: str = custody._profile.parameters_digest
            self._enabled: bool = read_enabled
            self._source_guard: Callable[[], bool] | None = source_guard
            self._source_pin: Callable[[], bool] | None = source_guard
            self._factory: Callable[..., Any] = connection_factory
            self._factory_pin: Callable[..., Any] = connection_factory
            self._clock: Callable[[], float] = http_clock
            self._clock_pin: Callable[[], float] = http_clock
            self._tls: ssl.SSLContext = context
            self._host: str = origin.hostname
            self._port: int = origin.port or 443
            self._attempt: str = "full-read." + phase + ".attempt.json"
            self._result: str = "full-read." + phase + ".result.json"
            self._started: bool = False
            self._failed_clock: bool = False
            self._last_time: float | None = None
            self._deadline: float | None = None
            self._attempt_identity: tuple[int, int] | None = None
            self._password_field_id: int | None = None
            self._lock: RLock = RLock()
        except Exception:
            raise WindowsServiceCredentialReadbackError(_ERROR) from None

    def _source_digest(self) -> str:
        self._config.__post_init__()
        observer = canonical_digest(dict(origin=self._config.base_url, ca=_ca_digest(self._config),
            bearer=hashlib.sha256(self._config.bearer_token.encode()).hexdigest(),
            timeout=self._config.timeout_seconds, serial=self._custody._profile.serial_digest))
        if self._owner_session is None:
            return observer
        return canonical_digest(dict(metadata_observer=observer, actual_authentication="owner-cookie",
            principal=self._owner_session.binding.binding_digest))

    def _now(self) -> float:
        try:
            value = self._clock()
            if (self._failed_clock or type(value) not in (int, float) or not math.isfinite(value)
                    or value < 0 or self._last_time is not None and value < self._last_time):
                raise ValueError
            self._last_time = float(value)
            return float(value)
        except Exception:
            self._failed_clock = True
            raise WindowsServiceCredentialReadbackError(_ERROR) from None

    def _remaining(self) -> float:
        if self._deadline is None:
            raise ValueError
        remaining = self._deadline - self._now()
        if remaining <= 0:
            raise ValueError
        return min(10.0, remaining)

    def _guard(self) -> None:
        if self._owner_session is not self._owner_session_pin:
            raise ValueError
        purpose: Literal["create", "recovery"] = "create" if self._phase == "original" else "recovery"
        check_owner_session_binding(self._config, self._custody._owner_binding, self._owner_session, purpose=purpose)
        if self._owner_session is not None:
            self._owner_session.require_current(self._custody, config=self._config, purpose=purpose)
        if (self._enabled is not True or self._source_guard is None
                or self._source_guard is not self._source_pin or self._source_guard() is not True
                or self._phase != self._phase_pin or self._phase not in _PHASES
                or self._attempt != "full-read." + self._phase_pin + ".attempt.json"
                or self._result != "full-read." + self._phase_pin + ".result.json"
                or self._factory is not self._factory_pin or self._clock is not self._clock_pin
                or self._source_digest() != self._source
                or not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED
                or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2
                or self._custody._context != self._context
                or self._custody._profile.parameters_digest != self._parameters
                or self._custody.inspect_original_creation() != (self._sealed_result or self._original)):
            raise ValueError
        origin = urlsplit(self._config.base_url)
        if self._host != origin.hostname or self._port != (origin.port or 443):
            raise ValueError
        if self._phase == "original": self._custody._writing_now()
        else: self._custody._validate()
        if self._attempt_identity is not None:
            info = (self._custody._directory / self._attempt).stat()
            if (info.st_dev, info.st_ino) != self._attempt_identity:
                raise ValueError
            record = self._custody._record(self._attempt,
                frozenset({"context_digest", "original_digest", "phase_digest", "source_context_digest"}))
            if (record["original_digest"] != self._original.custody_digest
                    or record["phase_digest"] != canonical_digest(self._phase)
                    or record["source_context_digest"] != self._source):
                raise ValueError

    def _receive(self, response: Any, maximum: int) -> bytearray:
        return _receive_fixed_json(response, maximum, guard=self._guard, remaining=self._remaining)

    def _request(self, field_id: int | None = None, *, totp: bool = False) -> bytearray:
        raw = bytearray()
        connection = response = None
        transferred = False
        try:
            self._guard(); self._remaining()
            if totp and field_id is not None:
                raise ValueError
            native_id = self._original.native_secret_id
            if field_id is not None or totp:
                original_frame = self._custody._record(_FRAME, _FRAME_FIELDS)
                if (self._password_field_id is None or self._password_field_id != original_frame["password_field_id"]
                        or field_id is not None and field_id != self._password_field_id):
                    raise ValueError
            path = "/api/v2/cmdb/secret/database/" + str(native_id) + "?with_meta=true&vdom=root"
            body = None
            if field_id is not None or totp:
                path = _CLEAR
                body = ('{"secret-id":' + str(native_id) + (',"totp-share-key":1}' if totp
                    else ',"field-id":' + str(field_id) + '}')).encode("ascii")
            connection = self._factory(self._host, self._port, timeout=self._remaining(), context=self._tls)
            connection.connect()
            self._guard(); self._remaining()
            headers = {"Authorization": "Bearer " + self._config.bearer_token,
                "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close", "Cache-Control": "no-store",
                "User-Agent": "fortipam-mcp-service-credential/1"}
            if body is not None: headers["Content-Type"] = "application/json"
            if self._owner_session is not None:
                headers = self._owner_session._headers("material" if body is not None else "full", self._custody, config=self._config)
            connection.request("POST" if body is not None else "GET", path, body=body, headers=headers)
            response = connection.getresponse()
            raw = self._receive(response, 16384 if body is not None else 1048576)
            self._guard(); self._remaining()
            # Close before transferring the buffer: even a post-EOF close failure
            # must clear it and retain the original consumed read attempt.
            response.close(); response = None
            connection.close(); connection = None
            self._guard(); self._remaining()
            transferred = True
            return raw
        finally:
            try:
                try:
                    if response is not None: response.close()
                finally:
                    if connection is not None: connection.close()
            finally:
                if not transferred: _zeroize_mutable(raw)

    def _envelope(self, raw: bytearray, field_id: int | None) -> dict[str, str | int]:
        left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
        if _skip_json_space(raw, right) != len(raw): raise ValueError
        parser._validate_json(raw, left, right, depth=0, budget=[50000])
        fields = _object_spans(raw, left, right)
        wanted: dict[str, str | int] = dict(version="v7.0.0", build=29, http_method="POST", http_status=200,
            status="OK", serial="", msg="Success", **{"secret-id": self._original.native_secret_id})
        serial = parser._text(parser._scalar(raw, fields["serial"]), maximum=128)
        if hashlib.sha256(serial.encode()).hexdigest() != self._custody._profile.serial_digest:
            raise ValueError
        wanted["serial"] = serial
        if field_id is not None: wanted["field-id"] = field_id
        if set(fields) != set(wanted) | {"results"}: raise ValueError
        for name, expected in wanted.items():
            value = parser._scalar(raw, fields[name])
            if type(value) is not type(expected) or value != expected: raise ValueError
        return wanted

    def read_once(self, *, max_deadline: float | None = None) -> WindowsServiceCredentialReadbackObservation:
        initial = before = after = raw = bytearray()
        key = bytearray()
        try:
            with self._lock:
                if self._started: raise ValueError
                self._started = True
                if os.path.lexists(self._custody._directory/self._attempt) or os.path.lexists(self._custody._directory/self._result):
                    raise ValueError
                self._guard()
                self._custody._write(self._attempt, {"context_digest": self._context,
                    "original_digest": self._original.custody_digest, "phase_digest": canonical_digest(self._phase),
                    "source_context_digest": self._source})
                info = (self._custody._directory/self._attempt).stat()
                self._attempt_identity = info.st_dev, info.st_ino
                self._deadline = self._now() + min(30.0, float(self._config.timeout_seconds))
                if max_deadline is not None:
                    if type(max_deadline) not in (int,float) or not math.isfinite(max_deadline): raise ValueError
                    self._deadline = min(self._deadline, max_deadline)
                self._remaining()
                key.extend(self._custody._material_key())
                native_id = self._original.native_secret_id
                initial = self._request()
                if self._phase == "original":
                    frame = self._custody.capture_original_frame(initial)
                    self._sealed_result = frame.original
                    native_uuid, field_id, initial_frame = frame.native_uuid, frame.password_field_id, frame.framing_digest
                else:
                    native_uuid, field_id, initial_frame = self._custody._full_frame(initial, native_id, key,
                        self._original.native_uuid)
                original_frame = self._custody._record(_FRAME, _FRAME_FIELDS)
                if (native_uuid != original_frame["native_uuid"] or field_id != original_frame["password_field_id"]
                        or initial_frame != original_frame["framing_digest"]):
                    raise ValueError
                self._password_field_id = field_id
                raw = self._request(field_id)
                password_before = consume_secret_instruction_build29_credential_response(raw,
                    expected_secret_id=native_id, expected_field_id=field_id, http_status=200,
                    content_type="application/json", expected_envelope=self._envelope(raw, field_id), witness_key=key)
                raw = self._request(totp=True)
                totp_before = consume_secret_approval_build29_totp_response(raw, http_status=200,
                    content_type="application/json", expected_envelope=self._envelope(raw, None), witness_key=key)
                before = self._request()
                uuid_before, id_before, before_frame = self._custody._full_frame(before, native_id, key, native_uuid)
                if (uuid_before != native_uuid or id_before != field_id or initial_frame != before_frame): raise ValueError
                raw = self._request(field_id)
                password_after = consume_secret_instruction_build29_credential_response(raw,
                    expected_secret_id=native_id, expected_field_id=field_id, http_status=200,
                    content_type="application/json", expected_envelope=self._envelope(raw, field_id), witness_key=key)
                raw = self._request(totp=True)
                totp_after = consume_secret_approval_build29_totp_response(raw, http_status=200,
                    content_type="application/json", expected_envelope=self._envelope(raw, None), witness_key=key)
                after = self._request()
                self._guard(); self._remaining()
                if self._phase == "original":
                    original_result = self._custody.capture_original_birth(before, after,
                        password_before=password_before, password_after=password_after,
                        totp_before=totp_before, totp_after=totp_after)
                    if original_result.state_digest is None: raise ValueError
                    result = WindowsReferenceSecretPristineState(original_result, original_result.state_digest, True)
                else:
                    result = self._custody.consume_original_frame_state(before, after,
                        password_before=password_before, password_after=password_after,
                        totp_before=totp_before, totp_after=totp_after)
                self._sealed_result = result.original
                self._guard(); self._remaining()
                self._custody._write(self._result, {"context_digest": self._context,
                    "original_digest": result.original.custody_digest, "state_digest": result.current_state_digest,
                    "phase_digest": canonical_digest(self._phase), "source_context_digest": self._source})
                self._guard(); self._remaining()
                return WindowsServiceCredentialReadbackObservation(result.original, result.current_state_digest,
                    result.original_material_seal_present, self._source, self._now(), self._deadline)
        except Exception:
            raise WindowsServiceCredentialReadbackError(_ERROR) from None
        finally:
            for buffer in (initial, before, after, raw, key): _zeroize_mutable(buffer)
