"""Private nine-GET JWT preflight; no mutation, key-body read or generic route."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import http.client
import math
from pathlib import Path
import ssl
from threading import RLock
import time
from typing import Any
from urllib.parse import quote, urlsplit

from v4_planning.material_provider import _OpaqueC3Object

from .jwt_manual_key_actor_evidence import JwtManualKeyActorEvidence, _name, consume_jwt_manual_key_actor_inputs
from .jwt_manual_key_contract import _NAME, _digest, _require_digest
from .jwt_manual_key_preflight import JwtManualKeyPreflight, consume_jwt_manual_key_preflight
from .jwt_manual_key_request_contract import JwtManualCreateRequest
from .jwt_manual_key_response_custody import jwt_manual_create_current_digest
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable

_ERROR = "The private manual JWT-key preflight reader is unavailable."
_MAX_BYTES = 1048576
_ACTOR = "/api/v2/monitor/web-ui/state"
_MAINTENANCE = "/api/v2/cmdb/system/maintenance"
_JWT = "/api/v2/cmdb/secret/jwt-key"


class JwtManualKeyPreflightReadError(RuntimeError):
    """Fixed non-disclosing read failure; no retries or inferred absence."""


@dataclass(frozen=True, slots=True, repr=False)
class JwtManualKeyPreflightRead(_OpaqueC3Object):
    actor: JwtManualKeyActorEvidence
    state: JwtManualKeyPreflight
    source_digest: str


def jwt_manual_create_current_from_preflight(request: JwtManualCreateRequest, preflight: JwtManualKeyPreflightRead) -> str:
    """Join only the same name/device/schema/defaults to the existing M4 recipe.

    The fixed trusted reader must supply this observation. Matching digests do
    not replace native transport provenance, authorization or recovery.
    """
    try:
        if (type(request) is not JwtManualCreateRequest or type(preflight) is not JwtManualKeyPreflightRead
                or type(preflight.state) is not JwtManualKeyPreflight):
            raise ValueError
        request.validate()
        state = preflight.state
        if (state.name_digest != hashlib.sha256(request._name.encode()).hexdigest()
                or state.serial_digest != request.serial_digest or state.schema_digest != request.schema_digest
                or state.defaults_digest != request.defaults_digest):
            raise ValueError
        return jwt_manual_create_current_digest(request, preflight.actor, preflight.source_digest, state.state_digest)
    except Exception:
        raise JwtManualKeyPreflightReadError(_ERROR) from None


class JwtManualKeyPreflightReader(_OpaqueC3Object):
    def __init__(self, config: SecretMetadataHttpTransportConfig, *, name: str,
                 expected_actor: str, expected_profile: str, serial_digest: str,
                 schema_digest: str, defaults_digest: str, source_guard: Callable[[], bool] | None = None,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
                 http_clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or not callable(connection_factory)
                    or not callable(http_clock) or source_guard is not None and not callable(source_guard)
                    or type(name) is not str or len(name) > 35 or _NAME.fullmatch(name) is None
                    or type(config.timeout_seconds) not in (int, float) or not math.isfinite(config.timeout_seconds)
                    or not 1 <= config.timeout_seconds <= 60 or config.ca_file is None):
                raise ValueError
            _name(expected_actor); _name(expected_profile)
            for value in (serial_digest, schema_digest, defaults_digest):
                _require_digest(value)
            parsed = urlsplit(config.base_url)
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None
                    or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
                raise ValueError
            context = _ssl_context(config)
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._config, self._host, self._port, self._tls = config, parsed.hostname, parsed.port or 443, context
            self._name, self._actor, self._profile = name, expected_actor, expected_profile
            self._serial, self._schema, self._defaults = serial_digest, schema_digest, defaults_digest
            self._source_guard = self._source_guard_pin = source_guard
            self._factory, self._clock = connection_factory, http_clock
            self._source = self._fingerprint()
            self._paths = (_ACTOR,
                "/api/v2/cmdb/system/api-user/" + quote(expected_actor, safe="") + "?format=name%7Caccprofile",
                "/api/v2/cmdb/system/accprofile/" + quote(expected_profile, safe="") + "?format=name%7Csysgrp%7Csysgrp-permission",
                _MAINTENANCE, _JWT + "?action=schema&with_meta=true", _JWT + "?action=default&with_meta=true",
                _JWT + "?format=name%7Ctype&with_meta=true",
                "/api/v2/cmdb/system/api-user?format=name%7Ctype%7Cjwt-key&with_meta=true",
                _JWT + "/" + quote(name, safe="") + "?format=name%7Ctype&with_meta=true")
            self._last_time: float | None = None
            self._failed_clock = False
            self._deadline: float | None = None
            self._lock = RLock()
        except Exception:
            raise JwtManualKeyPreflightReadError(_ERROR) from None

    def _fingerprint(self) -> str:
        return _digest({"origin": self._config.base_url,
            "token": hashlib.sha256(self._config.bearer_token.encode()).hexdigest(),
            "ca_path": self._config.ca_file,
            "ca": hashlib.sha256(Path(self._config.ca_file or "").read_bytes()).hexdigest()})

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
            raise JwtManualKeyPreflightReadError(_ERROR) from None

    def _check_source(self) -> None:
        if (self._source_guard is None or self._source_guard is not self._source_guard_pin
                or self._source_guard() is not True or self._fingerprint() != self._source):
            raise JwtManualKeyPreflightReadError(_ERROR)

    def _remaining(self) -> float:
        if self._deadline is None:
            raise JwtManualKeyPreflightReadError(_ERROR)
        remaining = self._deadline - self._now()
        if remaining <= 0:
            raise JwtManualKeyPreflightReadError(_ERROR)
        return min(10.0, remaining)

    def _read(self, index: int) -> bytearray:
        raw, chunk = bytearray(), bytearray(4096)
        connection = response = None
        transferred = False
        try:
            if type(index) is not int or not 0 <= index < 9:
                raise ValueError
            self._check_source()
            connection = self._factory(self._host, self._port, timeout=self._remaining(), context=self._tls)
            connection.connect()
            self._check_source()
            connection.timeout = self._remaining()
            if getattr(connection, "sock", None) is not None:
                connection.sock.settimeout(connection.timeout)
            connection.request("GET", self._paths[index], headers={
                "Authorization": "Bearer " + self._config.bearer_token, "Accept": "application/json",
                "Accept-Encoding": "identity", "Connection": "close", "Cache-Control": "no-store",
                "User-Agent": "fortipam-mcp-jwt-preflight/1"})
            response = connection.getresponse()
            if (type(response.status) is not int or response.status not in ({200, 404} if index == 8 else {200})
                    or response.getheader("content-type", "").split(";", 1)[0].strip().lower() != "application/json"
                    or response.getheader("content-encoding", "identity").strip().lower() != "identity"):
                raise ValueError
            while True:
                timeout = self._remaining()
                if getattr(connection, "sock", None) is not None:
                    connection.sock.settimeout(timeout)
                count = response.readinto(chunk)
                if type(count) is not int or not 0 <= count <= len(chunk) or len(raw) + count > _MAX_BYTES:
                    raise ValueError
                if not count:
                    break
                with memoryview(chunk)[:count] as part:
                    raw.extend(part)
                chunk[:] = b"\x00" * len(chunk)
            if index == 8 and response.status != 404:
                raise ValueError
            self._check_source(); self._remaining()
            transferred = True
            return raw
        finally:
            _zeroize_mutable(chunk)
            close_error: BaseException | None = None
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException as error:
                        close_error = close_error or error
            if not transferred or close_error is not None:
                _zeroize_mutable(raw)
            if close_error is not None:
                raise close_error

    def observe(self) -> JwtManualKeyPreflightRead:
        """Read exactly nine fixed routes in one fresh source-bound window."""
        with self._lock:
            buffers: list[bytearray] = []
            try:
                self._check_source()
                self._deadline = self._now() + min(45.0, float(self._config.timeout_seconds))
                for index in range(9):
                    buffers.append(self._read(index))
                actor = consume_jwt_manual_key_actor_inputs(*buffers[:4], expected_actor=self._actor,
                    expected_profile=self._profile, serial_digest=self._serial)
                state = consume_jwt_manual_key_preflight(*buffers[4:], name=self._name, serial_digest=self._serial,
                    expected_schema_digest=self._schema, expected_defaults_digest=self._defaults)
                self._check_source(); self._remaining()
                return JwtManualKeyPreflightRead(actor, state, self._source)
            except Exception:
                raise JwtManualKeyPreflightReadError(_ERROR) from None
            finally:
                self._deadline = None
                for raw in buffers:
                    _zeroize_mutable(raw)

    def observe_actor(self) -> JwtManualKeyActorEvidence:
        """Fresh four-GET actor/Role/maintenance observation for original send."""
        with self._lock:
            buffers: list[bytearray] = []
            try:
                self._check_source()
                self._deadline = self._now() + min(45.0, float(self._config.timeout_seconds))
                for index in range(4):
                    buffers.append(self._read(index))
                actor = consume_jwt_manual_key_actor_inputs(*buffers, expected_actor=self._actor,
                    expected_profile=self._profile, serial_digest=self._serial)
                self._check_source(); self._remaining()
                return actor
            except Exception:
                raise JwtManualKeyPreflightReadError(_ERROR) from None
            finally:
                self._deadline = None
                for raw in buffers:
                    _zeroize_mutable(raw)


__all__ = ["JwtManualKeyPreflightReadError", "JwtManualKeyPreflightRead", "JwtManualKeyPreflightReader",
           "jwt_manual_create_current_from_preflight"]
