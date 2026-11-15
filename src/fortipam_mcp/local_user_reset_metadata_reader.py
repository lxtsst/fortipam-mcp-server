"""Four fixed read-only BP002 routes; no fixture or reset authorization."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
import hashlib
import http.client
import hmac
import json
import re
import ssl
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from v4_planning.material_provider import C3MaterialBinding

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .local_user_reset_http_transport import _NAME, _members
from .local_user_reset_projection import (
    LocalUserResetUserProjection, _object_spans, _schema_fields, _string_or_empty,
    project_local_user_reset_detail,
)
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space,
    _ssl_context, _zeroize_mutable,
)

_SCHEMA = "/api/v2/cmdb/system/admin?action=schema&with_meta=true"
_TYPES = "/api/v2/monitor/web-ui/object-urls"
_USAGE = "/api/v2/monitor/system/object/usage"
_MAX_BYTES = 1_048_576
_UNAVAILABLE = "The private Local User reset metadata read is unavailable."


class LocalUserResetReadFailure(str, Enum):
    AUTHORIZATION_DENIED = "authorization_denied"
    NOT_FOUND = "not_found"
    TIMED_OUT = "timed_out"
    TRANSPORT_UNAVAILABLE = "transport_unavailable"
    UNQUALIFIED_RESPONSE = "unqualified_response"


class LocalUserResetMetadataReadError(RuntimeError):
    def __init__(self, reason: LocalUserResetReadFailure) -> None:
        super().__init__(_UNAVAILABLE)
        self.reason = reason


@dataclass(frozen=True, slots=True, repr=False)
class LocalUserResetMetadataObservation(C3MaterialBinding):
    """Product reports only; creation provenance is deliberately not supplied."""

    user: LocalUserResetUserProjection
    usage_entry_count: int


class FortiPamLocalUserResetMetadataReader:
    """Full reads for one constructor-bound reset-namespace user, never a relay.

No public method accepts a selector, method, body or path. This reader does
not create a LocalUserResetBaseline or attest a fixture-creation digest.
    """

    def __init__(self, config: SecretMetadataHttpTransportConfig, *, username: str,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection) -> None:
        try:
            if type(config) is not SecretMetadataHttpTransportConfig:
                raise ValueError
            origin = urlsplit(config.base_url)
            port = 443 if origin.port is None else origin.port
            if (origin.scheme != "https" or not origin.hostname or origin.username is not None
                or origin.password is not None or origin.path not in {"", "/"}
                or origin.query or origin.fragment or not 1 <= port <= 65535
                or not isinstance(username, str) or len(username) > 64 or _NAME.fullmatch(username) is None
                or not callable(connection_factory)):
                raise ValueError
            context = _ssl_context(config)
            if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                raise ValueError
        except Exception:
            raise LocalUserResetMetadataReadError(LocalUserResetReadFailure.UNQUALIFIED_RESPONSE) from None
        self._config, self._username, self._factory = config, username, connection_factory
        self._host, self._port, self._context = origin.hostname, port, context
        self._detail = f"/api/v2/cmdb/system/admin/{quote(username, safe='')}?with_meta=true"

    def read_device_identity_digest(self) -> str:
        """Bind the fixed schema endpoint's device identity without exposing it."""
        content = self._read(_SCHEMA)
        try:
            schema = json.loads(content)
            _schema_fields(schema)
            start = _skip_json_space(content, 0)
            end = _json_value_end(content, start)
            _object_spans(content, start, end)
            serial = schema.get("serial")
            if type(serial) is not str or re.fullmatch(r"[A-Za-z0-9-]{8,64}", serial) is None:
                raise ValueError
            return _device_identity_digest(serial.encode("ascii"))
        except Exception:
            raise LocalUserResetMetadataReadError(LocalUserResetReadFailure.UNQUALIFIED_RESPONSE) from None
        finally:
            _zeroize_mutable(content)

    def read_observation(self) -> LocalUserResetMetadataObservation:
        """Require an exact existing user before asking for reported usage."""
        buffers: list[bytearray] = []
        try:
            schema_body = self._read(_SCHEMA)
            buffers.append(schema_body)
            schema = json.loads(schema_body)
            _schema_fields(schema)
            detail = self._read(self._detail)
            buffers.append(detail)
            user = project_local_user_reset_detail(detail, schema, expected_username=self._username)
            qtype = self._read_user_type()
            query = urlencode({"mkey": self._username, "qtypes": json.dumps([qtype], separators=(",", ":"))})
            usage = self._read(_USAGE, usage_query=query, qtype=qtype)
            buffers.append(usage)
            left, right = _monitor_results(usage, expected_route="system/object/usage", expected_mkey=self._username)
            result = _object_spans(usage, left, right)
            # Missing/wrong-type is never the GUI's empty-array fallback.
            if "currently_using" not in result:
                raise ValueError
            for field_left, field_right in result.values():
                _validate_value(usage, field_left, field_right, depth=0)
            count = _array_count(usage, *result["currently_using"], depth=0, objects_only=True)
            return LocalUserResetMetadataObservation(user, count)
        except LocalUserResetMetadataReadError:
            raise
        except Exception:
            raise LocalUserResetMetadataReadError(LocalUserResetReadFailure.UNQUALIFIED_RESPONSE) from None
        finally:
            for content in buffers:
                _zeroize_mutable(content)

    def _read_user_type(self) -> int:
        content = self._read(_TYPES)
        try:
            left, right = _monitor_results(content, expected_route="web-ui/object-urls")
            result = _object_spans(content, left, right)
            if "by_type" not in result:
                raise ValueError
            # This endpoint is source metadata, not a User/material response.
            with memoryview(content)[left:right] as view:
                _validate_value(content, left, right, depth=0)
                mapping = json.loads(view.tobytes())["by_type"]
            if not isinstance(mapping, dict):
                raise ValueError
            matches = [key for key, value in mapping.items()
                       if isinstance(value, dict) and value.get("path") == "system.admin"]
            if (len(matches) != 1 or not isinstance(matches[0], str)
                or re.fullmatch(r"0|[1-9][0-9]{0,8}", matches[0]) is None):
                raise ValueError
            return int(matches[0])
        except Exception:
            raise LocalUserResetMetadataReadError(LocalUserResetReadFailure.UNQUALIFIED_RESPONSE) from None
        finally:
            _zeroize_mutable(content)

    def _read(self, path: str, *, usage_query: str | None = None, qtype: int | None = None) -> bytearray:
        content = bytearray()
        try:
            content = bytearray(_MAX_BYTES + 1)
            connection = response = None
            transfer = False
            reason = LocalUserResetReadFailure.TRANSPORT_UNAVAILABLE
            try:
                if path == _USAGE:
                    if (type(qtype) is not int or not 0 <= qtype <= 999_999_999
                        or usage_query != urlencode({"mkey": self._username,
                            "qtypes": json.dumps([qtype], separators=(",", ":"))})):
                        raise ValueError
                    target = path + "?" + usage_query
                elif path in {_SCHEMA, _TYPES, self._detail} and usage_query is None and qtype is None:
                    target = path
                else:
                    raise ValueError
                connection = self._factory(self._host, self._port,
                    timeout=self._config.timeout_seconds, context=self._context)
                connection.request("GET", target, headers={
                    "Accept": "application/json", "Accept-Encoding": "identity",
                    "Authorization": f"Bearer {self._config.bearer_token}", "Connection": "close",
                    "Cache-Control": "no-cache, no-store", "User-Agent": "fortipam-bp002-metadata-read/1",
                })
                response = connection.getresponse()
                if response.status in {401, 403}:
                    raise LocalUserResetMetadataReadError(LocalUserResetReadFailure.AUTHORIZATION_DENIED)
                if response.status == 404:
                    raise LocalUserResetMetadataReadError(LocalUserResetReadFailure.NOT_FOUND)
                reason = LocalUserResetReadFailure.UNQUALIFIED_RESPONSE
                if (type(response.status) is not int or response.status != 200
                    or response.getheader("content-type", "").split(";", 1)[0].strip().lower() != "application/json"
                    or response.getheader("content-encoding", "identity").strip().lower() != "identity"):
                    raise ValueError
                total = 0
                while total < len(content):
                    with memoryview(content)[total:] as view:
                        count = response.readinto(view)
                    if type(count) is not int or not 0 <= count <= len(content) - total:
                        raise ValueError
                    if not count:
                        break
                    total += count
                if total > _MAX_BYTES:
                    raise ValueError
                content = _take_mutable_prefix(content, total)
                transfer = True
                return content
            except LocalUserResetMetadataReadError:
                raise
            except TimeoutError:
                raise LocalUserResetMetadataReadError(LocalUserResetReadFailure.TIMED_OUT) from None
            except (OSError, http.client.HTTPException):
                raise LocalUserResetMetadataReadError(LocalUserResetReadFailure.TRANSPORT_UNAVAILABLE) from None
            except Exception:
                raise LocalUserResetMetadataReadError(reason) from None
            finally:
                if not transfer:
                    _zeroize_mutable(content)
                for resource in (response, connection):
                    if resource is not None:
                        try:
                            resource.close()
                        except Exception:
                            pass
        except BaseException:
            _erase_transfer_storage(content)
            raise


def _device_identity_digest(serial: bytes) -> str:
    return hashlib.sha256(b"bp002-device-identity/v1\0" + serial).hexdigest()


def _monitor_results(content: bytearray, *, expected_route: str,
                     expected_mkey: str | None = None) -> tuple[int, int]:
    start = _skip_json_space(content, 0)
    end = _json_value_end(content, start)
    if _skip_json_space(content, end) != len(content):
        raise ValueError
    allowed = {
        b'"http_method"', b'"results"', b'"vdom"', b'"path"', b'"name"', b'"action"',
        b'"status"', b'"serial"', b'"version"', b'"build"', b'"http_status"',
    }
    if expected_mkey is not None:
        allowed.add(b'"mkey"')
    fields = _members(content, start, end, allowed)
    if expected_mkey is not None:
        with memoryview(content)[slice(*fields[b'"mkey"'])] as token:
            if not hmac.compare_digest(token, json.dumps(expected_mkey).encode("ascii")):
                raise ValueError
    for key, value in {b'"http_method"': b'"GET"', b'"status"': b'"success"',
        b'"version"': b'"v7.0.0"', b'"build"': b'29'}.items():
        with memoryview(content)[slice(*fields[key])] as token:
            if token != value:
                raise ValueError
    if b'"http_status"' in fields:
        with memoryview(content)[slice(*fields[b'"http_status"'])] as token:
            if not hmac.compare_digest(token, b"200"):
                raise ValueError
    route = []
    for key in (b'"path"', b'"name"', b'"action"'):
        if key not in fields and key == b'"action"':
            continue
        left, right = fields[key]
        with memoryview(content)[left:right] as token:
            _string_or_empty(token)
            value = json.loads(content[left:right])
        if value:
            route.append(value)
    if "/".join(route) != expected_route:
        raise ValueError
    for key in (b'"serial"', b'"vdom"'):
        if key in fields:
            with memoryview(content)[slice(*fields[key])] as token:
                _string_or_empty(token)
    return fields[b'"results"']


def _array_count(content: bytearray, start: int, end: int, *, depth: int, objects_only: bool = False) -> int:
    if depth > 16 or content[start] != 91 or content[end - 1] != 93:
        raise ValueError
    cursor, count = _skip_json_space(content, start + 1), 0
    while cursor < end - 1:
        if count >= 4096:
            raise ValueError
        if objects_only and content[cursor] != 123:
            raise ValueError
        right = _json_value_end(content, cursor)
        if right >= end:
            raise ValueError
        _validate_value(content, cursor, right, depth=depth + 1)
        count += 1
        cursor = _skip_json_space(content, right)
        if cursor == end - 1:
            break
        if content[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(content, cursor + 1)
        if cursor >= end - 1:
            raise ValueError
    return count


def _validate_value(content: bytearray, start: int, end: int, *, depth: int) -> None:
    if depth > 16:
        raise ValueError
    if content[start] == 123:
        for left, right in _object_spans(content, start, end).values():
            _validate_value(content, left, right, depth=depth + 1)
    elif content[start] == 91:
        _array_count(content, start, end, depth=depth)
    else:
        with memoryview(content)[start:end] as token:
            if content[start] == 34:
                _string_or_empty(token)
            elif not any(hmac.compare_digest(token, literal) for literal in (b"true", b"false", b"null")):
                if re.fullmatch(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", token) is None:
                    raise ValueError
