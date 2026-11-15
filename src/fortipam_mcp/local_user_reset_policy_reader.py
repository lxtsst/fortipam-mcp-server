"""Fixed build-29 BP002 User Password Policy projection; no password values."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import http.client
import json
import ssl
from typing import Any
from urllib.parse import urlsplit

from .mutable_json_buffer import _take_mutable_prefix
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space,
    _ssl_context, _zeroize_mutable,
)


_PATH = "/api/v2/cmdb/system/password-policy"
_MAX_BYTES = 65_536
_DOMAIN = b"bp002-local-user-password-policy-build29/v1\0"
_UNAVAILABLE = "The private Local User password policy read is unavailable."
_NUMERIC = (
    "minimum-length", "min-change-characters", "min-upper-case-letter",
    "min-lower-case-letter", "min-number", "min-non-alphanumeric",
)
_OPTIONS = ("status", "reuse-password", "expire-status")


class LocalUserResetPolicyReadError(RuntimeError):
    """Fixed non-disclosing policy-read failure."""


@dataclass(frozen=True, slots=True, repr=False)
class LocalUserResetPolicySnapshot:
    """Exact non-material policy fields used by the User password workflow."""

    minimum_length: int
    min_change_characters: int
    min_upper_case_letter: int
    min_lower_case_letter: int
    min_number: int
    min_non_alphanumeric: int
    status: str
    reuse_password: str
    expire_status: str

    def __post_init__(self) -> None:
        if (
            type(self.minimum_length) is not int or not 1 <= self.minimum_length <= 128
            or any(type(value) is not int or not 0 <= value <= 200 for value in (
                self.min_change_characters, self.min_upper_case_letter,
                self.min_lower_case_letter, self.min_number, self.min_non_alphanumeric,
            ))
            or any(type(value) is not str or value not in {"enable", "disable"} for value in (
                self.status, self.reuse_password, self.expire_status,
            ))
        ):
            raise LocalUserResetPolicyReadError(_UNAVAILABLE)

    @property
    def digest(self) -> str:
        self.__post_init__()
        body = {
            "minimum-length": self.minimum_length,
            "min-change-characters": self.min_change_characters,
            "min-upper-case-letter": self.min_upper_case_letter,
            "min-lower-case-letter": self.min_lower_case_letter,
            "min-number": self.min_number,
            "min-non-alphanumeric": self.min_non_alphanumeric,
            "status": self.status,
            "reuse-password": self.reuse_password,
            "expire-status": self.expire_status,
        }
        return hashlib.sha256(_DOMAIN + json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")).hexdigest()


def _value(content: bytearray, span: tuple[int, int]) -> object:
    return json.loads(content[slice(*span)])


def _integer(content: bytearray, span: tuple[int, int]) -> int:
    value = _value(content, span)
    if type(value) is not int:
        raise ValueError
    return value


def _option(content: bytearray, span: tuple[int, int]) -> str:
    value = _value(content, span)
    if type(value) is not str or value not in {"enable", "disable"}:
        raise ValueError
    return value


def _project(content: bytearray) -> LocalUserResetPolicySnapshot:
    start = _skip_json_space(content, 0)
    end = _json_value_end(content, start)
    if _skip_json_space(content, end) != len(content):
        raise ValueError
    root = _object_spans(content, start, end)
    required = {
        "http_method": "GET", "http_status": 200,
        "version": "v7.0.0", "build": 29,
        "path": "system", "name": "password-policy",
    }
    if (any(key not in root or _value(content, root[key]) != value
            for key, value in required.items())
        or "status" not in root or _value(content, root["status"]) not in {"success", "OK"}
        or "results" not in root):
        raise ValueError
    left, right = root["results"]
    if content[left] == 91:
        item = _skip_json_space(content, left + 1)
        item_end = _json_value_end(content, item)
        if _skip_json_space(content, item_end) != right - 1:
            raise ValueError
        left, right = item, item_end
    row = _object_spans(content, left, right)
    if not set(_NUMERIC + _OPTIONS) <= row.keys():
        raise ValueError
    return LocalUserResetPolicySnapshot(
        minimum_length=_integer(content, row["minimum-length"]),
        min_change_characters=_integer(content, row["min-change-characters"]),
        min_upper_case_letter=_integer(content, row["min-upper-case-letter"]),
        min_lower_case_letter=_integer(content, row["min-lower-case-letter"]),
        min_number=_integer(content, row["min-number"]),
        min_non_alphanumeric=_integer(content, row["min-non-alphanumeric"]),
        status=_option(content, row["status"]),
        reuse_password=_option(content, row["reuse-password"]),
        expire_status=_option(content, row["expire-status"]),
    )


class FortiPamLocalUserResetPolicyReader:
    """Read only the fixed User password policy through the bound API identity."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, *,
        connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
    ) -> None:
        try:
            if type(config) is not SecretMetadataHttpTransportConfig or not callable(connection_factory):
                raise ValueError
            origin = urlsplit(config.base_url)
            port = 443 if origin.port is None else origin.port
            if (origin.scheme != "https" or not origin.hostname or not 1 <= port <= 65535
                or origin.username is not None or origin.password is not None
                or origin.path not in {"", "/"} or origin.query or origin.fragment):
                raise ValueError
            context = _ssl_context(config)
            if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                raise ValueError
        except Exception:
            raise LocalUserResetPolicyReadError(_UNAVAILABLE) from None
        self._config, self._factory, self._context = config, connection_factory, context
        self._host, self._port = origin.hostname, port

    def read_policy_snapshot(self) -> LocalUserResetPolicySnapshot:
        content = bytearray(_MAX_BYTES + 1)
        connection = response = None
        try:
            connection = self._factory(
                self._host, self._port, timeout=self._config.timeout_seconds,
                context=self._context,
            )
            connection.request("GET", _PATH, headers={
                "Accept": "application/json", "Accept-Encoding": "identity",
                "Authorization": "Bearer " + self._config.bearer_token,
                "Connection": "close", "Cache-Control": "no-cache, no-store",
                "User-Agent": "fortipam-bp002-policy-read/1",
            })
            response = connection.getresponse()
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
                if count == 0:
                    break
                total += count
            if total > _MAX_BYTES:
                raise ValueError
            content = _take_mutable_prefix(content, total)
            return _project(content)
        except Exception:
            raise LocalUserResetPolicyReadError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(content)
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        pass


__all__ = [
    "FortiPamLocalUserResetPolicyReader", "LocalUserResetPolicyReadError",
    "LocalUserResetPolicySnapshot",
]
