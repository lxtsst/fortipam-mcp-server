"""Fixed creator-collection read for FortiPAM Secret requests.

The target-version UI issues a POST with ``X-HTTP-Method-Override: GET`` and a
fixed ``query-type=creator`` JSON filter.  This module reproduces only that
read, keeps response identifiers internal, and skips identity, comments,
custom fields, and unknown values before generic JSON decoding.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import http.client
import json
import re
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from .mutable_json_buffer import _take_mutable_prefix
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES,
    SecretMetadataHttpTransportConfig,
    _json_string_end,
    _json_value_end,
    _skip_json_space,
    _ssl_context,
    _zeroize_mutable,
)


REQUEST_CREATOR_COLLECTION_METHOD: Literal["POST"] = "POST"
REQUEST_CREATOR_COLLECTION_PATH = "/api/v2/cmdb/secret/request"
REQUEST_CREATOR_COLLECTION_QUERY = "with_meta=true&vdom=root"
REQUEST_CREATOR_COLLECTION_OVERRIDE: Literal["GET"] = "GET"
_REQUEST_BODY = (
    b'{"json_filter":[{"logic":"and","filters":['
    b'{"key":"query-type","type":"string","operator":"exact",'
    b'"pattern":"creator"}]}]}'
)
_TOP_LEVEL_FIELDS = frozenset(
    {
        "results",
        "status",
        "http_status",
        "size",
        "filtered_count",
        "http_method",
        "vdom",
        "path",
        "name",
        "serial",
        "version",
        "build",
    }
)
_RECORD_FIELDS = frozenset(
    {"id", "secret-id", "request-type", "creation-time"}
)
_REQUEST_TYPES = frozenset({"launcher", "job"})
_SUPPORTED_VERSIONS = frozenset({("1.9.1", 1758), ("7.0.0", 29)})
_CMDB_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\Z")
_MAX_RECORDS = 512
_UNAVAILABLE = "FortiPAM Secret request collection inspection is unavailable."


class SecretRequestCollectionHttpTransportError(RuntimeError):
    """Stable non-disclosing collection-read failure."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestCollectionRecord:
    """Protected immutable fields needed to bind one newly created request."""

    request_id: int
    secret_id: int
    request_type: Literal["launcher", "job"]
    creation_time: str | int


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestCreatorSnapshot:
    """One complete fixed creator view; never expose it through MCP output."""

    records: tuple[SecretRequestCollectionRecord, ...]
    fortipam_version: Literal["1.9.1", "7.0.0"] = "1.9.1"
    fortipam_build: Literal[1758, 29] = 1758
    raw_values_returned: Literal[False] = False

    def __post_init__(self) -> None:
        if (
            (self.fortipam_version, self.fortipam_build)
            not in _SUPPORTED_VERSIONS
            or self.raw_values_returned is not False
        ):
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)


class FortiPamSecretRequestCollectionHttpTransport:
    """Read the authenticated principal's fixed creator collection."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        connection_factory: Any | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
        self._config = config
        self._connection_factory = connection_factory

    def snapshot(self) -> SecretRequestCreatorSnapshot:
        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
        connection: Any = None
        response: Any = None
        content = bytearray(MAX_RESPONSE_BYTES + 1)
        try:
            factory = self._connection_factory or http.client.HTTPSConnection
            connection = factory(
                parsed.hostname,
                parsed.port or 443,
                timeout=self._config.timeout_seconds,
                context=_ssl_context(self._config),
            )
            connection.request(
                REQUEST_CREATOR_COLLECTION_METHOD,
                f"{REQUEST_CREATOR_COLLECTION_PATH}?{REQUEST_CREATOR_COLLECTION_QUERY}",
                body=_REQUEST_BODY,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "Content-Type": "application/json",
                    "User-Agent": "fortipam-mcp-v4-secret-request-creator-read/1",
                    "X-HTTP-Method-Override": REQUEST_CREATOR_COLLECTION_OVERRIDE,
                },
            )
            response = connection.getresponse()
            if int(response.status) != 200:
                raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
            content_type = response.getheader("content-type", "")
            if not isinstance(content_type, str) or "json" not in content_type.lower():
                raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
            total = 0
            while total < len(content):
                view = memoryview(content)[total:]
                try:
                    count = response.readinto(view)
                finally:
                    view.release()
                if not isinstance(count, int) or count < 0:
                    raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
                if count == 0:
                    break
                total += count
            if total > MAX_RESPONSE_BYTES:
                raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
            content = _take_mutable_prefix(content, total)
            return _parse_snapshot(content)
        except SecretRequestCollectionHttpTransportError:
            raise
        except Exception as exc:
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE) from exc
        finally:
            _zeroize_mutable(content)
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass


def bind_new_secret_request(
    before: SecretRequestCreatorSnapshot,
    after: SecretRequestCreatorSnapshot,
    *,
    expected_secret_id: int,
    expected_request_type: Literal["launcher", "job"],
) -> SecretRequestCollectionRecord:
    """Bind exactly one new same-creator record without relying on POST output."""

    secret_id = _positive_id(expected_secret_id)
    if (
        not isinstance(before, SecretRequestCreatorSnapshot)
        or not isinstance(after, SecretRequestCreatorSnapshot)
        or expected_request_type not in _REQUEST_TYPES
        or before.fortipam_version != after.fortipam_version
        or before.fortipam_build != after.fortipam_build
    ):
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
    before_by_id = _records_by_id(before.records)
    after_by_id = _records_by_id(after.records)
    if any(
        after_by_id.get(identifier) != record
        for identifier, record in before_by_id.items()
    ):
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
    candidates = [
        record
        for identifier, record in after_by_id.items()
        if identifier not in before_by_id
        and record.secret_id == secret_id
        and record.request_type == expected_request_type
    ]
    if len(candidates) != 1:
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
    return candidates[0]


def _parse_snapshot(content: bytearray) -> SecretRequestCreatorSnapshot:
    root_start = _skip_json_space(content, 0)
    root_end = _json_value_end(content, root_start)
    if (
        root_start >= len(content)
        or content[root_start] != 123
        or _skip_json_space(content, root_end) != len(content)
    ):
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
    members = _object_members(
        content,
        root_start,
        root_end,
        _TOP_LEVEL_FIELDS,
        exact=True,
    )
    if (
        _json_string_value(content, members["status"]) != "OK"
        or _json_nonnegative_int(content, members["http_status"]) != 200
        or _json_string_value(content, members["http_method"]) != "POST"
        or _json_string_value(content, members["vdom"]) != "root"
        or _json_string_value(content, members["path"]) != "secret"
        or _json_string_value(content, members["name"]) != "request"
    ):
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
    version = _json_string_value(content, members["version"])
    build = _json_nonnegative_int(content, members["build"])
    pair = (version[1:] if version.startswith("v") else version, build)
    if pair not in _SUPPORTED_VERSIONS:
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
    _validate_bounded_nonempty_json_string(content, members["serial"], 128)
    records = _parse_records(
        content,
        members["results"],
        allow_epoch_seconds=pair == ("7.0.0", 29),
    )
    size = _json_nonnegative_int(content, members["size"])
    filtered_count = _json_nonnegative_int(content, members["filtered_count"])
    if (
        filtered_count != len(records)
        or size < filtered_count
        or (pair != ("7.0.0", 29) and size != filtered_count)
    ):
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
    _records_by_id(records)
    return SecretRequestCreatorSnapshot(
        records,
        cast(Literal["1.9.1", "7.0.0"], pair[0]),
        cast(Literal[1758, 29], pair[1]),
    )


def _parse_records(
    content: bytearray,
    value_range: tuple[int, int],
    *,
    allow_epoch_seconds: bool,
) -> tuple[SecretRequestCollectionRecord, ...]:
    start, end = value_range
    if content[start] != 91 or end <= start or content[end - 1] != 93:
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
    cursor = _skip_json_space(content, start + 1)
    records: list[SecretRequestCollectionRecord] = []
    while cursor < end - 1:
        item_end = _json_value_end(content, cursor)
        if content[cursor] != 123:
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
        fields = _object_members(content, cursor, item_end, _RECORD_FIELDS, exact=False)
        request_type = _json_string_value(content, fields["request-type"])
        creation_time = _parse_creation_time(
            content,
            fields["creation-time"],
            allow_epoch_seconds=allow_epoch_seconds,
        )
        if request_type not in _REQUEST_TYPES:
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
        records.append(
            SecretRequestCollectionRecord(
                _json_positive_id(content, fields["id"]),
                _json_positive_id(content, fields["secret-id"]),
                cast(Literal["launcher", "job"], request_type),
                creation_time,
            )
        )
        if len(records) > _MAX_RECORDS:
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
        cursor = _skip_json_space(content, item_end)
        if cursor == end - 1:
            break
        if content[cursor] != 44:
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
        cursor = _skip_json_space(content, cursor + 1)
    return tuple(records)


def _parse_creation_time(
    content: bytearray,
    value_range: tuple[int, int],
    *,
    allow_epoch_seconds: bool,
) -> str | int:
    start, end = value_range
    if content[start] == 34:
        text_value = _json_string_value(content, value_range)
        if _valid_timestamp(text_value):
            return text_value
    elif allow_epoch_seconds and end - start == 10:
        epoch_value = _json_nonnegative_int(content, value_range)
        if 946_684_800 <= epoch_value <= 4_102_444_800:
            return epoch_value
    raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)


def _object_members(
    content: bytearray,
    start: int,
    end: int,
    selected: frozenset[str],
    *,
    exact: bool,
) -> dict[str, tuple[int, int]]:
    if content[start] != 123 or end <= start or content[end - 1] != 125:
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
    cursor = _skip_json_space(content, start + 1)
    result: dict[str, tuple[int, int]] = {}
    observed: set[str] = set()
    while cursor < end - 1:
        if content[cursor] != 34:
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
        key_end = _json_string_end(content, cursor)
        try:
            key = json.loads(content[cursor : key_end + 1])
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE) from exc
        separator = _skip_json_space(content, key_end + 1)
        if (
            not isinstance(key, str)
            or key in observed
            or separator >= end
            or content[separator] != 58
        ):
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
        observed.add(key)
        value_start = _skip_json_space(content, separator + 1)
        value_end = _json_value_end(content, value_start)
        if key in selected:
            result[key] = (value_start, value_end)
        elif exact:
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
        cursor = _skip_json_space(content, value_end)
        if cursor == end - 1:
            break
        if content[cursor] != 44:
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
        cursor = _skip_json_space(content, cursor + 1)
    if set(result) != selected or (exact and observed != selected):
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
    return result


def _json_string_value(content: bytearray, value_range: tuple[int, int]) -> str:
    start, end = value_range
    try:
        value = json.loads(content[start:end])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE) from exc
    if not isinstance(value, str):
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
    return value


def _json_nonnegative_int(content: bytearray, value_range: tuple[int, int]) -> int:
    start, end = value_range
    raw = content[start:end]
    if not raw or len(raw) > 10 or any(value < 48 or value > 57 for value in raw):
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
    return int(raw)


def _json_positive_id(content: bytearray, value_range: tuple[int, int]) -> int:
    value = _json_nonnegative_int(content, value_range)
    return _positive_id(value)


def _positive_id(value: int) -> int:
    if type(value) is not int or not 0 < value <= 2_147_483_647:
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
    return value


def _validate_bounded_nonempty_json_string(
    content: bytearray,
    value_range: tuple[int, int],
    maximum: int,
) -> None:
    start, end = value_range
    if (
        start >= end
        or content[start] != 34
        or _json_string_end(content, start) + 1 != end
        or not 2 < end - start <= maximum + 2
    ):
        raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)


def _valid_timestamp(value: str) -> bool:
    if not _CMDB_TIMESTAMP.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    return True


def _records_by_id(
    records: tuple[SecretRequestCollectionRecord, ...],
) -> dict[int, SecretRequestCollectionRecord]:
    result: dict[int, SecretRequestCollectionRecord] = {}
    for record in records:
        if not isinstance(record, SecretRequestCollectionRecord):
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
        if record.request_id in result:
            raise SecretRequestCollectionHttpTransportError(_UNAVAILABLE)
        result[record.request_id] = record
    return result


__all__ = [
    "FortiPamSecretRequestCollectionHttpTransport",
    "REQUEST_CREATOR_COLLECTION_METHOD",
    "REQUEST_CREATOR_COLLECTION_OVERRIDE",
    "REQUEST_CREATOR_COLLECTION_PATH",
    "REQUEST_CREATOR_COLLECTION_QUERY",
    "SecretRequestCollectionHttpTransportError",
    "SecretRequestCollectionRecord",
    "SecretRequestCreatorSnapshot",
    "bind_new_secret_request",
]
