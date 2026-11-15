"""Private build-29 User/API-User name collision read, not create authority.

The retained New User validator compares both name collections case-insensitively.
This mirrors its unpaged name-only reads, without its cache or edit-name exemption.
It does not establish global visibility, permission to create, fixture ownership,
or a creation receipt. No public method accepts a route, query, body or selector.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import http.client
import json
import ssl
from typing import Any
from urllib.parse import urlsplit

from v4_planning.material_provider import C3MaterialBinding

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .local_user_reset_http_transport import _NAME
from .local_user_reset_metadata_reader import (
    LocalUserResetMetadataReadError, LocalUserResetReadFailure as Failure, _validate_value,
)
from .local_user_reset_projection import _object_spans, _string_or_empty
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space, _ssl_context, _zeroize_mutable,
)

_MAX_BYTES = 1_048_576
_MAX_NAMES = 4096
_ENVELOPE = frozenset({
    "action", "build", "http_method", "http_status", "matched_count", "name", "next_idx",
    "path", "results", "revision", "serial", "size", "status", "vdom", "version", "limit_reached",
})
# Observed with_meta decorations are outside a name-collision decision. Validate
# their JSON syntax but never decode their values or treat edit flags as authority.
_NAME_METADATA = frozenset({"q_mkey_type", "q_name", "q_no_edit", "q_no_rename", "q_path", "q_type"})
_ROW = frozenset({"name", "q_origin_key", "q_ref", "q_static", "q_global_entry"}) | _NAME_METADATA
_QUERIES = (
    ("admin", json.dumps({"json_filter": [{"logic": "or", "filters": [{
        "key": "name", "type": "string", "operator": "exact",
        "pattern": "invitation_guests", "negate": True,
    }]}]}, separators=(",", ":")).encode("ascii")),
    ("api-user", b'{"json_filter":[]}'),
)


@dataclass(frozen=True, slots=True, repr=False)
class LocalUserResetNameObservation(C3MaterialBinding):
    """Private source-equivalent visibility evidence; not an absence authority."""

    local_user_collision: bool
    api_user_collision: bool
    source_name_check_clear: bool
    state_digest: str


class FortiPamLocalUserResetNameReader:
    """Read both fixed name collections using one constructor-bound API identity."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, *, username: str, api_principal: str,
        connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
    ) -> None:
        try:
            if type(config) is not SecretMetadataHttpTransportConfig:
                raise ValueError
            origin = urlsplit(config.base_url)
            port = 443 if origin.port is None else origin.port
            if (
                origin.scheme != "https" or not origin.hostname or origin.username is not None
                or origin.password is not None or origin.path not in {"", "/"}
                or origin.query or origin.fragment or not 1 <= port <= 65535
                or type(username) is not str or len(username) > 64 or _NAME.fullmatch(username) is None
                or type(api_principal) is not str or not 0 < len(api_principal) <= 255
                or any(ord(c) < 32 or ord(c) == 127 for c in api_principal)
                or username.lower() == api_principal.lower() or not callable(connection_factory)
            ):
                raise ValueError
            context = _ssl_context(config)
            if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                raise ValueError
        except Exception:
            raise LocalUserResetMetadataReadError(Failure.UNQUALIFIED_RESPONSE) from None
        self._config, self._username, self._principal = config, username, api_principal
        self._host, self._port, self._context = origin.hostname, port, context
        self._factory = connection_factory

    def read_observation(self) -> LocalUserResetNameObservation:
        """Require both valid responses and the bound API principal as a control."""
        collisions: list[bool] = []
        try:
            for table, body in _QUERIES:
                content = self._read(table, body)
                try:
                    names = _project_names(content, table=table)
                    # Use lower(), as in the frontend, not Unicode casefold().
                    collisions.append(any(name.lower() == self._username.lower() for name in names))
                    if table == "api-user" and (names.count(self._principal) != 1
                        or sum(name.lower() == self._principal.lower() for name in names) != 1):
                        raise ValueError
                    if table == "admin" and not names:
                        # An empty entire namespace is not a useful positive
                        # visibility control for this retained lab candidate.
                        raise ValueError
                finally:
                    _zeroize_mutable(content)
            payload = {
                "contract": "bp002-build29-name-collision-read/v1", "host": self._host,
                "port": self._port, "username": self._username, "api_principal": self._principal,
                "local_collision": collisions[0], "api_collision": collisions[1],
                "api_principal_visible": True,
            }
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                                ensure_ascii=True).encode("utf-8")).hexdigest()
            return LocalUserResetNameObservation(collisions[0], collisions[1], not any(collisions), digest)
        except LocalUserResetMetadataReadError:
            raise
        except Exception:
            raise LocalUserResetMetadataReadError(Failure.UNQUALIFIED_RESPONSE) from None

    def _read(self, table: str, body: bytes) -> bytearray:
        content = bytearray()
        try:
            content = bytearray(_MAX_BYTES + 1)
            connection = response = None
            transfer = False
            try:
                if (table, body) not in _QUERIES:
                    raise ValueError
                connection = self._factory(self._host, self._port, timeout=self._config.timeout_seconds,
                                           context=self._context)
                connection.request("POST", f"/api/v2/cmdb/system/{table}?format=name&with_meta=true", body=body, headers={
                    "X-HTTP-Method-Override": "GET", "Content-Type": "application/json",
                    "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close",
                    "Authorization": f"Bearer {self._config.bearer_token}", "Cache-Control": "no-cache, no-store",
                    "User-Agent": "fortipam-bp002-name-collision-read/1",
                })
                response = connection.getresponse()
                if response.status in {401, 403}:
                    raise LocalUserResetMetadataReadError(Failure.AUTHORIZATION_DENIED)
                if response.status == 404:
                    raise LocalUserResetMetadataReadError(Failure.NOT_FOUND)
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
                raise LocalUserResetMetadataReadError(Failure.TIMED_OUT) from None
            except (OSError, http.client.HTTPException):
                raise LocalUserResetMetadataReadError(Failure.TRANSPORT_UNAVAILABLE) from None
            except Exception:
                raise LocalUserResetMetadataReadError(Failure.UNQUALIFIED_RESPONSE) from None
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


def _project_names(content: bytearray, *, table: str) -> list[str]:
    """Decode only names; reject unexpected row fields before their values decode."""
    left = _skip_json_space(content, 0)
    right = _json_value_end(content, left)
    if _skip_json_space(content, right) != len(content) or table not in {"admin", "api-user"}:
        raise ValueError
    envelope = _object_spans(content, left, right)
    if not envelope.keys() <= _ENVELOPE:
        raise ValueError
    for key, expected in {
        "http_method": "POST", "http_status": 200, "status": "success", "version": "v7.0.0",
        "build": 29, "path": "system", "name": table,
    }.items():
        with memoryview(content)[slice(*envelope[key])] as token:
            if token != json.dumps(expected, separators=(",", ":")).encode("ascii"):
                raise ValueError
    for key in ("serial", "revision", "vdom", "action"):
        if key in envelope:
            with memoryview(content)[slice(*envelope[key])] as token:
                _string_or_empty(token)
                if key == "action" and not hmac.compare_digest(token, b'""'):
                    raise ValueError
    left, right = envelope["results"]
    if content[left] != 91 or content[right - 1] != 93:
        raise ValueError
    cursor = _skip_json_space(content, left + 1)
    names: list[str] = []
    while cursor < right - 1:
        end = _json_value_end(content, cursor)
        row = _object_spans(content, cursor, end)
        if len(names) >= _MAX_NAMES or not row.keys() <= _ROW or "name" not in row:
            raise ValueError
        for a, b in row.values():
            _validate_value(content, a, b, depth=0)
        with memoryview(content)[slice(*row["name"])] as token:
            _string_or_empty(token)
        name = json.loads(content[slice(*row["name"])])
        if (type(name) is not str or not 0 < len(name) <= 255
            or any(ord(c) < 32 or ord(c) == 127 for c in name) or name in names):
            raise ValueError
        if "q_origin_key" in row:
            with memoryview(content)[slice(*row["q_origin_key"])] as token:
                _string_or_empty(token)
            if json.loads(content[slice(*row["q_origin_key"])]) != name:
                raise ValueError
        for key in ("q_static", "q_global_entry"):
            if key in row:
                with memoryview(content)[slice(*row[key])] as token:
                    if not any(hmac.compare_digest(token, value) for value in (b"true", b"false")):
                        raise ValueError
        if "q_ref" in row:
            _count(content, row["q_ref"])
        names.append(name)
        cursor = _skip_json_space(content, end)
        if cursor == right - 1:
            break
        if content[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(content, cursor + 1)
        if cursor >= right - 1:
            raise ValueError
    # The source fetch requests no page limit and does not interpret next_idx.
    # Require the reported match count to agree with the rows, but do not invent
    # an end-cursor convention: build 29 reports size - 1 for the live User
    # name read. Bounded cursors are metadata, NOT proof of global exhaustion.
    paging = {key for key in ("matched_count", "next_idx", "size") if key in envelope}
    if paging:
        if len(paging) != 3:
            raise ValueError
        counts = {key: _count(content, envelope[key]) for key in paging}
        if (counts["matched_count"] != len(names) or counts["size"] < len(names)
            or counts["next_idx"] > counts["size"]):
            raise ValueError
    if "limit_reached" in envelope:
        with memoryview(content)[slice(*envelope["limit_reached"])] as token:
            if not hmac.compare_digest(token, b"false"):
                raise ValueError
    return names


def _count(content: bytearray, span: tuple[int, int]) -> int:
    with memoryview(content)[slice(*span)] as token:
        if not 0 < len(token) <= 6 or any(not 48 <= value <= 57 for value in token):
            raise ValueError
        if len(token) > 1 and token[0] == 48:
            raise ValueError
        value = int(token)
        if value > 100_000:
            raise ValueError
        return value
