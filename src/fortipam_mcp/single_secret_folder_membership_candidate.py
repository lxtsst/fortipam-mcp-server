"""Explicit lazy Owner/API/SSH provider for one fixed membership observation.

No environment loader, write route, MCP registration or default Host composition
is provided. API listings calibrate visible fixed identities and are required
only to be subsets of complete CLI namespaces; their matched_count is never a
global membership proof. This composition requires separate live acceptance.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import json
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import quote

import httpx

from .folder_namespace_ssh_reader import _folder_names, _safe_observed_name
from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_metadata_reader import _validate_value
from .local_user_reset_name_reader import _ENVELOPE
from .local_user_reset_projection import _object_spans
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig,
    _folder_path, _json_string_end, _json_value_end, _redact_json_field_values, _skip_json_space, _zeroize_mutable,
)
from .secret_dlp_opaque_carrier import _normalize_build29_clipboard_duplicate
from .secret_namespace_ssh_reader import _safe_secret_name, _secret_names
from .single_secret_folder_membership_source import (
    SingleSecretFolderMembershipBinding, SingleSecretFolderMembershipColumns,
    SingleSecretFolderMembershipObservation, SingleSecretFolderMembershipSource,
)
from .single_secret_folder_membership_ssh_reader import SingleSecretFolderMembershipSshReader
from .target_ssh_transport import TargetSshTransportConfig, _private_regular_file, _safe_host

_UNAVAILABLE = "The private single-Secret Folder membership candidate is unavailable."
_ACTOR = "/api/v2/monitor/web-ui/state"
_ROLE_FIELDS = "name|accprofile|status|remote-auth|wildcard"
_FOLDERS = "/api/v2/cmdb/secret/folder?format=id%7Cname&count=512&start=0"
_SECRETS = "/api/v2/cmdb/secret/database?format=id%7Cname%7Cfolder&count=512&start=0"
_HEADER = {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
           "vdom": "root"}


def build_single_secret_folder_membership_observer(
    config: SecretMetadataHttpTransportConfig, *, binding: SingleSecretFolderMembershipBinding,
    owner_name: str, folder_path: str, credentials: Callable[[], tuple[str, str]],
    ssh_host: str, ssh_port: int, ssh_known_hosts_file: Path,
    client_factory: Callable[..., Any] = httpx.Client,
) -> Callable[[], SingleSecretFolderMembershipObservation]:
    """Validate local composition only; each no-input call takes fresh credentials."""
    try:
        if (type(config) is not SecretMetadataHttpTransportConfig
            or type(binding) is not SingleSecretFolderMembershipBinding
            or type(owner_name) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", owner_name) is None
            or _folder_path(folder_path).rsplit("/", 1)[-1] != binding.folder_name
            or not callable(credentials) or not callable(client_factory)
            or not _safe_host(ssh_host) or type(ssh_port) is not int or not 1 <= ssh_port <= 65535):
            raise ValueError
        _known_hosts(ssh_known_hosts_file)
    except Exception:
        raise ValueError(_UNAVAILABLE) from None

    def observe() -> SingleSecretFolderMembershipObservation:
        try:
            _known_hosts(ssh_known_hosts_file)
            snapshot = credentials()
            if (type(snapshot) is not tuple or len(snapshot) != 2 or snapshot[0] != owner_name
                or type(snapshot[1]) is not str or not snapshot[1]):
                raise ValueError
            session = OwnerSessionMetadataTransport(
                config, owner_name=owner_name, credentials=lambda: snapshot,
                folder_path=folder_path, secret_name=binding.secret_name, target_name="membership-observer",
                witness=FortiPamSecretMetadataHttpTransport(config), client_factory=client_factory,
            )
            ssh = SingleSecretFolderMembershipSshReader(
                TargetSshTransportConfig(ssh_host, ssh_port, snapshot[0], snapshot[1],
                                         ssh_known_hosts_file, config.timeout_seconds),
                expected_serial=binding.expected_serial,
            )
            with session.authenticated():
                provider = _SessionProvider(session, binding, owner_name, ssh)
                provider.qualify()
                observation = SingleSecretFolderMembershipSource(binding, provider).observe()
            if not session.logout_verified:
                raise ValueError
            return observation
        except Exception:
            raise ValueError(_UNAVAILABLE) from None

    return observe


def _known_hosts(path: Path) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError
    _private_regular_file(path, "known_hosts")
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_size == 0:
        raise ValueError


class _SessionProvider:
    """Only fixed GETs and no-selector global captures within one Owner session."""

    def __init__(self, session: OwnerSessionMetadataTransport, binding: SingleSecretFolderMembershipBinding,
                 owner: str, ssh: SingleSecretFolderMembershipSshReader) -> None:
        self._session, self._binding, self._owner, self._ssh = session, binding, owner, ssh
        self._role = "/api/v2/cmdb/system/admin/" + quote(owner, safe="") + "?format=" + quote(_ROLE_FIELDS, safe="")
        self._detail = "/api/v2/cmdb/secret/database/" + str(binding.secret_id)
        self._allowed = {_ACTOR, self._role, _FOLDERS, _SECRETS, self._detail}
        self._folder_api_names: tuple[str, ...] = ()
        self._secret_api_names: tuple[str, ...] = ()

    def qualify(self) -> None:
        actor = self._bytes(_ACTOR)
        try:
            _actor_context(actor, expected_name=self._owner)
        finally:
            _zeroize_mutable(actor)
        role = self._json(self._role)
        row = self._row(role, "system", "admin")
        expected = {"name": self._owner, "accprofile": "super_admin", "status": "enable",
                    "remote-auth": "disable", "wildcard": "disable"}
        if (not set(expected) <= set(row) or not set(row) <= set(expected) | {"q_origin_key"}
            or any(type(row.get(key)) is not type(value) or row.get(key) != value for key, value in expected.items())
            or "q_origin_key" in row and row["q_origin_key"] != self._owner):
            raise ValueError
        self._folder_api_names = self._collection(self._json(_FOLDERS), "folder")
        self._secret_api_names = self._collection(self._json(_SECRETS), "database")

    def read_global_columns(self) -> SingleSecretFolderMembershipColumns:
        self._active()
        if not self._folder_api_names or not self._secret_api_names:
            raise ValueError
        columns = self._ssh.read_columns()
        root = columns.root_prompt
        folder_names = _folder_names(columns.folder_names, root[:-2] + b" (folder) #")
        secret_names = _secret_names(columns.secret_names, root[:-2] + b" (database) #")
        if (not set(self._folder_api_names) <= set(folder_names)
            or not set(self._secret_api_names) <= set(secret_names)):
            raise ValueError
        return columns

    def read_bound_secret_metadata(self) -> Mapping[str, object]:
        payload = self._json(self._detail)
        row = self._row(payload, "secret", "database")
        if (any(type(payload[key]) is not int or payload[key] != 1
                for key in ("size", "matched_count") if key in payload)
            or payload.get("limit_reached", False) is not False
            or any(key in payload for key in ("next_idx", "next_index", "total", "total_count"))):
            raise ValueError
        identity = {"id": self._binding.secret_id, "name": self._binding.secret_name,
                    "folder": self._binding.folder_id}
        if any(type(row.get(key)) is not type(value) or row.get(key) != value for key, value in identity.items()):
            raise ValueError
        if "mkey" in payload and (type(payload["mkey"]) not in {int, str}
            or payload["mkey"] not in {self._binding.secret_id, str(self._binding.secret_id)}):
            raise ValueError
        projected = {key: row[key] for key in (*identity, "q_origin_key") if key in row}
        # Discard native metadata outside the fixed source contract. Field values
        # were erased before decoding; the full GET is never a returned projection.
        header = {key: payload[key] for key in (*_HEADER, "serial", "path", "name", "status", "action") if key in payload}
        return {**header, "results": projected,
                **{key: payload[key] for key in ("size", "matched_count", "limit_reached") if key in payload}}

    def _active(self) -> None:
        if self._session._client is None or self._session._clock() >= self._session._expires_at:
            raise ValueError

    def _bytes(self, path: str) -> bytearray:
        self._active()
        if path not in self._allowed:
            raise ValueError
        raw = bytearray()
        try:
            with self._session._client.stream("GET", path, headers={"Accept": "application/json"}) as response:
                if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            return raw
        except Exception:
            _zeroize_mutable(raw)
            raise

    def _json(self, path: str) -> Mapping[str, object]:
        raw = self._bytes(path)
        try:
            _redact_json_field_values(raw)
            if path == self._detail:
                _normalize_fixed_detail(raw, self._binding)
            elif path == _SECRETS:
                _normalize_fixed_secret_collection(raw, self._binding)
            value = json.loads(raw, object_pairs_hook=_unique)
            if not isinstance(value, Mapping):
                raise ValueError
            return value
        finally:
            _zeroize_mutable(raw)

    def _header(self, payload: Mapping[str, object], path: str, name: str) -> None:
        expected = {**_HEADER, "serial": self._binding.expected_serial, "path": path, "name": name}
        # Qualified compiled GETs preserve native action absence; present action
        # must be an empty string and is never synthesized into the projection.
        if ("action" in payload and (type(payload["action"]) is not str or payload["action"] != "")
            or any(type(payload.get(key)) is not type(value) or payload.get(key) != value for key, value in expected.items())
            or type(payload.get("status")) is not str or payload["status"] not in {"OK", "success"}
            or "error" in payload and (type(payload["error"]) is not int or payload["error"] != 0)):
            raise ValueError

    def _row(self, payload: Mapping[str, object], path: str, name: str) -> Mapping[str, object]:
        self._header(payload, path, name)
        row = payload.get("results")
        if isinstance(row, list) and len(row) == 1:
            row = row[0]
        if not isinstance(row, Mapping):
            raise ValueError
        return row

    def _collection(self, payload: Mapping[str, object], table: str) -> tuple[str, ...]:
        self._header(payload, "secret", table)
        rows = payload.get("results")
        if (not isinstance(rows, list) or not 2 <= len(rows) < 512
            or type(payload.get("matched_count")) is not int or payload["matched_count"] != len(rows)
            or "size" in payload and (type(payload["size"]) is not int or not len(rows) <= payload["size"] <= 512)
            or payload.get("limit_reached", False) is not False
            or any(type(payload[key]) is not int or payload[key] != 0 for key in ("next_idx", "next_index") if key in payload)
            or any(type(payload[key]) is not int or payload[key] != len(rows) for key in ("total", "total_count") if key in payload)):
            raise ValueError
        names: list[str] = []
        ids: set[int] = set()
        b = self._binding
        selected_id, selected_name, witness = ((b.folder_id, b.folder_name, b.folder_witness_name) if table == "folder"
                                               else (b.secret_id, b.secret_name, b.secret_witness_name))
        selected = False
        for row in rows:
            if not isinstance(row, Mapping):
                raise ValueError
            identifier, name = row.get("id"), row.get("name")
            safe_name = _safe_observed_name(name) if table == "folder" else _safe_secret_name(name)
            if (type(identifier) is not int or not 0 < identifier <= 2_147_483_647 or identifier in ids
                or type(name) is not str or not safe_name or name in names):
                raise ValueError
            ids.add(identifier); names.append(name)
            if identifier == selected_id:
                if name != selected_name or table == "database" and (
                    type(row.get("folder")) is not int or row["folder"] != b.folder_id):
                    raise ValueError
                selected = True
        if not selected or witness not in names:
            raise ValueError
        return tuple(names)


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    row: dict[str, object] = {}
    for key, value in pairs:
        if key in row:
            raise ValueError
        row[key] = value
    return row


def _normalize_fixed_detail(raw: bytearray, binding: SingleSecretFolderMembershipBinding) -> None:
    """Qualify fixed metadata bytes before the existing row-only native kernel.

    Field values have already been erased. Only bounded keys and approved
    metadata tokens are inspected here; no Secret field value is decoded.
    """
    left = _skip_json_space(raw, 0)
    right = _json_value_end(raw, left)
    if _skip_json_space(raw, right) != len(raw):
        raise ValueError
    root = _object_spans(raw, left, right)
    if not root.keys() <= _ENVELOPE | {"mkey", "error"} or "next_idx" in root:
        raise ValueError
    _qualify_database_header(raw, root, binding)
    for key, token in (("size", b"1"), ("matched_count", b"1"), ("limit_reached", b"false")):
        if key in root and raw[slice(*root[key])] != token:
            raise ValueError
    if "mkey" in root and bytes(raw[slice(*root["mkey"])]) not in (
        str(binding.secret_id).encode("ascii"), json.dumps(str(binding.secret_id)).encode("ascii"),
    ):
        raise ValueError
    row_left, row_right = root["results"]
    if raw[row_left] == 91:
        row_left = _skip_json_space(raw, row_left + 1)
        row_end = _json_value_end(raw, row_left)
        if _skip_json_space(raw, row_end) != row_right - 1:
            raise ValueError
        row_right = row_end
    identity = {"id": binding.secret_id, "name": binding.secret_name, "folder": binding.folder_id}
    spans = _row_identity_spans(raw, row_left, row_right)
    for key, value in identity.items():
        if raw[slice(*spans[key])] != json.dumps(value, ensure_ascii=True).encode("ascii"):
            raise ValueError
    _normalize_build29_clipboard_duplicate(raw, (row_left, row_right))
    _validate_value(raw, left, right, depth=0)
    _object_spans(raw, row_left, row_right)


def _qualify_database_header(
    raw: bytearray, root: Mapping[str, tuple[int, int]], binding: SingleSecretFolderMembershipBinding,
) -> None:
    expected = {**_HEADER, "serial": binding.expected_serial, "path": "secret", "name": "database"}
    for key, value in expected.items():
        if raw[slice(*root[key])] != json.dumps(value, ensure_ascii=True).encode("ascii"):
            raise ValueError
    if bytes(raw[slice(*root["status"])]) not in (b'"OK"', b'"success"'):
        raise ValueError
    for key, token in (("action", b'""'), ("error", b"0")):
        if key in root and raw[slice(*root[key])] != token:
            raise ValueError


def _row_identity_spans(raw: bytearray, row_left: int, row_right: int) -> dict[str, tuple[int, int]]:
    """Locate each required top-level metadata member once without decoding values."""
    if raw[row_left] != 123 or raw[row_right - 1] != 125:
        raise ValueError
    identity = {"id", "name", "folder"}
    spans: dict[str, tuple[int, int]] = {}
    cursor = _skip_json_space(raw, row_left + 1)
    members = 0
    while cursor < row_right - 1:
        members += 1
        key_end = _json_string_end(raw, cursor)
        if members > 512 or key_end - cursor > 66:
            raise ValueError
        key = json.loads(raw[cursor:key_end + 1])
        colon = _skip_json_space(raw, key_end + 1)
        if raw[colon] != 58:
            raise ValueError
        value_start = _skip_json_space(raw, colon + 1)
        value_end = _json_value_end(raw, value_start)
        if value_end >= row_right:
            raise ValueError
        if key in identity:
            if key in spans:
                raise ValueError
            spans[key] = value_start, value_end
        cursor = _skip_json_space(raw, value_end)
        if cursor == row_right - 1:
            break
        if raw[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(raw, cursor + 1)
        if cursor >= row_right - 1:
            raise ValueError
    if spans.keys() != identity:
        raise ValueError
    return spans


def _normalize_fixed_secret_collection(raw: bytearray, binding: SingleSecretFolderMembershipBinding) -> None:
    """Qualify the one compiled visible Secret collection before row normalization."""
    left = _skip_json_space(raw, 0)
    right = _json_value_end(raw, left)
    if _skip_json_space(raw, right) != len(raw):
        raise ValueError
    root = _object_spans(raw, left, right)
    if not root.keys() <= _ENVELOPE | {"error", "next_index", "total", "total_count"}:
        raise ValueError
    _qualify_database_header(raw, root, binding)
    for key, token in (("limit_reached", b"false"), ("next_idx", b"0"), ("next_index", b"0")):
        if key in root and raw[slice(*root[key])] != token:
            raise ValueError
    array_left, array_right = root["results"]
    if raw[array_left] != 91 or raw[array_right - 1] != 93:
        raise ValueError
    cursor = _skip_json_space(raw, array_left + 1)
    rows: list[tuple[int, int]] = []
    while cursor < array_right - 1:
        if len(rows) >= 511:
            raise ValueError
        row_end = _json_value_end(raw, cursor)
        if row_end >= array_right:
            raise ValueError
        rows.append((cursor, row_end))
        cursor = _skip_json_space(raw, row_end)
        if cursor == array_right - 1:
            break
        if raw[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(raw, cursor + 1)
        if cursor >= array_right - 1:
            raise ValueError
    if not 2 <= len(rows) < 512:
        raise ValueError
    count_token = str(len(rows)).encode("ascii")
    if raw[slice(*root["matched_count"])] != count_token:
        raise ValueError
    for key in ("total", "total_count"):
        if key in root and raw[slice(*root[key])] != count_token:
            raise ValueError
    if "size" in root:
        size_token = raw[slice(*root["size"])]
        if re.fullmatch(rb"0|[1-9][0-9]{0,2}", size_token) is None or not len(rows) <= int(size_token) <= 512:
            raise ValueError
    ids: set[int] = set()
    names: set[str] = set()
    selected = False
    for row_left, row_right in rows:
        spans = _row_identity_spans(raw, row_left, row_right)
        metadata: dict[str, object] = {}
        for key, span in spans.items():
            # Only id/name/folder tokens are decoded, never field values.
            identity_token = raw[slice(*span)]
            if key == "name":
                if (len(identity_token) > 3062 or identity_token[0] != 34 or identity_token[-1] != 34):
                    raise ValueError
            elif re.fullmatch(rb"0|[1-9][0-9]{0,9}", identity_token) is None:
                raise ValueError
            metadata[key] = json.loads(identity_token)
        identifier, name, folder = metadata["id"], metadata["name"], metadata["folder"]
        if (type(identifier) is not int or not 0 < identifier <= 2_147_483_647 or identifier in ids
            or type(name) is not str or not _safe_secret_name(name) or name in names
            or type(folder) is not int or not 0 <= folder <= 2_147_483_647):
            raise ValueError
        ids.add(identifier); names.add(name)
        if identifier == binding.secret_id:
            if name != binding.secret_name or folder != binding.folder_id:
                raise ValueError
            selected = True
    if not selected or binding.secret_witness_name not in names:
        raise ValueError
    for span in rows:
        _normalize_build29_clipboard_duplicate(raw, span)
    _validate_value(raw, left, right, depth=0)
    for span in rows:
        _object_spans(raw, *span)
