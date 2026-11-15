"""Fixed private build-29 approval sources; no login, dispatch, or registration.

The caller owns authorization and the existing Owner session. This producer
supports only disabled TOTP with explicit empty material, and does not qualify
the new schema HTTP producer or grant mutation authority.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
from http.cookies import SimpleCookie
import hmac
import json
import re
import time
from typing import Any, cast
from urllib.parse import quote, urlsplit

from .cli_safety import _complete_pre_login
from .folder_namespace_ssh_reader import (
    _MAX_OUTPUT_BYTES, _SERIAL_COMMAND, _VERSION_COMMAND, _frame_lines, _qualified_version_metadata,
)
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_approval_build29_contract import APPROVAL_FIELDS, qualify_secret_approval_build29_schema
from .secret_approval_build29_http_transport import (
    _FIELD_ORDER, _NATIVE_ENVELOPE, _normalize_one_native_metadata_duplicate,
    _redact_material_members, _unique_members,
)
from .secret_approval_build29_linux_metadata import qualify_secret_approval_build29_linux_metadata
from .secret_approval_build29_metadata_reader import _one_row, _reject_constant
from .secret_approval_build29_native_preservation import (
    _safe_name, consume_secret_approval_build29_native_preservation,
)
from .secret_approval_build29_totp_boundary import (
    SecretApprovalBuild29TotpWitness, consume_secret_approval_build29_totp_response,
)
from .secret_metadata_http_transport import (
    COLLECTION_PATH, MAX_RESPONSE_BYTES, UTILITY_ID_PATH, _folder_path, _path_for_url,
    _redact_json_field_values, _secret_name, _zeroize_mutable,
)
from .target_contract import DEFAULT_TEMPLATE
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport
from .target_ssh_transport import TargetSshTransportConfig, _close_cli, _send_and_read

_UNAVAILABLE = "The fixed build-29 approval private sources are unavailable."
_TOTP_PATH = "/api/v2/internal/secret-clear-text"
_SCHEMA_PATH = COLLECTION_PATH + "?action=schema&with_meta=true"


class SecretApprovalBuild29PrivateSourcesError(RuntimeError):
    """Categorical refusal without source, material, or upstream details."""


class SecretApprovalBuild29PrivateSources:
    """Private fixed reads for one Web Account or explicitly bound Linux Secret."""

    def __init__(self, owner: OwnerSessionMetadataTransport, ssh_config: TargetSshTransportConfig, *,
                 expected_serial: str, expected_secret_id: int, expected_secret_name: str,
                 folder_path: str, expected_folder_id: int, web_url: str | None = None,
                 witness_key: bytes | bytearray, linux_target_name: str | None = None,
                 expected_ssh_host: str | None = None) -> None:
        """Bind private sources; SSH aliases are Linux read-only evidence only.

        An explicit SSH host must come from a protected central same-device
        mapping, never an MCP caller's selection. The caller must verify that
        mapping and existing host-key pin; serial/version checks remain required.
        """
        try:
            if (not isinstance(owner, OwnerSessionMetadataTransport)
                or not isinstance(ssh_config, TargetSshTransportConfig)
                or type(expected_serial) is not str or not 1 <= len(expected_serial) <= 64
                or not expected_serial.isascii() or not expected_serial.isalnum()
                or any(type(value) is not int or not 0 < value <= 2_147_483_647
                       for value in (expected_secret_id, expected_folder_id))
                or not _safe_name(expected_secret_name, 64)
                or type(witness_key) not in (bytes, bytearray) or len(witness_key) < 32):
                raise ValueError
            if linux_target_name is None:
                if (type(web_url) is not str or len(web_url) > 2048
                    or any(ord(char) < 32 or ord(char) == 127 for char in web_url)):
                    raise ValueError
                parsed = urlsplit(web_url)
                if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None or parsed.fragment):
                    raise ValueError
            elif web_url is not None or not _safe_name(linux_target_name, 255):
                raise ValueError
            if (expected_ssh_host is not None
                and (linux_target_name is None or type(expected_ssh_host) is not str
                     or expected_ssh_host != ssh_config.host)):
                raise ValueError
            self._expected_ssh_host = expected_ssh_host
            origin = urlsplit(owner._config.base_url)
            self._http_origin = (origin.scheme, origin.hostname, origin.port)
            self._ssh_port = ssh_config.port
            self._linux_target_name = linux_target_name
            folder = _folder_path(folder_path)
            name = _secret_name(expected_secret_name, bound_name=owner._bound_secret_name)
            self._owner = owner
            self._ssh = FortiPamTargetReferenceSshTransport(ssh_config)
            self._serial = expected_serial
            self._identity = {"id": expected_secret_id, "name": name, "folder": expected_folder_id}
            self._folder = folder
            self._path = COLLECTION_PATH + "/" + str(expected_secret_id)
            self._check_binding()
            self._key = bytearray(witness_key)
            self._closed = False
        except Exception:
            raise SecretApprovalBuild29PrivateSourcesError(_UNAVAILABLE) from None

    def _check_binding(self) -> None:
        owner = self._owner
        origin = urlsplit(owner._config.base_url)
        expected_host = origin.hostname if self._expected_ssh_host is None else self._expected_ssh_host
        if (origin.scheme != "https" or expected_host != self._ssh._config.host
            or owner._owner_name != self._ssh._config.username
            or owner._bound_secret_name != self._identity["name"]
            or owner._folder_lookup_path != UTILITY_ID_PATH + "/" + _path_for_url(self._folder)
            or owner._secret_lookup_path != UTILITY_ID_PATH + "/" + _path_for_url(
                self._folder + "/" + str(self._identity["name"]))):
            raise ValueError
        if (self._expected_ssh_host is not None
            and (self._linux_target_name is None or type(self._expected_ssh_host) is not str
                 or (origin.scheme, origin.hostname, origin.port) != self._http_origin
                 or self._ssh._config.port != self._ssh_port)):
            raise ValueError
        if (self._linux_target_name is not None
            and "/api/v2/cmdb/secret/target/" + quote(self._linux_target_name, safe="")
                not in owner._allowed_paths):
            raise ValueError

    def _active(self, client: Any = None) -> Any:
        self._check_binding()
        owner = self._owner
        if (self._closed or not self._key or owner._client is None
            or owner._clock() >= owner._expires_at
            or client is not None and owner._client is not client):
            raise ValueError
        return owner._client

    def close(self) -> None:
        self._closed = True
        _zeroize_mutable(self._key)

    def native_preservation_digest(self, approval_values: tuple[str, str, str, str]) -> str:
        """Bracket one exact native frame inside the caller's active Owner session."""
        try:
            if (type(approval_values) is not tuple or len(approval_values) != 4
                or any(type(value) is not str for value in approval_values)
                or any(value not in {"enable", "disable"} for value in approval_values[:3])
                or approval_values[3] and not _safe_name(approval_values[3], 79)):
                raise ValueError
            client = self._active()
            self._qualify_secret(client, approval_values)
            before = self._totp(client)
            # No SSH connection is attempted for unqualified/nonempty material.
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                digest = asyncio.run(self._native(client, approval_values, before))
                self._active(client)
                return digest
            raise ValueError
        except Exception:
            raise SecretApprovalBuild29PrivateSourcesError(_UNAVAILABLE) from None

    async def _native(self, client: Any, approval_values: tuple[str, str, str, str],
                      before: SecretApprovalBuild29TotpWitness) -> str:
        raw, output = bytearray(), bytearray()
        lines: tuple[bytearray, ...] = ()
        try:
            self._active(client)
            async with self._ssh._connection() as connection:
                process = await connection.create_process(term_type="vt100", term_size=(1024, 1024), encoding=None)
                try:
                    deadline = time.monotonic() + self._ssh._config.timeout_seconds
                    prompt = await _complete_pre_login(process.stdout, process.stdin, deadline,
                        _MAX_OUTPUT_BYTES, accept_pre_login_banner=False)
                    if re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", prompt) is None:
                        raise ValueError
                    for command in (_SERIAL_COMMAND, _VERSION_COMMAND):
                        self._active(client)
                        output.extend(await _send_and_read(process, command, prompt, deadline))
                        lines = self._lines(output, command, prompt)
                        present = tuple(line for line in lines if line.strip(b" \t"))
                        if command == _SERIAL_COMMAND:
                            if (len(present) != 1 or not hmac.compare_digest(present[0],
                                b"Serial-Number: " + self._serial.encode("ascii"))):
                                raise ValueError
                        elif not _qualified_version_metadata(cast(tuple[bytes, ...], present)):
                            raise ValueError
                        for line in lines: _zeroize_mutable(line)
                        lines = ()
                        _zeroize_mutable(output)
                    self._active(client)
                    command = "show full-configuration secret database " + str(self._identity["id"])
                    output.extend(await _send_and_read(process, command, prompt, deadline))
                    lines = self._lines(output, command, prompt)
                    # The qualified CLI frame may contain one empty footer.
                    selected = lines[:-1] if lines and not lines[-1] else lines
                    for index, line in enumerate(selected):
                        if index: raw.extend(b"\n")
                        raw.extend(line)
                    self._active(client)
                    after = self._totp(client)
                    digest = consume_secret_approval_build29_native_preservation(raw,
                        expected_secret_id=cast(int, self._identity["id"]),
                        expected_secret_name=cast(str, self._identity["name"]), approval_values=approval_values,
                        totp_before=before, totp_after=after, witness_key=self._key).preservation_digest
                    self._active(client)
                    return digest
                finally:
                    await _close_cli(process)
        finally:
            for line in lines: _zeroize_mutable(line)
            _zeroize_mutable(output)
            _zeroize_mutable(raw)

    @staticmethod
    def _lines(raw: bytearray, command: str, prompt: bytes) -> tuple[bytearray, ...]:
        # The existing frame guard preserves bytearray slicing/splitting at
        # runtime. Keep those line buffers mutable for erasure, without bytes().
        return cast(tuple[bytearray, ...], _frame_lines(cast(bytes, raw), command, prompt))

    def _totp(self, client: Any) -> SecretApprovalBuild29TotpWitness:
        raw = bytearray()
        try:
            self._active(client)
            cookie = client.build_request("GET", _TOTP_PATH).headers.get("cookie")
            jar: SimpleCookie = SimpleCookie()
            jar.load(cookie or "")
            csrf = jar.get("ccsrftoken")
            if (csrf is None or not csrf.value or len(csrf.value) > 4096
                or any(ord(char) < 33 or ord(char) > 126 for char in csrf.value)):
                raise ValueError
            with client.stream("POST", _TOTP_PATH,
                json={"secret-id": self._identity["id"], "totp-share-key": 1},
                headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest", "X-CSRFTOKEN": csrf.value}) as response:
                self._collect(raw, response)
                self._active(client)
                witness = consume_secret_approval_build29_totp_response(raw, http_status=response.status_code,
                    content_type=response.headers.get("content-type", ""), witness_key=self._key,
                    expected_envelope={"http_method": "POST", "http_status": 200,
                        "msg": "Successfully fetched clear_text", "status": "OK",
                        "secret-id": cast(int, self._identity["id"])})
            if witness.explicit_empty is not True:
                raise ValueError
            return witness
        finally:
            _zeroize_mutable(raw)

    def _qualify_secret(self, client: Any, approval_values: tuple[str, str, str, str]) -> None:
        raw = self._get(self._path, client)
        try:
            if self._linux_target_name is not None:
                observed = qualify_secret_approval_build29_linux_metadata(raw,
                    identity={**self._identity, "template": DEFAULT_TEMPLATE,
                              "target": self._linux_target_name}, expected_serial=self._serial)
                if observed.approval_values != approval_values or observed.totp_disabled is not True:
                    raise ValueError
                self._active(client)
                return
            _redact_json_field_values(raw)
            _redact_material_members(raw)
            _normalize_one_native_metadata_duplicate(raw)
            payload = json.loads(raw, object_pairs_hook=_unique_members, parse_constant=_reject_constant)
            if (type(payload) is not dict or set(payload) != set(_NATIVE_ENVELOPE) | {"serial", "results"}
                or any(type(payload.get(key)) is not type(value) or payload[key] != value
                       for key, value in _NATIVE_ENVELOPE.items())
                or type(payload["serial"]) is not str or payload["serial"] != self._serial):
                raise ValueError
            row = _one_row(payload)
            totp = row.get("totp-setting")
            if (any(type(row.get(key)) is not type(value) or row[key] != value for key, value in self._identity.items())
                or row.get("template") != "Web Account" or row.get("target") != ""
                or type(totp) is not dict or totp.get("status") != "disable"
                or any(type(row.get(key)) is not str or row[key] != value for key, value in zip(_FIELD_ORDER, approval_values))):
                raise ValueError
            self._active(client)
        finally:
            _zeroize_mutable(raw)

    def approval_schema(self) -> dict[str, object]:
        """Return only the four source-validated schema fields, never full schema."""
        raw = bytearray()
        try:
            client = self._active()
            raw = self._get(_SCHEMA_PATH, client)
            _redact_json_field_values(raw)
            _redact_material_members(raw)
            payload = json.loads(raw, object_pairs_hook=_unique_members, parse_constant=_reject_constant)
            if (type(payload) is not dict or type(payload.get("version")) is not str or payload["version"] != "v7.0.0"
                or type(payload.get("build")) is not int or payload["build"] != 29
                or type(payload.get("results")) is not dict or type(payload["results"].get("children")) is not dict):
                raise ValueError
            children = payload["results"]["children"]
            schema = {"version": "v7.0.0", "build": 29,
                      "selected_schema": {name: deepcopy(children[name]) for name in APPROVAL_FIELDS}}
            qualify_secret_approval_build29_schema(schema)
            self._active(client)
            return schema
        except Exception:
            raise SecretApprovalBuild29PrivateSourcesError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(raw)

    def _get(self, path: str, client: Any) -> bytearray:
        raw = bytearray()
        try:
            if path not in {self._path, _SCHEMA_PATH}:
                raise ValueError
            self._active(client)
            with client.stream("GET", path, headers={"Accept": "application/json", "Cache-Control": "no-cache, no-store"}) as response:
                self._collect(raw, response)
            self._active(client)
            return raw
        except Exception:
            _zeroize_mutable(raw)
            raise

    @staticmethod
    def _collect(raw: bytearray, response: Any) -> None:
        if (type(response.status_code) is not int or response.status_code != 200
            or response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json"):
            raise ValueError
        for chunk in response.iter_bytes():
            if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                raise ValueError
            raw.extend(chunk)
        if not raw:
            raise ValueError
