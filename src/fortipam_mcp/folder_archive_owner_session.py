"""Fixed build-29 Folder archive through an existing protected Owner session."""
from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
from http.cookies import SimpleCookie
import json
import re
import threading
from typing import Any
from urllib.parse import quote

import httpx

from .folder_archive_live_workflow import _ARCHIVE_NAME, _folder_id, _isolated_permissions
from .folder_http_transport import COLLECTION_PATH, FolderTransportConfig, MAX_RESPONSE_BYTES
from .isolated_folder_http_transport import _FOLDER_FIELDS
from .local_user_reset_fixture_preflight import _actor_context
from .owner_collector_runtime import PREFIX as _LOGIN_PREFIX, owner_login_provider
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig, _zeroize_mutable,
)

PREFIX = "FPA_HOME_LAB_FPA1_V4_FOLDER_ARCHIVE_OWNER_"
_UNAVAILABLE = "The fixed Folder archive Owner session is unavailable."
_QUERY = "?format=" + quote(_FOLDER_FIELDS, safe="")


class FolderArchiveOwnerSessionError(RuntimeError):
    """Stable non-disclosing failure; uncertain DELETEs never replay."""


def build_folder_archive_owner_session(
    config: FolderTransportConfig, environment: Mapping[str, str],
) -> FixedFolderArchiveOwnerSession:
    """Load only the dedicated private Owner/name bindings and retained provider."""
    try:
        binding = {_LOGIN_PREFIX + "SESSION_ENABLED": "true"}
        for suffix in ("LOGIN_ENV_FILE", "USERNAME_VARIABLE", "PASSWORD_VARIABLE"):
            binding[_LOGIN_PREFIX + suffix] = environment[PREFIX + suffix]
        provider = owner_login_provider(binding)
        if provider is None:
            raise ValueError
        return FixedFolderArchiveOwnerSession(
            config, owner_name=environment[PREFIX + "USERNAME"], credentials=provider,
            folder_name=environment[PREFIX + "FOLDER_NAME"],
        )
    except Exception:
        raise FolderArchiveOwnerSessionError(_UNAVAILABLE) from None


class FixedFolderArchiveOwnerSession:
    """One private-bound Folder, fresh actor checks, one DELETE and verified logout.

    The workflow retains its durable claim, independent CLI hierarchy/reference
    checks and readback. This adapter pins the first eligible full projection and
    rejects subsequent drift, including changes between preflight and DELETE.
    """

    def __init__(
        self, config: FolderTransportConfig, *, owner_name: str, folder_name: str,
        credentials: Callable[[], tuple[str, str]],
        client_factory: Callable[..., Any] = httpx.Client,
    ) -> None:
        if (
            _ARCHIVE_NAME.fullmatch(folder_name) is None
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", owner_name) is None
        ):
            raise FolderArchiveOwnerSessionError(_UNAVAILABLE)
        self._initialize_owner_binding(config, owner_name=owner_name, folder_name=folder_name,
            credentials=credentials, client_factory=client_factory)

    def _initialize_owner_binding(self, config: FolderTransportConfig, *, owner_name: str, folder_name: str,
            credentials: Callable[[], tuple[str, str]], client_factory: Callable[..., Any]) -> None:
        """Shared private session plumbing; each fixed constructor validates scope."""
        if hasattr(self, "_session"):
            raise FolderArchiveOwnerSessionError(_UNAVAILABLE)
        metadata = SecretMetadataHttpTransportConfig(
            config.base_url, config.bearer_token, config.timeout_seconds, config.ca_file,
        )
        self._session = OwnerSessionMetadataTransport(
            metadata, owner_name=owner_name, credentials=credentials,
            folder_path="folder-archive", secret_name="folder-archive", target_name="folder-archive",
            witness=FortiPamSecretMetadataHttpTransport(metadata), client_factory=client_factory,
        )
        self.folder_name = folder_name
        self._owner_name = owner_name
        self._baseline: tuple[int, str, str] | None = None
        self._actor_qualified = False
        self._attempted = False
        self._lock = threading.Lock()

    @property
    def logout_verified(self) -> bool:
        return self._session.logout_verified

    def read_collection(self) -> Mapping[str, object]:
        """Read a fixed projection as the Owner; no API-token fallback."""
        with self._lock:
            self._actor_qualified = False
            try:
                with self._session.authenticated():
                    self._verify_actor()
                    body = self._read("GET", COLLECTION_PATH + _QUERY + "&count=512&start=0")
                    rows = body.get("results")
                    if (
                        not isinstance(rows, list) or len(rows) >= 512
                        or type(body.get("matched_count")) is not int
                        or body["matched_count"] != len(rows)
                        or body.get("limit_reached", False) is not False
                        or not all(isinstance(row, Mapping) for row in rows)
                    ):
                        raise ValueError
                    selected = [row for row in rows if row.get("name") == self.folder_name]
                    if len(selected) > 1:
                        raise ValueError
                    if selected:
                        snapshot = self._snapshot(selected[0], body["serial"])
                        if self._baseline is not None and snapshot != self._baseline:
                            raise ValueError
                        self._baseline = snapshot
                self._actor_qualified = True
                return body
            except Exception:
                raise FolderArchiveOwnerSessionError(_UNAVAILABLE) from None

    def inspect(self, expected_requester: str) -> None:
        """Consume the identity observation from the immediately preceding read."""
        with self._lock:
            qualified = self._actor_qualified
            self._actor_qualified = False
            if not qualified or expected_requester != self._owner_name or self._attempted:
                raise FolderArchiveOwnerSessionError(_UNAVAILABLE)

    def delete_empty_folder(self, folder_id: int) -> Mapping[str, object]:
        """Send one bodyless exact-ID DELETE after fresh Owner/record/CSRF checks."""
        result = self._delete_empty_folder(folder_id)
        if not isinstance(result, Mapping):
            raise FolderArchiveOwnerSessionError(_UNAVAILABLE)
        return result

    def delete_empty_folder_original(self, folder_id: int, *, before_dispatch: Callable[[], None],
            observe_response: Callable[[int, str, str], None],
            consume_original_ack: Callable[[bytearray, int, str], object]) -> object:
        """Private original-M4 handoff; raw bytes cannot be supplied by callers."""
        if not all(callable(item) for item in (before_dispatch, observe_response, consume_original_ack)):
            raise FolderArchiveOwnerSessionError(_UNAVAILABLE)
        return self._delete_empty_folder(folder_id, before_dispatch=before_dispatch,
            observe_response=observe_response, consume_original_ack=consume_original_ack)

    def _delete_empty_folder(self, folder_id: int, *, before_dispatch: Callable[[], None] | None = None,
            observe_response: Callable[[int, str, str], None] | None = None,
            consume_original_ack: Callable[[bytearray, int, str], object] | None = None) -> object:
        with self._lock:
            if self._attempted or self._baseline is None or _folder_id(folder_id) != self._baseline[0]:
                raise FolderArchiveOwnerSessionError(_UNAVAILABLE)
            self._attempted = True
            try:
                with self._session.authenticated():
                    self._verify_actor()
                    path = COLLECTION_PATH + "/" + str(folder_id)
                    current = self._read("GET", path + _QUERY)
                    rows = current.get("results")
                    if not isinstance(rows, list) or len(rows) != 1:
                        raise ValueError
                    if self._snapshot(rows[0], current["serial"]) != self._baseline:
                        raise ValueError
                    cookies: SimpleCookie = SimpleCookie()
                    cookies.load(self._session._client.build_request("GET", path).headers.get("cookie", ""))
                    csrf = cookies.get("ccsrftoken")
                    if (csrf is None or not csrf.value or len(csrf.value) > 4096
                            or any(ord(c) < 33 or ord(c) > 126 for c in csrf.value)):
                        raise ValueError
                    headers = {
                        "Accept": "application/json", "X-CSRFTOKEN": csrf.value,
                        "Content-Length": "0", "Cache-Control": "no-cache, no-store",
                    }
                    result: object
                    if consume_original_ack is None:
                        body = self._read("DELETE", path, headers=headers)
                        if body["serial"] != self._baseline[1]:
                            raise ValueError
                        result = body
                    else:
                        if before_dispatch is None or observe_response is None:
                            raise ValueError
                        before_dispatch()
                        result = self._original_delete(path, headers, before_dispatch, observe_response, consume_original_ack)
                return result
            except Exception:
                raise FolderArchiveOwnerSessionError(_UNAVAILABLE) from None

    def _original_delete(self, path: str, headers: Mapping[str, str],
            guard: Callable[[], None],
            observe_response: Callable[[int, str, str], None],
            consumer: Callable[[bytearray, int, str], object]) -> object:
        raw = bytearray()
        try:
            if (self._baseline is None or path != COLLECTION_PATH + "/" + str(self._baseline[0])
                    or self._session._client is None or not self._attempted):
                raise ValueError
            with self._session._client.stream("DELETE", path,
                    headers={**headers, "Accept-Encoding":"identity"}) as response:
                content_type = response.headers.get("content-type", "")
                encoding = response.headers.get("content-encoding", "identity")
                observe_response(response.status_code, content_type, encoding)
                if response.status_code != 200 or content_type.split(";")[0] != "application/json" or encoding not in ("", "identity"):
                    raise ValueError
                guard()
                for part in response.iter_raw():
                    guard()
                    if len(raw) + len(part) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(part)
                return consumer(raw, response.status_code, content_type)
        finally:
            _zeroize_mutable(raw)

    def _snapshot(self, row: Mapping[str, object], serial: object) -> tuple[int, str, str]:
        identifier = _folder_id(row.get("id"))
        if (row.get("name") != self.folder_name or row.get("folder-type") != "public"
                or _folder_id(row.get("parent-folder")) == identifier or not isinstance(serial, str)):
            raise ValueError
        _, owner = _isolated_permissions(row)
        if owner != self._owner_name:
            raise ValueError
        projection = {key: row[key] for key in _FOLDER_FIELDS.split("|")}
        digest = hashlib.sha256(json.dumps(projection, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        return identifier, serial, digest

    def _verify_actor(self) -> None:
        raw = self._read_bytes("GET", "/api/v2/monitor/web-ui/state")
        try:
            _actor_context(raw, expected_name=self._owner_name)
        finally:
            _zeroize_mutable(raw)

    def _read_bytes(self, method: str, path: str, *, headers: Mapping[str, str] | None = None) -> bytearray:
        raw = bytearray()
        try:
            with self._session._client.stream(method, path, headers=headers) as response:
                if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            return raw
        except Exception:
            _zeroize_mutable(raw)
            raise FolderArchiveOwnerSessionError(_UNAVAILABLE) from None

    def _read(self, method: str, path: str, *, headers: Mapping[str, str] | None = None) -> dict[str, Any]:
        raw = self._read_bytes(method, path, headers=headers)
        try:
            body = json.loads(raw)
            if (not isinstance(body, dict) or body.get("version") != "v7.0.0"
                    or type(body.get("build")) is not int or body["build"] != 29
                    or type(body.get("http_status")) is not int or body["http_status"] != 200
                    or body.get("http_method") != method or body.get("path") != "secret"
                    or body.get("name") != "folder" or body.get("status") not in {"success", "OK"}
                    or not isinstance(body.get("serial"), str)
                    or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", body["serial"]) is None
                    or ("error" in body and (type(body["error"]) is not int or body["error"] != 0))):
                raise ValueError
            return body
        finally:
            _zeroize_mutable(raw)
