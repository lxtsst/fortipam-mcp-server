"""Fixed, read-only build-29 System Events reader for one retained BP002 fixture.

The constructor binds an owner-only fixture directory and an API principal
from the protected lab configuration. No public selector, filter, raw log,
or mutation route is exposed. A successful read is evidence, not a reset
authorization or an amendment to the original create ledger.
"""

from __future__ import annotations

from collections.abc import Callable
import http.client
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .local_user_reset_creation_audit_projection import (
    LocalUserResetCreationAuditObservation, _ACTOR as _ACTOR_NAME,
    _MAX_BYTES, _NAME, _normalize_log_metadata_key,
    project_local_user_reset_creation_audit,
)
from .local_user_reset_fixture_preflight import _ACTOR, _actor_context
from .local_user_reset_metadata_reader import _validate_value
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space,
    _ssl_context, _zeroize_mutable,
)

_STATE = "/api/v2/monitor/log/device/state"
_EVENTS = "/api/v2/log/disk/event/system"
_ABORT = "/api/v2/log/search/abort/"
_LIMIT = 25
_MAX_AGE_SECONDS = 48 * 60 * 60
_UNAVAILABLE = "The private Local User creation audit read is unavailable."


class LocalUserResetCreationAuditReadError(RuntimeError):
    """Fixed failure with no endpoint, fixture, log, or credential values."""


def _value(content: bytearray, span: tuple[int, int]) -> object:
    return json.loads(content[slice(*span)])


def _validated_root(content: bytearray) -> dict[str, tuple[int, int]]:
    left = _skip_json_space(content, 0)
    right = _json_value_end(content, left)
    if _skip_json_space(content, right) != len(content):
        raise ValueError
    _normalize_log_metadata_key(content)
    _validate_value(content, left, right, depth=0)
    return _object_spans(content, left, right)


def _disk_log_serial(content: bytearray) -> str:
    """Read only fixed disk-log readiness and appliance serial metadata."""
    root = _validated_root(content)
    for key, expected in (("status", "success"), ("version", "v7.0.0"), ("build", 29)):
        if key not in root or _value(content, root[key]) != expected:
            raise ValueError
    if "http_method" in root and _value(content, root["http_method"]) != "GET":
        raise ValueError
    serial = _value(content, root["serial"])
    if not isinstance(serial, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", serial) is None:
        raise ValueError
    results = _object_spans(content, *root["results"])
    disk = _object_spans(content, *results["disk"])
    for key in ("is_enabled", "is_loggable"):
        if _value(content, disk[key]) is not True:
            raise ValueError
    excluded = _value(content, disk["excluded_categories"]) if "excluded_categories" in disk else []
    if (not isinstance(excluded, list) or len(excluded) > 64
        or any(not isinstance(category, str) for category in excluded)
        or "event" in excluded):
        raise ValueError
    return serial


def _progress(content: bytearray) -> tuple[int, int]:
    root = _validated_root(content)
    session = _value(content, root["session_id"])
    if isinstance(session, str) and re.fullmatch(r"[1-9][0-9]{0,15}", session):
        session = int(session)
    completed = _value(content, root["completed"])
    if (not isinstance(session, int) or isinstance(session, bool)
        or not 0 < session <= 9_007_199_254_740_991
        or not isinstance(completed, (int, float)) or isinstance(completed, bool)
        or not 0 <= completed <= 100):
        raise ValueError
    return session, int(completed)


class FortiPamLocalUserResetCreationAuditReader:
    """One fixed exact-object search, with bounded polling and session cleanup."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, *, fixture_directory: Path,
        api_principal: str,
        connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
        clock: Callable[[], int] | None = None,
        pause: Callable[[float], None] = time.sleep,
    ) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                or not isinstance(api_principal, str)
                or _ACTOR_NAME.fullmatch(api_principal) is None
                or not callable(connection_factory) or not callable(pause)
                or (clock is not None and not callable(clock))):
                raise ValueError
            origin = urlsplit(config.base_url)
            port = origin.port or 443
            if (origin.scheme != "https" or not origin.hostname
                or origin.username is not None or origin.password is not None
                or origin.path not in {"", "/"} or origin.query or origin.fragment
                or not 1 <= port <= 65535):
                raise ValueError
            self._context = _ssl_context(config)
            self._directory = Path(fixture_directory)
            self._directory_identity, self._username, self._created = self._binding()
        except Exception:
            raise LocalUserResetCreationAuditReadError(_UNAVAILABLE) from None
        self._config, self._principal, self._factory = config, api_principal, connection_factory
        self._clock = (lambda: int(time.time())) if clock is None else clock
        self._pause = pause
        self._host, self._port = origin.hostname, port

    def _binding(self) -> tuple[tuple[int, int], str, int]:
        directory = self._directory
        binding = directory / "binding.json"
        directory_stat = directory.lstat()
        binding_stat = binding.lstat()
        if (not directory.is_absolute() or directory.is_symlink()
            or not stat.S_ISDIR(directory_stat.st_mode)
            or stat.S_IMODE(directory_stat.st_mode) != 0o700
            or directory_stat.st_uid != os.getuid()
            or binding.is_symlink() or not stat.S_ISREG(binding_stat.st_mode)
            or stat.S_IMODE(binding_stat.st_mode) != 0o600
            or binding_stat.st_uid != os.getuid() or binding_stat.st_size > 512):
            raise ValueError
        document = json.loads(binding.read_bytes())
        if not isinstance(document, dict) or set(document) != {"username", "purpose"}:
            raise ValueError
        username = document["username"]
        match = _NAME.fullmatch(username) if isinstance(username, str) else None
        if match is None or document["purpose"] != "new_disabled_reset_fixture":
            raise ValueError
        created = int(match.group(1))
        if abs(binding_stat.st_mtime - created) > 60:
            raise ValueError
        return (directory_stat.st_dev, directory_stat.st_ino), username, created

    def _read(self, method: str, path: str, *, query: list[tuple[str, str]] | None = None) -> bytearray:
        content = bytearray()
        try:
            if ((method != "GET" or path not in {_ACTOR, _STATE, _EVENTS})
                and (method != "POST" or not path.startswith(_ABORT)
                     or re.fullmatch(r"[1-9][0-9]{0,15}", path[len(_ABORT):]) is None)):
                raise ValueError
            if (query is not None and (method != "GET" or path != _EVENTS)):
                raise ValueError
            target = path + ("?" + urlencode(query) if query is not None else "")
            content = bytearray(_MAX_BYTES + 1)
            connection = response = None
            transferred = False
            try:
                connection = self._factory(self._host, self._port,
                    timeout=self._config.timeout_seconds, context=self._context)
                connection.request(method, target, headers={
                    "Authorization": "Bearer " + self._config.bearer_token,
                    "Accept": "application/json", "Accept-Encoding": "identity",
                    "Connection": "close", "Cache-Control": "no-cache, no-store",
                    "User-Agent": "fortipam-bp002-creation-audit-read/1",
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
                transferred = True
                return content
            finally:
                if not transferred:
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

    def read_creation_event(self) -> LocalUserResetCreationAuditObservation:
        """Return the exact creation event only after all fixed reads qualify."""
        sessions: set[int] = set()
        observation: LocalUserResetCreationAuditObservation | None = None
        failed = False
        try:
            identity, username, created = self._binding()
            now = self._clock()
            if (identity != self._directory_identity or username != self._username
                or created != self._created or type(now) is not int
                or not created <= now <= created + _MAX_AGE_SECONDS):
                raise ValueError
            start_ms, end_ms = (created - 60) * 1000, now * 1000
            actor = self._read("GET", _ACTOR)
            try:
                _actor_context(actor, expected_name=self._principal)
            finally:
                _zeroize_mutable(actor)
            state = self._read("GET", _STATE)
            try:
                serial = _disk_log_serial(state)
            finally:
                _zeroize_mutable(state)
            base_query = [
                ("start", "0"), ("rows", str(_LIMIT)),
                ("filter", 'subtype=="system"'),
                ("filter", f'cfgobj=="{self._username}"'),
                ("filter", f'_metadata.timestamp>="{start_ms}"'),
                ("filter", f'_metadata.timestamp<="{end_ms}"'),
                ("extra", "country_id"), ("serial_no", serial),
            ]
            session: int | None = None
            last_completed = -1
            for attempt in range(8):
                query = base_query + ([("session_id", str(session))] if session is not None else [])
                content = self._read("GET", _EVENTS, query=query)
                try:
                    current, completed = _progress(content)
                    sessions.add(current)
                    if session is not None and current != session:
                        raise ValueError
                    if completed < last_completed:
                        raise ValueError
                    session = current
                    last_completed = completed
                    if completed == 100:
                        observation = project_local_user_reset_creation_audit(
                            content, username=self._username, api_actor=self._principal,
                            start_ms=start_ms, end_ms=end_ms,
                        )
                        break
                finally:
                    _zeroize_mutable(content)
                if attempt < 7:
                    self._pause(0.25)
            if observation is None:
                raise ValueError
            if self._binding() != (identity, username, created):
                raise ValueError
        except Exception:
            failed = True
        finally:
            cleanup_ok = True
            for session in sessions:
                try:
                    cleanup = self._read("POST", _ABORT + str(session))
                    _zeroize_mutable(cleanup)
                except Exception:
                    cleanup_ok = False
        if failed or not cleanup_ok or observation is None:
            raise LocalUserResetCreationAuditReadError(_UNAVAILABLE) from None
        return observation
