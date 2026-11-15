"""Private fixed Owner file-log query with durable one-attempt cleanup records."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import re
import stat
from threading import Lock
import time
from typing import Literal
from urllib.parse import quote, urlencode

from .local_user_reset_creation_audit_reader import _progress, _validated_root
from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_projection import _object_spans
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_file_audit_projection import (
    SecretFileAuditObservation, _ACTOR, _MAX_BYTES, _MAX_WINDOW_MS, _UINT32_MAX, _scalar,
    project_secret_file_audit,
)
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space, _ssl_context, _zeroize_mutable,
)

_STATE = "/api/v2/monitor/log/device/state"
_ACTOR_PATH = "/api/v2/monitor/web-ui/state"
_EVENTS = "/api/v2/log/disk/secret/secret-file"
_ABORT = "/api/v2/log/search/abort/"
_UNAVAILABLE = "The private Secret file audit Owner read is unavailable."


@dataclass(frozen=True, slots=True)
class SecretFileAuditCleanupObservation:
    qualified_handle_count: int
    abort_attempted_count: int
    cleanup_confirmed_count: int
    cleanup_complete: bool
    category: Literal["not_started", "confirmed", "cleanup_unconfirmed"]


@dataclass(frozen=True, slots=True)
class SecretFileAuditOwnerReadResult:
    observation: SecretFileAuditObservation
    cleanup: SecretFileAuditCleanupObservation


class SecretFileAuditOwnerReadError(RuntimeError):
    def __init__(self, cleanup: SecretFileAuditCleanupObservation) -> None:
        super().__init__(_UNAVAILABLE)
        self.cleanup = cleanup


class FortiPamSecretFileAuditOwnerReader:
    """Constructor-bound one-use reader; existing manifests never grant authority."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, owner: OwnerSessionMetadataTransport, *,
                 expected_serial: str, owner_name: str, expected_secret_id: int, expected_actor: str,
                 start_ms: int, end_ms: int, requester: str, manifest_path: Path,
                 pause: Callable[[float], None] = time.sleep) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                or type(owner) is not OwnerSessionMetadataTransport or owner._config != config
                or type(expected_serial) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", expected_serial) is None
                or type(owner_name) is not str or _ACTOR.fullmatch(owner_name) is None
                or owner._owner_name != owner_name or type(expected_actor) is not str
                or _ACTOR.fullmatch(expected_actor) is None
                or type(expected_secret_id) is not int or not 0 < expected_secret_id <= _UINT32_MAX
                or type(start_ms) is not int or type(end_ms) is not int
                or not 0 <= start_ms < end_ms <= 9_223_372_036_854_775_807
                or end_ms - start_ms > _MAX_WINDOW_MS or type(requester) is not str
                or _ACTOR.fullmatch(requester) is None or not callable(pause)):
                raise ValueError
            _ssl_context(config)
            path = Path(manifest_path)
            if not path.is_absolute() or path.name in {"", ".", ".."} or ".." in path.parts:
                raise ValueError
        except Exception:
            raise SecretFileAuditOwnerReadError(_cleanup(0, 0, 0)) from None
        self._config, self._owner = config, owner
        self._serial, self._owner_name = expected_serial, owner_name
        self._secret_id, self._actor = expected_secret_id, expected_actor
        self._start, self._end = start_ms, end_ms
        self._requester, self._manifest, self._pause = requester, path, pause
        self._role = "/api/v2/cmdb/system/admin/" + quote(owner_name, safe="") + "?" + urlencode({
            "format": "name|accprofile|status|remote-auth|wildcard"})
        self._lock, self._used = Lock(), False
        self._last_cleanup = _cleanup(0, 0, 0)

    def _reserve(self) -> int:
        parent = self._manifest.parent
        missing: list[Path] = []
        current = parent
        while not current.exists():
            missing.append(current)
            current = current.parent
        for ancestor in (current, *current.parents):
            if ancestor.is_symlink() or not stat.S_ISDIR(ancestor.lstat().st_mode):
                raise ValueError
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
        info = parent.lstat()
        if (parent.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError
        fd = os.open(self._manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            metadata = os.fstat(fd)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1):
                raise ValueError
            self._append(fd, {"kind": "binding", "requester": self._requester, "serial": self._serial,
                              "secret_id": self._secret_id, "owner": self._owner_name, "actor": self._actor,
                              "start_ms": self._start, "end_ms": self._end})
            parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            return fd
        except Exception:
            os.close(fd)
            raise

    def _append(self, fd: int, document: dict[str, object]) -> None:
        info, named = os.fstat(fd), self._manifest.lstat()
        if ((info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
            or not stat.S_ISREG(named.st_mode) or named.st_uid != os.getuid()
            or stat.S_IMODE(named.st_mode) != 0o600 or named.st_nlink != 1):
            raise ValueError
        raw = bytearray(json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n")
        try:
            offset = 0
            while offset < len(raw):
                count = os.write(fd, memoryview(raw)[offset:])
                if count <= 0:
                    raise ValueError
                offset += count
            os.fsync(fd)
        finally:
            _zeroize_mutable(raw)

    def _csrf(self) -> str:
        if self._owner._client is None:
            raise ValueError
        cookie = self._owner._client.build_request("GET", self._config.base_url + _EVENTS).headers.get("cookie")
        jar: SimpleCookie = SimpleCookie()
        if not cookie:
            raise ValueError
        jar.load(cookie)
        token = jar.get("ccsrftoken")
        if token is None or not token.value or len(token.value) > 512 or any(not 33 <= ord(c) <= 126 for c in token.value):
            raise ValueError
        return token.value

    def _exchange(self, path: str, *, abort: bool = False, csrf: str | None = None) -> bytearray:
        if (self._owner._client is None or self._owner._clock() >= self._owner._expires_at
            or (abort and (not csrf or re.fullmatch(re.escape(_ABORT) + r"[1-9][0-9]{0,15}", path) is None))
            or (not abort and path not in {_ACTOR_PATH, _STATE, self._role} and not path.startswith(_EVENTS + "?"))):
            raise ValueError
        raw = bytearray()
        headers = {"Accept": "application/json", "Accept-Encoding": "identity",
                   "Cache-Control": "no-cache, no-store", "User-Agent": "fortipam-bp005-file-audit/1"}
        if abort:
            headers.update({"X-Requested-With": "XMLHttpRequest", "X-CSRFTOKEN": str(csrf)})
        try:
            # Qualified build-29 Angular null body serializes to no wire body
            # and does not produce a detected Content-Type header.
            with self._owner._client.stream("POST" if abort else "GET", path, headers=headers) as response:
                if (type(response.status_code) is not int or response.status_code != 200
                    or response.headers.get("content-encoding", "identity").lower() != "identity"
                    or not abort and "json" not in response.headers.get("content-type", "").lower()):
                    raise ValueError
                for chunk in response.iter_bytes(chunk_size=4096):
                    if len(raw) + len(chunk) > _MAX_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            return raw
        except Exception:
            _zeroize_mutable(raw)
            raise
        finally:
            headers.clear()

    def _envelope(self, raw: bytearray, *, path: str | None, name: str | None) -> dict[str, tuple[int, int]]:
        root = _validated_root(raw)
        expected_values: dict[str, object] = {"version": "v7.0.0", "build": 29, "serial": self._serial,
                                             "status": "success"}
        if path is not None and name is not None:
            expected_values.update({"http_method": "GET", "path": path, "name": name})
        elif "http_method" in root:
            expected_values["http_method"] = "GET"
        for key, expected in expected_values.items():
            value = _scalar(raw, root[key])
            if type(value) is not type(expected) or value != expected:
                raise ValueError
        if "http_status" in root and _scalar(raw, root["http_status"]) != 200:
            raise ValueError
        return root

    def _preflight(self) -> None:
        actor, role, state = bytearray(), bytearray(), bytearray()
        try:
            actor = self._exchange(_ACTOR_PATH)
            self._envelope(actor, path="web-ui", name="state")
            _actor_context(actor, expected_name=self._owner_name)
            role = self._exchange(self._role)
            root = self._envelope(role, path="system", name="admin")
            left, right = root["results"]
            if role[left] == 91:
                left = _skip_json_space(role, left + 1)
                end = _json_value_end(role, left)
                if _skip_json_space(role, end) != right - 1:
                    raise ValueError
                right = end
            fields = _object_spans(role, left, right)
            expected = {"name": self._owner_name, "accprofile": "super_admin", "status": "enable",
                        "remote-auth": "disable", "wildcard": "disable"}
            if not set(expected) <= fields.keys() or not fields.keys() <= set(expected) | {"q_origin_key"}:
                raise ValueError
            for key, value in expected.items():
                if _scalar(role, fields[key]) != value:
                    raise ValueError
            if "q_origin_key" in fields and _scalar(role, fields["q_origin_key"]) != self._owner_name:
                raise ValueError
            state = self._exchange(_STATE)
            root = self._envelope(state, path=None, name=None)
            results = _object_spans(state, *root["results"])
            disk = _object_spans(state, *results["disk"])
            if any(_scalar(state, disk[key]) is not True for key in ("is_enabled", "is_loggable")):
                raise ValueError
            if "excluded_categories" in disk:
                # This fixed state metadata is not a log or Secret response.
                excluded = json.loads(state[slice(*disk["excluded_categories"])])
                if (type(excluded) is not list or len(excluded) > 64
                    or any(type(value) is not str for value in excluded) or "secret" in excluded):
                    raise ValueError
            self._csrf()
        finally:
            for raw in (actor, role, state):
                _zeroize_mutable(raw)

    def read_file_audit(self) -> SecretFileAuditOwnerReadResult:
        handles: list[int] = []
        attempted = confirmed = 0
        observation: SecretFileAuditObservation | None = None
        failed = False
        query_attempted = False
        query_unconfirmed = False
        fd: int | None = None
        with self._lock:
            if self._used:
                raise SecretFileAuditOwnerReadError(self._last_cleanup)
            self._used = True
            try:
                fd = self._reserve()
                with self._owner.authenticated():
                    try:
                        self._preflight()
                        base = [("start", "0"), ("rows", "25"), ("filter", 'subtype=="secret-file"'),
                                ("filter", f'secretid=="{self._secret_id}"'), ("filter", f'user=="{self._actor}"'),
                                ("filter", f'_metadata.timestamp>="{self._start}"'),
                                ("filter", f'_metadata.timestamp<="{self._end}"'),
                                ("extra", "country_id"), ("serial_no", self._serial)]
                        previous = -1.0
                        session: int | None = None
                        for poll in range(8):
                            query = base + ([("session_id", str(session))] if session is not None else [])
                            if poll == 0:
                                self._append(fd, {"kind": "query_attempted"})
                                query_attempted = True
                            query_unconfirmed = True
                            raw = self._exchange(_EVENTS + "?" + urlencode(query))
                            try:
                                root = _validated_root(raw)
                                for key, expected in {"version": "v7.0.0", "build": 29, "serial": self._serial}.items():
                                    if key in root:
                                        value = _scalar(raw, root[key])
                                        if type(value) is not type(expected) or value != expected:
                                            raise ValueError
                                handle = _scalar(raw, root["session_id"])
                                if type(handle) is str and re.fullmatch(r"[1-9][0-9]{0,15}", handle):
                                    handle = int(handle)
                                if type(handle) is not int or not 0 < handle <= 9_007_199_254_740_991:
                                    raise ValueError
                                if handle not in handles:
                                    handles.append(handle)
                                    self._append(fd, {"kind": "handle", "handle": handle})
                                query_unconfirmed = False
                                for key, minimum in (("rows", 1), ("total_lines", 0)):
                                    if key in root:
                                        value = _scalar(raw, root[key])
                                        if type(value) is not int or not minimum <= value <= 25:
                                            raise ValueError
                                current, completed = _progress(raw)
                                exact_progress = _scalar(raw, root["completed"])
                                if type(exact_progress) not in {int, float}:
                                    raise ValueError
                                assert isinstance(exact_progress, (int, float))
                                if (session is not None and current != session) or exact_progress < previous:
                                    raise ValueError
                                session, previous = current, float(exact_progress)
                                if completed == 100:
                                    observation = project_secret_file_audit(raw, expected_secret_id=self._secret_id,
                                        expected_actor=self._actor, start_ms=self._start, end_ms=self._end)
                                    break
                            finally:
                                _zeroize_mutable(raw)
                            if poll < 7:
                                self._pause(0.25)
                        if observation is None:
                            raise ValueError
                    except Exception:
                        failed = True
                    finally:
                        for handle in handles:
                            cleanup_raw = bytearray()
                            try:
                                csrf = self._csrf()
                                self._append(fd, {"kind": "abort_attempted", "handle": handle})
                                attempted += 1
                                cleanup_raw = self._exchange(_ABORT + str(handle), abort=True, csrf=csrf)
                                self._append(fd, {"kind": "cleanup_confirmed", "handle": handle})
                                confirmed += 1
                            except Exception:
                                failed = True
                                try:
                                    self._append(fd, {"kind": "cleanup_unconfirmed", "handle": handle})
                                except Exception:
                                    pass
                                break
                            finally:
                                _zeroize_mutable(cleanup_raw)
            except Exception:
                failed = True
            finally:
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        failed = True
            self._last_cleanup = _cleanup(len(handles), attempted, confirmed,
                                          query_attempted=query_attempted, query_unconfirmed=query_unconfirmed)
        cleanup = self._last_cleanup
        if failed or observation is None or not cleanup.cleanup_complete:
            raise SecretFileAuditOwnerReadError(cleanup) from None
        return SecretFileAuditOwnerReadResult(observation, cleanup)


def _cleanup(handles: int, attempted: int, confirmed: int, *, query_attempted: bool = False,
             query_unconfirmed: bool = False) -> SecretFileAuditCleanupObservation:
    complete = handles > 0 and confirmed == handles and not query_unconfirmed
    category: Literal["not_started", "confirmed", "cleanup_unconfirmed"] = (
        "confirmed" if complete else "cleanup_unconfirmed" if handles or query_attempted else "not_started")
    return SecretFileAuditCleanupObservation(handles, attempted, confirmed, complete, category)
