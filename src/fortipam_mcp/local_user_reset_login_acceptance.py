"""Private, one-attempt login acceptance and current-material promotion.

This module neither resets a password nor registers an MCP tool. It consumes
already persisted successful execution evidence and a matching pending
transition. Uncertain acceptance preserves that transition for reconciliation.
"""

from __future__ import annotations

from collections.abc import Callable
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
from time import sleep
from typing import Any, cast
from urllib.parse import urlsplit

import httpx

from v4_planning import M4Compensation, M4Outcome, M4Verification, canonical_digest

from .local_user_reset_fixture_preflight import _ACTOR, _actor_context
from .local_user_reset_material_source import (
    OwnerOnlyLocalUserResetMaterialSource, _canonical, _directory_identity,
    _read_current_login_selection, _read_manifest, _read_material, _read_small, _write_once,
)
from .local_user_reset_owner_session import _AUTH, _LOGIN, _LoginForm
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import (
    SYSTEM_STATUS_PATH, SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable,
)

_CONTRACT = "fortipam-700-build29-bound-local-user-reset-candidate-v1"
_PENDING = "current-login-transition.json"
_POINTER = "current-login-binding.json"
_RESET_NAME = re.compile(r"reset(?:-[A-Za-z0-9][A-Za-z0-9._-]{0,95})?\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_LOGIN_SETTLE_SECONDS = 2.0
_HTTP_STATUSES = frozenset({200, 201, 202, 204, 301, 302, 303, 307, 308,
    400, 401, 403, 404, 405, 409, 413, 422, 429, 500, 502, 503, 504})


class _Failure(Exception):
    pass


def _document(content: bytearray) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    value = json.loads(content, object_pairs_hook=unique)
    if type(value) is not dict:
        raise ValueError
    return value


def _pending(source: OwnerOnlyLocalUserResetMaterialSource) -> None:
    expected = {"version": 1, "reset_directory": source._reset.name,
        "current_selection_digest": source._current_selection_digest,
        "staged_binding_digest": source._staged_binding_digest,
        "material_pair_digest": source._binding_digest}
    content = _read_small(source._fixture, source._fixture_id, _PENDING, 4096)
    try:
        if _canonical(_document(content)) != _canonical(expected):
            raise ValueError
    finally:
        _zeroize_mutable(content)


def _current(source: OwnerOnlyLocalUserResetMaterialSource) -> None:
    if (_directory_identity(source._fixture) != source._fixture_id
        or _directory_identity(source._reset) != source._reset_id
        or _read_current_login_selection(source._fixture, source._binding) != (
            source._current, source._current_binding_digest, source._current_selection_digest)):
        raise ValueError
    _pending(source)


def _evidence(source: OwnerOnlyLocalUserResetMaterialSource,
              store: PersistentM4ExecutionStateStore) -> str:
    marker = _read_small(source._reset, source._reset_id, "dispatch-invocation", 4096)
    content = bytearray()
    try:
        dispatch = _document(marker)
        if (set(dispatch) != {"contract", "plan_ref", "context_digest"}
            or dispatch["contract"] != _CONTRACT
            or type(dispatch["plan_ref"]) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", dispatch["plan_ref"]) is None
            or type(dispatch["context_digest"]) is not str
            or _DIGEST.fullmatch(dispatch["context_digest"]) is None):
            raise ValueError
        content = _read_small(source._reset, source._reset_id, "result.json", 4096)
        result_document = _document(content)
        with store._connect() as connection:
            connection.execute("BEGIN")
            state = store._read_state(connection)
            connection.commit()
        if len(state.claims) != 1 or len(state.audit) != 1:
            raise ValueError
        namespace, claim = next(iter(state.claims.items()))
        result, audit = claim.result, state.audit[0]
        m4_fields = {"outcome", "verification", "compensation", "idempotent_replay"}
        legacy_fields = {"contract": _CONTRACT, "password_change_confirmed": True,
            "current_login_reconciliation_required": True, "login_verified": False,
            "credential_values_returned": False, "raw_cli_returned": False}
        current_fields = {**legacy_fields, "password_change_confirmed": False,
                          "password_write_acknowledged": True}
        extra_document = {key: value for key, value in result_document.items() if key not in m4_fields}
        # Preserve the original bare M4 record and complete consumed legacy
        # envelopes. Neither format proves a usable password; login still must.
        if (not m4_fields <= result_document.keys()
            or _canonical(extra_document) not in {
                _canonical({}), _canonical(legacy_fields), _canonical(current_fields)}):
            raise ValueError
        if (namespace.plan_key != store._reference_key("plan", dispatch["plan_ref"])
            or claim.context_key != store._digest_key("context", dispatch["context_digest"])
            or result is None or result.outcome is not M4Outcome.SUCCEEDED
            or result.verification is not M4Verification.VERIFIED
            or result.compensation is not M4Compensation.NOT_REQUESTED or result.idempotent_replay
            or audit.authorization != "verified" or audit.outcome is not result.outcome
            or audit.verification is not result.verification or audit.compensation is not result.compensation
            or audit.digest_reference != canonical_digest({"context": dispatch["context_digest"],
                                                           "result": result.as_dict()})
            or _canonical({key: result_document[key] for key in m4_fields}) != _canonical(result.as_dict())):
            raise ValueError
        return hashlib.sha256(content).hexdigest()
    finally:
        _zeroize_mutable(marker)
        _zeroize_mutable(content)


def _new_material(source: OwnerOnlyLocalUserResetMaterialSource) -> tuple[bytearray, int]:
    if _read_manifest(source._reset, source._reset_id, source._binding.expected.fixture_creation_digest) != (
        source._staged_binding_digest, source._expected_new_digest):
        raise ValueError
    material, length = _read_material(source._reset, source._reset_id, "next-password")
    with memoryview(material)[:length] as view:
        if not hmac.compare_digest(hashlib.sha256(view).hexdigest(), source._expected_new_digest):
            _zeroize_mutable(material)
            raise ValueError
    return material, length


def _exception_category(error: Exception) -> str:
    if isinstance(error, httpx.TimeoutException):
        return "timeout"
    if isinstance(error, httpx.TransportError):
        return "transport"
    if isinstance(error, (ValueError, TypeError)):
        return "validation"
    return "unexpected"


def _exchange(client: Any, method: str, path: str, *, data: dict[str, str] | None = None,
              require_json: bool = False, diagnostic: dict[str, object] | None = None,
              phase: str = "") -> tuple[int, str | None, bytearray]:
    content = bytearray()
    if diagnostic is not None:
        diagnostic["phase"] = phase
        cast(dict[str, object], diagnostic["http_status"])[phase] = "not_received"
    try:
        with client.stream(method, path, data=data) as response:
            status = int(response.status_code)
            if diagnostic is not None:
                cast(dict[str, object], diagnostic["http_status"])[phase] = (
                    status if status in _HTTP_STATUSES else "other")
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise ValueError
            if require_json and response.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
                raise ValueError
            for chunk in response.iter_bytes(chunk_size=4096):
                if len(content) + len(chunk) > 1_048_576:
                    raise ValueError
                content.extend(chunk)
            return status, response.headers.get("location"), content
    except Exception:
        _zeroize_mutable(content)
        raise


def _login(source: OwnerOnlyLocalUserResetMaterialSource, config: SecretMetadataHttpTransportConfig,
           material: bytearray, length: int, client_factory: Callable[..., Any],
           result: dict[str, object]) -> None:
    client: Any = None
    content = bytearray()
    failure = "login_failed"
    login: dict[str, object] = {"phase": "client_setup", "http_status": {},
                               "exception_category": "none"}
    logout: dict[str, object] = {"phase": "not_started", "http_status": {},
                                "exception_category": "none"}
    result.update(login_diagnostic=login, logout_diagnostic=logout)
    try:
        client = client_factory(base_url=config.base_url, verify=_ssl_context(config),
            timeout=config.timeout_seconds, follow_redirects=False, trust_env=False,
            headers={"Accept-Encoding": "identity", "User-Agent": "fortipam-bp002-login-acceptance/1"})
        status, _, content = _exchange(client, "GET", _LOGIN, diagnostic=login, phase="login_page")
        form = _LoginForm()
        form.feed(content.decode("utf-8"))
        if status != 200 or form.matches != 1:
            raise ValueError
        _zeroize_mutable(content)
        result["login_post_attempted"] = True
        login["phase"] = "login_post"
        cast(dict[str, object], login["http_status"])["login_post"] = "not_received"
        status, location, content = _exchange(client, "POST", _AUTH, data={
            "username": source._binding.expected.username, "password": material[:length].decode("utf-8"),
            "magic": "0", "4Tredir": "/", "4Tmthd": "0"}, diagnostic=login, phase="login_post")
        _zeroize_mutable(content)
        login["phase"] = "redirect"
        redirect = urlsplit(location or "")
        if (status != 303 or not location or len(location) > 2048
            or redirect.scheme or redirect.netloc or redirect.fragment
            or not redirect.path.startswith("/") or redirect.path.startswith("//")
            or "%" in redirect.path or "\\" in redirect.path
            or any(ord(character) < 33 or ord(character) > 126 for character in location)
            or redirect.path == "/api" or redirect.path.startswith("/api/")
            or redirect.path in {_AUTH, "/logout", "/remote/login"}):
            raise ValueError
        _, _, content = _exchange(client, "GET", location, diagnostic=login, phase="landing")
        _zeroize_mutable(content)
        status, _, content = _exchange(client, "GET", SYSTEM_STATUS_PATH, require_json=True,
                                       diagnostic=login, phase="status")
        if status != 200:
            raise ValueError
        _zeroize_mutable(content)
        failure = "identity_failed"
        status, _, content = _exchange(client, "GET", _ACTOR, require_json=True,
                                       diagnostic=login, phase="identity")
        if status != 200 or not _actor_context(content, expected_name=source._binding.expected.username):
            raise ValueError
        result["login_verified"] = True
        login["phase"] = "verified"
        failure = ""
    except Exception as error:
        login["exception_category"] = _exception_category(error)
    finally:
        _zeroize_mutable(content)
        if client is not None:
            try:
                if result["login_post_attempted"]:
                    logged_out, _, content = _exchange(client, "GET", "/logout",
                                                       diagnostic=logout, phase="logout")
                    _zeroize_mutable(content)
                    denied, _, content = _exchange(client, "GET", SYSTEM_STATUS_PATH,
                                                    diagnostic=logout, phase="logout_status")
                    result["logout_verified"] = logged_out == 200 and denied in {401, 403}
                    if result["logout_verified"]:
                        logout["phase"] = "verified"
                    if not result["logout_verified"] and not failure:
                        failure = "logout_failed"
            except Exception as error:
                logout["exception_category"] = _exception_category(error)
                if not failure:
                    failure = "logout_failed"
            finally:
                _zeroize_mutable(content)
                for cleanup in (client.cookies.clear, client.close):
                    try:
                        cleanup()
                    except Exception as error:
                        if logout["exception_category"] == "none":
                            logout.update(phase="cleanup", exception_category=_exception_category(error))
                        if not failure:
                            failure = "cleanup_failed"
        if failure:
            raise _Failure(failure) from None


def _unchanged_execution_material(source: OwnerOnlyLocalUserResetMaterialSource,
                                 store: PersistentM4ExecutionStateStore, result_digest: str) -> None:
    if _evidence(source, store) != result_digest:
        raise ValueError
    material, _ = _new_material(source)
    _zeroize_mutable(material)


def _promote(source: OwnerOnlyLocalUserResetMaterialSource, store: PersistentM4ExecutionStateStore,
             result_digest: str, observed_at: int, result: dict[str, object]) -> None:
    _current(source)
    _unchanged_execution_material(source, store, result_digest)
    acceptance = bytearray(_canonical({"execution_outcome": "succeeded", "execution_result_sha256": result_digest,
        "authenticated_identity_verified": True, "authenticated_status": 200,
        "new_password_login_http_status": 303, "observed_at": observed_at,
        "logout_requested": True, "logout_verified": True}))
    pointer = bytearray(_canonical({"username": source._binding.expected.username,
        "material_source": f"../{source._reset.name}/next-password",
        "acceptance_record": f"../{source._reset.name}/acceptance.json", "verified_at": observed_at,
        "identity_verified": True, "initial_password_is_historical": True}))
    directory_fd = os.open(source._fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lock_fd: int | None = None
    temporary = ".current-login-binding-" + secrets.token_hex(12) + ".json"
    temporary_created = False
    try:
        details = os.fstat(directory_fd)
        if ((details.st_dev, details.st_ino) != source._fixture_id
            or details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) != 0o700):
            raise ValueError
        lock_fd = os.open(_PENDING, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _current(source)
        _write_once(source._reset, source._reset_id, "acceptance.json", acceptance)
        _write_once(source._fixture, source._fixture_id, temporary, pointer)
        temporary_created = True
        _current(source)
        _unchanged_execution_material(source, store, result_digest)
        if os.fstat(lock_fd).st_ino != os.stat(_PENDING, dir_fd=directory_fd, follow_symlinks=False).st_ino:
            raise ValueError
        os.replace(temporary, _POINTER, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        temporary_created = False
        result["current_binding_updated"] = True
        os.fsync(directory_fd)
        current, manifest, _ = _read_current_login_selection(source._fixture, source._binding)
        if current != source._reset or manifest != source._staged_binding_digest:
            raise ValueError
        _pending(source)
        _unchanged_execution_material(source, store, result_digest)
        if os.fstat(lock_fd).st_ino != os.stat(_PENDING, dir_fd=directory_fd, follow_symlinks=False).st_ino:
            raise ValueError
        os.unlink(_PENDING, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        if temporary_created:
            os.unlink(temporary, dir_fd=directory_fd)
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(directory_fd)
        _zeroize_mutable(acceptance)
        _zeroize_mutable(pointer)


def finalize_verified_reset_login(
    source: OwnerOnlyLocalUserResetMaterialSource, store: PersistentM4ExecutionStateStore,
    config: SecretMetadataHttpTransportConfig, *, enabled: bool = False,
    client_factory: Callable[..., Any] = httpx.Client, clock: Callable[[], int] = lambda: int(time.time()),
) -> dict[str, object]:
    """Verify one persisted successful reset and promote its private material."""
    result: dict[str, object] = {"outcome": "reconciliation_required", "reason": "precondition_failed",
        "login_post_attempted": False, "login_verified": False, "logout_verified": False,
        "current_binding_updated": False}
    material = bytearray()
    try:
        if enabled is not True:
            return {**result, "outcome": "denied", "reason": "gate_closed"}
        if (type(source) is not OwnerOnlyLocalUserResetMaterialSource
            or type(store) is not PersistentM4ExecutionStateStore
            or type(config) is not SecretMetadataHttpTransportConfig
            or getattr(source._inspector, "_config", None) is not config
            or not callable(client_factory) or not callable(clock)
            or source._current_selection_digest is None
            or _RESET_NAME.fullmatch(source._reset.name) is None
            or source._reset.parent != source._fixture.parent
            or store._path != source._reset / "execution.sqlite3"
            or store._key_path != source._reset / "execution.key"):
            raise ValueError
        origin = urlsplit(config.base_url)
        if (origin.scheme != "https" or not origin.hostname or origin.username or origin.password
            or origin.path not in {"", "/"} or origin.query or origin.fragment):
            raise ValueError
        _current(source)
        digest = _evidence(source, store)
        material, length = _new_material(source)
        marker = bytearray(_canonical({"version": 1, "execution_result_sha256": digest,
                                      "material_pair_digest": source._binding_digest}))
        try:
            _write_once(source._reset, source._reset_id, "login-invocation", marker)
        except FileExistsError:
            raise _Failure("already_attempted") from None
        finally:
            _zeroize_mutable(marker)
        # Allow the fixed build-29 CLI commit to settle before the sole AUTH.
        # The reservation already exists; interrupted waits cannot repeat it.
        sleep(_LOGIN_SETTLE_SECONDS)
        _login(source, config, material, length, client_factory, result)
        result["reason"] = "persistence_failed"
        observed = clock()
        if type(observed) is not int or observed <= 0:
            raise ValueError
        _promote(source, store, digest, observed, result)
        result.update(outcome="succeeded", reason="verified")
    except _Failure as error:
        result["reason"] = str(error)
    except Exception:
        pass
    finally:
        _zeroize_mutable(material)
    return result
