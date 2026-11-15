"""Fixed build-29 Target recovery using an existing protected Owner login."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from http.cookies import SimpleCookie
import hmac
import json
import re
import threading
from typing import Any
from urllib.parse import quote

import httpx

from .local_user_reset_fixture_preflight import _actor_context
from .owner_collector_runtime import PREFIX as _LOGIN_PREFIX, owner_login_provider
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig,
    _zeroize_mutable,
)
from .target_delete_http_transport import (
    COLLECTION_PATH, MAX_RESPONSE_BYTES, TargetDeleteHttpTransportError,
    _TARGET_NAME, _digest, _record_digest,
)
from .target_http_transport import TargetHttpTransportConfig, _owner_relation_matches, _record

PREFIX = "FPA_HOME_LAB_FPA1_V4_TARGET_DELETE_OWNER_"
_UNAVAILABLE = "The fixed Target Owner session is unavailable."


def build_target_delete_owner_session(
    config: TargetHttpTransportConfig, environment: Mapping[str, str], *,
    target_name: str, accepted_digest: str,
) -> FixedTargetDeleteOwnerSession:
    """Reuse a prebound central login provider; never copy or infer credentials."""
    try:
        binding = {_LOGIN_PREFIX + "SESSION_ENABLED": "true"}
        for key in ("LOGIN_ENV_FILE", "USERNAME_VARIABLE", "PASSWORD_VARIABLE"):
            binding[_LOGIN_PREFIX + key] = environment[PREFIX + key]
        provider = owner_login_provider(binding)
        if provider is None:
            raise ValueError
        return FixedTargetDeleteOwnerSession(
            config, owner_name=environment[PREFIX + "USERNAME"],
            credentials=provider, target_name=target_name, accepted_digest=accepted_digest,
        )
    except Exception:
        raise TargetDeleteHttpTransportError(_UNAVAILABLE) from None


class FixedTargetDeleteOwnerSession:
    """One fixed bodyless DELETE, exact Owner/record checks and verified logout.

    The outer Target recovery transport owns the durable claim, reference
    checks and independent API/SSH absence readback. This private dependency
    adds no Tool, selector input, credential change or generic HTTP route.
    """

    def __init__(
        self, config: TargetHttpTransportConfig, *, owner_name: str,
        credentials: Callable[[], tuple[str, str]], target_name: str,
        accepted_digest: str, client_factory: Callable[..., Any] = httpx.Client,
    ) -> None:
        try:
            if (_TARGET_NAME.fullmatch(target_name) is None or not _digest(accepted_digest)
                    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", owner_name) is None):
                raise ValueError
            metadata = SecretMetadataHttpTransportConfig(
                config.base_url, config.bearer_token, config.timeout_seconds, config.ca_file,
            )
            self._session = OwnerSessionMetadataTransport(
                metadata, owner_name=owner_name, credentials=credentials,
                folder_path="target-recovery", secret_name="target-recovery",
                target_name=target_name, witness=FortiPamSecretMetadataHttpTransport(metadata),
                client_factory=client_factory,
            )
        except Exception:
            raise TargetDeleteHttpTransportError(_UNAVAILABLE) from None
        self._owner_name, self._target_name = owner_name, target_name
        self._accepted_digest = accepted_digest
        self._path = COLLECTION_PATH + "/" + quote(target_name, safe="")
        self._lock = threading.Lock()
        self._attempted = False

    @property
    def logout_verified(self) -> bool:
        return self._session.logout_verified

    def inspect(self) -> None:
        """Qualify login, exact actor, unchanged ownership and CSRF before intent."""
        with self._lock:
            if self._attempted:
                raise TargetDeleteHttpTransportError(_UNAVAILABLE)
            try:
                with self._session.authenticated():
                    self._preflight()
            except Exception:
                raise TargetDeleteHttpTransportError(_UNAVAILABLE) from None

    def dispatch(self) -> tuple[int, object]:
        """Reserve this session attempt before login; never retry an uncertain DELETE."""
        with self._lock:
            if self._attempted:
                raise TargetDeleteHttpTransportError(_UNAVAILABLE)
            self._attempted = True
            try:
                with self._session.authenticated():
                    csrf = self._preflight()
                    status, payload = self._read_json("DELETE", self._path, headers={
                        "Accept": "application/json", "X-CSRFTOKEN": csrf,
                        "Content-Length": "0", "Cache-Control": "no-cache, no-store",
                    })
                    self._qualify(payload, status, "DELETE")
                # authenticated() raises when successful work cannot prove logout.
                return status, payload
            except Exception:
                raise TargetDeleteHttpTransportError(_UNAVAILABLE) from None

    def _preflight(self) -> str:
        raw = bytearray()
        try:
            with self._session._client.stream("GET", "/api/v2/monitor/web-ui/state") as response:
                if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            _actor_context(raw, expected_name=self._owner_name)
        finally:
            _zeroize_mutable(raw)
        status, payload = self._read_json("GET", self._path)
        self._qualify(payload, status, "GET")
        record = _record(payload)
        if (record is None or record.get("name") != self._target_name
                or not _owner_relation_matches(record, self._owner_name)
                or not hmac.compare_digest(_record_digest(record), self._accepted_digest)):
            raise ValueError
        cookie = self._session._client.build_request("GET", self._path).headers.get("cookie", "")
        cookies: SimpleCookie = SimpleCookie()
        cookies.load(cookie)
        token = cookies.get("ccsrftoken")
        if (token is None or not token.value or len(token.value) > 4096
                or any(ord(c) < 33 or ord(c) > 126 for c in token.value)):
            raise ValueError
        return str(token.value)

    def _read_json(self, method: str, path: str, *, headers: Mapping[str, str] | None = None) -> tuple[int, object]:
        raw = bytearray()
        try:
            with self._session._client.stream(method, path, headers=headers) as response:
                if "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
                return response.status_code, json.loads(raw)
        finally:
            _zeroize_mutable(raw)

    @staticmethod
    def _qualify(payload: object, status: int, method: str) -> None:
        if (status != 200 or not isinstance(payload, Mapping)
                or type(payload.get("build")) is not int
                or type(payload.get("http_status")) is not int
                or any(payload.get(key) != value for key, value in {
                    "version": "v7.0.0", "build": 29, "http_method": method,
                    "http_status": 200, "status": "success", "path": "secret", "name": "target",
                }.items())
                or ("error" in payload and (type(payload["error"]) is not int or payload["error"] != 0))):
            raise ValueError
