"""Verify the FortiPAM API token actor before a same-requester Request POST."""

from __future__ import annotations

import hmac
import http.client
import json
from typing import Any
from urllib.parse import urlsplit

from .mutable_json_buffer import _take_mutable_prefix
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES,
    SecretMetadataHttpTransportConfig,
    _json_value_end,
    _skip_json_space,
    _ssl_context,
    _zeroize_mutable,
)
from .secret_request_collection_http_transport import _object_members


_ACTOR_PATH = "/api/v2/monitor/web-ui/state"
_UNAVAILABLE = "FortiPAM Request actor inspection is unavailable."


class SecretRequestActorHttpTransportError(RuntimeError):
    """Stable non-disclosing actor-inspection failure."""


class FortiPamSecretRequestActorHttpTransport:
    """Require the authenticated product actor to match the bound requester."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        connection_factory: Any | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise SecretRequestActorHttpTransportError(_UNAVAILABLE)
        self._config = config
        self._connection_factory = connection_factory

    def inspect(self, expected_requester: str) -> None:
        if not isinstance(expected_requester, str) or not expected_requester:
            raise SecretRequestActorHttpTransportError(_UNAVAILABLE)
        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise SecretRequestActorHttpTransportError(_UNAVAILABLE)
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
                "GET",
                _ACTOR_PATH,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "User-Agent": "fortipam-mcp-v4-secret-request-actor/1",
                },
            )
            response = connection.getresponse()
            if (
                type(response.status) is not int
                or response.status != 200
                or response.getheader("content-type", "").split(";", 1)[0].strip().lower()
                != "application/json"
                or response.getheader("content-encoding", "identity").strip().lower()
                != "identity"
            ):
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
            if total > MAX_RESPONSE_BYTES:
                raise ValueError
            content = _take_mutable_prefix(content, total)
            start = _skip_json_space(content, 0)
            end = _json_value_end(content, start)
            if _skip_json_space(content, end) != len(content):
                raise ValueError
            root = _object_members(
                content,
                start,
                end,
                frozenset({"http_method", "status", "version", "build", "path", "name", "results"}),
                exact=False,
            )
            fixed = {
                "http_method": b'"GET"',
                "status": b'"success"',
                "version": b'"v7.0.0"',
                "build": b"29",
                "path": b'"web-ui"',
                "name": b'"state"',
            }
            for field, expected in fixed.items():
                with memoryview(content)[slice(*root[field])] as value:
                    if not hmac.compare_digest(value, expected):
                        raise ValueError
            state = _object_members(
                content, *root["results"], frozenset({"admin"}), exact=False
            )
            actor = _object_members(
                content,
                *state["admin"],
                frozenset({"name", "login_name"}),
                exact=False,
            )
            expected = json.dumps(expected_requester, ensure_ascii=True).encode("ascii")
            for field in ("name", "login_name"):
                with memoryview(content)[slice(*actor[field])] as value:
                    if not hmac.compare_digest(value, expected):
                        raise ValueError
        except Exception as exc:
            raise SecretRequestActorHttpTransportError(_UNAVAILABLE) from exc
        finally:
            _zeroize_mutable(content)
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        pass
