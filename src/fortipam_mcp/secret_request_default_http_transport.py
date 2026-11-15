"""Fixed read-only transport for the FortiPAM Secret-request default object."""

from __future__ import annotations

from collections.abc import Mapping
import http.client
import json
from typing import Any, cast
from urllib.parse import urlsplit

from .mutable_json_buffer import _take_mutable_prefix
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES,
    SecretMetadataHttpTransportConfig,
    _ssl_context,
    _zeroize_mutable,
)
from .secret_request_create_contract import (
    REQUEST_CREATE_PATH,
    REQUEST_DEFAULT_QUERY,
    SecretRequestCreateContractError,
    SecretRequestDefaultEvidence,
    validate_secret_request_default_response,
)


_UNAVAILABLE = "FortiPAM Secret request default inspection is unavailable."


class SecretRequestDefaultHttpTransportError(RuntimeError):
    """Stable non-disclosing default-inspection failure."""


class FortiPamSecretRequestDefaultHttpTransport:
    """Read and validate one exact source-pinned default without returning it."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        connection_factory: Any | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise SecretRequestDefaultHttpTransportError(_UNAVAILABLE)
        self._config = config
        self._connection_factory = connection_factory

    def inspect(self) -> SecretRequestDefaultEvidence:
        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise SecretRequestDefaultHttpTransportError(_UNAVAILABLE)
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
                f"{REQUEST_CREATE_PATH}?{REQUEST_DEFAULT_QUERY}",
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "User-Agent": "fortipam-mcp-v4-secret-request-default/1",
                },
            )
            response = connection.getresponse()
            if int(response.status) != 200:
                raise SecretRequestDefaultHttpTransportError(_UNAVAILABLE)
            content_type = response.getheader("content-type", "")
            if not isinstance(content_type, str) or "json" not in content_type.lower():
                raise SecretRequestDefaultHttpTransportError(_UNAVAILABLE)
            total = 0
            while total < len(content):
                view = memoryview(content)[total:]
                try:
                    count = response.readinto(view)
                finally:
                    view.release()
                if not isinstance(count, int) or count < 0:
                    raise SecretRequestDefaultHttpTransportError(_UNAVAILABLE)
                if count == 0:
                    break
                total += count
            if total > MAX_RESPONSE_BYTES:
                raise SecretRequestDefaultHttpTransportError(_UNAVAILABLE)
            content = _take_mutable_prefix(content, total)
            payload = json.loads(content)
            if not isinstance(payload, Mapping):
                raise SecretRequestDefaultHttpTransportError(_UNAVAILABLE)
            return validate_secret_request_default_response(
                cast(Mapping[str, object], payload)
            )
        except SecretRequestDefaultHttpTransportError:
            raise
        except (
            SecretRequestCreateContractError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise SecretRequestDefaultHttpTransportError(_UNAVAILABLE) from exc
        except Exception as exc:
            raise SecretRequestDefaultHttpTransportError(_UNAVAILABLE) from exc
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


__all__ = [
    "FortiPamSecretRequestDefaultHttpTransport",
    "SecretRequestDefaultHttpTransportError",
]
