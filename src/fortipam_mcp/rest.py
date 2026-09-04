"""Small HTTPS-only FortiPAM client with non-disclosing error behavior."""

from __future__ import annotations

from dataclasses import dataclass
import json
import ssl
from typing import Any
from urllib.parse import urljoin

from . import __version__
from .config import FortiPamConfig
from .redaction import redact
from .safety import assert_curated_read

MAX_RESPONSE_BYTES = 1_048_576


class FortiPamRequestError(RuntimeError):
    """A safe error for a failed FortiPAM request."""


@dataclass(frozen=True, slots=True)
class PreparedRead:
    """Prepared request details kept internal to the local process."""

    path: str
    url: str
    headers: dict[str, str]


@dataclass(frozen=True, slots=True)
class ReadResponse:
    """Sanitized successful FortiPAM API response."""

    status_code: int
    content_type: str | None
    data: Any


def prepare_read(config: FortiPamConfig, path: str) -> PreparedRead:
    """Validate and prepare a fixed Bearer GET request without sending it."""

    safe_path = assert_curated_read(config, "GET", path)
    return PreparedRead(
        path=safe_path,
        url=urljoin(f"{config.base_url}/", safe_path.lstrip("/")),
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {config.authentication.token}",
            "User-Agent": f"fortipam-mcp/{__version__}",
        },
    )


def build_ssl_context(config: FortiPamConfig) -> ssl.SSLContext:
    """Build an explicit verified context from a local CA or native system trust."""

    if config.ca_file:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - dependency guard.
        raise RuntimeError("truststore is required for native system TLS verification.") from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


class FortiPamRestClient:
    """Dispatch exact read-only FortiPAM requests over verified TLS."""

    def __init__(self, config: FortiPamConfig) -> None:
        self._config = config

    async def get_json(self, path: str) -> ReadResponse:
        """Issue one approved GET request and redact JSON before return."""

        prepared = prepare_read(self._config, path)
        try:
            import httpx
        except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard.
            raise RuntimeError("httpx is required for FortiPAM live requests.") from exc

        try:
            async with httpx.AsyncClient(
                verify=build_ssl_context(self._config),
                timeout=self._config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    "GET",
                    prepared.url,
                    headers=prepared.headers,
                ) as response:
                    if response.status_code < 200 or response.status_code >= 300:
                        raise FortiPamRequestError(
                            f"FortiPAM returned HTTP {response.status_code}."
                        )
                    content = await _bounded_content(response)
                    status_code = response.status_code
                    content_type = response.headers.get("content-type")
        except FortiPamRequestError:
            raise
        except httpx.RequestError as exc:
            raise FortiPamRequestError(
                "Unable to connect to the configured FortiPAM target."
            ) from exc

        if not content:
            return ReadResponse(status_code=status_code, content_type=content_type, data=None)
        if not _is_json(content_type):
            raise FortiPamRequestError("FortiPAM returned an unexpected non-JSON response.")
        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            raise FortiPamRequestError("FortiPAM returned malformed JSON.") from exc
        return ReadResponse(
            status_code=status_code,
            content_type=content_type,
            data=redact(decoded),
        )


async def _bounded_content(response: Any) -> bytes:
    declared = response.headers.get("content-length")
    if declared:
        try:
            declared_size = int(declared)
        except ValueError:
            declared_size = 0
        if declared_size > MAX_RESPONSE_BYTES:
            raise FortiPamRequestError("FortiPAM response exceeded the 1 MiB safety limit.")
    chunks: list[bytes] = []
    received = 0
    async for chunk in response.aiter_bytes():
        received += len(chunk)
        if received > MAX_RESPONSE_BYTES:
            raise FortiPamRequestError("FortiPAM response exceeded the 1 MiB safety limit.")
        chunks.append(chunk)
    return b"".join(chunks)


def _is_json(content_type: str | None) -> bool:
    return bool(content_type and "json" in content_type.lower())
