"""API-first delete transport for one disposable FortiPAM Secret Template.

The FortiPAM 1.9.1 runtime catalog documents the fixed no-body
``DELETE /api/v2/cmdb/secret/template/{name}`` route.  This module exposes
only that route for an archive-specific, laboratory-prefixed Template name.
It is not a generic HTTP client and never returns API response content.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import re
import ssl
from typing import Any
from urllib.parse import quote, urlsplit


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_API_"
COLLECTION_PATH = "/api/v2/cmdb/secret/template"
MAX_RESPONSE_BYTES = 1_048_576
_ARCHIVE_TEMPLATE_NAME = re.compile(
    r"mcp-v4-template-archive-[A-Za-z0-9][A-Za-z0-9._-]{0,38}\Z"
)
_UNAVAILABLE = "FortiPAM V4 Template archive API transport is unavailable."


class TemplateArchiveHttpTransportConfigurationError(ValueError):
    """Raised when the isolated API transport configuration is unsafe."""


class TemplateArchiveHttpTransportError(RuntimeError):
    """Raised for a bounded archive API failure without response disclosure."""


@dataclass(frozen=True, slots=True)
class TemplateArchiveHttpTransportConfig:
    """Dedicated HTTPS and bearer-token settings held only in process memory."""

    base_url: str
    bearer_token: str
    timeout_seconds: float
    ca_file: str | None

    def __post_init__(self) -> None:
        normalized = _base_url(self.base_url)
        object.__setattr__(self, "base_url", normalized)
        if (
            not isinstance(self.bearer_token, str)
            or not self.bearer_token
            or self.bearer_token != self.bearer_token.strip()
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.bearer_token
            )
        ):
            raise TemplateArchiveHttpTransportConfigurationError(
                "A dedicated Template archive bearer token is required."
            )
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(
            self.timeout_seconds, bool
        ):
            raise TemplateArchiveHttpTransportConfigurationError(
                "The Template archive API timeout is invalid."
            )
        if not 1 <= float(self.timeout_seconds) <= 60:
            raise TemplateArchiveHttpTransportConfigurationError(
                "The Template archive API timeout must be between 1 and 60 seconds."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise TemplateArchiveHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class TemplateArchiveDeleteReadback:
    """Internal categorical result for the exact HTTP delete request."""

    deletion_accepted: bool


def load_template_archive_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> TemplateArchiveHttpTransportConfig:
    """Load the independently enabled, isolated Template archive API scope."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise TemplateArchiveHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    supplied = _value(env, "BASE_URL") or _value(env, "HOST")
    token = _value(env, "API_TOKEN")
    if supplied is None or token is None:
        raise TemplateArchiveHttpTransportConfigurationError(
            "Dedicated Template archive HTTPS target and bearer token are required."
        )
    raw_timeout = _value(env, "TIMEOUT_SECONDS") or "15"
    try:
        timeout = float(raw_timeout)
    except ValueError as exc:
        raise TemplateArchiveHttpTransportConfigurationError(
            "The Template archive API timeout is invalid."
        ) from exc
    ca_file = _value(env, "CA_FILE")
    return TemplateArchiveHttpTransportConfig(
        base_url=supplied if "://" in supplied else f"https://{supplied}",
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamTemplateArchiveHttpTransport:
    """Issue only a fixed, URL-encoded Template DELETE request."""

    def __init__(
        self,
        config: TemplateArchiveHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def delete_template(self, template_name: str) -> TemplateArchiveDeleteReadback:
        """Delete one archive-specific Template using the catalogued API route."""

        name = _archive_template_name(template_name)
        status = self._request("DELETE", self._detail_path(name))
        return TemplateArchiveDeleteReadback(deletion_accepted=status == 200)

    def _request(self, method: str, path: str) -> int:
        if method != "DELETE" or not path.startswith(f"{COLLECTION_PATH}/"):
            raise TemplateArchiveHttpTransportError(_UNAVAILABLE)
        requested_name = path.removeprefix(f"{COLLECTION_PATH}/")
        if quote(_archive_template_name(requested_name), safe="") != requested_name:
            raise TemplateArchiveHttpTransportError(_UNAVAILABLE)
        try:
            import httpx

            factory = self._client_factory or httpx.Client
            with factory(
                verify=_ssl_context(self._config),
                timeout=float(self._config.timeout_seconds),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.request(
                    method,
                    f"{self._config.base_url}{path}",
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                    },
                )
        except Exception as exc:
            raise TemplateArchiveHttpTransportError(_UNAVAILABLE) from exc
        try:
            content_length = len(response.content)
            status = int(response.status_code)
        except Exception as exc:
            raise TemplateArchiveHttpTransportError(_UNAVAILABLE) from exc
        if content_length > MAX_RESPONSE_BYTES or status != 200:
            raise TemplateArchiveHttpTransportError(_UNAVAILABLE)
        return status

    @staticmethod
    def _detail_path(template_name: str) -> str:
        return f"{COLLECTION_PATH}/{quote(template_name, safe='')}"


def _archive_template_name(value: object) -> str:
    if not isinstance(value, str) or _ARCHIVE_TEMPLATE_NAME.fullmatch(value) is None:
        raise TemplateArchiveHttpTransportError(_UNAVAILABLE)
    return value


def _base_url(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise TemplateArchiveHttpTransportConfigurationError(
            "The Template archive HTTPS target is invalid."
        )
    normalized = value.rstrip("/")
    parsed = urlsplit(normalized)
    try:
        port = parsed.port
    except ValueError as exc:
        raise TemplateArchiveHttpTransportConfigurationError(
            "The Template archive HTTPS target port is invalid."
        ) from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise TemplateArchiveHttpTransportConfigurationError(
            "The Template archive target must be an HTTPS origin without credentials, path, query, or fragment."
        )
    return normalized


def _ssl_context(config: TemplateArchiveHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        context = ssl.create_default_context(cafile=config.ca_file)
    else:
        try:
            import truststore
        except ImportError as exc:  # pragma: no cover - dependency guard.
            raise RuntimeError("truststore is required for TLS verification.") from exc
        context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


__all__ = [
    "COLLECTION_PATH",
    "ENV_PREFIX",
    "FortiPamTemplateArchiveHttpTransport",
    "MAX_RESPONSE_BYTES",
    "TemplateArchiveDeleteReadback",
    "TemplateArchiveHttpTransportConfig",
    "TemplateArchiveHttpTransportConfigurationError",
    "TemplateArchiveHttpTransportError",
    "load_template_archive_http_transport_config",
]
