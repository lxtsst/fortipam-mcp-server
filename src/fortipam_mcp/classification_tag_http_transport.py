"""Fixed REST transport for one FortiPAM Classification Tag creation action.

Only exact detail GET, collection POST, and detail readback routes are compiled
here.  The transport is not a generic REST client and never returns raw API
payloads or Tag identifier/description values through the MCP boundary.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
import re
import ssl
from typing import Any, Literal
from urllib.parse import quote

from .folder_http_transport import FolderTransportConfig


COLLECTION_PATH = "/api/v2/cmdb/secret/classification-tag"
MAX_RESPONSE_BYTES = 1_048_576
MAX_NAME_LENGTH = 64
MAX_DESCRIPTION_LENGTH = 255
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Classification Tag action is unavailable."


class ClassificationTagTransportError(RuntimeError):
    """Stable non-disclosing error for the bounded Tag transport."""


@dataclass(frozen=True, slots=True)
class ClassificationTagInspection:
    """Private presence-only current-state projection."""

    exists: bool


@dataclass(frozen=True, slots=True)
class ClassificationTagReadback:
    """Categorical post-write evidence without raw metadata values."""

    exists: bool
    name_matches: bool
    description_matches: bool

    @property
    def verified(self) -> bool:
        return self.exists and self.name_matches and self.description_matches


class FortiPamClassificationTagHttpTransport:
    """Issue only compiled Classification Tag detail/create/readback requests."""

    def __init__(
        self,
        config: FolderTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def inspect(self, name: str) -> ClassificationTagInspection:
        """Read one Tag existence state without returning Tag data."""

        tag_name = _name(name)
        status, payload = self._request("GET", self._detail_path(tag_name), None)
        if status == 404:
            return ClassificationTagInspection(exists=False)
        if status != 200 or _record(payload) is None:
            raise ClassificationTagTransportError(_UNAVAILABLE)
        return ClassificationTagInspection(exists=True)

    def create_and_readback(
        self,
        name: str,
        description: str,
    ) -> ClassificationTagReadback:
        """Create one Tag with the fixed minimal request body then read it back."""

        tag_name = _name(name)
        tag_description = _description(description)
        status, payload = self._request(
            "POST",
            COLLECTION_PATH,
            {"name": tag_name, "description": tag_description},
        )
        if status != 200 or not _successful_response(payload):
            raise ClassificationTagTransportError(_UNAVAILABLE)
        detail_status, detail_payload = self._request(
            "GET", self._detail_path(tag_name), None
        )
        detail = _record(detail_payload)
        if detail_status != 200 or detail is None:
            return ClassificationTagReadback(False, False, False)
        return ClassificationTagReadback(
            exists=True,
            name_matches=detail.get("name") == tag_name,
            description_matches=detail.get("description") == tag_description,
        )

    def _request(
        self,
        method: Literal["GET", "POST"],
        path: str,
        body: Mapping[str, object] | None,
    ) -> tuple[int, object | None]:
        try:
            import httpx

            factory = self._client_factory or httpx.Client
            with factory(
                verify=_ssl_context(self._config),
                timeout=self._config.timeout_seconds,
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
                    json=body,
                )
        except Exception as exc:
            raise ClassificationTagTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise ClassificationTagTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ClassificationTagTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path(name: str) -> str:
        return f"{COLLECTION_PATH}/{quote(name, safe='')}"


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise ClassificationTagTransportError(_UNAVAILABLE)
    return value


def _description(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_DESCRIPTION_LENGTH
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ClassificationTagTransportError(_UNAVAILABLE)
    return value


def _successful_response(payload: object) -> bool:
    if not isinstance(payload, Mapping):
        return False
    return payload.get("http_status") in {None, 200}


def _ssl_context(config: FolderTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise ClassificationTagTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "ClassificationTagInspection",
    "ClassificationTagReadback",
    "ClassificationTagTransportError",
    "FortiPamClassificationTagHttpTransport",
]
