"""Fixed REST transport for one FortiPAM IPv4 subnet address creation action.

Only exact address detail GET, collection POST, and detail readback routes are
compiled here. This is not a generic HTTP relay and it never returns raw
address data through the MCP boundary.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
from typing import Any, Literal
from urllib.parse import quote, urlsplit


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ADDRESS_API_"
COLLECTION_PATH = "/api/v2/cmdb/firewall/address"
MAX_RESPONSE_BYTES = 1_048_576
MAX_NAME_LENGTH = 64
ADDRESS_TYPE = "ipmask"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Address action is unavailable."


class AddressHttpTransportConfigurationError(ValueError):
    """Raised when dedicated Address API configuration is unsafe."""


class AddressHttpTransportError(RuntimeError):
    """Raised for a bounded Address API transport failure."""


@dataclass(frozen=True, slots=True)
class AddressHttpTransportConfig:
    """Dedicated HTTPS and bearer settings held only in process memory."""

    base_url: str
    bearer_token: str
    timeout_seconds: float
    ca_file: str | None

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise AddressHttpTransportConfigurationError(
                "A dedicated HTTPS Address API target is required."
            )
        if not self.bearer_token or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.bearer_token
        ):
            raise AddressHttpTransportConfigurationError(
                "A dedicated Address API bearer token is required."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise AddressHttpTransportConfigurationError(
                "The Address API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise AddressHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class AddressInspection:
    """Private presence-only current-state projection."""

    exists: bool
    is_ipv4_ipmask: bool = False


@dataclass(frozen=True, slots=True)
class AddressReadback:
    """Categorical post-write evidence without returning address values."""

    exists: bool
    name_matches: bool
    type_matches: bool
    subnet_matches: bool

    @property
    def verified(self) -> bool:
        return (
            self.exists
            and self.name_matches
            and self.type_matches
            and self.subnet_matches
        )


def load_address_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> AddressHttpTransportConfig:
    """Load the independent IPv4 Address API configuration after opt-in."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise AddressHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token = _value(env, "API_TOKEN")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    if base_url is None or token is None:
        raise AddressHttpTransportConfigurationError(
            "Dedicated Address API target and bearer token are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise AddressHttpTransportConfigurationError(
            "The Address API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return AddressHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamAddressHttpTransport:
    """Issue only compiled Address detail/create/readback REST requests."""

    def __init__(
        self,
        config: AddressHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def inspect(self, name: str) -> AddressInspection:
        """Read one address existence state without returning object data."""

        address_name = _name(name)
        status, payload = self._request("GET", self._detail_path(address_name), None)
        if status == 404:
            return AddressInspection(exists=False)
        detail = _record(payload)
        if status != 200 or detail is None:
            raise AddressHttpTransportError(_UNAVAILABLE)
        return AddressInspection(
            exists=True,
            is_ipv4_ipmask=_is_ipv4_ipmask(detail),
        )

    def create_and_readback(self, name: str, cidr: str) -> AddressReadback:
        """Create one fixed IPv4 ``ipmask`` address and verify by detail GET."""

        address_name = _name(name)
        normalized_subnet = _subnet(cidr)
        status, payload = self._request(
            "POST",
            COLLECTION_PATH,
            {
                "name": address_name,
                "type": ADDRESS_TYPE,
                "subnet": normalized_subnet,
            },
        )
        if status != 200 or not _successful_response(payload):
            raise AddressHttpTransportError(_UNAVAILABLE)
        detail_status, detail_payload = self._request(
            "GET", self._detail_path(address_name), None
        )
        detail = _record(detail_payload)
        if detail_status != 200 or detail is None:
            return AddressReadback(False, False, False, False)
        return AddressReadback(
            exists=True,
            name_matches=detail.get("name") == address_name,
            type_matches=detail.get("type") == ADDRESS_TYPE,
            subnet_matches=detail.get("subnet") == normalized_subnet,
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
            raise AddressHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise AddressHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AddressHttpTransportError(_UNAVAILABLE) from exc

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


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise AddressHttpTransportError(_UNAVAILABLE)
    return value


def _subnet(value: str) -> str:
    if not isinstance(value, str):
        raise AddressHttpTransportError(_UNAVAILABLE)
    try:
        network = ipaddress.IPv4Network(value, strict=True)
    except ValueError as exc:
        raise AddressHttpTransportError(_UNAVAILABLE) from exc
    if network.prefixlen < 8:
        raise AddressHttpTransportError(_UNAVAILABLE)
    return f"{network.network_address} {network.netmask}"


def _is_ipv4_ipmask(detail: Mapping[str, object]) -> bool:
    """Return only the constrained member-eligibility category."""

    if detail.get("type") != ADDRESS_TYPE:
        return False
    subnet = detail.get("subnet")
    if not isinstance(subnet, str):
        return False
    parts = subnet.split()
    if len(parts) != 2:
        return False
    try:
        ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False)
    except ValueError:
        return False
    return True


def _successful_response(payload: object) -> bool:
    return isinstance(payload, Mapping) and payload.get("http_status") in {None, 200}


def _ssl_context(config: AddressHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise AddressHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "ADDRESS_TYPE",
    "AddressHttpTransportConfigurationError",
    "AddressHttpTransportConfig",
    "AddressHttpTransportError",
    "AddressInspection",
    "AddressReadback",
    "COLLECTION_PATH",
    "ENV_PREFIX",
    "FortiPamAddressHttpTransport",
    "load_address_http_transport_config",
]
