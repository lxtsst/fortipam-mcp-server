"""Fixed REST/SSH recovery transport for the accepted b63 IPv4 Address."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import ssl
from typing import Any, Literal
from urllib.parse import quote

from .address_group_ssh_transport import (
    AddressSshInspection,
    FortiPamAddressGroupSshTransport,
)
from .address_http_transport import AddressHttpTransportConfig


COLLECTION_PATH = "/api/v2/cmdb/firewall/address"
ADDRESS_DELETE_NAME = "mcp-v4-address-b63"
ADDRESS_ACCEPTED_DIGEST = (
    "197786e8ebeee1da3021c69b4da620d63fd0f0e386d599b1a44958683fc1ba1f"
)
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 Address recovery is unavailable."


class AddressDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the fixed Address recovery configuration is unsafe."""


class AddressDeleteHttpTransportError(RuntimeError):
    """Stable, non-disclosing fixed Address recovery failure."""


@dataclass(frozen=True, slots=True)
class AddressDeleteInspection:
    """Categorical eligibility for only the accepted b63 Address."""

    exists: bool
    eligible_fixed_address: bool
    address_reference_count: int
    target_digest: str


@dataclass(frozen=True, slots=True)
class AddressDeleteReadback:
    """REST and SSH absence after the exact Address DELETE."""

    api_absent: bool
    ssh_absent: bool

    @property
    def verified(self) -> bool:
        return self.api_absent and self.ssh_absent


class FortiPamAddressDeleteHttpTransport:
    """Inspect and delete only the unchanged, unreferenced b63 Address."""

    def __init__(
        self,
        config: AddressHttpTransportConfig,
        ssh_transport: FortiPamAddressGroupSshTransport,
        *,
        client_factory: Callable[..., Any] | None = None,
        accepted_digest: str = ADDRESS_ACCEPTED_DIGEST,
    ) -> None:
        if not _digest(accepted_digest):
            raise AddressDeleteHttpTransportConfigurationError(
                "The accepted Address digest is invalid."
            )
        self._config = config
        self._ssh_transport = ssh_transport
        self._client_factory = client_factory
        self._accepted_digest = accepted_digest

    def inspect_delete_target(self) -> AddressDeleteInspection:
        """Prove the complete fixed record, IPv4 type, and zero references."""

        status, payload = self._request("GET", self._detail_path())
        if status == 404:
            return AddressDeleteInspection(
                exists=False,
                eligible_fixed_address=False,
                address_reference_count=0,
                target_digest="0" * 64,
            )
        record = _record(payload)
        if status != 200 or record is None:
            raise AddressDeleteHttpTransportError(_UNAVAILABLE)
        target_digest = _record_digest(record)
        if (
            not hmac.compare_digest(target_digest, self._accepted_digest)
            or not _fixed_address_projection(record)
        ):
            raise AddressDeleteHttpTransportError(_UNAVAILABLE)
        address = self._ssh_transport.inspect_address(ADDRESS_DELETE_NAME)
        reference_count = self._ssh_transport.address_reference_count(
            ADDRESS_DELETE_NAME
        )
        if not isinstance(address, AddressSshInspection) or not address.exists:
            raise AddressDeleteHttpTransportError(_UNAVAILABLE)
        return AddressDeleteInspection(
            exists=True,
            eligible_fixed_address=reference_count == 0,
            address_reference_count=reference_count,
            target_digest=target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> AddressDeleteReadback:
        """Delete exactly once and prove fixed Address absence."""

        if not _digest(expected_target_digest):
            raise AddressDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_address
            or inspection.address_reference_count != 0
            or not hmac.compare_digest(
                inspection.target_digest,
                expected_target_digest,
            )
            or not hmac.compare_digest(
                inspection.target_digest,
                self._accepted_digest,
            )
        ):
            raise AddressDeleteHttpTransportError(_UNAVAILABLE)

        status, payload = self._request("DELETE", self._detail_path())
        if status != 200 or not _successful_response(payload):
            raise AddressDeleteHttpTransportError(_UNAVAILABLE)

        readback_status, _ = self._request("GET", self._detail_path())
        ssh_address = self._ssh_transport.inspect_address(ADDRESS_DELETE_NAME)
        return AddressDeleteReadback(
            api_absent=readback_status == 404,
            ssh_absent=not ssh_address.exists,
        )

    def _request(
        self,
        method: Literal["GET", "DELETE"],
        path: str,
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
                )
        except Exception as exc:
            raise AddressDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise AddressDeleteHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AddressDeleteHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path() -> str:
        return f"{COLLECTION_PATH}/{quote(ADDRESS_DELETE_NAME, safe='')}"


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _fixed_address_projection(record: Mapping[str, object]) -> bool:
    subnet = record.get("subnet")
    if (
        record.get("name") != ADDRESS_DELETE_NAME
        or record.get("q_origin_key") != ADDRESS_DELETE_NAME
        or record.get("type") != "ipmask"
        or not isinstance(subnet, str)
    ):
        return False
    parts = subnet.split()
    if len(parts) != 2:
        return False
    try:
        network = ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=True)
    except ValueError:
        return False
    return network.prefixlen >= 8


def _record_digest(record: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            record,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _digest(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _successful_response(payload: object) -> bool:
    return isinstance(payload, Mapping) and payload.get("http_status") in {None, 200}


def _ssl_context(config: AddressHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover
        raise AddressDeleteHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "ADDRESS_ACCEPTED_DIGEST",
    "ADDRESS_DELETE_NAME",
    "AddressDeleteHttpTransportConfigurationError",
    "AddressDeleteHttpTransportError",
    "AddressDeleteInspection",
    "AddressDeleteReadback",
    "COLLECTION_PATH",
    "FortiPamAddressDeleteHttpTransport",
]
