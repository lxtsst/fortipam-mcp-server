"""Fixed REST/SSH recovery transport for the accepted b65 Address Group.

The transport compiles one exact bodyless detail DELETE, pins the complete
accepted REST record, checks the one-member REST/SSH projection, and uses one
calibrated fixed CMDB reference command. It never returns object names, raw
responses, or caller-selected API/CLI input through MCP.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import ssl
from typing import Any, Literal
from urllib.parse import quote

from .address_group_ssh_transport import (
    AddressGroupReadback,
    AddressGroupReferenceReadback,
    FortiPamAddressGroupSshTransport,
)
from .address_http_transport import (
    AddressHttpTransportConfig,
    AddressInspection,
    FortiPamAddressHttpTransport,
)


COLLECTION_PATH = "/api/v2/cmdb/firewall/addrgrp"
ADDRESS_GROUP_DELETE_NAME = "mcp-v4-address-group-b65"
ADDRESS_GROUP_MEMBER_NAME = "mcp-v4-address-b63"
ADDRESS_GROUP_ACCEPTED_DIGEST = (
    "96be5f4b6e108e456e02466384ae6d7ecb3c3f88e0efbe57c62ebeaef918dbf3"
)
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 Address Group recovery is unavailable."


class AddressGroupDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the fixed recovery transport configuration is unsafe."""


class AddressGroupDeleteHttpTransportError(RuntimeError):
    """Stable, non-disclosing fixed Address Group recovery failure."""


@dataclass(frozen=True, slots=True)
class AddressGroupDeleteInspection:
    """Categorical eligibility for only the accepted b65 Address Group."""

    exists: bool
    eligible_fixed_group: bool
    group_reference_count: int
    calibration_address_reference_count: int
    target_digest: str


@dataclass(frozen=True, slots=True)
class AddressGroupDeleteReadback:
    """Group absence plus preserved b63 member after the exact DELETE."""

    api_absent: bool
    ssh_absent: bool
    member_preserved_api: bool

    @property
    def verified(self) -> bool:
        return self.api_absent and self.ssh_absent and self.member_preserved_api


class FortiPamAddressGroupDeleteHttpTransport:
    """Inspect and delete only the unchanged, unreferenced b65 Group."""

    def __init__(
        self,
        config: AddressHttpTransportConfig,
        group_ssh_transport: FortiPamAddressGroupSshTransport,
        member_http_transport: FortiPamAddressHttpTransport,
        *,
        client_factory: Callable[..., Any] | None = None,
        accepted_digest: str = ADDRESS_GROUP_ACCEPTED_DIGEST,
    ) -> None:
        if not _digest(accepted_digest):
            raise AddressGroupDeleteHttpTransportConfigurationError(
                "The accepted Address Group digest is invalid."
            )
        self._config = config
        self._group_ssh_transport = group_ssh_transport
        self._member_http_transport = member_http_transport
        self._client_factory = client_factory
        self._accepted_digest = accepted_digest

    def inspect_delete_target(self) -> AddressGroupDeleteInspection:
        """Prove the complete fixed record, projection, member, and references."""

        status, payload = self._request("GET", self._detail_path(), None)
        if status == 404:
            return AddressGroupDeleteInspection(
                exists=False,
                eligible_fixed_group=False,
                group_reference_count=0,
                calibration_address_reference_count=0,
                target_digest="0" * 64,
            )
        record = _record(payload)
        if status != 200 or record is None:
            raise AddressGroupDeleteHttpTransportError(_UNAVAILABLE)
        target_digest = _record_digest(record)
        if (
            not hmac.compare_digest(target_digest, self._accepted_digest)
            or not _fixed_group_projection(record)
        ):
            raise AddressGroupDeleteHttpTransportError(_UNAVAILABLE)

        group_readback = self._group_ssh_transport.readback(
            ADDRESS_GROUP_DELETE_NAME,
            ADDRESS_GROUP_MEMBER_NAME,
        )
        references = self._group_ssh_transport.reference_readback(
            ADDRESS_GROUP_DELETE_NAME,
            ADDRESS_GROUP_MEMBER_NAME,
        )
        member = self._member_http_transport.inspect(ADDRESS_GROUP_MEMBER_NAME)
        if (
            not isinstance(group_readback, AddressGroupReadback)
            or not group_readback.verified
            or not isinstance(references, AddressGroupReferenceReadback)
            or not isinstance(member, AddressInspection)
            or not member.exists
            or not member.is_ipv4_ipmask
        ):
            raise AddressGroupDeleteHttpTransportError(_UNAVAILABLE)
        return AddressGroupDeleteInspection(
            exists=True,
            eligible_fixed_group=references.verified_zero_reference,
            group_reference_count=references.group_reference_count,
            calibration_address_reference_count=(
                references.calibration_address_reference_count
            ),
            target_digest=target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> AddressGroupDeleteReadback:
        """Delete exactly once and prove Group absence plus member preservation."""

        if not _digest(expected_target_digest):
            raise AddressGroupDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_group
            or inspection.group_reference_count != 0
            or inspection.calibration_address_reference_count != 1
            or not hmac.compare_digest(
                inspection.target_digest,
                expected_target_digest,
            )
            or not hmac.compare_digest(
                inspection.target_digest,
                self._accepted_digest,
            )
        ):
            raise AddressGroupDeleteHttpTransportError(_UNAVAILABLE)

        status, payload = self._request("DELETE", self._detail_path(), None)
        if status != 200 or not _successful_response(payload):
            raise AddressGroupDeleteHttpTransportError(_UNAVAILABLE)

        readback_status, _ = self._request("GET", self._detail_path(), None)
        group = self._group_ssh_transport.inspect(ADDRESS_GROUP_DELETE_NAME)
        member = self._member_http_transport.inspect(ADDRESS_GROUP_MEMBER_NAME)
        return AddressGroupDeleteReadback(
            api_absent=readback_status == 404,
            ssh_absent=not group.exists,
            member_preserved_api=member.exists and member.is_ipv4_ipmask,
        )

    def _request(
        self,
        method: Literal["GET", "DELETE"],
        path: str,
        body: Mapping[str, object] | None,
    ) -> tuple[int, object | None]:
        if body is not None:
            raise AddressGroupDeleteHttpTransportError(_UNAVAILABLE)
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
            raise AddressGroupDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise AddressGroupDeleteHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AddressGroupDeleteHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path() -> str:
        return f"{COLLECTION_PATH}/{quote(ADDRESS_GROUP_DELETE_NAME, safe='')}"


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _fixed_group_projection(record: Mapping[str, object]) -> bool:
    members = record.get("member")
    member = members[0] if isinstance(members, list) and len(members) == 1 else None
    return (
        record.get("name") == ADDRESS_GROUP_DELETE_NAME
        and record.get("q_origin_key") == ADDRESS_GROUP_DELETE_NAME
        and isinstance(member, Mapping)
        and member.get("name") == ADDRESS_GROUP_MEMBER_NAME
        and member.get("q_origin_key") == ADDRESS_GROUP_MEMBER_NAME
    )


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
        raise AddressGroupDeleteHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "ADDRESS_GROUP_ACCEPTED_DIGEST",
    "ADDRESS_GROUP_DELETE_NAME",
    "ADDRESS_GROUP_MEMBER_NAME",
    "AddressGroupDeleteHttpTransportConfigurationError",
    "AddressGroupDeleteHttpTransportError",
    "AddressGroupDeleteInspection",
    "AddressGroupDeleteReadback",
    "COLLECTION_PATH",
    "FortiPamAddressGroupDeleteHttpTransport",
]
