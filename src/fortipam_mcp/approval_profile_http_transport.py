"""Fixed REST readback for one BP008 Approval Profile.

The transport reuses the dedicated Secret-metadata API identity because BP008
already requires that identity for the matching Secret projection.  It exposes
only the existing categorical ``ApprovalProfileReadback`` contract and never
registers a generic Approval Profile API surface.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import http.client
import json
import re
from typing import Any, Protocol, cast
from urllib.parse import quote, urlsplit

from .approval_profile_ssh_transport import ApprovalProfileReadback
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
    _ssl_context,
    _zeroize_mutable,
)


COLLECTION_PATH = "/api/v2/cmdb/secret/approval-profile"
MAX_RESPONSE_BYTES = 1_048_576
_NAME = re.compile(r"mcp-v4-approval-profile-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")
_UNAVAILABLE = "FortiPAM V4 Approval Profile readback is unavailable."
_FIXED_APPROVER = "admin"
_FIXED_DESCRIPTION = "MCP V4 unbound approval profile"


class ApprovalProfileHttpTransportError(RuntimeError):
    """Stable non-disclosing error for the fixed Profile readback."""


class _HttpResponse(Protocol):
    status: int

    def getheader(self, name: str, default: str = "") -> str: ...

    def read(self, amount: int | None = None) -> bytes: ...

    def close(self) -> None: ...


class _HttpsConnection(Protocol):
    def request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None: ...

    def getresponse(self) -> _HttpResponse: ...

    def close(self) -> None: ...


class FortiPamApprovalProfileHttpTransport:
    """Read one exact fixed Profile without a second SSH credential."""

    __slots__ = ("_config", "_connection_factory")

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        connection_factory: Callable[..., _HttpsConnection] | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise ApprovalProfileHttpTransportError(_UNAVAILABLE)
        self._config = config
        self._connection_factory = connection_factory

    def readback(self, profile_name: str) -> ApprovalProfileReadback:
        """Return only the fixed categorical BP008 Profile projection."""

        if not isinstance(profile_name, str) or _NAME.fullmatch(profile_name) is None:
            raise ApprovalProfileHttpTransportError(_UNAVAILABLE)
        payload = self._get(profile_name)
        if payload is None:
            return _empty_readback()
        record = _record(payload)
        if record is None:
            raise ApprovalProfileHttpTransportError(_UNAVAILABLE)
        return ApprovalProfileReadback(
            profile_name_exists=(
                record.get("name") == profile_name
                and record.get("q_origin_key") in {None, profile_name}
            ),
            single_tier_enabled=(
                record.get("type") == "single"
                # FortiPAM keeps numeric defaults for inactive tiers.  The
                # selected ``single`` type makes them inoperative; only a
                # populated user or group would make the projection unsafe.
                and _disabled_principals(record.get("second-user"))
                and _disabled_principals(record.get("second-group"))
                and _disabled_principals(record.get("third-user"))
                and _disabled_principals(record.get("third-group"))
            ),
            first_approval_count_one=record.get("first-num") == 1,
            fixed_approver_present=(
                _is_fixed_approver(record.get("first-user"))
                and _disabled_principals(record.get("first-group"))
                and record.get("self-approval") == "disable"
            ),
            fixed_description_present=(
                record.get("description") == _FIXED_DESCRIPTION
                and record.get("field") == []
                and record.get("auto-approval-schedule") in {None, ""}
                and record.get("max-allowed-duration") in {None, 0}
            ),
            remote_group_email_disabled=(
                record.get("remote-group-email") == "disable"
            ),
            approver_permission_requirement_none=(
                record.get("approver-perm-req") == "none"
            ),
            email_template_unset=record.get("email-template") in {None, ""},
            email_approval_link_expiry_default=(
                record.get("email-approval-link-expiry") == 120
            ),
        )

    def _get(self, profile_name: str) -> object | None:
        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise ApprovalProfileHttpTransportError(_UNAVAILABLE)
        connection: _HttpsConnection | None = None
        response: _HttpResponse | None = None
        content = bytearray()
        try:
            factory = self._connection_factory or http.client.HTTPSConnection
            connection = cast(
                _HttpsConnection,
                factory(
                    parsed.hostname,
                    parsed.port or 443,
                    timeout=self._config.timeout_seconds,
                    context=_ssl_context(self._config),
                ),
            )
            connection.request(
                "GET",
                f"{COLLECTION_PATH}/{quote(profile_name, safe='')}",
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "User-Agent": "fortipam-mcp-v4-approval-profile-read/1",
                },
            )
            response = connection.getresponse()
            content = bytearray(response.read(MAX_RESPONSE_BYTES + 1))
            if len(content) > MAX_RESPONSE_BYTES:
                raise ApprovalProfileHttpTransportError(_UNAVAILABLE)
            if int(response.status) == 404:
                return None
            if (
                int(response.status) != 200
                or "json" not in response.getheader("content-type", "").lower()
            ):
                raise ApprovalProfileHttpTransportError(_UNAVAILABLE)
            value: object = json.loads(content)
            return value
        except ApprovalProfileHttpTransportError:
            raise
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise ApprovalProfileHttpTransportError(_UNAVAILABLE) from exc
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


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    value = payload.get("results", payload.get("result"))
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], Mapping):
        return value[0]
    return None


def _empty_readback() -> ApprovalProfileReadback:
    return ApprovalProfileReadback(False, False, False, False, False, False, False, False, False)


def _disabled_principals(value: object) -> bool:
    """Accept the two empty collection encodings returned by FortiPAM."""

    return value is None or value == "" or (isinstance(value, list) and not value)


def _is_fixed_approver(value: object) -> bool:
    """Match the API's compact or expanded representation of the fixed user."""

    if value == [_FIXED_APPROVER]:
        return True
    if not isinstance(value, list) or len(value) != 1:
        return False
    candidate = value[0]
    return (
        isinstance(candidate, Mapping)
        and candidate.get("name") == _FIXED_APPROVER
        and candidate.get("q_origin_key") in {None, _FIXED_APPROVER}
    )


__all__ = [
    "ApprovalProfileHttpTransportError",
    "COLLECTION_PATH",
    "FortiPamApprovalProfileHttpTransport",
]
