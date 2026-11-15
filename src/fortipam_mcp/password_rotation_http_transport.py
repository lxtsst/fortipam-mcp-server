"""Fixed FortiPAM 7.0 Unix Secret manual password rotation transport."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import http.client
import json
from typing import Any
from urllib.parse import urlsplit

from .mutable_json_buffer import _take_mutable_prefix
from .password_verification_http_transport import PasswordVerificationBinding
from .secret_metadata_http_transport import (
    COLLECTION_PATH,
    MAX_RESPONSE_BYTES,
    FortiPamSecretMetadataHttpTransport,
    SecretMetadataHttpTransportConfig,
    _record,
    _ssl_context,
    _zeroize_mutable,
)


_UNAVAILABLE = "FortiPAM V4 password rotation is unavailable."
_TEMPLATE = "Unix Account (SSH Password)"
_CHANGE_PATH = "/api/v2/internal/password-change"


class PasswordRotationHttpTransportError(RuntimeError):
    """Stable error without credential, identifier, or raw device content."""


@dataclass(frozen=True, slots=True)
class PasswordRotationState:
    secret_id: int
    folder_id: int
    change_marker: str | None
    relations_preserved: bool
    ssh_enabled: bool
    sftp_enabled: bool
    recording_enabled: bool


@dataclass(frozen=True, slots=True)
class PasswordRotationReadback:
    http_accepted: bool
    change_marker_advanced: bool
    relations_preserved: bool


class FortiPamPasswordRotationHttpTransport:
    """Rotate one privately bound Unix Secret without receiving a new password."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        binding: PasswordVerificationBinding,
        *,
        connection_factory: Callable[..., Any] | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig) or not isinstance(
            binding, PasswordVerificationBinding
        ):
            raise PasswordRotationHttpTransportError(_UNAVAILABLE)
        if not all(
            isinstance(value, str) and value and "\n" not in value and "\r" not in value
            for value in (
                binding.folder_path, binding.secret_name, binding.target_name,
                binding.target_address, binding.account_name,
            )
        ):
            raise PasswordRotationHttpTransportError(_UNAVAILABLE)
        self._config = config
        self._binding = binding
        self._connection_factory = connection_factory or http.client.HTTPSConnection
        self._metadata = FortiPamSecretMetadataHttpTransport(
            config, bound_secret_name=binding.secret_name
        )

    def inspect(self) -> PasswordRotationState:
        """Return only fixed identity, relation flags, and a change-time digest."""

        try:
            if self._metadata.read_product_version_and_build() != ("7.0.0", 29):
                raise PasswordRotationHttpTransportError(_UNAVAILABLE)
            bound = self._binding
            projection = self._metadata.inspect_projection(
                bound.folder_path, bound.secret_name, _TEMPLATE, bound.target_name,
            )
            secret_id = self._metadata.resolve_existing_secret_id(
                bound.folder_path, bound.secret_name,
            )
            folder_id = self._metadata.resolve_folder_id(bound.folder_path)
            status, payload, redacted = self._metadata._request_projection_detail(secret_id)
            detail = _record(payload)
            if (
                status != 200 or not redacted or detail is None
                or detail.get("id") != secret_id
                or detail.get("name") != bound.secret_name
                or detail.get("folder") != folder_id
                or detail.get("template") != _TEMPLATE
                or detail.get("target") != bound.target_name
            ):
                raise PasswordRotationHttpTransportError(_UNAVAILABLE)
            marker = _change_marker(detail.get("last-success-password-change-time"))
            return PasswordRotationState(
                secret_id=secret_id,
                folder_id=folder_id,
                change_marker=marker,
                relations_preserved=projection.metadata_relation_verified,
                ssh_enabled=projection.ssh_service_enabled,
                sftp_enabled=projection.sftp_service_enabled,
                recording_enabled=projection.recording_matches,
            )
        except Exception:
            raise PasswordRotationHttpTransportError(_UNAVAILABLE) from None

    def rotate_once(self, expected: PasswordRotationState) -> PasswordRotationReadback:
        """Recheck fixed state, send one POST, then classify one fresh readback."""

        if not _eligible(expected) or self.inspect() != expected:
            raise PasswordRotationHttpTransportError(_UNAVAILABLE)
        self._require_protected_account_match(expected)
        http_accepted = self._post_once(expected.secret_id)
        # A successful HTTP response alone does not prove target credential effect.
        try:
            after = self.inspect()
        except PasswordRotationHttpTransportError:
            return PasswordRotationReadback(http_accepted, False, False)
        preserved = (
            after.secret_id == expected.secret_id
            and after.folder_id == expected.folder_id
            and after.relations_preserved and after.ssh_enabled
            and after.sftp_enabled and after.recording_enabled
        )
        return PasswordRotationReadback(
            http_accepted=http_accepted,
            change_marker_advanced=bool(
                http_accepted and after.change_marker is not None
                and after.change_marker != expected.change_marker
            ),
            relations_preserved=preserved,
        )

    def _require_protected_account_match(self, expected: PasswordRotationState) -> None:
        """Compare only in memory; never return the protected Secret fields."""

        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise PasswordRotationHttpTransportError(_UNAVAILABLE)
        connection: Any = None
        response: Any = None
        content = bytearray(MAX_RESPONSE_BYTES + 1)
        detail: Mapping[str, object] | None = None
        names: dict[object, object] | None = None
        try:
            connection = self._connection_factory(
                parsed.hostname, parsed.port or 443,
                timeout=self._config.timeout_seconds, context=_ssl_context(self._config),
            )
            connection.request(
                "GET", f"{COLLECTION_PATH}/{expected.secret_id}?with_meta=true&vdom=root",
                headers=_headers(self._config.bearer_token),
            )
            response = connection.getresponse()
            if response.status != 200 or "json" not in response.getheader("content-type", "").lower():
                raise PasswordRotationHttpTransportError(_UNAVAILABLE)
            size = _read_bounded(response, content)
            content = _take_mutable_prefix(content, size)
            detail = _record(json.loads(content))
            bound = self._binding
            if (
                detail is None or detail.get("id") != expected.secret_id
                or detail.get("folder") != expected.folder_id
                or detail.get("name") != bound.secret_name
                or detail.get("template") != _TEMPLATE
                or detail.get("target") != bound.target_name
            ):
                raise PasswordRotationHttpTransportError(_UNAVAILABLE)
            fields = detail.get("field")
            if not isinstance(fields, list):
                raise PasswordRotationHttpTransportError(_UNAVAILABLE)
            names = {item.get("name"): item.get("value") for item in fields if isinstance(item, dict)}
            if (
                names.get("Host") != bound.target_address
                or names.get("Username") != bound.account_name
                or not isinstance(names.get("Password"), str)
                or not names["Password"]
            ):
                raise PasswordRotationHttpTransportError(_UNAVAILABLE)
        except Exception:
            raise PasswordRotationHttpTransportError(_UNAVAILABLE) from None
        finally:
            if names is not None:
                names.clear()
            if isinstance(detail, dict):
                detail.clear()
            _zeroize_mutable(content)
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()

    def _post_once(self, secret_id: int) -> bool:
        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise PasswordRotationHttpTransportError(_UNAVAILABLE)
        body = bytearray(json.dumps({"secret-id": secret_id}, separators=(",", ":")).encode("ascii"))
        connection: Any = None
        response: Any = None
        try:
            connection = self._connection_factory(
                parsed.hostname, parsed.port or 443,
                timeout=self._config.timeout_seconds, context=_ssl_context(self._config),
            )
            headers = _headers(self._config.bearer_token)
            headers.update({"Content-Type": "application/json", "Content-Length": str(len(body))})
            connection.request("POST", _CHANGE_PATH, body=body, headers=headers)
            response = connection.getresponse()
            status = response.status
            return type(status) is int and status == 200
        except Exception:
            raise PasswordRotationHttpTransportError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(body)
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()


def _headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/json", "Authorization": f"Bearer {token}",
        "Connection": "close", "Cache-Control": "no-cache, no-store",
        "User-Agent": "fortipam-mcp-v4-password-rotation/1",
    }


def _read_bounded(response: Any, content: bytearray) -> int:
    total = 0
    while total < len(content):
        view = memoryview(content)[total:]
        try:
            count = response.readinto(view)
        finally:
            view.release()
        if type(count) is not int or count < 0:
            raise PasswordRotationHttpTransportError(_UNAVAILABLE)
        if count == 0:
            break
        total += count
    if total > MAX_RESPONSE_BYTES:
        raise PasswordRotationHttpTransportError(_UNAVAILABLE)
    return total


def _change_marker(value: object) -> str | None:
    if value in (None, "", 0):
        return None
    if (type(value) is int and value > 0) or (type(value) is str and 0 < len(value) <= 64):
        return hashlib.sha256(f"{type(value).__name__}:{value}".encode()).hexdigest()
    raise PasswordRotationHttpTransportError(_UNAVAILABLE)


def _eligible(state: PasswordRotationState) -> bool:
    return (
        isinstance(state, PasswordRotationState)
        and type(state.secret_id) is int and state.secret_id > 0
        and type(state.folder_id) is int and state.folder_id > 0
        and state.relations_preserved and state.ssh_enabled
        and state.sftp_enabled and state.recording_enabled
    )


__all__ = [
    "FortiPamPasswordRotationHttpTransport", "PasswordRotationHttpTransportError",
    "PasswordRotationReadback", "PasswordRotationState",
]
