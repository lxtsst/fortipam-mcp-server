"""Bounded FortiPAM 7.0 Unix Secret automatic-verification update.

The protected existing fields are read only during the final dispatch and are
sent back unchanged because build 29 rejects a scheduler-only Secret PUT.
Neither credential fields nor the raw device response leave this transport.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import http.client
import json
from typing import Any
from urllib.parse import urlsplit

from .secret_metadata_http_transport import (
    COLLECTION_PATH,
    MAX_RESPONSE_BYTES,
    FortiPamSecretMetadataHttpTransport,
    SecretMetadataHttpTransportConfig,
    _record,
    _redact_json_field_values,
    _ssl_context,
    _zeroize_mutable,
)
from .secret_session_controls_http_transport import _successful_response


_UNAVAILABLE = "FortiPAM V4 password verification configuration is unavailable."
_TEMPLATE = "Unix Account (SSH Password)"
_INTERVAL_MINUTES = 60
_START_DELAY_MINUTES = 5
_GMT_PLUS_EIGHT = timezone(timedelta(hours=8))


class PasswordVerificationHttpTransportError(RuntimeError):
    """Stable error that never includes a protected field or device response."""


@dataclass(frozen=True, slots=True)
class PasswordVerificationBinding:
    """Private exact-object binding supplied by the action composition root."""

    folder_path: str
    secret_name: str
    target_name: str
    target_address: str
    account_name: str


@dataclass(frozen=True, slots=True)
class PasswordVerificationState:
    """Only the state needed to detect drift and verify this fixed update."""

    secret_id: int
    folder_id: int
    enabled: bool
    uses_policy_default: bool
    interval_minutes: int
    start_time_present: bool
    relations_preserved: bool
    ssh_enabled: bool
    sftp_enabled: bool
    recording_enabled: bool


@dataclass(frozen=True, slots=True)
class PasswordVerificationReadback:
    accepted: bool
    verified: bool
    scheduled_start_epoch: int


class FortiPamPasswordVerificationHttpTransport:
    """Apply only the tested build-29 60-minute Unix Secret configuration."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        binding: PasswordVerificationBinding,
        *,
        connection_factory: Callable[..., Any] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig) or not isinstance(
            binding, PasswordVerificationBinding
        ):
            raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
        if not all(
            isinstance(value, str) and value and "\n" not in value and "\r" not in value
            for value in (
                binding.folder_path,
                binding.secret_name,
                binding.target_name,
                binding.target_address,
                binding.account_name,
            )
        ):
            raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
        self._config = config
        self._binding = binding
        self._connection_factory = connection_factory
        self._clock = clock or (lambda: datetime.now(_GMT_PLUS_EIGHT))
        self._metadata = FortiPamSecretMetadataHttpTransport(
            config, bound_secret_name=binding.secret_name
        )

    def inspect(self) -> PasswordVerificationState:
        """Read only redacted current state; no Secret field is decoded."""

        try:
            if self._metadata.read_product_version_and_build() != ("7.0.0", 29):
                raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
            binding = self._binding
            projection = self._metadata.inspect_projection(
                binding.folder_path, binding.secret_name, _TEMPLATE,
                binding.target_name,
            )
            schedule = self._metadata.inspect_password_verification(
                binding.folder_path, binding.secret_name,
            )
            return PasswordVerificationState(
                secret_id=self._metadata.resolve_existing_secret_id(
                    binding.folder_path, binding.secret_name,
                ),
                folder_id=self._metadata.resolve_folder_id(binding.folder_path),
                enabled=schedule.enabled,
                uses_policy_default=schedule.uses_policy_default,
                interval_minutes=schedule.interval_minutes,
                start_time_present=schedule.start_time_present,
                relations_preserved=projection.metadata_relation_verified,
                ssh_enabled=projection.ssh_service_enabled,
                sftp_enabled=projection.sftp_service_enabled,
                recording_enabled=projection.recording_matches,
            )
        except Exception:
            raise PasswordVerificationHttpTransportError(_UNAVAILABLE) from None

    def enable_and_readback(
        self, expected: PasswordVerificationState,
    ) -> PasswordVerificationReadback:
        """Use a fresh exact state, submit one PUT, then read only categories."""

        if not isinstance(expected, PasswordVerificationState) or not _eligible(expected):
            raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
        if self.inspect() != expected:
            raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
        binding = self._binding
        secret_id = self._metadata.resolve_existing_secret_id(
            binding.folder_path, binding.secret_name,
        )
        folder_id = self._metadata.resolve_folder_id(binding.folder_path)
        if secret_id != expected.secret_id or folder_id != expected.folder_id:
            raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
        raw = self._get_protected_detail(secret_id)
        try:
            if not _exact_raw_detail(raw, binding, secret_id, folder_id):
                raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
            fields = raw["field"]
            if not isinstance(fields, list):
                raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
            retained = [
                {key: item[key] for key in ("id", "name", "value", "keyinfo") if key in item}
                for item in fields if isinstance(item, dict) and item.get("name") != "Host"
            ]
            if len(retained) != 2 or {item.get("name") for item in retained} != {
                "Username", "Password"
            }:
                raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
            moment = self._clock().astimezone(_GMT_PLUS_EIGHT) + timedelta(
                minutes=_START_DELAY_MINUTES
            )
            start_epoch = int(moment.timestamp())
            body: dict[str, object] = {
                "id": secret_id,
                "name": binding.secret_name,
                "folder": folder_id,
                "template": _TEMPLATE,
                "target": binding.target_name,
                "field": retained,
                "password-heartbeat": "enable",
                "heartbeat-use-policy-default": "enable",
                "heartbeat-interval": _INTERVAL_MINUTES,
                "heartbeat-start-time": moment.strftime("%Y-%m-%d %H:%M:%S"),
            }
            accepted = self._put_once(secret_id, body)
        finally:
            raw.clear()
            if "fields" in locals():
                fields.clear()
            if "retained" in locals():
                retained.clear()
            if "body" in locals():
                body.clear()
        # The accepted write is not retried, even if the following read fails.
        after = self.inspect()
        status, payload, redacted = self._metadata._request_projection_detail(secret_id)
        detail = _record(payload)
        actual_start = detail.get("heartbeat-start-time") if detail else None
        verified = bool(
            accepted and status == 200 and redacted and detail is not None
            and type(actual_start) is int and actual_start == start_epoch
            and after.secret_id == expected.secret_id
            and after.folder_id == expected.folder_id
            and after.enabled and after.uses_policy_default
            and after.interval_minutes == _INTERVAL_MINUTES
            and after.relations_preserved and after.ssh_enabled
            and after.sftp_enabled and after.recording_enabled
        )
        return PasswordVerificationReadback(accepted, verified, start_epoch)

    def _get_protected_detail(self, secret_id: int) -> dict[str, Any]:
        status, payload = self._request("GET", secret_id)
        record = _record(payload)
        if status != 200 or record is None:
            raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
        return dict(record)

    def _put_once(self, secret_id: int, body: Mapping[str, object]) -> bool:
        status, payload = self._request("PUT", secret_id, body)
        return status == 200 and _successful_response(payload)

    def _request(
        self, method: str, secret_id: int, body: Mapping[str, object] | None = None,
    ) -> tuple[int, object]:
        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None or method not in {"GET", "PUT"}:
            raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
        request_bytes = bytearray(
            json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ) if body is not None else bytearray()
        response_bytes = bytearray(MAX_RESPONSE_BYTES + 1)
        connection: Any = None
        response: Any = None
        try:
            if len(request_bytes) > MAX_RESPONSE_BYTES:
                raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
            factory = self._connection_factory or http.client.HTTPSConnection
            connection = factory(
                parsed.hostname, parsed.port or 443,
                timeout=self._config.timeout_seconds, context=_ssl_context(self._config),
            )
            headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {self._config.bearer_token}",
                "Connection": "close",
                "Cache-Control": "no-cache, no-store",
                "User-Agent": "fortipam-mcp-v4-password-verification/1",
            }
            if method == "PUT":
                headers["Content-Type"] = "application/json"
                headers["Content-Length"] = str(len(request_bytes))
            connection.request(
                method, f"{COLLECTION_PATH}/{secret_id}",
                body=request_bytes if method == "PUT" else None,
                headers=headers,
            )
            response = connection.getresponse()
            status = response.status
            if type(status) is not int or not 100 <= status <= 599:
                raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
            content_type = response.getheader("content-type", "")
            if not isinstance(content_type, str) or "json" not in content_type.lower():
                raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
            total = 0
            while total < len(response_bytes):
                view = memoryview(response_bytes)[total:]
                try:
                    count = response.readinto(view)
                finally:
                    view.release()
                if type(count) is not int or count < 0:
                    raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
                if count == 0:
                    break
                total += count
            if total > MAX_RESPONSE_BYTES:
                raise PasswordVerificationHttpTransportError(_UNAVAILABLE)
            del response_bytes[total:]
            if method == "PUT":
                _redact_json_field_values(response_bytes)
            return status, json.loads(response_bytes)
        except Exception:
            raise PasswordVerificationHttpTransportError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(request_bytes)
            _zeroize_mutable(response_bytes)
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


def _eligible(state: PasswordVerificationState) -> bool:
    return (
        type(state.secret_id) is int and state.secret_id > 0
        and type(state.folder_id) is int and state.folder_id > 0
        and not state.enabled and state.uses_policy_default
        and not state.start_time_present
        and state.interval_minutes == _INTERVAL_MINUTES
        and state.relations_preserved and state.ssh_enabled
        and state.sftp_enabled and state.recording_enabled
    )


def _exact_raw_detail(
    raw: Mapping[str, object], binding: PasswordVerificationBinding,
    secret_id: int, folder_id: int,
) -> bool:
    if (
        raw.get("id") != secret_id or raw.get("name") != binding.secret_name
        or raw.get("folder") != folder_id or raw.get("template") != _TEMPLATE
        or raw.get("target") != binding.target_name
        or raw.get("password-heartbeat") != "disable"
        or raw.get("heartbeat-use-policy-default") != "enable"
        or raw.get("heartbeat-interval") != _INTERVAL_MINUTES
        or raw.get("heartbeat-start-time") not in ("", 0)
        or raw.get("inherit-permission") != "enable"
        or raw.get("ssh-service-status") != "up"
        or raw.get("sftp-service-status") != "up"
        or raw.get("recording") != "enable"
    ):
        return False
    fields = raw.get("field")
    if not isinstance(fields, list) or len(fields) != 3:
        return False
    if any(not isinstance(item, dict) for item in fields):
        return False
    named = {item.get("name"): item for item in fields}
    if set(named) != {"Host", "Username", "Password"}:
        return False
    return bool(
        named["Host"].get("value") == binding.target_address
        and named["Username"].get("value") == binding.account_name
        and isinstance(named["Password"].get("value"), str)
        and named["Password"]["value"]
    )


__all__ = [
    "FortiPamPasswordVerificationHttpTransport",
    "PasswordVerificationBinding",
    "PasswordVerificationHttpTransportError",
    "PasswordVerificationReadback",
    "PasswordVerificationState",
]
