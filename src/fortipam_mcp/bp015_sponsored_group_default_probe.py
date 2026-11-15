"""Fixed, non-disclosing BP015 Group default probe for FortiPAM 7.0."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import http.client
import json
from typing import Any, Final
from urllib.parse import urlsplit

from .mutable_json_buffer import _take_mutable_prefix
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES,
    SecretMetadataHttpTransportConfig,
    SecretMetadataHttpTransportError,
    _ssl_context,
    _zeroize_mutable,
    load_secret_metadata_http_transport_config,
)


DEFAULT_PATH: Final = "/api/v2/cmdb/user/group?action=default&with_meta=true"
_UNAVAILABLE: Final = "FortiPAM BP015 Group default inspection is unavailable."
_ALLOWED_ENVELOPE_KEYS: Final = frozenset(
    {
        "action", "build", "http_method", "http_status", "name", "path",
        "results", "revision", "serial", "status", "vdom", "version",
    }
)
_EXPECTED_RESULTS_KEYS: Final = frozenset(
    {
        "access",
        "auth-concurrent-override",
        "auth-concurrent-value",
        "authtimeout",
        "company",
        "creation-time",
        "email",
        "expire",
        "expire-type",
        "group-max-users",
        "group-type",
        "guest",
        "http-digest-realm",
        "id",
        "logic-type",
        "match",
        "max-accounts",
        "member",
        "mobile-phone",
        "multiple-guest-add",
        "name",
        "password",
        "sms-custom-server",
        "sms-server",
        "sponsor",
        "sso-attribute-value",
        "user-id",
        "user-name",
        "user-permission",
    }
)
_DEFAULT_GROUP_TYPE: Final = "firewall"


class BP015SponsoredGroupDefaultProbeError(RuntimeError):
    """Stable non-disclosing failure for the fixed Group default inspection."""


def load_bp015_sponsored_group_default_probe_config(
    environment: Mapping[str, str] | None = None,
) -> SecretMetadataHttpTransportConfig:
    """Reuse the existing protected, dedicated central API-token configuration."""

    return load_secret_metadata_http_transport_config(environment)


class FortiPamBP015SponsoredGroupDefaultProbe:
    """Read exactly one Group default route and return categorical evidence only."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        connection_factory: Any | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise BP015SponsoredGroupDefaultProbeError(_UNAVAILABLE)
        self._config = config
        self._connection_factory = connection_factory

    def inspect(self) -> dict[str, object]:
        """Issue the fixed strict-TLS GET and project only default compatibility facts."""

        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise BP015SponsoredGroupDefaultProbeError(_UNAVAILABLE)
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
                DEFAULT_PATH,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "User-Agent": "fortipam-mcp-v4-bp015-default-probe/1",
                },
            )
            response = connection.getresponse()
            if int(response.status) != 200:
                raise BP015SponsoredGroupDefaultProbeError(_UNAVAILABLE)
            content_type = response.getheader("content-type", "")
            if not isinstance(content_type, str) or "json" not in content_type.lower():
                raise BP015SponsoredGroupDefaultProbeError(_UNAVAILABLE)
            total = _read_bounded(response, content)
            content = _take_mutable_prefix(content, total)
            return _project_default(json.loads(content))
        except BP015SponsoredGroupDefaultProbeError:
            raise
        except (
            SecretMetadataHttpTransportError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as exc:
            raise BP015SponsoredGroupDefaultProbeError(_UNAVAILABLE) from exc
        except Exception as exc:
            raise BP015SponsoredGroupDefaultProbeError(_UNAVAILABLE) from exc
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


def _read_bounded(response: Any, content: bytearray) -> int:
    total = 0
    while total < len(content):
        view = memoryview(content)[total:]
        try:
            count = response.readinto(view)
        finally:
            view.release()
        if not isinstance(count, int) or count < 0:
            raise BP015SponsoredGroupDefaultProbeError(_UNAVAILABLE)
        if count == 0:
            break
        total += count
    if total > MAX_RESPONSE_BYTES:
        raise BP015SponsoredGroupDefaultProbeError(_UNAVAILABLE)
    return total


def _project_default(payload: object) -> dict[str, object]:
    envelope = _mapping(payload)
    if set(envelope) - _ALLOWED_ENVELOPE_KEYS:
        raise BP015SponsoredGroupDefaultProbeError(_UNAVAILABLE)
    if (
        envelope.get("status") != "success"
        or envelope.get("version") != "v7.0.0"
        or type(envelope.get("build")) is not int
        or envelope.get("build") != 29
        or envelope.get("http_method") != "GET"
        or envelope.get("http_status") != 200
        or envelope.get("action") != "default"
        or envelope.get("path") != "user"
        or envelope.get("name") != "group"
    ):
        raise BP015SponsoredGroupDefaultProbeError(_UNAVAILABLE)
    results = _mapping(envelope.get("results"))
    if set(results) != _EXPECTED_RESULTS_KEYS:
        raise BP015SponsoredGroupDefaultProbeError(_UNAVAILABLE)
    if (
        results.get("group-type") != _DEFAULT_GROUP_TYPE
        or results.get("access") != "everyone"
        or type(results.get("id")) is not int
        or results.get("id") != 0
        or results.get("name") != ""
        or type(results.get("group-max-users")) is not int
        or results.get("group-max-users") != 10
        or results.get("user-permission") != []
        or results.get("member") != []
        or results.get("match") != []
    ):
        raise BP015SponsoredGroupDefaultProbeError(_UNAVAILABLE)
    categorical = {
        "default_group_type": _DEFAULT_GROUP_TYPE,
        "version_build_is_7_0_0_build_29": True,
        "default_group_type_is_firewall": True,
        "default_group_access_is_everyone": True,
        "default_group_max_users_is_10": True,
        "default_user_permission_is_empty": True,
        "default_member_is_empty": True,
        "default_match_is_empty": True,
    }
    return {
        **categorical,
        "default_group_digest": _digest(categorical),
        "create_contract_ready": False,
        "device_write_executed": False,
    }


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise BP015SponsoredGroupDefaultProbeError(_UNAVAILABLE)
    return value


def _digest(categorical: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(categorical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


__all__ = [
    "BP015SponsoredGroupDefaultProbeError",
    "DEFAULT_PATH",
    "FortiPamBP015SponsoredGroupDefaultProbe",
    "load_bp015_sponsored_group_default_probe_config",
]
