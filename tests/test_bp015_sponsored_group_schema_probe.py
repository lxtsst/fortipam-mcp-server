from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

import pytest

from fortipam_mcp.bp015_sponsored_group_schema_probe import (
    BP015SponsoredGroupSchemaProbeError,
    FortiPamBP015SponsoredGroupSchemaProbe,
    SCHEMA_PATH,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


class _Response:
    def __init__(self, body: bytes, *, status: int = 200, content_type: str = "application/json") -> None:
        self.status = status
        self._body = body
        self._offset = 0
        self._content_type = content_type
        self.closed = False

    def getheader(self, name: str, default: str = "") -> str:
        return self._content_type if name.lower() == "content-type" else default

    def readinto(self, view: memoryview) -> int:
        remaining = self._body[self._offset :]
        count = min(len(view), len(remaining))
        view[:count] = remaining[:count]
        self._offset += count
        return count

    def close(self) -> None:
        self.closed = True


class _Connection:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.request_args: tuple[object, ...] | None = None
        self.closed = False

    def request(self, *args: object, **kwargs: object) -> None:
        self.request_args = (*args, kwargs)

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True


def _config() -> SecretMetadataHttpTransportConfig:
    return SecretMetadataHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _payload() -> dict[str, object]:
    integer = {
        "category": "",
        "default": 0,
        "help": "must-not-escape",
        "max-value": 2_147_483_647,
        "min-value": 0,
        "multiple_values": False,
        "name": "id",
        "type": "integer",
    }
    option = {
        "category": "",
        "default": "use",
        "help": "must-not-escape",
        "multiple_values": False,
        "name": "permission",
        "options": [
            {"name": "use", "help": "must-not-escape"},
            {"name": "owner", "help": "must-not-escape"},
        ],
        "type": "option",
    }
    user_name_value = {
        "category": "",
        "datasource": "user.local",
        "default": "",
        "help": "must-not-escape",
        "multiple_values": False,
        "name": "name",
        "required": True,
        "size": 128,
        "type": "string",
    }
    table_keys = {
        "category": "",
        "help": "must-not-escape",
        "max_table_size_global": 0,
        "max_table_size_item": 64,
        "max_table_size_vdom": 0,
        "mkey": "id",
        "mkey_type": "integer",
    }
    return {
        "action": "schema",
        "http_status": 200,
        "http_method": "GET",
        "results": {
            "access_group": "",
            "category": "",
            "children": {
                "group-type": {
                    "category": "",
                    "default": "pam-users",
                    "help": "must-not-escape",
                    "multiple_values": False,
                    "name": "group-type",
                    "options": [
                        {"name": name, "help": "must-not-escape"}
                        for name in (
                            "pam-users", "firewall", "sponsor", "fsso-service",
                            "guest", "rsso",
                        )
                    ],
                    "type": "option",
                },
                "group-max-users": {
                    "category": "",
                    "default": 10,
                    "help": "must-not-escape",
                    "max-value": 10_000,
                    "min-value": 1,
                    "multiple_values": False,
                    "name": "group-max-users",
                    "type": "integer",
                },
                "user-permission": {
                    **table_keys,
                    "children": {
                        "id": integer,
                        "permission": option,
                        "user-name": {
                            **table_keys,
                            "children": {"name": user_name_value},
                            "member_table": True,
                            "name": "user-name",
                            "required": False,
                        },
                    },
                    "name": "user-permission",
                },
            },
            "help": "must-not-escape",
            "max_table_size_global": 0,
            "max_table_size_item": 0,
            "max_table_size_vdom": 0,
            "mkey": "name",
            "mkey_type": "string",
            "name": "group",
            "path": "user",
            "q_type": 0,
        },
        "status": "success",
        "version": "v7.0.0",
        "build": 29,
        "vdom": "root",
        "path": "user",
        "name": "group",
    }


def _probe(payload: object) -> tuple[FortiPamBP015SponsoredGroupSchemaProbe, _Connection]:
    response = _Response(json.dumps(payload).encode("utf-8"))
    connection = _Connection(response)
    return (
        FortiPamBP015SponsoredGroupSchemaProbe(
            _config(), connection_factory=lambda *args, **kwargs: connection
        ),
        connection,
    )


def test_inspect_uses_one_fixed_get_and_returns_only_categorical_evidence() -> None:
    probe, connection = _probe(_payload())

    result = probe.inspect()

    expected_digest = hashlib.sha256(
        json.dumps(
            {
                "group-max-users": {"max": 10_000, "min": 1, "type": "integer"},
                "group-type": {
                    "options": [
                        "firewall", "fsso-service", "guest", "pam-users", "rsso", "sponsor"
                    ],
                    "type": "option",
                },
                "user-permission": {
                    "children": {
                        "id": "integer",
                        "permission": {
                            "options": ["owner", "use"],
                            "type": "option",
                        },
                        "user-name": {"children": {"name": "string"}},
                    }
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert result == {
        "version_build_is_7_0_0_build_29": True,
        "group_type_schema_defined": True,
        "group_max_users_schema_defined": True,
        "user_permission_schema_defined": True,
        "group_type_frontend_compatible": True,
        "group_max_users_frontend_compatible": True,
        "user_permission_frontend_compatible": True,
        "schema_digest": expected_digest,
        "device_write_executed": False,
    }
    assert connection.request_args is not None
    assert connection.request_args[0:2] == ("GET", SCHEMA_PATH)
    request_kwargs = connection.request_args[2]
    assert isinstance(request_kwargs, dict)
    headers = request_kwargs["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == "Bearer unit-test-token"
    assert "must-not-escape" not in repr(result)
    assert connection.closed is True


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.__setitem__("version", "v7.0.1"),
        lambda payload: payload.__setitem__("build", 30),
        lambda payload: payload["results"]["children"].pop("group-type"),
        lambda payload: payload["results"]["children"]["group-type"].__setitem__("options", []),
        lambda payload: payload["results"]["children"]["group-max-users"].__setitem__("type", "string"),
        lambda payload: payload["results"]["children"]["user-permission"]["children"].pop("permission"),
        lambda payload: payload["results"]["children"]["user-permission"].__setitem__("unknown", True),
        lambda payload: payload.__setitem__("unexpected", True),
    ),
)
def test_inspect_fails_closed_for_version_field_or_structure_drift(
    mutate: Callable[[dict[str, object]], None],
) -> None:
    payload = _payload()
    mutate(payload)
    probe, _ = _probe(payload)

    with pytest.raises(BP015SponsoredGroupSchemaProbeError, match="unavailable"):
        probe.inspect()


def test_inspect_fails_closed_for_non_json_or_oversized_response() -> None:
    response = _Response(b"{}", content_type="text/html")
    connection = _Connection(response)
    probe = FortiPamBP015SponsoredGroupSchemaProbe(
        _config(), connection_factory=lambda *args, **kwargs: connection
    )

    with pytest.raises(BP015SponsoredGroupSchemaProbeError, match="unavailable"):
        probe.inspect()

    oversized = _Response(b"x" * 1_048_577)
    oversized_connection = _Connection(oversized)
    oversized_probe = FortiPamBP015SponsoredGroupSchemaProbe(
        _config(), connection_factory=lambda *args, **kwargs: oversized_connection
    )
    with pytest.raises(BP015SponsoredGroupSchemaProbeError, match="unavailable"):
        oversized_probe.inspect()
