from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

import pytest

import fortipam_mcp.bp015_sponsored_group_default_probe as probe_module
from fortipam_mcp.bp015_sponsored_group_default_probe import (
    BP015SponsoredGroupDefaultProbeError,
    DEFAULT_PATH,
    FortiPamBP015SponsoredGroupDefaultProbe,
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
    results: dict[str, object] = {
        key: None
        for key in (
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
        )
    }
    results.update(
        {
            "access": "everyone",
            "group-max-users": 10,
            "group-type": "firewall",
            "id": 0,
            "match": [],
            "member": [],
            "name": "",
            "user-permission": [],
        }
    )
    return {
        "action": "default",
        "build": 29,
        "http_method": "GET",
        "http_status": 200,
        "name": "group",
        "path": "user",
        "results": results,
        "serial": "name-id-password-must-not-escape",
        "status": "success",
        "version": "v7.0.0",
    }


def _probe(payload: object) -> tuple[FortiPamBP015SponsoredGroupDefaultProbe, _Connection]:
    connection = _Connection(_Response(json.dumps(payload).encode("utf-8")))
    return (
        FortiPamBP015SponsoredGroupDefaultProbe(
            _config(), connection_factory=lambda *args, **kwargs: connection
        ),
        connection,
    )


def test_inspect_uses_fixed_get_and_projects_only_safe_default_evidence() -> None:
    probe, connection = _probe(_payload())

    result = probe.inspect()

    categorical = {
        "default_group_type": "firewall",
        "version_build_is_7_0_0_build_29": True,
        "default_group_type_is_firewall": True,
        "default_group_access_is_everyone": True,
        "default_group_max_users_is_10": True,
        "default_user_permission_is_empty": True,
        "default_member_is_empty": True,
        "default_match_is_empty": True,
    }
    assert result == {
        **categorical,
        "default_group_digest": hashlib.sha256(
            json.dumps(categorical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "create_contract_ready": False,
        "device_write_executed": False,
    }
    assert connection.request_args is not None
    assert connection.request_args[0:2] == ("GET", DEFAULT_PATH)
    request_kwargs = connection.request_args[2]
    assert isinstance(request_kwargs, dict)
    headers = request_kwargs["headers"]
    assert isinstance(headers, dict)
    assert headers["Accept"] == "application/json"
    assert headers["Authorization"] == "Bearer unit-test-token"
    assert headers["Connection"] == "close"
    assert "name-id-password-must-not-escape" not in repr(result)
    assert "password" not in repr(result).lower()
    assert "name" not in result
    assert "id" not in result
    assert connection.response.closed is True
    assert connection.closed is True


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.__setitem__("version", "v7.0.1"),
        lambda payload: payload.__setitem__("build", 30),
        lambda payload: payload.__setitem__("action", "schema"),
        lambda payload: payload.__setitem__("http_method", "POST"),
        lambda payload: payload.__setitem__("unexpected", True),
        lambda payload: payload["results"].__setitem__("id", 1),
        lambda payload: payload["results"].__setitem__("name", "must-not-escape"),
        lambda payload: payload["results"].__setitem__("group-type", "sponsor"),
        lambda payload: payload["results"].__setitem__("access", "custom"),
        lambda payload: payload["results"].__setitem__("group-max-users", True),
        lambda payload: payload["results"].__setitem__("user-permission", {}),
        lambda payload: payload["results"].__setitem__("member", [{"name": "must-not-escape"}]),
        lambda payload: payload["results"].__setitem__("match", ["must-not-escape"]),
    ),
)
def test_inspect_fails_closed_for_envelope_result_type_or_value_drift(
    mutate: Callable[[dict[str, object]], None],
) -> None:
    payload = _payload()
    mutate(payload)
    probe, _ = _probe(payload)

    with pytest.raises(BP015SponsoredGroupDefaultProbeError, match="unavailable"):
        probe.inspect()


def test_inspect_fails_closed_for_non_json_oversized_or_invalid_json_response() -> None:
    non_json_connection = _Connection(_Response(b"{}", content_type="text/html"))
    non_json_probe = FortiPamBP015SponsoredGroupDefaultProbe(
        _config(), connection_factory=lambda *args, **kwargs: non_json_connection
    )
    with pytest.raises(BP015SponsoredGroupDefaultProbeError, match="unavailable"):
        non_json_probe.inspect()

    oversized_connection = _Connection(_Response(b"x" * (probe_module.MAX_RESPONSE_BYTES + 1)))
    oversized_probe = FortiPamBP015SponsoredGroupDefaultProbe(
        _config(), connection_factory=lambda *args, **kwargs: oversized_connection
    )
    with pytest.raises(BP015SponsoredGroupDefaultProbeError, match="unavailable"):
        oversized_probe.inspect()

    invalid_json_connection = _Connection(_Response(b"{"))
    invalid_json_probe = FortiPamBP015SponsoredGroupDefaultProbe(
        _config(), connection_factory=lambda *args, **kwargs: invalid_json_connection
    )
    with pytest.raises(BP015SponsoredGroupDefaultProbeError, match="unavailable"):
        invalid_json_probe.inspect()


def test_inspect_zeroizes_response_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[bytearray] = []
    original_zeroize = probe_module._zeroize_mutable

    def _zeroize(content: bytearray) -> None:
        observed.append(content)
        original_zeroize(content)

    monkeypatch.setattr(probe_module, "_zeroize_mutable", _zeroize)
    probe, _ = _probe(_payload())

    probe.inspect()

    assert len(observed) == 1
    assert observed[0] == bytearray()
