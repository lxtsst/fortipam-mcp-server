from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

import pytest

import fortipam_mcp.bp015_sponsor_member_schema_probe as module
from fortipam_mcp.bp015_sponsor_member_schema_probe import (
    BP015SponsorMemberSchemaProbeError,
    FortiPamBP015SponsorMemberSchemaProbe,
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
        remaining = self._body[self._offset:]
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
        base_url="https://fpa.example.test", bearer_token="unit-test-token",
        timeout_seconds=15, ca_file=None,
    )


def _string(
    name: str,
    default: str,
    *,
    required: bool | None = None,
    datasource: bool = False,
) -> dict[str, object]:
    result: dict[str, object] = {
        "category": "", "default": default, "help": "must-not-escape", "multiple_values": False,
        "name": name, "size": 128, "type": "string",
    }
    if required is not None:
        result["required"] = required
    if datasource:
        result["datasource"] = "unsafe-device-specific-source"
    return result


def _option(name: str, default: str) -> dict[str, object]:
    return {
        "category": "", "default": default, "help": "must-not-escape", "multiple_values": False,
        "name": name, "options": [
            {"help": "must-not-escape", "name": "enable"},
            {"help": "must-not-escape", "name": "disable"},
        ], "type": "option",
    }


def _payload() -> dict[str, object]:
    return {
        "action": "schema", "build": 29, "http_method": "GET", "http_status": 200,
        "name": "admin", "path": "system", "status": "success", "version": "v7.0.0",
        "vdom": "root", "results": {
            "access_group": "", "category": "", "help": "must-not-escape",
            "max_table_size_global": 0, "max_table_size_item": 0, "max_table_size_vdom": 0,
            "mkey": "name", "mkey_type": "string", "name": "admin", "path": "system", "q_type": 0,
            "children": {
                "name": _string("name", ""),
                "accprofile": _string(
                    "accprofile", "pam_standard_user", required=True, datasource=True
                ),
                "schedule": _string("schedule", ""),
                "sponsor-group": _string("sponsor-group", ""),
                "status": _option("status", "enable"),
                "remote-auth": _option("remote-auth", "disable"),
                "unexamined-device-field": {"any": "value"},
            },
        },
    }


def _probe(payload: object) -> tuple[FortiPamBP015SponsorMemberSchemaProbe, _Connection]:
    connection = _Connection(_Response(json.dumps(payload).encode("utf-8")))
    return FortiPamBP015SponsorMemberSchemaProbe(
        _config(), connection_factory=lambda *args, **kwargs: connection,
    ), connection


def test_inspect_uses_exact_get_and_returns_only_non_disclosing_evidence() -> None:
    probe, connection = _probe(_payload())

    result = probe.inspect()

    expected_digest = hashlib.sha256(json.dumps({
        "name": {"type": "string", "default": ""},
        "accprofile": {"type": "string", "default": "pam_standard_user", "required": True},
        "schedule": {"type": "string", "default": ""},
        "sponsor-group": {"type": "string", "default": ""},
        "status": {"type": "option", "default": "enable", "options": ["disable", "enable"]},
        "remote-auth": {"type": "option", "default": "disable", "options": ["disable", "enable"]},
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    assert result == {
        "version_build_is_7_0_0_build_29": True,
        "name_schema_defined": True, "accprofile_schema_defined": True,
        "schedule_schema_defined": True, "sponsor_group_schema_defined": True,
        "status_schema_defined": True, "remote_auth_schema_defined": True,
        "member_schema_frontend_compatible": True, "schema_digest": expected_digest,
        "member_relation_contract_ready": False, "device_write_executed": False,
    }
    assert connection.request_args is not None
    assert connection.request_args[:2] == ("GET", SCHEMA_PATH)
    request_kwargs = connection.request_args[2]
    assert isinstance(request_kwargs, dict)
    assert request_kwargs["headers"]["Authorization"] == "Bearer unit-test-token"
    assert "must-not-escape" not in repr(result)
    assert "unsafe-device-specific-source" not in repr(result)
    assert connection.closed is True


@pytest.mark.parametrize("mutate", (
    lambda payload: payload.__setitem__("version", "v7.0.1"),
    lambda payload: payload.__setitem__("build", 30),
    lambda payload: payload.__setitem__("unexpected", True),
    lambda payload: payload["results"].__setitem__("unexpected", True),
    lambda payload: payload["results"]["children"]["accprofile"].__setitem__("default", "Guest"),
    lambda payload: payload["results"]["children"]["schedule"].__setitem__("type", "option"),
    lambda payload: payload["results"]["children"]["status"].__setitem__("options", []),
    lambda payload: payload["results"]["children"]["remote-auth"]["options"][0].__setitem__("extra", True),
))
def test_inspect_fails_closed_for_schema_drift(mutate: Callable[[dict[str, object]], None]) -> None:
    payload = _payload()
    mutate(payload)
    probe, _ = _probe(payload)

    with pytest.raises(BP015SponsorMemberSchemaProbeError, match="unavailable"):
        probe.inspect()


def test_inspect_fails_closed_for_non_json_oversize_and_zeroizes_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    zeroized: list[bytearray] = []

    def capture_zeroize(content: bytearray) -> None:
        zeroized.append(content)
        content[:] = b"\x00" * len(content)

    monkeypatch.setattr(module, "_zeroize_mutable", capture_zeroize)
    response = _Response(b"{}", content_type="text/html")
    probe = FortiPamBP015SponsorMemberSchemaProbe(
        _config(), connection_factory=lambda *args, **kwargs: _Connection(response),
    )
    with pytest.raises(BP015SponsorMemberSchemaProbeError, match="unavailable"):
        probe.inspect()
    assert zeroized and set(zeroized[0]) == {0}

    oversized_probe = FortiPamBP015SponsorMemberSchemaProbe(
        _config(), connection_factory=lambda *args, **kwargs: _Connection(_Response(b"x" * 1_048_577)),
    )
    with pytest.raises(BP015SponsorMemberSchemaProbeError, match="unavailable"):
        oversized_probe.inspect()
