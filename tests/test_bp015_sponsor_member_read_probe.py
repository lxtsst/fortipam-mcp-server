from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

import pytest

import fortipam_mcp.bp015_sponsor_member_read_probe as module
from fortipam_mcp.bp015_sponsor_member_read_probe import (
    BP015SponsorMemberReadProbeError,
    FortiPamBP015SponsorMemberReadProbe,
    MEMBER_READ_BODY,
    MEMBER_READ_PATH,
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
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _payload() -> dict[str, object]:
    return {
        "build": 29,
        "http_method": "POST",
        "http_status": 200,
        "matched_count": 0,
        "name": "admin",
        "next_idx": 0,
        "path": "system",
        "results": [],
        "serial": "identity-must-not-escape",
        "size": 7,
        "status": "success",
        "version": "v7.0.0",
    }


def _probe(payload: object) -> tuple[FortiPamBP015SponsorMemberReadProbe, _Connection]:
    connection = _Connection(_Response(json.dumps(payload).encode("utf-8")))
    return (
        FortiPamBP015SponsorMemberReadProbe(
            _config(), connection_factory=lambda *args, **kwargs: connection
        ),
        connection,
    )


def test_inspect_uses_exact_frontend_no_match_request_and_safe_evidence() -> None:
    probe, connection = _probe(_payload())

    result = probe.inspect()

    categorical = {
        "route_contract_accepted": True,
        "filter_contract_accepted": True,
        "device_response_accepted": True,
        "member_relation_count_band": "zero",
    }
    assert result == {
        **categorical,
        "member_relation_read_digest": hashlib.sha256(
            json.dumps(categorical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "member_relation_contract_ready": False,
        "device_write_executed": False,
    }
    assert connection.request_args is not None
    assert connection.request_args[:2] == ("POST", MEMBER_READ_PATH)
    request_kwargs = connection.request_args[2]
    assert isinstance(request_kwargs, dict)
    assert request_kwargs["body"] == MEMBER_READ_BODY
    assert json.loads(request_kwargs["body"]) == {
        "json_filter": [
            {"logic": "and", "filters": [{"key": "name", "type": "string", "operator": "exact", "pattern": "invitation_guest", "negate": True}]},
            {"logic": "or", "filters": [{"key": "sponsor-group", "type": "string", "operator": "exact", "pattern": "mcp-v4-bp015-contract-probe-nonexistent", "negate": False}]},
            {"logic": "or", "filters": [{"key": "name", "type": "string", "operator": "exact", "pattern": "invitation_guests", "negate": True}]},
        ]
    }
    headers = request_kwargs["headers"]
    assert isinstance(headers, dict)
    assert headers["Accept"] == "application/json"
    assert headers["Authorization"] == "Bearer unit-test-token"
    assert headers["Content-Type"] == "application/json"
    assert headers["X-HTTP-Method-Override"] == "GET"
    assert "identity-must-not-escape" not in repr(result)
    assert "mcp-v4-bp015-contract-probe-nonexistent" not in repr(result)
    assert "id" not in result
    assert connection.response.closed is True
    assert connection.closed is True


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.__setitem__("version", "v7.0.1"),
        lambda payload: payload.__setitem__("build", 30),
        lambda payload: payload.__setitem__("status", "OK"),
        lambda payload: payload.__setitem__("http_method", "GET"),
        lambda payload: payload.__setitem__("http_status", 201),
        lambda payload: payload.__setitem__("path", "user"),
        lambda payload: payload.__setitem__("name", "group"),
        lambda payload: payload.__setitem__("matched_count", 1),
        lambda payload: payload.__setitem__("next_idx", 1),
        lambda payload: payload.__setitem__("size", True),
        lambda payload: payload.__setitem__("results", [{"name": "identity-must-not-escape", "id": 1}]),
        lambda payload: payload.__setitem__("unexpected", True),
    ),
)
def test_inspect_fails_closed_for_contract_or_no_match_drift(
    mutate: Callable[[dict[str, object]], None],
) -> None:
    payload = _payload()
    mutate(payload)
    probe, _ = _probe(payload)

    with pytest.raises(BP015SponsorMemberReadProbeError, match="unavailable"):
        probe.inspect()


def test_inspect_fails_closed_for_non_json_oversized_and_invalid_json() -> None:
    non_json_probe = FortiPamBP015SponsorMemberReadProbe(
        _config(), connection_factory=lambda *args, **kwargs: _Connection(_Response(b"{}", content_type="text/html"))
    )
    with pytest.raises(BP015SponsorMemberReadProbeError, match="unavailable"):
        non_json_probe.inspect()

    oversized_probe = FortiPamBP015SponsorMemberReadProbe(
        _config(), connection_factory=lambda *args, **kwargs: _Connection(_Response(b"x" * (module.MAX_RESPONSE_BYTES + 1)))
    )
    with pytest.raises(BP015SponsorMemberReadProbeError, match="unavailable"):
        oversized_probe.inspect()

    invalid_json_probe = FortiPamBP015SponsorMemberReadProbe(
        _config(), connection_factory=lambda *args, **kwargs: _Connection(_Response(b"{"))
    )
    with pytest.raises(BP015SponsorMemberReadProbeError, match="unavailable"):
        invalid_json_probe.inspect()


def test_inspect_zeroizes_response_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[bytearray] = []
    original_zeroize = module._zeroize_mutable

    def _zeroize(content: bytearray) -> None:
        observed.append(content)
        original_zeroize(content)

    monkeypatch.setattr(module, "_zeroize_mutable", _zeroize)
    probe, _ = _probe(_payload())

    probe.inspect()

    assert observed == [bytearray()]
