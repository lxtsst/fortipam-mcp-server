from __future__ import annotations

import hashlib
import json

import pytest

import fortipam_mcp.address_delete_http_transport as transport_module
from fortipam_mcp.address_delete_http_transport import (
    ADDRESS_DELETE_NAME,
    AddressDeleteHttpTransportError,
    FortiPamAddressDeleteHttpTransport,
)
from fortipam_mcp.address_group_ssh_transport import AddressSshInspection
from fortipam_mcp.address_http_transport import AddressHttpTransportConfig


class _Response:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self.content = json.dumps(payload).encode("utf-8")
        self.headers = {"content-type": "application/json"}


class _Client:
    def __init__(self, responses: list[_Response], calls: list[dict[str, object]]) -> None:
        self._responses = responses
        self._calls = calls

    def __enter__(self) -> "_Client":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def request(self, method: str, url: str, **kwargs: object) -> _Response:
        self._calls.append({"method": method, "url": url, **kwargs})
        return self._responses.pop(0)


class _Ssh:
    def __init__(self) -> None:
        self.exists = True
        self.references = 0
        self.calls: list[tuple[str, str]] = []

    def inspect_address(self, name: str) -> AddressSshInspection:
        self.calls.append(("inspect", name))
        return AddressSshInspection(self.exists)

    def address_reference_count(self, name: str) -> int:
        self.calls.append(("references", name))
        return self.references


def _config() -> AddressHttpTransportConfig:
    return AddressHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _record() -> dict[str, object]:
    return {
        "name": ADDRESS_DELETE_NAME,
        "q_origin_key": ADDRESS_DELETE_NAME,
        "type": "ipmask",
        "subnet": "198.51.100.0 255.255.255.0",
        "comment": "accepted",
    }


def _digest(record: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            record,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _transport(
    responses: list[_Response],
    ssh: _Ssh,
    calls: list[dict[str, object]] | None = None,
) -> FortiPamAddressDeleteHttpTransport:
    request_calls = calls if calls is not None else []
    return FortiPamAddressDeleteHttpTransport(
        _config(),
        ssh,  # type: ignore[arg-type]
        client_factory=lambda **_: _Client(responses, request_calls),
        accepted_digest=_digest(_record()),
    )


def test_inspect_requires_complete_digest_ipv4_projection_and_zero_refs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    ssh = _Ssh()

    result = _transport(
        [_Response(200, {"results": [_record()]})],
        ssh,
    ).inspect_delete_target()

    assert result.exists is True
    assert result.eligible_fixed_address is True
    assert result.address_reference_count == 0
    assert result.target_digest == _digest(_record())
    assert ssh.calls == [
        ("inspect", ADDRESS_DELETE_NAME),
        ("references", ADDRESS_DELETE_NAME),
    ]


def test_inspect_fails_closed_on_digest_projection_or_ssh_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    drifted = _record()
    drifted["comment"] = "changed"
    with pytest.raises(AddressDeleteHttpTransportError):
        _transport(
            [_Response(200, {"results": [drifted]})],
            _Ssh(),
        ).inspect_delete_target()

    invalid = _record()
    invalid["type"] = "iprange"
    with pytest.raises(AddressDeleteHttpTransportError):
        FortiPamAddressDeleteHttpTransport(
            _config(),
            _Ssh(),  # type: ignore[arg-type]
            client_factory=lambda **_: _Client(
                [_Response(200, {"results": [invalid]})],
                [],
            ),
            accepted_digest=_digest(invalid),
        ).inspect_delete_target()

    ssh = _Ssh()
    ssh.exists = False
    with pytest.raises(AddressDeleteHttpTransportError):
        _transport(
            [_Response(200, {"results": [_record()]})],
            ssh,
        ).inspect_delete_target()


def test_nonzero_reference_is_ineligible(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    ssh = _Ssh()
    ssh.references = 1

    result = _transport(
        [_Response(200, {"results": [_record()]})],
        ssh,
    ).inspect_delete_target()

    assert result.eligible_fixed_address is False
    assert result.address_reference_count == 1


def test_delete_is_one_exact_bodyless_request_with_dual_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    ssh = _Ssh()
    calls: list[dict[str, object]] = []
    transport = _transport(
        [
            _Response(200, {"results": [_record()]}),
            _Response(200, {"http_status": 200}),
            _Response(404, {"http_status": 404}),
        ],
        ssh,
        calls,
    )
    inspect_count = 0

    def inspect_address(name: str) -> AddressSshInspection:
        nonlocal inspect_count
        inspect_count += 1
        ssh.calls.append(("inspect", name))
        return AddressSshInspection(inspect_count == 1)

    monkeypatch.setattr(ssh, "inspect_address", inspect_address)

    result = transport.delete_and_readback(_digest(_record()))

    assert result.verified is True
    assert [call["method"] for call in calls] == ["GET", "DELETE", "GET"]
    assert calls[1]["url"] == (
        "https://fpa.example.test/api/v2/cmdb/firewall/address/"
        "mcp-v4-address-b63"
    )
    assert "json" not in calls[1]
    assert "content" not in calls[1]


def test_absent_is_categorical(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())

    result = _transport(
        [_Response(404, {"http_status": 404})],
        _Ssh(),
    ).inspect_delete_target()

    assert result.exists is False
    assert result.eligible_fixed_address is False
