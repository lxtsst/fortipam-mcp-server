from __future__ import annotations

import hashlib
import json

import pytest

import fortipam_mcp.address_group_delete_http_transport as transport_module
from fortipam_mcp.address_group_delete_http_transport import (
    ADDRESS_GROUP_DELETE_NAME,
    ADDRESS_GROUP_MEMBER_NAME,
    AddressGroupDeleteHttpTransportError,
    FortiPamAddressGroupDeleteHttpTransport,
)
from fortipam_mcp.address_group_ssh_transport import (
    AddressGroupInspection,
    AddressGroupReadback,
    AddressGroupReferenceReadback,
)
from fortipam_mcp.address_http_transport import (
    AddressHttpTransportConfig,
    AddressInspection,
)


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


class _GroupSsh:
    def __init__(self) -> None:
        self.group_exists = True
        self.group_references = 0
        self.calibration_references = 1
        self.readback_verified = True
        self.calls: list[tuple[str, str, str]] = []

    def readback(self, group: str, member: str) -> AddressGroupReadback:
        self.calls.append(("readback", group, member))
        return AddressGroupReadback(
            group_exists=self.readback_verified,
            exactly_one_member_matches=self.readback_verified,
        )

    def reference_readback(
        self,
        group: str,
        member: str,
    ) -> AddressGroupReferenceReadback:
        self.calls.append(("references", group, member))
        return AddressGroupReferenceReadback(
            self.group_references,
            self.calibration_references,
        )

    def inspect(self, group: str) -> AddressGroupInspection:
        self.calls.append(("inspect", group, ""))
        return AddressGroupInspection(self.group_exists)


class _MemberHttp:
    def __init__(self) -> None:
        self.exists = True
        self.is_ipv4_ipmask = True
        self.calls: list[str] = []

    def inspect(self, name: str) -> AddressInspection:
        self.calls.append(name)
        return AddressInspection(self.exists, self.is_ipv4_ipmask)


def _config() -> AddressHttpTransportConfig:
    return AddressHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _record() -> dict[str, object]:
    return {
        "name": ADDRESS_GROUP_DELETE_NAME,
        "q_origin_key": ADDRESS_GROUP_DELETE_NAME,
        "member": [
            {
                "name": ADDRESS_GROUP_MEMBER_NAME,
                "q_origin_key": ADDRESS_GROUP_MEMBER_NAME,
            }
        ],
        "type": "default",
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


def _detail(record: dict[str, object]) -> dict[str, object]:
    return {"results": [record]}


def _transport(
    responses: list[_Response],
    group: _GroupSsh,
    member: _MemberHttp,
    calls: list[dict[str, object]] | None = None,
) -> FortiPamAddressGroupDeleteHttpTransport:
    request_calls = calls if calls is not None else []
    return FortiPamAddressGroupDeleteHttpTransport(
        _config(),
        group,  # type: ignore[arg-type]
        member,  # type: ignore[arg-type]
        client_factory=lambda **_: _Client(responses, request_calls),
        accepted_digest=_digest(_record()),
    )


def test_inspect_requires_complete_digest_projection_member_and_calibrated_refs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    group = _GroupSsh()
    member = _MemberHttp()

    inspection = _transport(
        [_Response(200, _detail(_record()))],
        group,
        member,
    ).inspect_delete_target()

    assert inspection.exists is True
    assert inspection.eligible_fixed_group is True
    assert inspection.group_reference_count == 0
    assert inspection.calibration_address_reference_count == 1
    assert inspection.target_digest == _digest(_record())
    assert group.calls == [
        ("readback", ADDRESS_GROUP_DELETE_NAME, ADDRESS_GROUP_MEMBER_NAME),
        ("references", ADDRESS_GROUP_DELETE_NAME, ADDRESS_GROUP_MEMBER_NAME),
    ]
    assert member.calls == [ADDRESS_GROUP_MEMBER_NAME]


def test_inspect_fails_closed_on_digest_projection_or_member_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    drifted = _record()
    drifted["comment"] = "changed"
    with pytest.raises(AddressGroupDeleteHttpTransportError):
        _transport(
            [_Response(200, _detail(drifted))],
            _GroupSsh(),
            _MemberHttp(),
        ).inspect_delete_target()

    wrong_member = _record()
    wrong_member["member"] = [{"name": "other", "q_origin_key": "other"}]
    transport = FortiPamAddressGroupDeleteHttpTransport(
        _config(),
        _GroupSsh(),  # type: ignore[arg-type]
        _MemberHttp(),  # type: ignore[arg-type]
        client_factory=lambda **_: _Client(
            [_Response(200, _detail(wrong_member))],
            [],
        ),
        accepted_digest=_digest(wrong_member),
    )
    with pytest.raises(AddressGroupDeleteHttpTransportError):
        transport.inspect_delete_target()

    member = _MemberHttp()
    member.exists = False
    with pytest.raises(AddressGroupDeleteHttpTransportError):
        _transport(
            [_Response(200, _detail(_record()))],
            _GroupSsh(),
            member,
        ).inspect_delete_target()


@pytest.mark.parametrize(
    ("group_references", "calibration_references"),
    [(1, 1), (0, 0), (0, 2)],
)
def test_reference_or_calibration_mismatch_is_ineligible(
    monkeypatch: pytest.MonkeyPatch,
    group_references: int,
    calibration_references: int,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    group = _GroupSsh()
    group.group_references = group_references
    group.calibration_references = calibration_references

    inspection = _transport(
        [_Response(200, _detail(_record()))],
        group,
        _MemberHttp(),
    ).inspect_delete_target()

    assert inspection.eligible_fixed_group is False


def test_delete_is_one_exact_bodyless_request_and_preserves_member(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    group = _GroupSsh()
    member = _MemberHttp()
    calls: list[dict[str, object]] = []
    transport = _transport(
        [
            _Response(200, _detail(_record())),
            _Response(200, {"http_status": 200}),
            _Response(404, {"http_status": 404}),
        ],
        group,
        member,
        calls,
    )
    group.group_exists = False

    result = transport.delete_and_readback(_digest(_record()))

    assert result.verified is True
    assert [call["method"] for call in calls] == ["GET", "DELETE", "GET"]
    assert calls[1]["url"] == (
        "https://fpa.example.test/api/v2/cmdb/firewall/addrgrp/"
        "mcp-v4-address-group-b65"
    )
    assert "json" not in calls[1]
    assert "content" not in calls[1]
    assert member.calls == [ADDRESS_GROUP_MEMBER_NAME, ADDRESS_GROUP_MEMBER_NAME]


def test_absent_is_categorical_and_body_input_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = _transport(
        [_Response(404, {"http_status": 404})],
        _GroupSsh(),
        _MemberHttp(),
    )
    inspection = transport.inspect_delete_target()
    assert inspection.exists is False
    assert inspection.eligible_fixed_group is False

    with pytest.raises(AddressGroupDeleteHttpTransportError):
        transport._request("DELETE", transport._detail_path(), {"name": "unsafe"})
